"""macOS key-candidate acquisition using a bundled, read-only Mach helper."""
from __future__ import annotations

from collections import Counter
import hashlib
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Callable, Iterable, Optional

from chatlog_keeper.core._path_resolver import data_dir

_LAST_ERROR = ""
_DEBUGGER_ENTITLEMENTS = {"com.apple.security.cs.debugger": True}
_HELPER_FORMAT = b"hardened-runtime-same-uid-pid-identity-v3"
_RUNTIME_FLAGS_RE = re.compile(
    r"^CodeDirectory\b[^\n]*\bflags=0x[0-9a-f]+\([^\n)]*\bruntime\b[^\n)]*\)",
    re.IGNORECASE | re.MULTILINE,
)
_TEAM_IDENTIFIER_RE = re.compile(
    r"^TeamIdentifier=(?P<team>[^\r\n]+)$",
    re.MULTILINE,
)
_MAX_CANDIDATE_LINES = 1_000_000
_MAX_UNIQUE_CANDIDATES = 250_000
_TRUSTED_HELPER: Optional[tuple[bytes, Path, bytes, int, int]] = None

_ProcessIdentity = tuple[bytes, int, int]


def _source_path() -> Path:
    return Path(__file__).resolve().parent / "scripts" / "macos_memory_scan.c"


def _prebuilt_path() -> Path:
    return Path(__file__).resolve().parent / "scripts" / "macos_memory_scan"


def _helper_input_path() -> Path:
    prebuilt = _prebuilt_path()
    return prebuilt if prebuilt.is_file() else _source_path()


def _debugger_entitlements_bytes() -> bytes:
    return plistlib.dumps(_DEBUGGER_ENTITLEMENTS, fmt=plistlib.FMT_XML)


def _helper_path() -> Path:
    digest = hashlib.sha256()
    digest.update(_helper_input_path().read_bytes())
    digest.update(b"\0chatlog-keeper-debugger-entitlements\0")
    digest.update(_HELPER_FORMAT)
    digest.update(_debugger_entitlements_bytes())
    short_digest = digest.hexdigest()[:12]
    return data_dir() / "bin" / f"macos-memory-scan-{short_digest}"


def _helper_build_digest() -> bytes:
    """Bind one local build to its source/prebuilt bytes and signing policy."""
    digest = hashlib.sha256()
    digest.update(_helper_input_path().read_bytes())
    digest.update(b"\0chatlog-keeper-debugger-entitlements\0")
    digest.update(_HELPER_FORMAT)
    digest.update(_debugger_entitlements_bytes())
    return digest.digest()


def _ensure_private_directory(path: Path) -> bool:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
        ):
            return False
        if (info.st_mode & 0o777) != 0o700:
            path.chmod(0o700)
            current = path.lstat()
            if (
                current.st_dev != info.st_dev
                or current.st_ino != info.st_ino
                or (current.st_mode & 0o777) != 0o700
            ):
                return False
        return True
    except OSError:
        return False


def _file_digest_and_identity(
    path: Path,
    *,
    expected_mode: int,
) -> Optional[tuple[bytes, int, int]]:
    """Hash one no-follow regular-file generation and prove it stayed stable."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or (before.st_mode & 0o777) != expected_mode
        ):
            return None
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        entry = path.lstat()
        stable = (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and (entry.st_dev, entry.st_ino) == (before.st_dev, before.st_ino)
            and not path.is_symlink()
        )
        if not stable:
            return None
        return digest.digest(), before.st_dev, before.st_ino
    except OSError:
        return None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _code_team_identifier(path: Path) -> Optional[str]:
    """Return a Team ID, ``""`` for expected ad-hoc code, else ``None``."""
    try:
        described = subprocess.run(
            ["codesign", "-d", "--verbose=4", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if described.returncode != 0:
        return None
    raw = (described.stdout or "") + "\n" + (described.stderr or "")
    match = _TEAM_IDENTIFIER_RE.search(raw)
    if match is None:
        return None
    team = match.group("team").strip()
    return "" if team.lower() == "not set" else team


def _validate_helper_artifact(
    helper: Path,
    *,
    expected_digest: bytes,
    expected_identity: Optional[tuple[int, int]] = None,
    require_canonical_path: bool = True,
) -> Optional[tuple[int, int]]:
    try:
        actual = Path(os.path.abspath(os.fspath(helper)))
        expected = Path(os.path.abspath(os.fspath(_helper_path())))
    except OSError:
        return None
    if require_canonical_path and actual != expected:
        return None
    if require_canonical_path and not _ensure_private_directory(expected.parent):
        return None
    first = _file_digest_and_identity(actual, expected_mode=0o700)
    if first is None or first[0] != expected_digest:
        return None
    identity = (first[1], first[2])
    if expected_identity is not None and identity != expected_identity:
        return None
    try:
        signed = _has_debugger_entitlement(actual)
        team = _code_team_identifier(actual)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if not signed or team != "":
        return None
    second = _file_digest_and_identity(actual, expected_mode=0o700)
    if second is None or second[0] != expected_digest:
        return None
    if (second[1], second[2]) != identity:
        return None
    return identity


def _trusted_helper_for_launch(helper: Path) -> bool:
    """Revalidate the canonical cached generation immediately before use."""
    global _LAST_ERROR
    try:
        actual = Path(os.path.abspath(os.fspath(helper)))
        canonical = Path(os.path.abspath(os.fspath(_helper_path())))
    except OSError:
        _LAST_ERROR = "helper_validation_failed"
        return False
    # Preserve the private test/embedding hook for an explicitly supplied
    # non-cache helper. The product path always uses the canonical cache path.
    if actual != canonical:
        return True
    trusted = _TRUSTED_HELPER
    if trusted is None:
        _LAST_ERROR = "helper_validation_failed"
        return False
    build_digest, trusted_path, artifact_digest, device, inode = trusted
    try:
        current_build = _helper_build_digest()
    except OSError:
        _LAST_ERROR = "helper_validation_failed"
        return False
    if build_digest != current_build or trusted_path != canonical:
        _LAST_ERROR = "helper_validation_failed"
        return False
    valid = _validate_helper_artifact(
        actual,
        expected_digest=artifact_digest,
        expected_identity=(device, inode),
    )
    if valid is None:
        _LAST_ERROR = "helper_validation_failed"
        return False
    return True


def _has_hardened_runtime(path: Path) -> bool:
    described = subprocess.run(
        ["codesign", "-d", "--verbose=4", str(path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    raw = (described.stdout or "") + "\n" + (described.stderr or "")
    return described.returncode == 0 and bool(_RUNTIME_FLAGS_RE.search(raw))


def _has_debugger_entitlement(helper: Path) -> bool:
    verified = subprocess.run(
        ["codesign", "--verify", "--strict", str(helper)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if verified.returncode != 0:
        return False
    described = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(helper)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    raw = (described.stdout or "") + "\n" + (described.stderr or "")
    start = raw.find("<?xml")
    end = raw.find("</plist>", start)
    if start < 0 or end < 0:
        return False
    try:
        entitlements = plistlib.loads(raw[start:end + len("</plist>")].encode("utf-8"))
    except Exception:
        return False
    return (
        described.returncode == 0
        and isinstance(entitlements, dict)
        and entitlements == _DEBUGGER_ENTITLEMENTS
        and _has_hardened_runtime(helper)
    )


def ensure_helper() -> Optional[Path]:
    """Compile and ad-hoc sign our own helper; never modifies chat clients."""
    global _LAST_ERROR, _TRUSTED_HELPER
    _LAST_ERROR = ""
    if sys.platform != "darwin":
        return None
    source = _source_path()
    prebuilt = _prebuilt_path()
    if not source.is_file() and not prebuilt.is_file():
        _LAST_ERROR = "helper_source_missing"
        return None
    try:
        build_digest = _helper_build_digest()
        helper = _helper_path()
    except OSError:
        _LAST_ERROR = "helper_source_unreadable"
        return None
    trusted = _TRUSTED_HELPER
    if trusted is not None and trusted[:2] == (build_digest, helper):
        artifact_digest, device, inode = trusted[2:]
        if _validate_helper_artifact(
            helper,
            expected_digest=artifact_digest,
            expected_identity=(device, inode),
        ) is not None:
            return helper
    _TRUSTED_HELPER = None
    if not _ensure_private_directory(helper.parent):
        _LAST_ERROR = "helper_cache_directory_invalid"
        return None
    temporary: Optional[Path] = None
    entitlements: Optional[Path] = None
    try:
        temporary_fd, temporary_name = tempfile.mkstemp(
            prefix=f".{helper.name}.",
            suffix=".tmp",
            dir=str(helper.parent),
        )
        os.close(temporary_fd)
        temporary = Path(temporary_name)
        entitlement_fd, entitlement_name = tempfile.mkstemp(
            prefix=f".{helper.name}.",
            suffix=".entitlements.plist",
            dir=str(helper.parent),
        )
        entitlements = Path(entitlement_name)
        with os.fdopen(entitlement_fd, "wb") as handle:
            handle.write(_debugger_entitlements_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        entitlements.chmod(0o600)
        if prebuilt.is_file():
            shutil.copy2(prebuilt, temporary)
        else:
            proc = subprocess.run(
                [
                    "xcrun",
                    "clang",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    str(source),
                    "-o",
                    str(temporary),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.returncode != 0:
                _LAST_ERROR = "helper_compile_failed"
                return None
        temporary.chmod(0o700)
        # Ad-hoc signing makes the helper's code identity explicit. Fail closed:
        # an unsigned helper, or one lacking Apple's debugger entitlement,
        # cannot obtain a task port even when the isolated target explicitly
        # carries get-task-allow.
        signed = subprocess.run(
            [
                "codesign",
                "--force",
                "--sign",
                "-",
                "--identifier",
                "com.memexa.chatlog-keeper.macos-memory-scan",
                "--options",
                "runtime",
                "--entitlements",
                str(entitlements),
                str(temporary),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if signed.returncode != 0:
            _LAST_ERROR = "helper_codesign_failed"
            return None
        artifact = _file_digest_and_identity(temporary, expected_mode=0o700)
        if (
            artifact is None
            or not _has_debugger_entitlement(temporary)
            or _code_team_identifier(temporary) != ""
        ):
            _LAST_ERROR = "helper_signature_validation_failed"
            return None
        if _helper_build_digest() != build_digest:
            _LAST_ERROR = "helper_source_changed_during_build"
            return None
        os.replace(temporary, helper)
        temporary = None
        identity = _validate_helper_artifact(
            helper,
            expected_digest=artifact[0],
        )
        if identity is None:
            _LAST_ERROR = "helper_validation_failed"
            return None
        _TRUSTED_HELPER = (
            build_digest,
            helper,
            artifact[0],
            identity[0],
            identity[1],
        )
        return helper
    except subprocess.TimeoutExpired:
        _LAST_ERROR = "helper_build_timeout"
        return None
    except OSError as exc:
        _LAST_ERROR = f"helper_build_failed:{type(exc).__name__}"
        return None
    finally:
        for cleanup in (temporary, entitlements):
            if cleanup is None:
                continue
            try:
                cleanup.unlink()
            except OSError:
                pass


def _parse_candidates(text: str, marker: str) -> Iterable[bytes]:
    seen = set()
    prefix = marker + ":"
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        raw = line[len(prefix):].strip()
        try:
            value = bytes.fromhex(raw)
        except ValueError:
            continue
        if value not in seen:
            seen.add(value)
            yield value


def _rank_candidates(text: str, marker: str, expected: tuple[int, ...]) -> list[bytes]:
    """Return unique candidates in a source-appropriate verification order.

    The Mach helper emits one line per memory occurrence.  QQ's passphrase is
    normally present many times, while a large Electron process also contains
    tens of thousands of unrelated 16/32-byte strings.  Preserve that frequency
    signal and prefer the current 16-byte QQ format before trying legacy
    32-byte values.  WeChat keeps helper order because its candidates are
    already sparse and all have one expected length.

    Candidate bytes remain process-local: this function never logs or formats
    them for diagnostics.
    """
    if marker != "QQ":
        return [
            candidate
            for candidate in _parse_candidates(text, marker)
            if len(candidate) in expected
        ]

    counts: Counter[bytes] = Counter()
    prefix = marker + ":"
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        raw = line[len(prefix):].strip()
        try:
            value = bytes.fromhex(raw)
        except ValueError:
            continue
        if len(value) in expected:
            counts[value] += 1
    return sorted(
        counts,
        key=lambda value: (
            0 if len(value) == 16 else 1,
            -counts[value],
            value,
        ),
    )


def _stderr_codes(text: str) -> set[str]:
    """Reduce helper stderr to fixed machine codes; never retain raw text."""
    codes: set[str] = set()
    for line in text.splitlines():
        if "task_for_pid:" in line:
            codes.add("process_access_denied")
        elif "process_identity_mismatch" in line:
            codes.add("process_identity_mismatch")
        elif "process_identity_unavailable" in line:
            codes.add("process_identity_unavailable")
        elif "invalid_process_identity" in line:
            codes.add("invalid_process_identity")
        elif line.strip():
            codes.add("helper_error")
    return codes


def _safe_helper_error(returncode: int, codes: set[str]) -> str:
    for preferred in (
        "process_identity_mismatch",
        "process_identity_unavailable",
        "invalid_process_identity",
        "process_access_denied",
    ):
        if preferred in codes:
            return preferred
    return f"helper_exit_{int(returncode)}"


def process_identity(
    pid: int,
    *,
    helper: Optional[Path] = None,
    timeout: int = 10,
) -> Optional[_ProcessIdentity]:
    """Return exact path bytes and kernel start sec/usec for one PID."""
    global _LAST_ERROR
    if not isinstance(pid, int) or pid <= 0:
        _LAST_ERROR = "invalid_process_identity"
        return None
    helper = helper or ensure_helper()
    if helper is None:
        if not _LAST_ERROR:
            _LAST_ERROR = "helper_unavailable"
        return None
    if not _trusted_helper_for_launch(helper):
        return None
    try:
        proc = subprocess.run(
            [str(helper), "identity", str(pid)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, min(int(timeout), 30)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        _LAST_ERROR = "process_identity_timeout"
        return None
    except OSError as exc:
        _LAST_ERROR = f"helper_launch_failed:{type(exc).__name__}"
        return None
    if proc.returncode:
        _LAST_ERROR = _safe_helper_error(
            proc.returncode, _stderr_codes(proc.stderr or "")
        )
        return None
    raw = proc.stdout or ""
    if len(raw) > 2 * 4096 + 128:
        _LAST_ERROR = "invalid_process_identity"
        return None
    lines = raw.splitlines()
    if len(lines) != 1:
        _LAST_ERROR = "invalid_process_identity"
        return None
    parts = lines[0].split(":", 3)
    if len(parts) != 4 or parts[0] != "IDENTITY":
        _LAST_ERROR = "invalid_process_identity"
        return None
    try:
        start_sec = int(parts[1], 10)
        start_usec = int(parts[2], 10)
        path = bytes.fromhex(parts[3])
    except (TypeError, ValueError):
        _LAST_ERROR = "invalid_process_identity"
        return None
    if (
        start_sec <= 0
        or not 0 <= start_usec < 1_000_000
        or not path.startswith(b"/")
        or b"\0" in path
        or len(path) > 4095
    ):
        _LAST_ERROR = "invalid_process_identity"
        return None
    return path, start_sec, start_usec


def _run_helper_candidates(
    source: str,
    pid: int,
    *,
    elevate: bool,
    timeout: int,
    expected_identity: Optional[_ProcessIdentity] = None,
) -> list[bytes]:
    """Stream bounded candidates without retaining the helper transcript."""
    global _LAST_ERROR
    _LAST_ERROR = ""
    if elevate:
        # A helper stored in the user's Application Support directory must
        # never be executed as root. The isolated target carries
        # get-task-allow and the helper carries Apple's debugger entitlement.
        _LAST_ERROR = "privileged_helper_disabled"
        return []
    if source not in {"qq", "wechat"}:
        _LAST_ERROR = "invalid_helper_source"
        return []
    helper = ensure_helper()
    if not helper:
        if not _LAST_ERROR:
            _LAST_ERROR = "helper_unavailable"
        return []
    identity = expected_identity or process_identity(
        pid, helper=helper, timeout=min(timeout, 10)
    )
    if identity is None:
        return []
    path, start_sec, start_usec = identity
    if (
        not path.startswith(b"/")
        or b"\0" in path
        or start_sec <= 0
        or not 0 <= start_usec < 1_000_000
    ):
        _LAST_ERROR = "invalid_process_identity"
        return []
    if not _trusted_helper_for_launch(helper):
        return []

    marker = "QQ" if source == "qq" else "WX"
    expected_lengths = (16, 32) if source == "qq" else (32,)
    prefix = marker + ":"
    counts: Counter[bytes] = Counter()
    order: list[bytes] = []
    seen: set[bytes] = set()
    stderr_codes: set[str] = set()
    state = {"lines": 0, "invalid": False}
    process = None

    argv = [
        str(helper),
        source,
        str(int(pid)),
        str(start_sec),
        str(start_usec),
        path.hex(),
    ]
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        _LAST_ERROR = f"helper_launch_failed:{type(exc).__name__}"
        return []

    def fail_output() -> None:
        state["invalid"] = True
        try:
            process.terminate()
        except OSError:
            pass

    def read_stdout() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            state["lines"] += 1
            if state["lines"] > _MAX_CANDIDATE_LINES or len(line) > 80:
                fail_output()
                return
            stripped = line.rstrip("\r\n")
            if not stripped.startswith(prefix):
                fail_output()
                return
            raw = stripped[len(prefix):]
            if len(raw) not in {length * 2 for length in expected_lengths}:
                fail_output()
                return
            try:
                candidate = bytes.fromhex(raw)
            except ValueError:
                fail_output()
                return
            if len(candidate) not in expected_lengths:
                fail_output()
                return
            counts[candidate] += 1
            if candidate not in seen:
                if len(seen) >= _MAX_UNIQUE_CANDIDATES:
                    fail_output()
                    return
                seen.add(candidate)
                order.append(candidate)

    def read_stderr() -> None:
        assert process.stderr is not None
        for line in process.stderr:
            stderr_codes.update(_stderr_codes(line[:512]))

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    def current_candidates() -> list[bytes]:
        if source == "qq":
            return sorted(
                counts,
                key=lambda value: (
                    0 if len(value) == 16 else 1,
                    -counts[value],
                    value,
                ),
            )
        return list(order)

    try:
        returncode = process.wait(timeout=max(1, int(timeout)))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            _LAST_ERROR = "helper_stream_incomplete"
            return []
        if state["invalid"]:
            _LAST_ERROR = "candidate_output_limit_exceeded"
            return []
        # A login-time address-space scan can legitimately exceed one polling
        # slice. Preserve already parsed candidates only after independently
        # proving that the exact target generation is still alive; the caller
        # still HMAC-verifies every candidate against the local database and
        # rechecks the private process before accepting a key.
        partial = current_candidates()
        if not partial:
            _LAST_ERROR = "helper_timeout"
            return []
        current_identity = process_identity(pid, helper=helper, timeout=5)
        if current_identity != identity:
            if not _LAST_ERROR:
                _LAST_ERROR = "process_identity_mismatch"
            return []
        _LAST_ERROR = ""
        return partial
    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        _LAST_ERROR = "helper_stream_incomplete"
        return []
    if state["invalid"]:
        _LAST_ERROR = "candidate_output_limit_exceeded"
        return []
    if returncode:
        _LAST_ERROR = _safe_helper_error(returncode, stderr_codes)
        return []
    return current_candidates()


def _run_helper(
    source: str,
    pid: int,
    *,
    elevate: bool,
    timeout: int,
    expected_identity: Optional[_ProcessIdentity] = None,
) -> str:
    """Compatibility wrapper returning only bounded, normalized candidates."""
    marker = "QQ" if source == "qq" else "WX"
    candidates = _run_helper_candidates(
        source,
        pid,
        elevate=elevate,
        timeout=timeout,
        expected_identity=expected_identity,
    )
    return "\n".join(f"{marker}:{candidate.hex()}" for candidate in candidates)


def last_error() -> str:
    """Machine-readable diagnostic from the most recent helper invocation."""
    if "task_for_pid:" in _LAST_ERROR:
        return "process_access_denied"
    if "User canceled" in _LAST_ERROR or "-128" in _LAST_ERROR:
        return "authorization_cancelled"
    if (
        "-60007" in _LAST_ERROR
        or "no user interaction was possible" in _LAST_ERROR.lower()
    ):
        return "authorization_interaction_unavailable"
    return _LAST_ERROR


def clear_last_error() -> None:
    """Clear diagnostics before one independent active-key attempt."""
    global _LAST_ERROR
    _LAST_ERROR = ""


def extract_verified(
    source: str,
    pid: int,
    verify: Callable[[bytes], bool],
    *,
    primary_verify: Optional[Callable[[bytes], bool]] = None,
    elevate: bool = False,
    timeout: int = 120,
    expected_identity: Optional[_ProcessIdentity] = None,
) -> Optional[bytes]:
    """Return the first DB-verified candidate; unverified bytes are discarded.

    ``primary_verify`` is an optional fast oracle for the current client
    format.  A primary match is always confirmed by the full ``verify`` oracle.
    If the primary pass finds nothing, the full verifier still checks every
    ranked candidate so older client formats remain supported.
    """
    candidates = _run_helper_candidates(
        source,
        pid,
        elevate=elevate,
        timeout=timeout,
        expected_identity=expected_identity,
    )
    if primary_verify is not None:
        for candidate in candidates:
            if primary_verify(candidate) and verify(candidate):
                return candidate
    for candidate in candidates:
        if verify(candidate):
            return candidate
    return None
