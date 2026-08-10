"""macOS key-candidate acquisition using a bundled, read-only Mach helper."""
from __future__ import annotations

from collections import Counter
import hashlib
import os
import plistlib
import re
import select
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from chatlog_keeper.core._path_resolver import data_dir

_LAST_ERROR = ""
_DEBUGGER_ENTITLEMENTS = {"com.apple.security.cs.debugger": True}
_HELPER_FORMAT = b"hardened-runtime-same-uid-pid-identity-owner-watch-v6"
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
_LaunchPathIdentity = tuple[int, int, int, int]


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
        elif "owner_process_lost" in line:
            codes.add("owner_process_lost")
        elif line.strip():
            codes.add("helper_error")
    return codes


def _safe_helper_error(returncode: int, codes: set[str]) -> str:
    for preferred in (
        "process_identity_mismatch",
        "process_identity_unavailable",
        "invalid_process_identity",
        "owner_process_lost",
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
    _LAST_ERROR = ""
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


def _parsed_recorded_helper(
    record: dict[str, Any],
) -> tuple[Path, _ProcessIdentity, bytes, tuple[int, int]]:
    """验证持久化字段，但不要求旧 artifact 仍存在。"""

    required = {
        "schema",
        "operation_id",
        "source",
        "path_hex",
        "pid",
        "start_sec",
        "start_usec",
        "file_digest_hex",
        "file_device",
        "file_inode",
    }
    if (
        type(record) is not dict
        or set(record) != required
        or record.get("schema") not in {
            "chatlog-keeper.key-recovery-macos-helper.v1",
            "chatlog-keeper.key-recovery-macos-watchdog.v1",
        }
        or record.get("source") not in {"qq", "wechat"}
        or type(record.get("operation_id")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", record["operation_id"]) is None
        or type(record.get("path_hex")) is not str
        or type(record.get("file_digest_hex")) is not str
        or type(record.get("pid")) is not int
        or record["pid"] <= 0
        or type(record.get("start_sec")) is not int
        or record["start_sec"] <= 0
        or type(record.get("start_usec")) is not int
        or not 0 <= record["start_usec"] < 1_000_000
        or type(record.get("file_device")) is not int
        or record["file_device"] < 0
        or type(record.get("file_inode")) is not int
        or record["file_inode"] <= 0
    ):
        raise ValueError("invalid recorded helper")
    try:
        path_bytes = bytes.fromhex(record["path_hex"])
        artifact_digest = bytes.fromhex(record["file_digest_hex"])
    except ValueError as exc:
        raise ValueError("invalid recorded helper") from exc
    if (
        not path_bytes.startswith(b"/")
        or b"\0" in path_bytes
        or len(path_bytes) > 4095
        or len(artifact_digest) != 32
    ):
        raise ValueError("invalid recorded helper")
    helper = Path(os.fsdecode(path_bytes))
    try:
        canonical_bytes = os.fsencode(os.path.abspath(os.fspath(helper)))
    except OSError as exc:
        raise ValueError("invalid recorded helper") from exc
    if (
        canonical_bytes != path_bytes
        or re.fullmatch(r"macos-memory-scan-[0-9a-f]{12}", helper.name) is None
        or helper.parent.name != "bin"
    ):
        raise ValueError("invalid recorded helper")
    return (
        helper,
        (path_bytes, record["start_sec"], record["start_usec"]),
        artifact_digest,
        (record["file_device"], record["file_inode"]),
    )


def _validated_recorded_helper(
    record: dict[str, Any],
) -> tuple[Path, _ProcessIdentity]:
    """重新验证一个 live helper artifact 及其已记录代际。"""

    helper, expected, artifact_digest, file_identity = _parsed_recorded_helper(
        record
    )
    try:
        parent = helper.parent.lstat()
    except OSError as exc:
        raise ValueError("invalid recorded helper") from exc
    if (
        helper.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise ValueError("invalid recorded helper")
    if _validate_helper_artifact(
        helper,
        expected_digest=artifact_digest,
        expected_identity=file_identity,
        require_canonical_path=False,
    ) is None:
        raise ValueError("invalid recorded helper")
    return helper, expected


def _recorded_pid_is_absent(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except (PermissionError, OSError):
        return False
    return False


def _recorded_helper_current_identity(
    helper: Path,
    pid: int,
) -> Optional[_ProcessIdentity]:
    identity = process_identity(pid, helper=helper, timeout=5)
    if identity is not None:
        return identity
    if _recorded_pid_is_absent(pid):
        return None
    # A live/reused PID that cannot be enumerated is not proof that the exact
    # helper generation ended.  Force callers to retain the lease/journal.
    raise OSError("recorded helper process identity is unavailable")


def recorded_helper_is_running(record: dict[str, Any]) -> bool:
    """返回 journal 中 helper 精确代际是否仍存活。"""

    if sys.platform != "darwin":
        return False
    _helper, _expected, _digest, _identity = _parsed_recorded_helper(record)
    if _recorded_pid_is_absent(record["pid"]):
        return False
    try:
        helper, expected = _validated_recorded_helper(record)
    except ValueError:
        if _recorded_pid_is_absent(record["pid"]):
            return False
        raise
    current = _recorded_helper_current_identity(helper, record["pid"])
    return current == expected


def terminate_recorded_helper(record: dict[str, Any]) -> bool:
    """只终止 helper 的精确代际，绝不终止日常聊天客户端。"""

    if sys.platform != "darwin":
        return True
    pid = record["pid"]
    _helper, _expected, _digest, _identity = _parsed_recorded_helper(record)
    if _recorded_pid_is_absent(pid):
        return True
    try:
        helper, expected = _validated_recorded_helper(record)
    except ValueError:
        if _recorded_pid_is_absent(pid):
            return True
        raise
    current = _recorded_helper_current_identity(helper, pid)
    if current is None or current != expected:
        return True
    os.kill(pid, signal.SIGTERM)
    watchdog = (
        record.get("schema")
        == "chatlog-keeper.key-recovery-macos-watchdog.v1"
    )
    deadline = time.monotonic() + (40 if watchdog else 5)
    while time.monotonic() < deadline:
        current = _recorded_helper_current_identity(helper, pid)
        if current is None or current != expected:
            return True
        time.sleep(0.05)
    if watchdog:
        # The watcher owns a bounded late-launch cleanup grace.  SIGKILL here
        # could strand the exact private target it is responsible for.
        return False
    # Revalidate the generation immediately before escalation.  PID reuse or
    # any identity uncertainty fails closed without signaling the new process.
    current = _recorded_helper_current_identity(helper, pid)
    if current != expected:
        return current is None
    os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        current = _recorded_helper_current_identity(helper, pid)
        if current is None or current != expected:
            return True
        time.sleep(0.05)
    return False


def _watchdog_marker(
    process: subprocess.Popen,
    expected: bytes,
    *,
    timeout: float,
) -> bool:
    if process.stdout is None:
        return False
    ready, _, _ = select.select([process.stdout.fileno()], [], [], max(0.1, timeout))
    if not ready:
        return False
    line = process.stdout.readline(len(expected) + 2)
    return line == expected + b"\n"


def request_debug_copy_watchdog_cleanup(
    process: subprocess.Popen,
    *,
    timeout: float = 45.0,
) -> bool:
    """请求已就绪 watcher 清理其私有目标的精确进程代际。"""

    if process.poll() is None and process.stdin is not None:
        try:
            process.stdin.write(b"C")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        return process.wait(timeout=max(1.0, timeout)) == 0
    except subprocess.TimeoutExpired:
        # Killing an uncertain watcher could strand the target it owns.  Keep
        # the durable record active so cross-process control can retry.
        return False
    finally:
        if process.poll() is not None and process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass


def debug_copy_watchdog_is_running(process: subprocess.Popen) -> bool:
    return process.poll() is None


def _launch_path_identity(
    path: Path,
    *,
    expected_type: int,
    expected_permissions: Optional[int] = None,
) -> Optional[_LaunchPathIdentity]:
    """冻结启动路径的属主、设备、inode 和文件类型，并拒绝符号链接。"""

    try:
        info = path.lstat()
    except OSError:
        return None
    file_type = stat.S_IFMT(info.st_mode)
    permissions = stat.S_IMODE(info.st_mode)
    if (
        info.st_uid != os.geteuid()
        or file_type != expected_type
        or stat.S_ISLNK(info.st_mode)
        or permissions & 0o022
        or (
            expected_permissions is not None
            and permissions != expected_permissions
        )
    ):
        return None
    return info.st_uid, info.st_dev, info.st_ino, file_type


def _launch_path_arguments(
    path: Path,
    identity: _LaunchPathIdentity,
) -> list[str]:
    """把已冻结路径编码为不经 shell 解析的 watchdog 参数。"""

    # ``Path.resolve(strict=True)`` preserves the fail-closed canonicalization
    # contract on every supported Python.  ``os.path.realpath(..., strict=)``
    # only gained that keyword after Python 3.9, which is still in our CI and
    # declared support range.
    canonical = path.resolve(strict=True)
    current = canonical.lstat()
    current_identity = (
        current.st_uid,
        current.st_dev,
        current.st_ino,
        stat.S_IFMT(current.st_mode),
    )
    if current_identity != identity or stat.S_ISLNK(current.st_mode):
        raise ValueError("launch path generation changed")
    path_bytes = os.fsencode(canonical)
    if not path_bytes.startswith(b"/") or b"\0" in path_bytes:
        raise ValueError("invalid launch path")
    return [path_bytes.hex(), *(str(value) for value in identity)]


def launch_debug_copy_watchdog(
    source: str,
    executable: Path,
    app_bundle: Path,
    *,
    capture_library: Optional[Path] = None,
    capture_fifo: Optional[Path] = None,
    durable_record: Optional[Callable[[dict[str, Any]], None]] = None,
) -> Optional[subprocess.Popen]:
    """先冻结并记录 watchdog，再授权它启动和清理私有客户端。"""

    global _LAST_ERROR
    _LAST_ERROR = ""
    if sys.platform != "darwin" or source not in {"qq", "wechat"}:
        _LAST_ERROR = "watchdog_unavailable"
        return None
    helper = ensure_helper()
    if helper is None or not _trusted_helper_for_launch(helper):
        if not _LAST_ERROR:
            _LAST_ERROR = "watchdog_unavailable"
        return None
    capture_requested = capture_library is not None or capture_fifo is not None
    if capture_requested and (
        source != "wechat" or capture_library is None or capture_fifo is None
    ):
        _LAST_ERROR = "watchdog_launch_invalid"
        return None
    try:
        executable_identity = _launch_path_identity(
            executable,
            expected_type=stat.S_IFREG,
        )
        app_identity = _launch_path_identity(
            app_bundle,
            expected_type=stat.S_IFDIR,
            expected_permissions=0o700,
        )
        if executable_identity is None or app_identity is None:
            raise ValueError("invalid launch identity")
        argv = [
            str(helper),
            "watch-launch",
            str(os.getpid()),
            *_launch_path_arguments(executable, executable_identity),
            *_launch_path_arguments(app_bundle, app_identity),
        ]
        if capture_requested:
            capture_library_identity = _launch_path_identity(
                capture_library,
                expected_type=stat.S_IFREG,
                expected_permissions=0o700,
            )
            capture_fifo_identity = _launch_path_identity(
                capture_fifo,
                expected_type=stat.S_IFIFO,
                expected_permissions=0o600,
            )
            if (
                capture_library_identity is None
                or capture_fifo_identity is None
            ):
                raise ValueError("invalid capture identity")
            argv.extend(
                _launch_path_arguments(
                    capture_library,
                    capture_library_identity,
                )
            )
            argv.extend(
                _launch_path_arguments(
                    capture_fifo,
                    capture_fifo_identity,
                )
            )
    except (OSError, TypeError, ValueError):
        _LAST_ERROR = "watchdog_launch_invalid"
        return None

    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            close_fds=True,
        )
    except OSError as exc:
        _LAST_ERROR = f"watchdog_launch_failed:{type(exc).__name__}"
        return None
    launch_authorized = False
    try:
        if not _watchdog_marker(process, b"WATCH_ARMED", timeout=10):
            _LAST_ERROR = "watchdog_arm_failed"
            return None
        helper_process_identity = process_identity(
            process.pid,
            helper=helper,
            timeout=5,
        )
        helper_file_identity = _file_digest_and_identity(helper, expected_mode=0o700)
        if helper_process_identity is None or helper_file_identity is None:
            _LAST_ERROR = "watchdog_durable_record_failed"
            return None
        if durable_record is not None:
            helper_path, start_sec, start_usec = helper_process_identity
            durable_record(
                {
                    "source": source,
                    "path_hex": helper_path.hex(),
                    "pid": process.pid,
                    "start_sec": start_sec,
                    "start_usec": start_usec,
                    "file_digest_hex": helper_file_identity[0].hex(),
                    "file_device": helper_file_identity[1],
                    "file_inode": helper_file_identity[2],
                }
            )
        if process.stdin is None:
            _LAST_ERROR = "watchdog_arm_failed"
            return None
        process.stdin.write(b"L")
        process.stdin.flush()
        launch_authorized = True
        if not _watchdog_marker(process, b"WATCH_LAUNCHED", timeout=30):
            _LAST_ERROR = "watchdog_launch_failed"
            return None
        return process
    except Exception:
        _LAST_ERROR = "watchdog_durable_record_failed"
        return None
    finally:
        if process.poll() is None and not launch_authorized:
            try:
                if process.stdin is not None:
                    process.stdin.close()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except (OSError, subprocess.SubprocessError):
                    pass
        elif process.poll() is None and launch_authorized and _LAST_ERROR.startswith(
            "watchdog_"
        ):
            request_debug_copy_watchdog_cleanup(process)


def _run_helper_candidates(
    source: str,
    pid: int,
    *,
    elevate: bool,
    timeout: int,
    expected_identity: Optional[_ProcessIdentity] = None,
    _recovery_helper_notify: Optional[Callable[[dict[str, Any]], None]] = None,
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
        str(os.getpid()),
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

    if _recovery_helper_notify is not None:
        helper_process_identity = process_identity(
            process.pid,
            helper=helper,
            timeout=min(max(1, int(timeout)), 5),
        )
        helper_file_identity = _file_digest_and_identity(
            helper,
            expected_mode=0o700,
        )
        if helper_process_identity is None or helper_file_identity is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            _LAST_ERROR = "helper_durable_record_failed"
            return []
        helper_path, helper_start_sec, helper_start_usec = helper_process_identity
        try:
            _recovery_helper_notify(
                {
                    "source": source,
                    "path_hex": helper_path.hex(),
                    "pid": process.pid,
                    "start_sec": helper_start_sec,
                    "start_usec": helper_start_usec,
                    "file_digest_hex": helper_file_identity[0].hex(),
                    "file_device": helper_file_identity[1],
                    "file_inode": helper_file_identity[2],
                }
            )
        except Exception:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            _LAST_ERROR = "helper_durable_record_failed"
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
    _recovery_helper_notify: Optional[Callable[[dict[str, Any]], None]] = None,
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
        _recovery_helper_notify=_recovery_helper_notify,
    )
    if primary_verify is not None:
        for candidate in candidates:
            if primary_verify(candidate) and verify(candidate):
                return candidate
    for candidate in candidates:
        if verify(candidate):
            return candidate
    return None
