"""macOS key-candidate acquisition using a bundled, read-only Mach helper."""
from __future__ import annotations

from collections import Counter
import hashlib
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Optional

from chatlog_keeper.core._path_resolver import data_dir

_LAST_ERROR = ""
_DEBUGGER_ENTITLEMENTS = {"com.apple.security.cs.debugger": True}


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
    digest.update(_debugger_entitlements_bytes())
    short_digest = digest.hexdigest()[:12]
    return data_dir() / "bin" / f"macos-memory-scan-{short_digest}"


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
        and entitlements.get("com.apple.security.cs.debugger") is True
    )


def ensure_helper() -> Optional[Path]:
    """Compile and ad-hoc sign our own helper; never modifies chat clients."""
    global _LAST_ERROR
    if sys.platform != "darwin":
        return None
    source = _source_path()
    prebuilt = _prebuilt_path()
    if not source.is_file() and not prebuilt.is_file():
        _LAST_ERROR = "helper_source_missing"
        return None
    helper = _helper_path()
    if helper.is_file() and os.access(helper, os.X_OK):
        try:
            if _has_debugger_entitlement(helper):
                return helper
        except (OSError, subprocess.TimeoutExpired):
            pass
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.parent.chmod(0o700)
    temporary = helper.with_name(f".{helper.name}.{os.getpid()}.tmp")
    entitlements = helper.with_name(
        f".{helper.name}.{os.getpid()}.entitlements.plist"
    )
    try:
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
        entitlements.write_bytes(_debugger_entitlements_bytes())
        entitlements.chmod(0o600)
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
        if not _has_debugger_entitlement(temporary):
            _LAST_ERROR = "helper_debugger_entitlement_missing"
            return None
        os.replace(temporary, helper)
        return helper
    except subprocess.TimeoutExpired:
        _LAST_ERROR = "helper_build_timeout"
        return None
    except OSError as exc:
        _LAST_ERROR = f"helper_build_failed:{type(exc).__name__}"
        return None
    finally:
        for cleanup in (temporary, entitlements):
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


def _run_helper(source: str, pid: int, *, elevate: bool, timeout: int) -> str:
    global _LAST_ERROR
    _LAST_ERROR = ""
    helper = ensure_helper()
    if not helper:
        if not _LAST_ERROR:
            _LAST_ERROR = "helper_unavailable"
        return ""
    argv = [str(helper), source, str(int(pid))]
    if not elevate:
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired:
            _LAST_ERROR = "helper_timeout"
            return ""
        except OSError as exc:
            _LAST_ERROR = f"helper_launch_failed:{type(exc).__name__}"
            return ""
        if proc.returncode:
            _LAST_ERROR = (proc.stderr or f"helper_exit_{proc.returncode}").strip()
            return ""
        return proc.stdout
    command = " ".join(shlex.quote(part) for part in argv)
    # AppleScript string literals use double quotes, unlike Python repr().
    escaped = command.replace("\\", "\\\\").replace('"', '\\"')
    script = f'do shell script "{escaped}" with administrator privileges'
    try:
        proc = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _LAST_ERROR = "helper_timeout"
        return ""
    except OSError as exc:
        _LAST_ERROR = f"authorization_launch_failed:{type(exc).__name__}"
        return ""
    if proc.returncode:
        _LAST_ERROR = (proc.stderr or f"osascript_exit_{proc.returncode}").strip()
        return ""
    return proc.stdout


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


def extract_verified(
    source: str,
    pid: int,
    verify: Callable[[bytes], bool],
    *,
    primary_verify: Optional[Callable[[bytes], bool]] = None,
    elevate: bool = False,
    timeout: int = 120,
) -> Optional[bytes]:
    """Return the first DB-verified candidate; unverified bytes are discarded.

    ``primary_verify`` is an optional fast oracle for the current client
    format.  A primary match is always confirmed by the full ``verify`` oracle.
    If the primary pass finds nothing, the full verifier still checks every
    ranked candidate so older client formats remain supported.
    """
    marker = "QQ" if source == "qq" else "WX"
    text = _run_helper(source, pid, elevate=elevate, timeout=timeout)
    expected = (16, 32) if source == "qq" else (32,)
    candidates = _rank_candidates(text, marker, expected)
    if primary_verify is not None:
        for candidate in candidates:
            if primary_verify(candidate) and verify(candidate):
                return candidate
    for candidate in candidates:
        if verify(candidate):
            return candidate
    return None
