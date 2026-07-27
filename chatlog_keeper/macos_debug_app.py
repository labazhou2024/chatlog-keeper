"""Create an isolated, reversible debug-enabled copy of a macOS chat client.

The signed app in ``/Applications`` is never modified.  Explicit ``active``
extraction may launch this private copy so Apple's task-port policy can be met
without disabling SIP or weakening the user's daily client.
"""
from __future__ import annotations

import hashlib
import plistlib
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from chatlog_keeper.core._path_resolver import data_dir

_APPS = {
    "wechat": (Path("/Applications/WeChat.app"), "WeChat"),
    "qq": (Path("/Applications/QQ.app"), "QQ"),
}
_DEBUG_COPY_FORMAT = (
    b"preserve-nested-signatures-v4-executable-provenance-marker"
)


def _run(argv: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _app_identity(app: Path) -> str:
    info = (app / "Contents" / "Info.plist").read_bytes()
    try:
        metadata = plistlib.loads(info)
    except Exception as exc:
        raise OSError("app bundle has an invalid Info.plist") from exc
    executable_name = metadata.get("CFBundleExecutable")
    if not isinstance(executable_name, str) or not executable_name:
        raise OSError("app bundle has no CFBundleExecutable")
    executable = app / "Contents" / "MacOS" / executable_name
    digest = hashlib.sha256()
    digest.update(info)
    with executable.open("rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    digest.update(b"\0chatlog-keeper-debug-copy\0")
    digest.update(_DEBUG_COPY_FORMAT)
    return digest.hexdigest()[:12]


def _entitlements(app: Path) -> Optional[dict]:
    proc = _run(["codesign", "-d", "--entitlements", ":-", str(app)], timeout=30)
    raw = (proc.stdout or proc.stderr).encode("utf-8", errors="replace")
    start = raw.find(b"<?xml")
    if start < 0:
        return None
    try:
        value = plistlib.loads(raw[start:])
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _verified_debug_copy(
    target: Path,
    marker: Path,
    expected_identity: str,
) -> bool:
    if not marker.is_file():
        return False
    try:
        if marker.read_text(encoding="ascii").strip() != expected_identity:
            return False
    except (OSError, UnicodeError):
        return False
    current = _entitlements(target) or {}
    verified = _run(
        ["codesign", "--verify", "--deep", "--strict", str(target)], timeout=60
    )
    return (
        verified.returncode == 0
        and current.get("com.apple.security.get-task-allow") is True
    )


def prepare_debug_copy(source: str) -> Optional[Path]:
    """Return a verified debug-enabled app copy, or ``None`` on failure."""
    if sys.platform != "darwin" or source not in _APPS:
        return None
    original, _ = _APPS[source]
    if not original.is_dir():
        return None
    try:
        identity = _app_identity(original)
    except OSError:
        return None

    root = data_dir() / "debug-apps"
    target = root / f"{original.stem}-{identity}.app"
    marker = (
        target
        / "Contents"
        / "Resources"
        / ".chatlog-keeper-debug-copy"
    )
    if marker.is_file():
        if _verified_debug_copy(target, marker, identity):
            return target
        return None

    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    if target.exists():
        # A partial or foreign directory is never overwritten automatically.
        return None
    # Build and sign in a private staging directory. A failed ditto/codesign is
    # removed automatically and can be retried; the canonical target appears
    # only after every verification gate passes.
    with tempfile.TemporaryDirectory(
        prefix=f".{original.stem}-{identity}-", dir=str(root)
    ) as temporary:
        stage_root = Path(temporary)
        stage = stage_root / target.name
        copied = _run(["/usr/bin/ditto", str(original), str(stage)], timeout=600)
        if copied.returncode != 0:
            return None

        entitlements = _entitlements(original)
        if entitlements is None:
            return None
        entitlements["com.apple.security.get-task-allow"] = True
        ent_path = stage_root / "entitlements.plist"
        ent_path.write_bytes(plistlib.dumps(entitlements, fmt=plistlib.FMT_XML))
        stage_marker = (
            stage
            / "Contents"
            / "Resources"
            / ".chatlog-keeper-debug-copy"
        )
        # The provenance marker is covered by the final bundle resource seal.
        stage_marker.parent.mkdir(parents=True, exist_ok=True)
        stage_marker.write_text(identity, encoding="ascii")

        signed = _run(
            [
                "codesign",
                "--force",
                "--sign",
                "-",
                "--entitlements",
                str(ent_path),
                str(stage),
            ],
            timeout=600,
        )
        if signed.returncode != 0 or not _verified_debug_copy(
            stage, stage_marker, identity
        ):
            return None
        try:
            stage.replace(target)
        except OSError:
            # Another process may have won the same deterministic directory
            # rename race.  macOS can report this as ENOTEMPTY/EEXIST rather
            # than Python's FileExistsError.  Only accept the winner after the
            # complete signature + entitlement + marker verification gate;
            # every other rename error still fails closed.
            return (
                target
                if _verified_debug_copy(target, marker, identity)
                else None
            )
    return (
        target if _verified_debug_copy(target, marker, identity) else None
    )


def _wait_for_stable_pid(
    executable: Path,
    *,
    wait_s: float,
    settle_s: float,
) -> Optional[int]:
    """Return an exact executable PID only after it survives ``settle_s``."""
    from chatlog_keeper.core._macos import process_pids_for_executable

    wait_s = max(0.0, wait_s)
    settle_s = min(max(0.0, settle_s), wait_s)
    deadline = time.monotonic() + wait_s
    first_seen: dict[int, float] = {}
    while True:
        now = time.monotonic()
        current = set(process_pids_for_executable(executable))
        for pid in tuple(first_seen):
            if pid not in current:
                del first_seen[pid]
        for pid in sorted(current):
            first_seen.setdefault(pid, now)
            if now - first_seen[pid] >= settle_s:
                return pid
        if now >= deadline:
            return None
        time.sleep(min(0.25, max(0.0, deadline - now)))


def launch_debug_copy(
    source: str,
    wait_s: float = 15.0,
    settle_s: float = 5.0,
) -> Optional[int]:
    """Launch the isolated copy and return a stable, exact main PID.

    Current WeChat/QQ builds can briefly create a process and then exit when a
    signed daily client already owns the single-instance lock.  A transient
    PID must never be handed to ``task_for_pid``: it produces a misleading SIP
    denial and an unnecessary administrator prompt.
    """
    target = prepare_debug_copy(source)
    if not target:
        return None
    executable = target / "Contents" / "MacOS" / _APPS[source][1]

    from chatlog_keeper.core._macos import process_pids_for_executable
    if process_pids_for_executable(executable):
        existing = _wait_for_stable_pid(
            executable,
            wait_s=min(wait_s, max(settle_s, 0.0)),
            settle_s=settle_s,
        )
        if existing:
            return existing

    launched = _run(["/usr/bin/open", "-n", str(target)], timeout=30)
    if launched.returncode != 0:
        return None
    return _wait_for_stable_pid(
        executable,
        wait_s=wait_s,
        settle_s=settle_s,
    )
