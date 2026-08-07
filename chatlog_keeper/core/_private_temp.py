"""Private, owner-marked temporary directories for local plaintext artifacts.

The directory is restricted before callers may create plaintext in it.  A
strict owner-PID marker lets a later process scavenge directories left behind
by an uncatchable crash without deleting a live process's working directory.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Iterable, Optional

from chatlog_keeper.core._secrets import (
    _prepare_secret_parent,
    _windows_acl_is_private,
    read_secret_text,
    write_secret_text,
)


OWNER_FILE = ".chatlog-owner-v1"
_LEGACY_SCAVENGE_AGE_SECONDS = 24 * 60 * 60.0
_PREFIX_RE = re.compile(r"[a-z][a-z0-9_]*_")
_SUFFIX_RE = re.compile(r"[A-Za-z0-9_-]+")
_SCAVENGE_LOCK = threading.Lock()
_SCAVENGED_KEYS: set[tuple[str, tuple[str, ...]]] = set()


class PrivateTempLifecycleError(RuntimeError):
    """Stable, path-free failure for a private temporary directory."""


def process_is_alive(pid: int) -> bool:
    """Fail-safe process liveness check used by startup orphan cleanup."""

    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            kernel32.OpenProcess.argtypes = [
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.WaitForSingleObject.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
            ]
            kernel32.WaitForSingleObject.restype = wintypes.DWORD
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.GetLastError.restype = wintypes.DWORD
            handle = kernel32.OpenProcess(0x00100000, False, pid)
            if not handle:
                # ERROR_INVALID_PARAMETER proves that the PID does not exist.
                return kernel32.GetLastError() != 87
            try:
                # Only WAIT_OBJECT_0 proves termination.  Timeout/API failure
                # preserves the directory rather than risking a live owner.
                return kernel32.WaitForSingleObject(handle, 0) != 0
            finally:
                kernel32.CloseHandle(handle)
        except Exception:  # noqa: BLE001 - an uncertain owner is treated as live
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True
    return True


def private_temp_dir_is_safe(path: Path) -> bool:
    """Return whether ``path`` is a real, current-user-only directory."""

    path = Path(path)
    try:
        value = path.lstat()
    except OSError:
        return False
    if (
        not stat.S_ISDIR(value.st_mode)
        or path.is_symlink()
        or getattr(value, "st_file_attributes", 0) & 0x0400
    ):
        return False
    if os.name == "nt":
        return _windows_acl_is_private(path)
    return value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700


def _validated_prefix(prefix: str) -> str:
    if not isinstance(prefix, str) or _PREFIX_RE.fullmatch(prefix) is None:
        raise PrivateTempLifecycleError("private temporary prefix is invalid")
    return prefix


def create_private_temp_dir(prefix: str) -> Path:
    """Create and attest a private directory before any plaintext is written."""

    prefix = _validated_prefix(prefix)
    try:
        path = Path(tempfile.mkdtemp(prefix=prefix))
    except OSError as exc:
        raise PrivateTempLifecycleError(
            "private temporary directory setup failed"
        ) from exc
    try:
        _prepare_secret_parent(path)
        if not write_secret_text(path / OWNER_FILE, f"pid={os.getpid()}\n"):
            raise PermissionError("owner marker unavailable")
        if not private_temp_dir_is_safe(path):
            raise PermissionError("private directory verification failed")
        return path
    except Exception as exc:  # noqa: BLE001 - normalize without leaking a path
        try:
            shutil.rmtree(path)
        except OSError:
            pass
        raise PrivateTempLifecycleError(
            "private temporary directory setup failed"
        ) from exc


def _owner_pid(path: Path) -> Optional[int]:
    owner_text = read_secret_text(path / OWNER_FILE, max_bytes=128)
    owner_match = re.fullmatch(r"pid=([0-9]+)\n?", owner_text or "")
    if owner_match is None:
        return None
    try:
        return int(owner_match.group(1))
    except ValueError:
        return None


def _remove_private_temp_dir(
    path: Path,
    *,
    expected_owner_pid: Optional[int],
    allow_missing_owner: bool,
    retries: int,
    retry_delay: float,
) -> None:
    path = Path(path)
    try:
        initial = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PrivateTempLifecycleError(
            "private temporary plaintext cleanup failed"
        ) from exc
    if not private_temp_dir_is_safe(path):
        raise PrivateTempLifecycleError(
            "private temporary plaintext cleanup failed"
        )
    owner_pid = _owner_pid(path)
    if (
        (owner_pid is None and not allow_missing_owner)
        or (expected_owner_pid is not None and owner_pid != expected_owner_pid)
    ):
        raise PrivateTempLifecycleError(
            "private temporary plaintext cleanup failed"
        )
    identity = (initial.st_dev, initial.st_ino)
    last_error: Optional[BaseException] = None
    for attempt in range(max(1, retries)):
        try:
            current = path.lstat()
        except FileNotFoundError:
            return
        except Exception as exc:  # noqa: BLE001 - normalize cleanup failures
            last_error = exc
            current = None
        if current is not None and (current.st_dev, current.st_ino) != identity:
            raise PrivateTempLifecycleError(
                "private temporary plaintext cleanup failed"
            )
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            return
        except Exception as exc:  # noqa: BLE001 - normalize cleanup failures
            last_error = exc
        else:
            if not path.exists():
                return
            last_error = OSError("temporary directory still exists")
        if attempt + 1 < max(1, retries):
            time.sleep(max(0.0, retry_delay))
    raise PrivateTempLifecycleError(
        "private temporary plaintext cleanup failed"
    ) from last_error


def cleanup_private_temp_dir(
    path: Path,
    *,
    retries: int = 3,
    retry_delay: float = 0.05,
) -> None:
    """Delete one current-process directory, retrying transient file locks."""

    _remove_private_temp_dir(
        path,
        expected_owner_pid=os.getpid(),
        allow_missing_owner=False,
        retries=retries,
        retry_delay=retry_delay,
    )


def scavenge_private_temp_dirs(
    prefixes: Iterable[str],
    *,
    temp_root: Optional[Path] = None,
    force: bool = False,
) -> int:
    """Delete safely identified directories owned by terminated processes."""

    normalized_prefixes = tuple(sorted({_validated_prefix(item) for item in prefixes}))
    root = Path(temp_root) if temp_root is not None else Path(tempfile.gettempdir())
    key = (str(root.resolve()), normalized_prefixes)
    with _SCAVENGE_LOCK:
        if key in _SCAVENGED_KEYS and not force:
            return 0
        _SCAVENGED_KEYS.add(key)
    try:
        candidates = list(root.iterdir())
    except OSError as exc:
        raise PrivateTempLifecycleError(
            "private temporary plaintext scavenger failed"
        ) from exc
    removed = 0
    now = time.time()
    for candidate in candidates:
        prefix = next(
            (item for item in normalized_prefixes if candidate.name.startswith(item)),
            None,
        )
        if prefix is None or _SUFFIX_RE.fullmatch(candidate.name[len(prefix):]) is None:
            continue
        if candidate.parent != root:
            raise PrivateTempLifecycleError(
                "private temporary plaintext scavenger failed"
            )
        try:
            # Legacy directories created with tempfile.mkdtemp may predate the
            # explicit ACL contract.  Tighten them before reading a marker or
            # deciding whether their live owner must be preserved.
            _prepare_secret_parent(candidate)
        except (OSError, ValueError) as exc:
            raise PrivateTempLifecycleError(
                "private temporary plaintext scavenger failed"
            ) from exc
        if not private_temp_dir_is_safe(candidate):
            raise PrivateTempLifecycleError(
                "private temporary plaintext scavenger failed"
            )
        owner_pid = _owner_pid(candidate)
        allow_missing_owner = owner_pid is None
        if owner_pid is not None:
            if process_is_alive(owner_pid):
                continue
        else:
            try:
                age = now - candidate.stat().st_mtime
            except OSError as exc:
                raise PrivateTempLifecycleError(
                    "private temporary plaintext scavenger failed"
                ) from exc
            if age < _LEGACY_SCAVENGE_AGE_SECONDS:
                continue
        try:
            _remove_private_temp_dir(
                candidate,
                expected_owner_pid=owner_pid,
                allow_missing_owner=allow_missing_owner,
                retries=3,
                retry_delay=0.05,
            )
        except PrivateTempLifecycleError as exc:
            raise PrivateTempLifecycleError(
                "private temporary plaintext scavenger failed"
            ) from exc
        removed += 1
    return removed
