"""Linux key-candidate acquisition for official WeChat / QQ clients.

Passive scans use ``process_vm_readv``. Active extraction launches the official
binary as a child so Yama ``ptrace_scope=1`` still allows the parent to read
it. WeChat may also load a locally built LD_PRELOAD observer when those
symbols are dynamically resolved. Every candidate is HMAC-verified by the
caller before it can be cached.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from chatlog_keeper.core._linux import (
    is_linux,
    official_qq_executables,
    official_wechat_executables,
    process_pids,
    process_pids_for_executable,
)
from chatlog_keeper.core._path_resolver import data_dir
from chatlog_keeper.core._windows_process_memory import ProcessMemoryAccessDenied


_LAST_ERROR = ""
_HELPER_FORMAT = b"linux-readonly-process-vm-readv-ptrace-fallback-v1"
_CAPTURE_FORMAT = b"linux-wechat-ldpreload-sqlite3-pbkdf2-v1"
_RECORD_MAGIC = b"WXK1"
_CAPTURE_SYMBOLS = ("sqlite3_key", "sqlite3_key_v2", "PKCS5_PBKDF2_HMAC")
_RECORD_SIZE = len(_RECORD_MAGIC) + 32
_MAX_BUFFER_BYTES = _RECORD_SIZE * 1024
_SPAWNED: dict[int, subprocess.Popen] = {}


def last_error() -> str:
    return _LAST_ERROR


def clear_last_error() -> None:
    global _LAST_ERROR
    _LAST_ERROR = ""


def _set_error(code: str) -> None:
    global _LAST_ERROR
    _LAST_ERROR = code


def _scripts_dir() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        for cand in (Path(base) / "chatlog_keeper" / "scripts", Path(base) / "scripts"):
            if cand.exists():
                return cand
    return Path(__file__).resolve().parent / "scripts"


def _scan_source_path() -> Path:
    return _scripts_dir() / "linux_memory_scan.c"


def _scan_prebuilt_path() -> Path:
    return _scripts_dir() / "linux_memory_scan"


def _capture_source_path() -> Path:
    return _scripts_dir() / "linux_wechat_key_capture.c"


def _capture_prebuilt_path() -> Path:
    return _scripts_dir() / "linux_wechat_key_capture.so"


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
                (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                or (current.st_mode & 0o777) != 0o700
            ):
                return False
        return True
    except OSError:
        return False


def _compiler() -> Optional[str]:
    for name in ("cc", "gcc", "clang"):
        path = shutil_which(name)
        if path:
            return path
    return None


def shutil_which(name: str) -> Optional[str]:
    import shutil

    return shutil.which(name)


def official_client_executable(source: str) -> Optional[Path]:
    if source == "wechat":
        found = official_wechat_executables()
    else:
        found = official_qq_executables()
    return found[0] if found else None


def _dynamic_symbol_names(path: Path) -> set[str]:
    """Return exported dynamic symbol names from ``nm`` or ``readelf``."""
    commands = (
        ("nm", "-D", "--defined-only", "--", str(path)),
        ("readelf", "-Ws", "--", str(path)),
    )
    names: set[str] = set()
    for argv in commands:
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode != 0 or not completed.stdout:
            continue
        for line in completed.stdout.splitlines():
            parts = line.split()
            if parts:
                names.add(parts[-1])
        if names:
            return names
    return names


def wechat_exports_capture_symbols(executable: Path) -> bool:
    """True only when the official binary (or a sibling .so) exports KDF hooks."""
    try:
        candidates = [executable.resolve()]
    except OSError:
        return False
    parent = candidates[0].parent
    try:
        for sibling in parent.iterdir():
            name = sibling.name
            if ".so" in name and sibling.is_file():
                candidates.append(sibling)
    except OSError:
        pass
    wanted = set(_CAPTURE_SYMBOLS)
    for candidate in candidates:
        if _dynamic_symbol_names(candidate) & wanted:
            return True
    return False


def daily_client_running(source: str) -> bool:
    if source == "wechat":
        return bool(process_pids(("wechat", "WeChat", "weixin")))
    return bool(process_pids(("qq", "QQ")))


def ensure_helper() -> Optional[Path]:
    """Compile or reuse the read-only memory-scan helper."""
    if not is_linux():
        _set_error("helper_platform_unsupported")
        return None
    prebuilt = _scan_prebuilt_path()
    source = _scan_source_path()
    if not prebuilt.is_file() and not source.is_file():
        _set_error("helper_source_missing")
        return None
    digest = hashlib.sha256()
    digest.update((prebuilt if prebuilt.is_file() else source).read_bytes())
    digest.update(b"\0")
    digest.update(_HELPER_FORMAT)
    dest = data_dir() / "bin" / f"linux-memory-scan-{digest.hexdigest()[:12]}"
    if dest.is_file() and os.access(dest, os.X_OK):
        return dest
    if not _ensure_private_directory(dest.parent):
        _set_error("helper_compile_failed")
        return None
    if prebuilt.is_file():
        try:
            dest.write_bytes(prebuilt.read_bytes())
            dest.chmod(0o700)
            return dest
        except OSError:
            _set_error("helper_compile_failed")
            return None
    compiler = _compiler()
    if compiler is None:
        _set_error("helper_compile_failed")
        return None
    compiled = subprocess.run(
        [compiler, "-O2", "-Wall", "-Wextra", str(source), "-o", str(dest)],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if compiled.returncode != 0 or not dest.is_file():
        _set_error("helper_compile_failed")
        return None
    dest.chmod(0o700)
    return dest


def ensure_capture_library() -> Optional[Path]:
    """Compile or reuse the WeChat LD_PRELOAD observer."""
    if not is_linux():
        _set_error("capture_platform_unsupported")
        return None
    prebuilt = _capture_prebuilt_path()
    source = _capture_source_path()
    if not prebuilt.is_file() and not source.is_file():
        _set_error("capture_source_missing")
        return None
    digest = hashlib.sha256()
    digest.update((prebuilt if prebuilt.is_file() else source).read_bytes())
    digest.update(b"\0")
    digest.update(_CAPTURE_FORMAT)
    dest = data_dir() / "bin" / f"linux-wechat-key-capture-{digest.hexdigest()[:12]}.so"
    if dest.is_file():
        return dest
    if not _ensure_private_directory(dest.parent):
        _set_error("capture_compile_failed")
        return None
    if prebuilt.is_file():
        try:
            dest.write_bytes(prebuilt.read_bytes())
            dest.chmod(0o700)
            return dest
        except OSError:
            _set_error("capture_compile_failed")
            return None
    compiler = _compiler()
    if compiler is None:
        _set_error("capture_compile_failed")
        return None
    compiled = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            str(source),
            "-o",
            str(dest),
            "-ldl",
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if compiled.returncode != 0 or not dest.is_file():
        _set_error("capture_compile_failed")
        return None
    dest.chmod(0o700)
    return dest


@dataclass
class CaptureChannel:
    path: Path
    fd: int
    buffer: bytearray = field(default_factory=bytearray)
    invalid: bool = False

    def read_candidates(self) -> list[bytes]:
        if self.invalid:
            return []
        try:
            chunk = os.read(self.fd, 4096)
        except BlockingIOError:
            return []
        except OSError:
            self.invalid = True
            return []
        if chunk:
            self.buffer.extend(chunk)
        if len(self.buffer) > _MAX_BUFFER_BYTES:
            self.invalid = True
            return []
        found: list[bytes] = []
        while len(self.buffer) >= _RECORD_SIZE:
            record = bytes(self.buffer[:_RECORD_SIZE])
            del self.buffer[:_RECORD_SIZE]
            if record[:4] != _RECORD_MAGIC:
                self.invalid = True
                return []
            found.append(record[4:])
        return found

    def close(self) -> bool:
        try:
            os.close(self.fd)
        except OSError:
            pass
        try:
            info = self.path.lstat()
            if stat.S_ISFIFO(info.st_mode):
                self.path.unlink()
            return True
        except OSError:
            return False


def create_capture_channel() -> Optional[CaptureChannel]:
    root = data_dir() / "bin"
    if not _ensure_private_directory(root):
        _set_error("capture_channel_prepare_failed")
        return None
    fd, name = tempfile.mkstemp(prefix="wechat-key-", suffix=".fifo", dir=str(root))
    os.close(fd)
    path = Path(name)
    try:
        path.unlink()
        os.mkfifo(path, 0o600)
        path.chmod(0o600)
        info = path.lstat()
        if (
            not stat.S_ISFIFO(info.st_mode)
            or info.st_uid != os.geteuid()
            or (info.st_mode & 0o777) != 0o600
        ):
            path.unlink(missing_ok=True)
            _set_error("capture_channel_prepare_failed")
            return None
        read_fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        path.unlink(missing_ok=True)
        _set_error("capture_channel_prepare_failed")
        return None
    return CaptureChannel(path=path, fd=read_fd)


def spawn_official_client(
    source: str,
    *,
    capture_library: Optional[Path] = None,
    capture_fifo: Optional[Path] = None,
) -> Optional[int]:
    """Launch the official client as a child of this process."""
    if not is_linux():
        _set_error("helper_platform_unsupported")
        return None
    if daily_client_running(source):
        _set_error("daily_client_single_instance_conflict")
        return None
    executable = official_client_executable(source)
    if executable is None:
        _set_error("official_client_not_found")
        return None
    env = os.environ.copy()
    if capture_library is not None and capture_fifo is not None:
        env["LD_PRELOAD"] = str(capture_library)
        env["CHATLOG_KEEPER_WECHAT_KEY_FIFO"] = str(capture_fifo)
    try:
        proc = subprocess.Popen(
            [str(executable)],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        _set_error("official_client_launch_failed")
        return None
    _SPAWNED[proc.pid] = proc
    return proc.pid


def validate_spawned_process(source: str, pid: int) -> bool:
    executable = official_client_executable(source)
    if executable is None:
        return False
    return pid in process_pids_for_executable(executable) or pid in _SPAWNED


def terminate_spawned(pid: int) -> bool:
    proc = _SPAWNED.pop(pid, None)
    try:
        os.killpg(pid, signal.SIGTERM)
    except OSError:
        if proc is not None:
            proc.terminate()
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return True
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.1)
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        if proc is not None:
            proc.kill()
    if proc is not None:
        proc.wait(timeout=3)
    return True


def extract_verified(
    source: str,
    pid: int,
    verify: Callable[[bytes], bool],
    *,
    timeout: int = 120,
) -> Optional[bytes]:
    """Scan one Linux process and return the first HMAC-verified candidate."""
    from chatlog_keeper.core._linux_process_memory import iter_process_memory_chunks

    hex_key_re = __import__("re").compile(rb"x'([0-9a-fA-F]{64,192})'")
    try:
        if source == "wechat":
            for chunk in iter_process_memory_chunks(pid, timeout_s=float(timeout)):
                for match in hex_key_re.finditer(chunk):
                    candidate = bytes.fromhex(match.group(1).decode("ascii")[:64])
                    if verify(candidate):
                        return candidate
        else:
            from chatlog_keeper.qq_db import _is_printable_ascii

            for chunk in iter_process_memory_chunks(pid, timeout_s=float(timeout)):
                i = 0
                n = len(chunk)
                while i < n:
                    if _is_printable_ascii(chunk[i]):
                        j = i
                        while j < n and _is_printable_ascii(chunk[j]):
                            j += 1
                        if j < n and chunk[j] == 0 and (j - i) in (16, 32):
                            candidate = chunk[i:j]
                            if verify(candidate):
                                return candidate
                        i = j + 1
                    else:
                        i += 1
    except ProcessMemoryAccessDenied:
        _set_error("process_access_denied")
        raise
    return None


def extract_verified_with_helper(
    source: str,
    pid: int,
    verify: Callable[[bytes], bool],
    *,
    timeout: int = 120,
) -> Optional[bytes]:
    """Second-pass scan through the compiled ptrace/process_vm_readv helper."""
    helper = ensure_helper()
    if helper is None:
        return None
    try:
        completed = subprocess.run(
            [
                str(helper),
                "--pid",
                str(int(pid)),
                "--kind",
                source,
                "--timeout",
                str(max(1, int(timeout))),
            ],
            capture_output=True,
            timeout=max(2, int(timeout) + 5),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        _set_error("helper_timeout")
        return None
    if completed.returncode == 3:
        _set_error("process_access_denied")
        raise ProcessMemoryAccessDenied()
    for line in completed.stdout.splitlines():
        if line.startswith(b"HEX:") and len(line) >= 68:
            try:
                candidate = bytes.fromhex(line[4:68].decode("ascii"))
            except ValueError:
                continue
            if verify(candidate):
                return candidate
        if line.startswith(b"ASCII:"):
            candidate = line[6:]
            if verify(candidate):
                return candidate
    return None


def extract_qq_passphrase_active(
    *,
    db_path: Optional[str] = None,
    timeout: int = 600,
    analyze_only: bool = False,
    cancel_requested: Optional[Callable[[], bool]] = None,
) -> Optional[bytes]:
    """Spawn official Linux QQ and scan the child for a verified passphrase."""
    clear_last_error()
    if analyze_only:
        ensure_helper()
        return None
    resolved = Path(db_path) if db_path else None
    if resolved is None or not resolved.is_file():
        _set_error("verification_db_missing")
        return None
    from chatlog_keeper import qq_db

    def verify(candidate: bytes) -> bool:
        verification = qq_db._read_qq_verification_bytes(resolved)
        return bool(verification and qq_db._verify_key_qq(candidate, verification))

    pid = spawn_official_client("qq")
    if not pid:
        return None
    try:
        deadline = time.monotonic() + max(1, int(timeout))
        while time.monotonic() < deadline:
            if cancel_requested is not None and cancel_requested():
                return None
            remaining = max(1, int(deadline - time.monotonic()))
            try:
                key = extract_verified("qq", pid, verify, timeout=min(15, remaining))
            except ProcessMemoryAccessDenied:
                key = extract_verified_with_helper(
                    "qq", pid, verify, timeout=min(15, remaining)
                )
            if key:
                latest = qq_db._read_qq_verification_bytes(resolved)
                if latest and qq_db._verify_key_qq(key, latest):
                    return key
            time.sleep(1.0)
        return None
    finally:
        terminate_spawned(pid)


def extract_wechat_key_active(
    *,
    db_path: Optional[str] = None,
    timeout: int = 600,
    analyze_only: bool = False,
    cancel_requested: Optional[Callable[[], bool]] = None,
) -> Optional[bytes]:
    """Spawn official Linux WeChat and collect a verified master key."""
    clear_last_error()
    if analyze_only:
        ensure_helper()
        ensure_capture_library()
        return None
    resolved = Path(db_path) if db_path else None
    if resolved is None or not resolved.is_file():
        _set_error("verification_db_missing")
        return None
    from chatlog_keeper import wechat_db

    def verify(candidate: bytes) -> bool:
        page1 = wechat_db._read_stable_page1(resolved)
        return bool(page1 and wechat_db._verify_key_v4(candidate, page1))

    executable = official_client_executable("wechat")
    capture_library = None
    if executable is not None and wechat_exports_capture_symbols(executable):
        capture_library = ensure_capture_library()
    channel = create_capture_channel() if capture_library is not None else None
    pid = spawn_official_client(
        "wechat",
        capture_library=capture_library if channel is not None else None,
        capture_fifo=channel.path if channel is not None else None,
    )
    if not pid:
        if channel is not None:
            channel.close()
        return None
    try:
        deadline = time.monotonic() + max(1, int(timeout))
        pending: list[bytes] = []
        while time.monotonic() < deadline:
            if cancel_requested is not None and cancel_requested():
                return None
            if channel is not None:
                for candidate in channel.read_candidates():
                    if candidate not in pending:
                        pending.append(candidate)
                for candidate in pending:
                    if verify(candidate):
                        latest = wechat_db._read_stable_page1(resolved)
                        if latest and wechat_db._verify_key_v4(candidate, latest):
                            return candidate
            remaining = max(1, int(deadline - time.monotonic()))
            try:
                key = extract_verified(
                    "wechat", pid, verify, timeout=min(15, remaining)
                )
            except ProcessMemoryAccessDenied:
                key = extract_verified_with_helper(
                    "wechat", pid, verify, timeout=min(15, remaining)
                )
            if key:
                latest = wechat_db._read_stable_page1(resolved)
                if latest and wechat_db._verify_key_v4(key, latest):
                    return key
            time.sleep(1.0)
        return None
    finally:
        terminate_spawned(pid)
        if channel is not None:
            channel.close()
