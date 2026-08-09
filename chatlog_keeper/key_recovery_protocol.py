"""交互式取钥使用的私有、无路径生命周期协议。

协议刻意采用文件持久化。调用者未显式启用本协议时，``extract-key`` 保持原有 stdout 合同；
启用后，调用者观察一个原子写入的 owner-only 状态文件，并通过另一个 owner-only 文件请求
取消。两者都不包含原生账号标识、数据库路径、key 内容或 helper 诊断。
"""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, TextIO

from chatlog_keeper.core._secrets import (
    _prepare_secret_parent,
    _windows_acl_is_private,
    _windows_apply_private_acl,
    read_secret_text,
    write_secret_text,
)


REQUEST_SCHEMA = "chatlog-keeper.key-recovery-request.v1"
STATUS_SCHEMA = "chatlog-keeper.key-recovery-status.v1"
CANCEL_SCHEMA = "chatlog-keeper.key-recovery-cancel.v1"
RESULT_SCHEMA = "chatlog-keeper.key-recovery-result.v1"
CONTROL_REQUEST_SCHEMA = "chatlog-keeper.key-recovery-control-request.v1"
CONTROL_RESULT_SCHEMA = "chatlog-keeper.key-recovery-control-result.v1"
METADATA_SCHEMA = "chatlog-keeper.key-recovery-metadata.v1"
OWNER_SCHEMA = "chatlog-keeper.key-recovery-owner.v1"
CAPABILITIES_SCHEMA = "chatlog-keeper.key-recovery-capabilities.v1"
ARTIFACTS_SCHEMA = "chatlog-keeper.key-recovery-artifacts.v1"
MACOS_PROCESS_SCHEMA = "chatlog-keeper.key-recovery-macos-process.v1"
MACOS_HELPER_SCHEMA = "chatlog-keeper.key-recovery-macos-helper.v1"
MACOS_WATCHDOG_SCHEMA = "chatlog-keeper.key-recovery-macos-watchdog.v1"
PRIVATE_TEMP_SCHEMA = "chatlog-keeper.key-recovery-private-temp.v1"
CLEANUP_RECEIPT_SCHEMA = "chatlog-keeper.key-recovery-cleanup-receipt.v1"

_MAX_REQUEST_BYTES = 1024
_MAX_TIMEOUT_SECONDS = 3600
_OPERATION_ID_RE = re.compile(r"[0-9a-f]{64}")
_PHASES = frozenset(
    {"preparing", "client_open", "waiting_key", "verified", "terminal_error"}
)
_TERMINAL_PHASES = frozenset({"verified", "terminal_error"})
_ERROR_CODES = frozenset(
    {
        "cancelled",
        "active_operation_exists",
        "cleanup_failed",
        "client_running",
        "confirmation_required",
        "helper_unavailable",
        "internal_error",
        "invalid_request",
        "not_found",
        "not_terminal",
        "operation_active",
        "operation_exists",
        "owner_lost",
        "source_unavailable",
        "status_unavailable",
        "timed_out",
        "verification_failed",
        "write_failed",
    }
)
_SOURCES = frozenset({"qq", "wechat"})
_LEASE_STATES = frozenset(
    {"held", "released", "orphaned_client", "orphaned_helper", "terminal"}
)
_TERMINAL_RETENTION_SECONDS = 24 * 60 * 60
_CLEANUP_RECEIPT_RETENTION_SECONDS = 30 * 24 * 60 * 60
_MAX_PROCESS_PATH_BYTES = 1024
_MAX_OPERATION_ENTRIES = 4096
_MAX_ELAPSED_MS = (1 << 53) - 1
_OPERATION_FILES = frozenset(
    {
        "status.json",
        "cancel.json",
        "metadata.json",
        "artifacts.json",
        "macos-process.json",
        "macos-helper.json",
        "macos-watchdog.json",
        "private-temp.json",
    }
)
_TRANSITIONS = {
    None: frozenset({"preparing", "terminal_error"}),
    "preparing": frozenset({"client_open", "verified", "terminal_error"}),
    "client_open": frozenset({"waiting_key", "terminal_error"}),
    "waiting_key": frozenset({"verified", "terminal_error"}),
    "verified": frozenset(),
    "terminal_error": frozenset(),
}


def _bounded_elapsed_ms(value: int | float) -> int:
    return min(_MAX_ELAPSED_MS, max(0, int(value)))


class KeyRecoveryProtocolError(RuntimeError):
    """不携带路径且错误码稳定的协议异常。"""

    def __init__(self, code: str):
        normalized = code if code in _ERROR_CODES else "internal_error"
        super().__init__(normalized)
        self.code = normalized


@dataclass(frozen=True)
class KeyRecoveryRequest:
    """从私有 stdin 读取的严格启动请求。"""

    operation_id: str
    timeout_seconds: int
    confirmed: bool


@dataclass(frozen=True)
class KeyRecoveryControlRequest:
    """不携带路径的 status/cancel/cleanup 请求。"""

    operation_id: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def read_request(stream: TextIO) -> KeyRecoveryRequest:
    """读取一个有界且字段精确的 v1 请求，不保留非法值。"""

    try:
        raw = stream.read(_MAX_REQUEST_BYTES + 1)
    except (OSError, UnicodeError) as exc:
        raise KeyRecoveryProtocolError("invalid_request") from exc
    if len(raw.encode("utf-8", errors="replace")) > _MAX_REQUEST_BYTES:
        raise KeyRecoveryProtocolError("invalid_request")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise KeyRecoveryProtocolError("invalid_request") from exc
    if type(payload) is not dict or set(payload) != {
        "schema",
        "operation_id",
        "timeout_seconds",
        "confirmed",
    }:
        raise KeyRecoveryProtocolError("invalid_request")
    operation_id = payload.get("operation_id")
    timeout_seconds = payload.get("timeout_seconds")
    confirmed = payload.get("confirmed")
    if (
        payload.get("schema") != REQUEST_SCHEMA
        or type(operation_id) is not str
        or _OPERATION_ID_RE.fullmatch(operation_id) is None
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= _MAX_TIMEOUT_SECONDS
        or type(confirmed) is not bool
    ):
        raise KeyRecoveryProtocolError("invalid_request")
    return KeyRecoveryRequest(
        operation_id=operation_id,
        timeout_seconds=timeout_seconds,
        confirmed=confirmed,
    )


def read_control_request(stream: TextIO) -> KeyRecoveryControlRequest:
    """读取一个只含 operation ID 的严格控制请求。"""

    try:
        raw = stream.read(_MAX_REQUEST_BYTES + 1)
    except (OSError, UnicodeError) as exc:
        raise KeyRecoveryProtocolError("invalid_request") from exc
    if len(raw.encode("utf-8", errors="replace")) > _MAX_REQUEST_BYTES:
        raise KeyRecoveryProtocolError("invalid_request")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise KeyRecoveryProtocolError("invalid_request") from exc
    if (
        type(payload) is not dict
        or set(payload) != {"schema", "operation_id"}
        or payload.get("schema") != CONTROL_REQUEST_SCHEMA
        or type(payload.get("operation_id")) is not str
        or _OPERATION_ID_RE.fullmatch(payload["operation_id"]) is None
    ):
        raise KeyRecoveryProtocolError("invalid_request")
    return KeyRecoveryControlRequest(operation_id=payload["operation_id"])


def _operation_root() -> Path:
    """返回单一用户 operation 命名空间。

    宿主修改或移除 ``CHATLOG_KEEPER_DATA_DIR`` 后，恢复控制仍须可用。因此 journal 刻意与
    原生 source lease 共用 OS 已知根目录，而不使用可配置的 key/data 缓存根目录。
    """

    try:
        root = _machine_recovery_root() / "operations"
        _prepare_secret_parent(root)
        return root
    except (OSError, PermissionError, ValueError) as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc


def operation_directory(operation_id: str) -> Path:
    """为已验证的随机 ID 解析固定 operation 目录。"""

    if type(operation_id) is not str or _OPERATION_ID_RE.fullmatch(operation_id) is None:
        raise KeyRecoveryProtocolError("invalid_request")
    return _operation_root() / operation_id


def _receipt_root() -> Path:
    try:
        root = _machine_recovery_root() / "cleanup-receipts"
        _prepare_secret_parent(root)
        return root
    except (OSError, PermissionError, ValueError) as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc


def _receipt_path(operation_id: str) -> Path:
    if type(operation_id) is not str or _OPERATION_ID_RE.fullmatch(operation_id) is None:
        raise KeyRecoveryProtocolError("invalid_request")
    return _receipt_root() / f"{operation_id}.json"


def _directory_identity(path: Path) -> tuple[int, int]:
    try:
        value = path.lstat()
    except OSError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    if (
        not stat.S_ISDIR(value.st_mode)
        or path.is_symlink()
        or getattr(value, "st_file_attributes", 0) & 0x0400
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    return value.st_dev, value.st_ino


def _validate_source(source: str) -> str:
    if type(source) is not str or source not in _SOURCES:
        raise KeyRecoveryProtocolError("invalid_request")
    return source


def _windows_local_app_data() -> Path:
    """从操作系统解析当前用户 LocalAppData，并忽略环境变量覆盖。"""

    import ctypes
    from ctypes import wintypes

    class Guid(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    folder_id = Guid(
        0xF1B32785,
        0x6FBA,
        0x4FCF,
        (ctypes.c_ubyte * 8)(0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91),
    )
    value = wintypes.LPWSTR()
    shell32 = ctypes.windll.shell32
    ole32 = ctypes.windll.ole32
    shell32.SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(Guid),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    shell32.SHGetKnownFolderPath.restype = ctypes.c_long
    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    result = shell32.SHGetKnownFolderPath(
        ctypes.byref(folder_id),
        0,
        None,
        ctypes.byref(value),
    )
    if result != 0 or not value.value:
        raise OSError(result, "SHGetKnownFolderPath failed")
    try:
        return Path(value.value)
    finally:
        ole32.CoTaskMemFree(ctypes.cast(value, ctypes.c_void_p))


def _machine_recovery_root() -> Path:
    """返回配置覆盖无法分叉的 OS 用户级命名空间。"""

    try:
        if os.name == "nt":
            base = _windows_local_app_data()
        else:
            import pwd

            base = Path(pwd.getpwuid(os.geteuid()).pw_dir)
            if sys.platform == "darwin":
                base = base / "Library" / "Application Support"
            else:
                base = base / ".local" / "share"
        root = base / "chatlog-keeper" / "runtime" / "key-recovery-v1"
        _prepare_secret_parent(root)
        return root
    except (KeyError, OSError, PermissionError, ValueError) as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc


def _source_lock_path(source: str) -> Path:
    root = _machine_recovery_root() / "leases"
    try:
        _prepare_secret_parent(root)
    except (OSError, PermissionError, ValueError) as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    return root / f"{_validate_source(source)}.lock"


def _source_owner_path(source: str) -> Path:
    return _source_lock_path(source).with_suffix(".owner.json")


class _SourceLock:
    """在进程生命周期内持有的原生非阻塞 source lease。"""

    def __init__(self, source: str):
        self.source = _validate_source(source)
        self.path = _source_lock_path(source)
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            self.fd = os.open(self.path, flags, 0o600)
            if os.name == "nt":
                if not _windows_apply_private_acl(self.path, directory=False):
                    raise PermissionError("lock ACL unavailable")
                if not _windows_acl_is_private(self.path):
                    raise PermissionError("lock ACL invalid")
            else:
                os.fchmod(self.fd, 0o600)
            opened = os.fstat(self.fd)
            current = self.path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or getattr(opened, "st_file_attributes", 0) & 0x0400
                or (opened.st_dev, opened.st_ino)
                != (current.st_dev, current.st_ino)
                or (os.name != "nt" and opened.st_uid != os.geteuid())
            ):
                raise PermissionError("lock identity invalid")
        except (OSError, PermissionError) as exc:
            try:
                os.close(self.fd)
            except (AttributeError, OSError):
                pass
            raise KeyRecoveryProtocolError("status_unavailable") from exc
        self._locked = False
        self._overlapped = None
        self._mutex_handle = None
        self._opened_identity = (opened.st_dev, opened.st_ino)

    def acquire(self) -> bool:
        if self._locked:
            return True
        if os.name == "nt":
            acquired = self._acquire_windows()
        else:
            try:
                import fcntl

                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                acquired = False
            except OSError as exc:
                raise KeyRecoveryProtocolError("status_unavailable") from exc
        self._locked = acquired
        return acquired

    def _acquire_windows(self) -> bool:
        try:
            import ctypes
            import msvcrt
            from ctypes import wintypes

            class Overlapped(ctypes.Structure):
                _fields_ = [
                    ("Internal", ctypes.c_void_p),
                    ("InternalHigh", ctypes.c_void_p),
                    ("Offset", wintypes.DWORD),
                    ("OffsetHigh", wintypes.DWORD),
                    ("hEvent", wintypes.HANDLE),
                ]

            kernel32 = ctypes.windll.kernel32
            kernel32.CreateMutexW.argtypes = [
                ctypes.c_void_p,
                wintypes.BOOL,
                wintypes.LPCWSTR,
            ]
            kernel32.CreateMutexW.restype = wintypes.HANDLE
            kernel32.WaitForSingleObject.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
            ]
            kernel32.WaitForSingleObject.restype = wintypes.DWORD
            kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
            kernel32.ReleaseMutex.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.LockFileEx.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(Overlapped),
            ]
            kernel32.LockFileEx.restype = wintypes.BOOL
            mutex = kernel32.CreateMutexW(
                None,
                False,
                f"Local\\chatlog-keeper-key-recovery-v1-{self.source}",
            )
            if not mutex:
                raise OSError(ctypes.get_last_error(), "CreateMutexW failed")
            wait = kernel32.WaitForSingleObject(mutex, 0)
            if wait == 0x00000102:  # WAIT_TIMEOUT
                kernel32.CloseHandle(mutex)
                return False
            if wait not in {0x00000000, 0x00000080}:  # OBJECT_0 / ABANDONED
                error = ctypes.get_last_error()
                kernel32.CloseHandle(mutex)
                raise OSError(error, "WaitForSingleObject failed")
            overlapped = Overlapped()
            handle = wintypes.HANDLE(msvcrt.get_osfhandle(self.fd))
            if not kernel32.LockFileEx(
                handle,
                0x00000002 | 0x00000001,
                0,
                1,
                0,
                ctypes.byref(overlapped),
            ):
                error = ctypes.get_last_error()
                kernel32.ReleaseMutex(mutex)
                kernel32.CloseHandle(mutex)
                if error in {32, 33, 158}:
                    return False
                raise OSError(error, "LockFileEx failed")
            self._overlapped = overlapped
            self._mutex_handle = mutex
            return True
        except OSError as exc:
            raise KeyRecoveryProtocolError("status_unavailable") from exc

    def release(self) -> None:
        if not self._locked:
            return
        if os.name == "nt":
            try:
                import ctypes
                import msvcrt
                from ctypes import wintypes

                kernel32 = ctypes.windll.kernel32
                handle = wintypes.HANDLE(msvcrt.get_osfhandle(self.fd))
                kernel32.UnlockFileEx(
                    handle,
                    0,
                    1,
                    0,
                    ctypes.byref(self._overlapped),
                )
            except Exception:
                pass
            finally:
                if self._mutex_handle:
                    try:
                        kernel32.ReleaseMutex(self._mutex_handle)
                        kernel32.CloseHandle(self._mutex_handle)
                    except Exception:
                        pass
                    self._mutex_handle = None
        else:
            try:
                import fcntl

                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
        self._locked = False

    def assert_identity(self) -> None:
        """持有期间若规范 lock 条目被换代则立即失败。"""

        try:
            opened = os.fstat(self.fd)
            current = self.path.lstat()
        except OSError as exc:
            raise KeyRecoveryProtocolError("owner_lost") from exc
        if (
            not self._locked
            or (opened.st_dev, opened.st_ino) != self._opened_identity
            or (current.st_dev, current.st_ino) != self._opened_identity
            or not stat.S_ISREG(current.st_mode)
            or getattr(current, "st_file_attributes", 0) & 0x0400
        ):
            raise KeyRecoveryProtocolError("owner_lost")

    def close(self) -> None:
        self.release()
        try:
            os.close(self.fd)
        except OSError:
            pass


def _source_lease_is_held(source: str) -> bool:
    lock = _SourceLock(source)
    try:
        if not lock.acquire():
            return True
        return False
    finally:
        lock.close()


def _read_exact_json(path: Path, *, max_bytes: int = 4096) -> dict | None:
    raw = read_secret_text(path, max_bytes=max_bytes)
    if raw is None:
        return None
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return payload if type(payload) is dict else None


def _owner_payload(source: str) -> dict | None:
    path = _source_owner_path(source)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    payload = _read_exact_json(path)
    if (
        payload is None
        or set(payload) != {"schema", "source", "operation_id"}
        or payload.get("schema") != OWNER_SCHEMA
        or payload.get("source") != source
        or type(payload.get("operation_id")) is not str
        or _OPERATION_ID_RE.fullmatch(payload["operation_id"]) is None
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    return payload


class KeyRecoverySession:
    """一次不可重放的取钥操作及其严格阶段 journal。"""

    def __init__(self, request: KeyRecoveryRequest, *, source: str):
        self.request = request
        self.source = _validate_source(source)
        prune_expired_operations()
        self._started = time.monotonic()
        self._deadline = self._started + request.timeout_seconds
        self._sequence = 0
        self._phase: str | None = None
        self._events: list[dict[str, Any]] = []
        self._cancelled = False
        self._timed_out = False
        self._signal_cancelled = False
        self._source_lock = _SourceLock(self.source)
        if not self._source_lock.acquire():
            self._source_lock.close()
            raise KeyRecoveryProtocolError("active_operation_exists")
        try:
            if _owner_payload(self.source) is not None:
                raise KeyRecoveryProtocolError("active_operation_exists")
        except Exception:
            self._source_lock.close()
            raise
        try:
            receipt_exists = _cleanup_receipt_payload(request.operation_id) is not None
        except Exception:
            self._source_lock.close()
            raise
        if receipt_exists:
            self._source_lock.close()
            raise KeyRecoveryProtocolError("operation_exists")
        operation_dir = operation_directory(request.operation_id)
        try:
            os.mkdir(operation_dir, mode=0o700)
        except FileExistsError as exc:
            self._source_lock.close()
            raise KeyRecoveryProtocolError("operation_exists") from exc
        except OSError as exc:
            self._source_lock.close()
            raise KeyRecoveryProtocolError("status_unavailable") from exc
        try:
            _prepare_secret_parent(operation_dir)
            self._directory = operation_dir
            self._directory_identity = _directory_identity(operation_dir)
            self._status_path = operation_dir / "status.json"
            self._cancel_path = operation_dir / "cancel.json"
            self._metadata_path = operation_dir / "metadata.json"
            metadata = {
                "schema": METADATA_SCHEMA,
                "operation_id": request.operation_id,
                "source": self.source,
                "started_at_unix_ms": int(time.time() * 1000),
                "timeout_seconds": request.timeout_seconds,
            }
            if not write_secret_text(
                self._metadata_path,
                json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
            ):
                raise KeyRecoveryProtocolError("status_unavailable")
            if not write_secret_text(
                self._cancel_path,
                json.dumps(
                    {
                        "schema": CANCEL_SCHEMA,
                        "operation_id": request.operation_id,
                        "cancel": False,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
            ):
                raise KeyRecoveryProtocolError("status_unavailable")
            if not write_secret_text(
                _source_owner_path(self.source),
                json.dumps(
                    {
                        "schema": OWNER_SCHEMA,
                        "source": self.source,
                        "operation_id": request.operation_id,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
            ):
                raise KeyRecoveryProtocolError("status_unavailable")
        except Exception as exc:
            for path in (
                operation_dir / "status.json",
                operation_dir / "cancel.json",
                operation_dir / "metadata.json",
            ):
                try:
                    path.unlink()
                except OSError:
                    pass
            try:
                operation_dir.rmdir()
            except OSError:
                pass
            self._source_lock.close()
            if isinstance(exc, KeyRecoveryProtocolError):
                raise
            raise KeyRecoveryProtocolError("status_unavailable") from exc

    @property
    def operation_id(self) -> str:
        return self.request.operation_id

    @property
    def terminal(self) -> bool:
        return self._phase in _TERMINAL_PHASES

    @property
    def cancel_reason(self) -> str | None:
        if self._timed_out:
            return "timed_out"
        if self._cancelled or self._signal_cancelled:
            return "cancelled"
        return None

    def remaining_seconds(self) -> int:
        return max(1, int(self._deadline - time.monotonic()))

    def _assert_directory_identity(self) -> None:
        self._source_lock.assert_identity()
        if _directory_identity(self._directory) != self._directory_identity:
            raise KeyRecoveryProtocolError("status_unavailable")
        owner = _owner_payload(self.source)
        if owner is None or owner.get("operation_id") != self.operation_id:
            raise KeyRecoveryProtocolError("owner_lost")

    def _elapsed_ms(self) -> int:
        return _bounded_elapsed_ms((time.monotonic() - self._started) * 1000)

    def emit(self, phase: str, *, error_code: str | None = None) -> None:
        """原子发布一个允许的单调阶段转换。"""

        if phase not in _PHASES or phase not in _TRANSITIONS[self._phase]:
            raise KeyRecoveryProtocolError("internal_error")
        if phase == "terminal_error":
            if error_code not in _ERROR_CODES:
                raise KeyRecoveryProtocolError("internal_error")
        elif error_code is not None:
            raise KeyRecoveryProtocolError("internal_error")
        self._assert_directory_identity()
        self._sequence += 1
        event = {
            "sequence": self._sequence,
            "phase": phase,
            "terminal": phase in _TERMINAL_PHASES,
            "error_code": error_code,
            "elapsed_ms": self._elapsed_ms(),
        }
        self._events.append(event)
        payload = {
            "schema": STATUS_SCHEMA,
            "operation_id": self.operation_id,
            **event,
            "lease_state": "held",
            "events": list(self._events),
        }
        if not write_secret_text(
            self._status_path,
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        self._assert_directory_identity()
        self._phase = phase

    def client_opened(self) -> None:
        """精确发布一次客户端已打开和等待 key 阶段。"""

        if self._phase == "preparing":
            self.emit("client_open")
            self.emit("waiting_key")

    def record_artifacts(self, artifacts: list[dict[str, Any]]) -> None:
        """在客户端可能启动前，持久化私有清理对象的精确身份。"""

        self._assert_directory_identity()
        normalized = []
        if type(artifacts) is not list or not 1 <= len(artifacts) <= 4:
            raise KeyRecoveryProtocolError("status_unavailable")
        for item in artifacts:
            if (
                type(item) is not dict
                or set(item) != {"path", "kind", "mode", "device", "inode"}
                or type(item.get("path")) is not str
                or not Path(item["path"]).is_absolute()
                or item.get("kind") not in {"fifo", "file"}
                or item.get("mode") not in {0o600, 0o700}
                or type(item.get("device")) is not int
                or type(item.get("inode")) is not int
                or item["device"] < 0
                or item["inode"] <= 0
            ):
                raise KeyRecoveryProtocolError("status_unavailable")
            normalized.append(dict(item))
        path = self._directory / "artifacts.json"
        payload = {
            "schema": ARTIFACTS_SCHEMA,
            "operation_id": self.operation_id,
            "artifacts": normalized,
        }
        if not write_secret_text(
            path,
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        self._assert_directory_identity()

    def record_macos_process(self, record: dict[str, Any]) -> None:
        """在已验证的隔离启动可能脱离控制前持久化记录。

        该文件刻意保持私有，绝不经控制协议返回。它为后续进程提供隔离 App 的精确路径，以及
        已知后用于崩溃清理的内核进程代际。
        """

        self._assert_directory_identity()
        if type(record) is not dict:
            raise KeyRecoveryProtocolError("status_unavailable")
        required = {
            "state",
            "source",
            "path_hex",
            "pid",
            "start_sec",
            "start_usec",
        }
        if set(record) != required or record.get("source") != self.source:
            raise KeyRecoveryProtocolError("status_unavailable")
        state = record.get("state")
        path_hex = record.get("path_hex")
        try:
            path_bytes = bytes.fromhex(path_hex) if type(path_hex) is str else b""
        except ValueError as exc:
            raise KeyRecoveryProtocolError("status_unavailable") from exc
        if (
            state not in {"launching", "running"}
            or not path_bytes.startswith(b"/")
            or b"\0" in path_bytes
            or len(path_bytes) > _MAX_PROCESS_PATH_BYTES
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        if state == "launching":
            if any(record.get(field) is not None for field in ("pid", "start_sec", "start_usec")):
                raise KeyRecoveryProtocolError("status_unavailable")
        elif (
            type(record.get("pid")) is not int
            or record["pid"] <= 0
            or type(record.get("start_sec")) is not int
            or record["start_sec"] <= 0
            or type(record.get("start_usec")) is not int
            or not 0 <= record["start_usec"] < 1_000_000
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        payload = {
            "schema": MACOS_PROCESS_SCHEMA,
            "operation_id": self.operation_id,
            **record,
        }
        if not write_secret_text(
            self._directory / "macos-process.json",
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        self._assert_directory_identity()

    def record_private_temp(self, record: dict[str, Any]) -> None:
        """启动前记录明文 transcript 目录的精确身份。"""

        self._assert_directory_identity()
        if (
            type(record) is not dict
            or set(record) != {"path", "device", "inode", "owner_pid"}
            or type(record.get("path")) is not str
            or not Path(record["path"]).is_absolute()
            or type(record.get("device")) is not int
            or record["device"] < 0
            or type(record.get("inode")) is not int
            or record["inode"] <= 0
            or type(record.get("owner_pid")) is not int
            or record["owner_pid"] <= 0
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        payload = {
            "schema": PRIVATE_TEMP_SCHEMA,
            "operation_id": self.operation_id,
            **record,
        }
        if not write_secret_text(
            self._directory / "private-temp.json",
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        self._assert_directory_identity()

    def _record_macos_executable(
        self,
        record: dict[str, Any],
        *,
        schema: str,
        filename: str,
    ) -> None:
        self._assert_directory_identity()
        required = {
            "source",
            "path_hex",
            "pid",
            "start_sec",
            "start_usec",
            "file_digest_hex",
            "file_device",
            "file_inode",
        }
        if type(record) is not dict or set(record) != required:
            raise KeyRecoveryProtocolError("status_unavailable")
        try:
            path_bytes = bytes.fromhex(record.get("path_hex", ""))
            digest = bytes.fromhex(record.get("file_digest_hex", ""))
        except (TypeError, ValueError) as exc:
            raise KeyRecoveryProtocolError("status_unavailable") from exc
        if (
            record.get("source") != self.source
            or not path_bytes.startswith(b"/")
            or b"\0" in path_bytes
            or len(path_bytes) > _MAX_PROCESS_PATH_BYTES
            or len(digest) != 32
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
            raise KeyRecoveryProtocolError("status_unavailable")
        payload = {
            "schema": schema,
            "operation_id": self.operation_id,
            **record,
        }
        if not write_secret_text(
            self._directory / filename,
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        self._assert_directory_identity()

    def record_macos_helper(self, record: dict[str, Any]) -> None:
        """记录 memory-scan helper 的精确代际，供崩溃清理使用。"""

        self._record_macos_executable(
            record,
            schema=MACOS_HELPER_SCHEMA,
            filename="macos-helper.json",
        )

    def record_macos_watchdog(self, record: dict[str, Any]) -> None:
        """在允许启动客户端前，持久化已就绪 watchdog 的精确进程代际。"""

        self._record_macos_executable(
            record,
            schema=MACOS_WATCHDOG_SCHEMA,
            filename="macos-watchdog.json",
        )

    def request_signal_cancel(self) -> None:
        self._signal_cancelled = True

    def cancel_requested(self) -> bool:
        """轮询有界的严格 cancel 文件和 monotonic deadline。"""

        self._assert_directory_identity()
        if self._signal_cancelled:
            return True
        if time.monotonic() >= self._deadline:
            self._timed_out = True
            return True
        raw = read_secret_text(self._cancel_path, max_bytes=512)
        if raw is None:
            return False
        try:
            payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if (
            type(payload) is dict
            and set(payload) == {"schema", "operation_id", "cancel"}
            and payload.get("schema") == CANCEL_SCHEMA
            and payload.get("operation_id") == self.operation_id
            and payload.get("cancel") is True
        ):
            self._cancelled = True
            return True
        return False

    def terminal_error(self, error_code: str) -> None:
        if not self.terminal:
            self.emit("terminal_error", error_code=error_code)

    def release_active_lease(self) -> None:
        """释放进程 lease，同时保留清理所需的 owner metadata。"""

        self._source_lock.close()

    def result_payload(self, *, ok: bool, error_code: str | None = None) -> dict:
        """返回私有协议唯一允许的 stdout 结构。"""

        return {
            "schema": RESULT_SCHEMA,
            "operation_id": self.operation_id,
            "ok": bool(ok),
            "terminal": True,
            "error_code": None if ok else error_code,
        }


@contextmanager
def recovery_signal_handlers(session: KeyRecoverySession) -> Iterator[None]:
    """把可捕获的终止信号转换为协作式精确清理。"""

    previous = []

    def request_cancel(_signum, _frame) -> None:
        session.request_signal_cancel()

    for name in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            old_handler = signal.getsignal(signum)
            signal.signal(signum, request_cancel)
        except (OSError, RuntimeError, ValueError):
            continue
        previous.append((signum, old_handler))
    try:
        yield
    finally:
        for signum, old_handler in reversed(previous):
            try:
                signal.signal(signum, old_handler)
            except (OSError, RuntimeError, ValueError):
                pass


def safe_error_result(
    error_code: str,
    *,
    operation_id: str | None = None,
) -> dict:
    """在无法打开 operation 目录时构造不携带路径的结果。"""

    normalized = error_code if error_code in _ERROR_CODES else "internal_error"
    return {
        "schema": RESULT_SCHEMA,
        "operation_id": operation_id,
        "ok": False,
        "terminal": True,
        "error_code": normalized,
    }


def _metadata_payload(operation_id: str) -> dict:
    operation_dir = operation_directory(operation_id)
    try:
        _directory_identity(operation_dir)
    except KeyRecoveryProtocolError as exc:
        try:
            operation_dir.lstat()
        except FileNotFoundError:
            raise KeyRecoveryProtocolError("not_found") from exc
        except OSError:
            pass
        raise
    path = operation_dir / "metadata.json"
    payload = _read_exact_json(path)
    if payload is None:
        raise KeyRecoveryProtocolError("status_unavailable")
    if (
        set(payload)
        != {
            "schema",
            "operation_id",
            "source",
            "started_at_unix_ms",
            "timeout_seconds",
        }
        or payload.get("schema") != METADATA_SCHEMA
        or payload.get("operation_id") != operation_id
        or payload.get("source") not in _SOURCES
        or type(payload.get("started_at_unix_ms")) is not int
        or payload["started_at_unix_ms"] < 0
        or type(payload.get("timeout_seconds")) is not int
        or not 1 <= payload["timeout_seconds"] <= _MAX_TIMEOUT_SECONDS
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    return payload


def _validate_status_payload(payload: dict, operation_id: str) -> dict:
    required = {
        "schema",
        "operation_id",
        "sequence",
        "phase",
        "terminal",
        "error_code",
        "elapsed_ms",
        "lease_state",
        "events",
    }
    if (
        set(payload) != required
        or payload.get("schema") != STATUS_SCHEMA
        or payload.get("operation_id") != operation_id
        or type(payload.get("sequence")) is not int
        or payload["sequence"] < 1
        or payload.get("phase") not in _PHASES
        or type(payload.get("terminal")) is not bool
        or payload.get("lease_state") not in _LEASE_STATES
        or type(payload.get("elapsed_ms")) is not int
        or not 0 <= payload["elapsed_ms"] <= _MAX_ELAPSED_MS
        or type(payload.get("events")) is not list
        or not 1 <= len(payload["events"]) <= len(_PHASES)
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    previous_phase = None
    for index, event in enumerate(payload["events"], 1):
        if (
            type(event) is not dict
            or set(event)
            != {"sequence", "phase", "terminal", "error_code", "elapsed_ms"}
            or event.get("sequence") != index
            or event.get("phase") not in _TRANSITIONS[previous_phase]
            or type(event.get("terminal")) is not bool
            or event["terminal"] != (event["phase"] in _TERMINAL_PHASES)
            or type(event.get("elapsed_ms")) is not int
            or not 0 <= event["elapsed_ms"] <= _MAX_ELAPSED_MS
            or (
                event["phase"] == "terminal_error"
                and event.get("error_code") not in _ERROR_CODES
            )
            or (
                event["phase"] != "terminal_error"
                and event.get("error_code") is not None
            )
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        previous_phase = event["phase"]
    last = payload["events"][-1]
    for field in ("sequence", "phase", "terminal", "error_code", "elapsed_ms"):
        if payload[field] != last[field]:
            raise KeyRecoveryProtocolError("status_unavailable")
    return payload


def _validated_status_payload(operation_id: str) -> dict:
    payload = _read_exact_json(
        operation_directory(operation_id) / "status.json",
        max_bytes=4096,
    )
    if payload is None:
        raise KeyRecoveryProtocolError("status_unavailable")
    return _validate_status_payload(payload, operation_id)


def _cleanup_receipt_payload(operation_id: str) -> dict | None:
    path = _receipt_path(operation_id)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    payload = _read_exact_json(path)
    if (
        payload is None
        or set(payload)
        != {"schema", "operation_id", "source", "cleaned_at_unix_ms", "status"}
        or payload.get("schema") != CLEANUP_RECEIPT_SCHEMA
        or payload.get("operation_id") != operation_id
        or payload.get("source") not in _SOURCES
        or type(payload.get("cleaned_at_unix_ms")) is not int
        or payload["cleaned_at_unix_ms"] < 0
        or type(payload.get("status")) is not dict
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    status = _validate_status_payload(payload["status"], operation_id)
    if not status["terminal"] or status["lease_state"] != "terminal":
        raise KeyRecoveryProtocolError("status_unavailable")
    payload["status"] = status
    return payload


def _write_cleanup_receipt(
    operation_id: str,
    source: str,
    status: dict,
) -> dict:
    safe_source = _validate_source(source)
    safe_status = _validate_status_payload(dict(status), operation_id)
    if not safe_status["terminal"]:
        raise KeyRecoveryProtocolError("not_terminal")
    safe_status["lease_state"] = "terminal"
    existing = _cleanup_receipt_payload(operation_id)
    if existing is not None:
        if (
            existing["source"] != safe_source
            or existing["status"] != safe_status
        ):
            raise KeyRecoveryProtocolError("status_unavailable")
        return existing
    payload = {
        "schema": CLEANUP_RECEIPT_SCHEMA,
        "operation_id": operation_id,
        "source": safe_source,
        "cleaned_at_unix_ms": int(time.time() * 1000),
        "status": safe_status,
    }
    if not write_secret_text(
        _receipt_path(operation_id),
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    receipt = _cleanup_receipt_payload(operation_id)
    if receipt is None:
        raise KeyRecoveryProtocolError("status_unavailable")
    return receipt


def _windows_job_is_active(operation_id: str) -> bool:
    if os.name != "nt":
        return False
    try:
        from chatlog_keeper.active_key import windows_recovery_job_is_active

        return bool(windows_recovery_job_is_active(operation_id))
    except Exception as exc:
        # Only active_key's explicit ERROR_FILE_NOT_FOUND branch returns False.
        # ACCESS_DENIED and all enumeration/system faults are identity-unknown
        # and must block status repair, cleanup, and lease reuse.
        raise KeyRecoveryProtocolError("status_unavailable") from exc


def _terminate_windows_job(operation_id: str) -> bool:
    if os.name != "nt":
        return True
    try:
        from chatlog_keeper.active_key import terminate_windows_recovery_job

        return bool(terminate_windows_recovery_job(operation_id))
    except Exception:
        return False


def _macos_process_payload(operation_id: str, source: str) -> dict | None:
    path = operation_directory(operation_id) / "macos-process.json"
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    payload = _read_exact_json(path)
    required = {
        "schema",
        "operation_id",
        "state",
        "source",
        "path_hex",
        "pid",
        "start_sec",
        "start_usec",
    }
    if (
        payload is None
        or set(payload) != required
        or payload.get("schema") != MACOS_PROCESS_SCHEMA
        or payload.get("operation_id") != operation_id
        or payload.get("source") != source
        or payload.get("state") not in {"launching", "running"}
        or type(payload.get("path_hex")) is not str
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    try:
        path_bytes = bytes.fromhex(payload["path_hex"])
    except ValueError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    if (
        not path_bytes.startswith(b"/")
        or b"\0" in path_bytes
        or len(path_bytes) > _MAX_PROCESS_PATH_BYTES
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    if payload["state"] == "launching":
        if any(payload[field] is not None for field in ("pid", "start_sec", "start_usec")):
            raise KeyRecoveryProtocolError("status_unavailable")
    elif (
        type(payload.get("pid")) is not int
        or payload["pid"] <= 0
        or type(payload.get("start_sec")) is not int
        or payload["start_sec"] <= 0
        or type(payload.get("start_usec")) is not int
        or not 0 <= payload["start_usec"] < 1_000_000
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    return payload


def _macos_executable_payload(
    operation_id: str,
    source: str,
    *,
    filename: str,
    schema: str,
) -> dict | None:
    path = operation_directory(operation_id) / filename
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    payload = _read_exact_json(path)
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
        payload is None
        or set(payload) != required
        or payload.get("schema") != schema
        or payload.get("operation_id") != operation_id
        or payload.get("source") != source
        or type(payload.get("path_hex")) is not str
        or type(payload.get("file_digest_hex")) is not str
        or type(payload.get("pid")) is not int
        or payload["pid"] <= 0
        or type(payload.get("start_sec")) is not int
        or payload["start_sec"] <= 0
        or type(payload.get("start_usec")) is not int
        or not 0 <= payload["start_usec"] < 1_000_000
        or type(payload.get("file_device")) is not int
        or payload["file_device"] < 0
        or type(payload.get("file_inode")) is not int
        or payload["file_inode"] <= 0
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    try:
        path_bytes = bytes.fromhex(payload["path_hex"])
        digest = bytes.fromhex(payload["file_digest_hex"])
    except ValueError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    if (
        not path_bytes.startswith(b"/")
        or b"\0" in path_bytes
        or len(path_bytes) > _MAX_PROCESS_PATH_BYTES
        or len(digest) != 32
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    return payload


def _macos_helper_payload(operation_id: str, source: str) -> dict | None:
    return _macos_executable_payload(
        operation_id,
        source,
        filename="macos-helper.json",
        schema=MACOS_HELPER_SCHEMA,
    )


def _macos_watchdog_payload(operation_id: str, source: str) -> dict | None:
    return _macos_executable_payload(
        operation_id,
        source,
        filename="macos-watchdog.json",
        schema=MACOS_WATCHDOG_SCHEMA,
    )


def _macos_helper_is_active(operation_id: str, source: str) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        from chatlog_keeper.macos_key import recorded_helper_is_running

        record = _macos_helper_payload(operation_id, source)
        if record is None:
            return False
        return bool(recorded_helper_is_running(record))
    except Exception:
        # A malformed record or an uncertain PID/file generation must never
        # authorize owner/journal deletion or another source operation.
        return True


def _macos_watchdog_is_active(operation_id: str, source: str) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        from chatlog_keeper.macos_key import recorded_helper_is_running

        record = _macos_watchdog_payload(operation_id, source)
        if record is None:
            return False
        return bool(recorded_helper_is_running(record))
    except Exception:
        return True


def _macos_orphan_is_active(
    operation_id: str,
    source: str,
    *,
    phase: str | None = None,
) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        from chatlog_keeper.macos_debug_app import (
            recorded_debug_copy_is_running,
        )

        record = _macos_process_payload(operation_id, source)
        if record is None:
            # A client-open journal without its pre-launch record is not safe
            # to declare inactive.  Preparation-only crashes launched nothing.
            return phase in {"client_open", "waiting_key"}
        return bool(recorded_debug_copy_is_running(record))
    except Exception:
        # Enumeration/identity uncertainty must block cleanup and replay.
        return True


def _terminate_macos_orphan(operation_id: str, source: str) -> bool:
    if sys.platform != "darwin":
        return True
    try:
        from chatlog_keeper.macos_debug_app import (
            terminate_recorded_debug_copy,
        )
        from chatlog_keeper.macos_key import terminate_recorded_helper

        helper_record = _macos_helper_payload(operation_id, source)
        if helper_record is not None and not terminate_recorded_helper(helper_record):
            return False
        if _macos_helper_is_active(operation_id, source):
            return False
        watchdog_record = _macos_watchdog_payload(operation_id, source)
        if watchdog_record is not None and not terminate_recorded_helper(
            watchdog_record
        ):
            return False
        if _macos_watchdog_is_active(operation_id, source):
            return False
        process_record = _macos_process_payload(operation_id, source)
        if process_record is not None and not terminate_recorded_debug_copy(
            process_record
        ):
            return False
        return not _macos_orphan_is_active(operation_id, source)
    except Exception:
        return False


def _external_lease_state(
    operation_id: str,
    source: str,
    *,
    phase: str | None,
) -> str | None:
    if _windows_job_is_active(operation_id):
        return "orphaned_helper"
    if _macos_helper_is_active(operation_id, source):
        return "orphaned_helper"
    if _macos_watchdog_is_active(operation_id, source):
        return "orphaned_helper"
    if _macos_orphan_is_active(operation_id, source, phase=phase):
        return "orphaned_client"
    return None


def _write_owner(operation_id: str, source: str) -> None:
    if not write_secret_text(
        _source_owner_path(source),
        json.dumps(
            {
                "schema": OWNER_SCHEMA,
                "source": source,
                "operation_id": operation_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    ):
        raise KeyRecoveryProtocolError("status_unavailable")


def _write_recovered_status(
    operation_id: str,
    metadata: dict,
    *,
    orphan_state: str | None,
) -> dict:
    """用明确的恢复事实替换缺失或损坏的 journal。"""

    terminal = orphan_state is None
    phase = "terminal_error" if terminal else "preparing"
    error_code = "owner_lost" if terminal else None
    elapsed_ms = _bounded_elapsed_ms(
        int(time.time() * 1000) - metadata["started_at_unix_ms"]
    )
    event = {
        "sequence": 1,
        "phase": phase,
        "terminal": terminal,
        "error_code": error_code,
        "elapsed_ms": elapsed_ms,
    }
    payload = {
        "schema": STATUS_SCHEMA,
        "operation_id": operation_id,
        **event,
        "lease_state": "terminal" if terminal else orphan_state,
        "events": [event],
    }
    if not write_secret_text(
        operation_directory(operation_id) / "status.json",
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    return _validated_status_payload(operation_id)


def status_operation(operation_id: str) -> dict:
    """返回状态；仅在 lease 下修复已证明 owner 死亡的操作。"""

    try:
        metadata = _metadata_payload(operation_id)
    except KeyRecoveryProtocolError:
        receipt = _cleanup_receipt_payload(operation_id)
        if receipt is None:
            raise
        return dict(receipt["status"])
    source = metadata["source"]
    source_lock = _SourceLock(source)
    if not source_lock.acquire():
        source_lock.close()
        owner = _owner_payload(source)
        if owner is None or owner.get("operation_id") != operation_id:
            raise KeyRecoveryProtocolError("status_unavailable")
        payload = _validated_status_payload(operation_id)
        payload["lease_state"] = "held"
        return payload
    try:
        owner = _owner_payload(source)
        if owner is None:
            # Owner publication is the final setup write and precedes every
            # external action.  With the source lease free, adopting this exact
            # explicit operation is safe and makes crash cleanup reachable.
            _write_owner(operation_id, source)
        elif owner.get("operation_id") != operation_id:
            raise KeyRecoveryProtocolError("status_unavailable")

        try:
            payload = _validated_status_payload(operation_id)
        except KeyRecoveryProtocolError as exc:
            if exc.code != "status_unavailable":
                raise
            orphan_state = _external_lease_state(
                operation_id,
                source,
                phase=None,
            )
            if orphan_state is None:
                _cleanup_recorded_artifacts(operation_id)
                _cleanup_recorded_private_temp(operation_id)
            payload = _write_recovered_status(
                operation_id,
                metadata,
                orphan_state=orphan_state,
            )
        orphan_state = _external_lease_state(
            operation_id,
            source,
            phase=payload["phase"],
        )
        if orphan_state is None:
            # No process tree can still write these files.  Remove any
            # crash-left candidate transcript/capture channel before publishing
            # or returning a terminal state.
            _cleanup_recorded_artifacts(operation_id)
            _cleanup_recorded_private_temp(operation_id)
            if not payload["terminal"]:
                payload = _write_existing_terminal(
                    operation_id,
                    error_code="owner_lost",
                )
        payload["lease_state"] = (
            orphan_state
            or ("terminal" if payload["terminal"] else "released")
        )
        return payload
    finally:
        source_lock.close()


def _write_existing_terminal(
    operation_id: str,
    *,
    error_code: str,
) -> dict:
    metadata = _metadata_payload(operation_id)
    payload = _validated_status_payload(operation_id)
    if payload["terminal"]:
        return payload
    if error_code not in _ERROR_CODES:
        raise KeyRecoveryProtocolError("internal_error")
    previous_phase = payload["phase"]
    if "terminal_error" not in _TRANSITIONS[previous_phase]:
        raise KeyRecoveryProtocolError("status_unavailable")
    elapsed_ms = _bounded_elapsed_ms(
        max(
            payload["elapsed_ms"],
            int(time.time() * 1000) - metadata["started_at_unix_ms"],
        )
    )
    event = {
        "sequence": payload["sequence"] + 1,
        "phase": "terminal_error",
        "terminal": True,
        "error_code": error_code,
        "elapsed_ms": elapsed_ms,
    }
    payload.update(event)
    payload["lease_state"] = "terminal"
    payload["events"] = [*payload["events"], event]
    if len(payload["events"]) > len(_PHASES):
        raise KeyRecoveryProtocolError("status_unavailable")
    if not write_secret_text(
        operation_directory(operation_id) / "status.json",
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    return payload


def control_result(
    operation_id: str | None,
    *,
    action: str,
    ok: bool,
    terminal: bool,
    error_code: str | None,
    lease_state: str | None,
) -> dict:
    payload = {
        "schema": CONTROL_RESULT_SCHEMA,
        "operation_id": operation_id,
        "action": action,
        "ok": bool(ok),
        "terminal": bool(terminal),
        "error_code": error_code,
        "lease_state": lease_state,
    }
    return payload


def cancel_operation(operation_id: str) -> dict:
    """请求协作取消，或精确清理一个已崩溃操作。"""

    try:
        metadata = _metadata_payload(operation_id)
    except KeyRecoveryProtocolError:
        receipt = _cleanup_receipt_payload(operation_id)
        if receipt is None:
            raise
        status = receipt["status"]
        return control_result(
            operation_id,
            action="cancel",
            ok=True,
            terminal=True,
            error_code=None,
            lease_state="terminal",
        )
    current = status_operation(operation_id)
    if current["terminal"] and current["lease_state"] == "terminal":
        return control_result(
            operation_id,
            action="cancel",
            ok=True,
            terminal=True,
            error_code=None,
            lease_state="terminal",
        )
    cancel_path = operation_directory(operation_id) / "cancel.json"
    if not write_secret_text(
        cancel_path,
        json.dumps(
            {
                "schema": CANCEL_SCHEMA,
                "operation_id": operation_id,
                "cancel": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    ):
        raise KeyRecoveryProtocolError("status_unavailable")
    if current["lease_state"] == "held":
        if _windows_job_is_active(operation_id):
            if not _terminate_windows_job(operation_id):
                raise KeyRecoveryProtocolError("cleanup_failed")
        return control_result(
            operation_id,
            action="cancel",
            ok=True,
            terminal=current["terminal"],
            error_code=None,
            lease_state="held",
        )
    if current["lease_state"] == "orphaned_helper":
        if _windows_job_is_active(operation_id) and not _terminate_windows_job(
            operation_id
        ):
            raise KeyRecoveryProtocolError("cleanup_failed")
        if (
            _macos_helper_is_active(operation_id, metadata["source"])
            or _macos_watchdog_is_active(operation_id, metadata["source"])
        ) and not _terminate_macos_orphan(operation_id, metadata["source"]):
            raise KeyRecoveryProtocolError("cleanup_failed")
    if current["lease_state"] == "orphaned_client":
        if not _terminate_macos_orphan(operation_id, metadata["source"]):
            raise KeyRecoveryProtocolError("cleanup_failed")
    if _external_lease_state(
        operation_id,
        metadata["source"],
        phase=current["phase"],
    ) is not None:
        raise KeyRecoveryProtocolError("cleanup_failed")
    _cleanup_recorded_artifacts(operation_id)
    _cleanup_recorded_private_temp(operation_id)
    if not current["terminal"]:
        _write_existing_terminal(operation_id, error_code="cancelled")
    return control_result(
        operation_id,
        action="cancel",
        ok=True,
        terminal=True,
        error_code=None,
        lease_state="terminal",
    )


def _unlink_private_regular(path: Path) -> None:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise KeyRecoveryProtocolError("cleanup_failed") from exc
    if (
        not stat.S_ISREG(value.st_mode)
        or path.is_symlink()
        or getattr(value, "st_file_attributes", 0) & 0x0400
        or (os.name != "nt" and value.st_uid != os.geteuid())
        or (os.name == "nt" and not _windows_acl_is_private(path))
    ):
        raise KeyRecoveryProtocolError("cleanup_failed")
    try:
        path.unlink()
    except OSError as exc:
        raise KeyRecoveryProtocolError("cleanup_failed") from exc


def _cleanup_recorded_artifacts(operation_id: str) -> None:
    record_path = operation_directory(operation_id) / "artifacts.json"
    try:
        record_path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise KeyRecoveryProtocolError("cleanup_failed") from exc
    payload = _read_exact_json(record_path)
    if (
        payload is None
        or set(payload) != {"schema", "operation_id", "artifacts"}
        or payload.get("schema") != ARTIFACTS_SCHEMA
        or payload.get("operation_id") != operation_id
        or type(payload.get("artifacts")) is not list
        or not 1 <= len(payload["artifacts"]) <= 4
    ):
        raise KeyRecoveryProtocolError("cleanup_failed")
    for item in payload["artifacts"]:
        if (
            type(item) is not dict
            or set(item) != {"path", "kind", "mode", "device", "inode"}
            or type(item.get("path")) is not str
            or item.get("kind") not in {"fifo", "file"}
            or item.get("mode") not in {0o600, 0o700}
            or type(item.get("device")) is not int
            or type(item.get("inode")) is not int
        ):
            raise KeyRecoveryProtocolError("cleanup_failed")
        path = Path(item["path"])
        try:
            value = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise KeyRecoveryProtocolError("cleanup_failed") from exc
        if not _recorded_artifact_is_safe(path, value, item):
            raise KeyRecoveryProtocolError("cleanup_failed")
        try:
            path.unlink()
        except OSError as exc:
            raise KeyRecoveryProtocolError("cleanup_failed") from exc


def _recorded_artifact_is_safe(
    path: Path,
    value: os.stat_result,
    item: dict,
    *,
    _windows: bool | None = None,
) -> bool:
    """在 Windows 上不依赖 POSIX 专用 API 验证一个精确 artifact。"""

    windows = os.name == "nt" if _windows is None else _windows
    kind_ok = (
        stat.S_ISFIFO(value.st_mode)
        if item["kind"] == "fifo"
        else stat.S_ISREG(value.st_mode)
    )
    ownership_ok = (
        _windows_acl_is_private(path)
        if windows
        else value.st_uid == os.geteuid()
    )
    mode_ok = windows or stat.S_IMODE(value.st_mode) == item["mode"]
    return bool(
        kind_ok
        and not path.is_symlink()
        and not (getattr(value, "st_file_attributes", 0) & 0x0400)
        and ownership_ok
        and mode_ok
        and (value.st_dev, value.st_ino) == (item["device"], item["inode"])
    )


def _cleanup_recorded_private_temp(operation_id: str) -> None:
    """删除一个崩溃遗留明文 transcript 目录的精确代际。"""

    record_path = operation_directory(operation_id) / "private-temp.json"
    try:
        record_path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise KeyRecoveryProtocolError("cleanup_failed") from exc
    payload = _read_exact_json(record_path)
    required = {
        "schema",
        "operation_id",
        "path",
        "device",
        "inode",
        "owner_pid",
    }
    if (
        payload is None
        or set(payload) != required
        or payload.get("schema") != PRIVATE_TEMP_SCHEMA
        or payload.get("operation_id") != operation_id
        or type(payload.get("path")) is not str
        or not Path(payload["path"]).is_absolute()
        or type(payload.get("device")) is not int
        or payload["device"] < 0
        or type(payload.get("inode")) is not int
        or payload["inode"] <= 0
        or type(payload.get("owner_pid")) is not int
        or payload["owner_pid"] <= 0
    ):
        raise KeyRecoveryProtocolError("cleanup_failed")
    try:
        from chatlog_keeper.core._private_temp import (
            cleanup_recorded_private_temp_dir,
        )

        cleanup_recorded_private_temp_dir(
            Path(payload["path"]),
            expected_owner_pid=payload["owner_pid"],
            expected_identity=(payload["device"], payload["inode"]),
            prefix="chatlog_active_",
        )
    except Exception as exc:
        raise KeyRecoveryProtocolError("cleanup_failed") from exc


def _remove_operation_directory_locked(
    operation_id: str,
    source: str,
    *,
    remove_owner: bool,
) -> None:
    operation_dir = operation_directory(operation_id)
    _cleanup_recorded_artifacts(operation_id)
    _cleanup_recorded_private_temp(operation_id)
    try:
        entries = list(operation_dir.iterdir())
    except OSError as exc:
        raise KeyRecoveryProtocolError("cleanup_failed") from exc
    if any(entry.name not in _OPERATION_FILES for entry in entries):
        raise KeyRecoveryProtocolError("cleanup_failed")
    if remove_owner:
        owner = _owner_payload(source)
        if owner is None or owner.get("operation_id") != operation_id:
            raise KeyRecoveryProtocolError("cleanup_failed")
        # Release the global selector only after all external/plaintext
        # artifacts are gone, but before journal deletion.  A hard crash can
        # therefore leave only a harmless unowned terminal journal; it cannot
        # leave a permanent owner pointing at a missing operation.
        _unlink_private_regular(_source_owner_path(source))
    for entry in entries:
        _unlink_private_regular(entry)
    try:
        operation_dir.rmdir()
    except OSError as exc:
        raise KeyRecoveryProtocolError("cleanup_failed") from exc


def _finish_receipted_cleanup(receipt: dict) -> None:
    """cleanup receipt 提交后，以幂等方式完成剩余删除。"""

    operation_id = receipt["operation_id"]
    source = receipt["source"]
    source_lock = _SourceLock(source)
    if not source_lock.acquire():
        source_lock.close()
        raise KeyRecoveryProtocolError("operation_active")
    try:
        owner = _owner_payload(source)
        remove_owner = bool(
            owner is not None and owner.get("operation_id") == operation_id
        )
        operation_dir = operation_directory(operation_id)
        try:
            _directory_identity(operation_dir)
        except KeyRecoveryProtocolError:
            try:
                operation_dir.lstat()
            except FileNotFoundError:
                if remove_owner:
                    _unlink_private_regular(_source_owner_path(source))
                return
            except OSError as exc:
                raise KeyRecoveryProtocolError("cleanup_failed") from exc
            raise KeyRecoveryProtocolError("cleanup_failed")
        phase = receipt["status"]["phase"]
        if _external_lease_state(
            operation_id,
            source,
            phase=phase,
        ) is not None:
            raise KeyRecoveryProtocolError("operation_active")
        _remove_operation_directory_locked(
            operation_id,
            source,
            remove_owner=remove_owner,
        )
    finally:
        source_lock.close()


def prune_expired_cleanup_receipts(*, now_unix_ms: int | None = None) -> int:
    """限制幂等 receipt 保留量，且不把它们误当作 live journal。"""

    now_ms = int(time.time() * 1000) if now_unix_ms is None else now_unix_ms
    if type(now_ms) is not int or now_ms < 0:
        raise KeyRecoveryProtocolError("invalid_request")
    try:
        entries = list(_receipt_root().iterdir())
    except OSError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    if len(entries) > _MAX_OPERATION_ENTRIES:
        entries = sorted(entries, key=lambda item: item.name)[:_MAX_OPERATION_ENTRIES]
    cutoff_ms = now_ms - (_CLEANUP_RECEIPT_RETENTION_SECONDS * 1000)
    removed = 0
    for entry in entries:
        operation_id = entry.stem
        if entry.suffix != ".json" or _OPERATION_ID_RE.fullmatch(operation_id) is None:
            continue
        try:
            receipt = _cleanup_receipt_payload(operation_id)
            if (
                receipt is None
                or receipt["cleaned_at_unix_ms"] > cutoff_ms
                or operation_directory(operation_id).exists()
            ):
                continue
            _unlink_private_regular(entry)
            removed += 1
        except (KeyRecoveryProtocolError, OSError):
            continue
    return removed


def prune_expired_operations(*, now_unix_ms: int | None = None) -> int:
    """对已证明终态的 operation journal 执行有界尽力保留。"""

    now_ms = int(time.time() * 1000) if now_unix_ms is None else now_unix_ms
    if type(now_ms) is not int or now_ms < 0:
        raise KeyRecoveryProtocolError("invalid_request")
    try:
        prune_expired_cleanup_receipts(now_unix_ms=now_ms)
    except KeyRecoveryProtocolError:
        pass
    root = _operation_root()
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise KeyRecoveryProtocolError("status_unavailable") from exc
    if len(entries) > _MAX_OPERATION_ENTRIES:
        entries = sorted(entries, key=lambda item: item.name)[:_MAX_OPERATION_ENTRIES]
    removed = 0
    cutoff_ms = now_ms - (_TERMINAL_RETENTION_SECONDS * 1000)
    for entry in entries:
        if _OPERATION_ID_RE.fullmatch(entry.name) is None:
            continue
        operation_id = entry.name
        try:
            metadata = _metadata_payload(operation_id)
            if metadata["started_at_unix_ms"] > cutoff_ms:
                continue
            status = _validated_status_payload(operation_id)
            if not status["terminal"]:
                continue
            source = metadata["source"]
            source_lock = _SourceLock(source)
            if not source_lock.acquire():
                source_lock.close()
                continue
            try:
                if _external_lease_state(
                    operation_id,
                    source,
                    phase=status["phase"],
                ) is not None:
                    continue
                owner = _owner_payload(source)
                remove_owner = bool(
                    owner is not None and owner.get("operation_id") == operation_id
                )
                # Retention is an automatic form of cleanup.  Commit the same
                # durable receipt first so delayed status/cleanup calls remain
                # distinguishable from an operation that never existed.  If
                # receipt creation or exact comparison fails, preserve the
                # journal and owner unchanged for explicit audit.
                _write_cleanup_receipt(operation_id, source, status)
                _remove_operation_directory_locked(
                    operation_id,
                    source,
                    remove_owner=remove_owner,
                )
                removed += 1
            finally:
                source_lock.close()
        except KeyRecoveryProtocolError:
            # Corrupt or identity-uncertain entries are preserved for explicit
            # audit/repair; retention must never broaden a delete target.
            continue
    return removed


def cleanup_operation(operation_id: str) -> dict:
    """只删除一个已证明终态的操作，并释放对应 source owner。"""

    try:
        metadata = _metadata_payload(operation_id)
    except KeyRecoveryProtocolError:
        receipt = _cleanup_receipt_payload(operation_id)
        if receipt is None:
            raise
        _finish_receipted_cleanup(receipt)
        return control_result(
            operation_id,
            action="cleanup",
            ok=True,
            terminal=True,
            error_code=None,
            lease_state="terminal",
        )
    status = status_operation(operation_id)
    if not status["terminal"]:
        raise KeyRecoveryProtocolError("not_terminal")
    source_lock = _SourceLock(metadata["source"])
    if not source_lock.acquire():
        source_lock.close()
        raise KeyRecoveryProtocolError("operation_active")
    try:
        owner = _owner_payload(metadata["source"])
        if owner is None or owner.get("operation_id") != operation_id:
            raise KeyRecoveryProtocolError("status_unavailable")
        if _external_lease_state(
            operation_id,
            metadata["source"],
            phase=status["phase"],
        ) is not None:
            raise KeyRecoveryProtocolError("operation_active")
        _write_cleanup_receipt(operation_id, metadata["source"], status)
        _remove_operation_directory_locked(
            operation_id,
            metadata["source"],
            remove_owner=True,
        )
    finally:
        source_lock.close()
    return control_result(
        operation_id,
        action="cleanup",
        ok=True,
        terminal=True,
        error_code=None,
        lease_state="terminal",
    )


def capabilities_payload() -> dict:
    return {
        "schema": CAPABILITIES_SCHEMA,
        "version": 1,
        "operation_id_format": "lowercase-hex-64",
        "actions": ["start", "status", "cancel", "cleanup"],
        "phases": sorted(_PHASES),
        "error_codes": sorted(_ERROR_CODES),
        "terminal_phases": sorted(_TERMINAL_PHASES),
    }
