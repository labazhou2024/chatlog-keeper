"""Isolated SQLite reader for NTQQ's shifted Windows lock-byte page.

This module is executed as a script with ``python -I``.  It intentionally uses
only the standard library and never imports the rest of chatlog-keeper.  The
parent process communicates over newline-delimited JSON on stdin/stdout.

The helper is deliberately narrow: it is Windows-only, read-only, pins the one
SQLite build validated by the project, changes the process-global pending byte
before opening any connection, and refuses to serve queries unless
``PRAGMA quick_check`` returns exactly ``ok``.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


_SQLITE_TESTCTRL_PENDING_BYTE = 11
_SQLITE_STANDARD_PENDING_BYTE = 0x40000000
_NTQQ_STRIPPED_PENDING_BYTE = 0x3FFFFC00
_NTQQ_WRAPPER_SIZE = 1024
_NTQQ_PAGE_SIZE = 4096
_NTQQ_WRAPPED_LOCK_PAGE_NO = 262144
_SUPPORTED_SQLITE_VERSIONS = frozenset({"3.53.2"})
_BYTES_TAG = "__chatlog_keeper_bytes_b64__"
_OPEN_PROTOCOL = "ntqq-shifted-sqlite-v1"
_MAX_OPEN_ATTESTATION_BYTES = 65_536
_MAX_SQL_CHARS = 1_000_000
_ALLOWED_TABLE_INFO_TABLES = frozenset(
    {
        "buddy_list",
        "c2c_msg_table",
        "group_detail_info_ver1",
        "group_info",
        "group_list",
        "group_member3",
        "group_msg_table",
        "profile_info_v6",
    }
)
_ALLOWED_READ_TABLES = _ALLOWED_TABLE_INFO_TABLES | frozenset(
    {"sqlite_master", "sqlite_schema"}
)
_ALLOWED_SQL_FUNCTIONS = frozenset({"count", "max", "nullif", "trim"})
_TABLE_INFO_RE = re.compile(
    r'\APRAGMA\s+table_info\s*\(\s*"([A-Za-z0-9_]+)"\s*\)\s*\Z',
    re.IGNORECASE,
)
_FORBIDDEN_SELECT_TOKENS_RE = re.compile(
    r"\b(?:ALTER|ANALYZE|ATTACH|CREATE|DELETE|DETACH|DROP|INSERT|LOAD_EXTENSION|"
    r"PRAGMA|REINDEX|REPLACE|UPDATE|VACUUM|WRITABLE_SCHEMA)\b",
    re.IGNORECASE,
)


class _HelperRefusal(RuntimeError):
    """A sanitized, fail-closed helper startup or protocol refusal."""


def _send(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
    sys.stdout.write("\n")
    sys.stdout.flush()


def _encode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {_BYTES_TAG: base64.b64encode(value).decode("ascii")}
    if isinstance(value, tuple):
        return [_encode_value(item) for item in value]
    if isinstance(value, list):
        return [_encode_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise _HelperRefusal("unsupported_result_type")


def _decode_value(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) != {_BYTES_TAG} or not isinstance(value[_BYTES_TAG], str):
            raise _HelperRefusal("invalid_bytes_value")
        try:
            return base64.b64decode(value[_BYTES_TAG], validate=True)
        except ValueError as exc:
            raise _HelperRefusal("invalid_bytes_value") from exc
    if isinstance(value, list):
        return tuple(_decode_value(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise _HelperRefusal("invalid_parameter_type")


def _loaded_sqlite_dll(sqlite_version: str):
    """Return test-control from Python's exact already-loaded sqlite3.dll."""

    if os.name != "nt":
        raise _HelperRefusal("windows_only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_module_handle = kernel32.GetModuleHandleW
    get_module_handle.argtypes = [ctypes.c_wchar_p]
    get_module_handle.restype = ctypes.c_void_p
    handle = get_module_handle("sqlite3.dll")
    if not handle:
        raise _HelperRefusal("sqlite3_dll_not_loaded")

    get_module_filename = kernel32.GetModuleFileNameW
    get_module_filename.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint,
    ]
    get_module_filename.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    copied = get_module_filename(handle, buffer, len(buffer))
    if copied == 0 or copied >= len(buffer):
        raise _HelperRefusal("sqlite3_dll_path_unavailable")
    dll_path = Path(buffer.value).resolve()
    prefix = Path(getattr(sys, "_MEIPASS", sys.prefix)).resolve()
    try:
        dll_path.relative_to(prefix)
    except ValueError as exc:
        raise _HelperRefusal("sqlite3_dll_outside_python_prefix") from exc

    dll = ctypes.WinDLL(str(dll_path))
    if int(dll._handle) != int(handle):  # noqa: SLF001 - exact module identity gate
        raise _HelperRefusal("sqlite3_dll_identity_mismatch")
    try:
        libversion = dll.sqlite3_libversion
        libversion.restype = ctypes.c_char_p
        loaded_version_raw = libversion()
        test_control = dll.sqlite3_test_control
    except AttributeError as exc:
        raise _HelperRefusal("sqlite3_required_export_missing") from exc
    if not loaded_version_raw:
        raise _HelperRefusal("sqlite3_version_unavailable")
    loaded_version = loaded_version_raw.decode("ascii", errors="strict")
    if loaded_version != sqlite_version:
        raise _HelperRefusal("sqlite3_python_dll_version_mismatch")
    if loaded_version not in _SUPPORTED_SQLITE_VERSIONS:
        raise _HelperRefusal("sqlite3_version_not_pinned")
    test_control.restype = ctypes.c_int
    return test_control


def _pending_byte(test_control) -> int:
    return int(
        test_control(
            ctypes.c_int(_SQLITE_TESTCTRL_PENDING_BYTE),
            ctypes.c_uint(0),
        )
    )


def _validated_sqlite_runtime():
    """Validate DLL identity/ABI/exports without opening any database."""

    # Importing sqlite3 loads _sqlite3.pyd/sqlite3.dll but opens no connection.
    import sqlite3

    test_control = _loaded_sqlite_dll(sqlite3.sqlite_version)
    if _pending_byte(test_control) != _SQLITE_STANDARD_PENDING_BYTE:
        raise _HelperRefusal("sqlite3_pending_byte_not_pristine")
    return sqlite3, test_control


def _set_shifted_pending_byte(test_control) -> None:
    before = _pending_byte(test_control)
    if before != _SQLITE_STANDARD_PENDING_BYTE:
        raise _HelperRefusal("sqlite3_pending_byte_not_pristine")
    replaced = int(
        test_control(
            ctypes.c_int(_SQLITE_TESTCTRL_PENDING_BYTE),
            ctypes.c_uint(_NTQQ_STRIPPED_PENDING_BYTE),
        )
    )
    after = _pending_byte(test_control)
    if (
        replaced != _SQLITE_STANDARD_PENDING_BYTE
        or after != _NTQQ_STRIPPED_PENDING_BYTE
    ):
        raise _HelperRefusal("sqlite3_pending_byte_change_failed")


def _read_open_attestation() -> Path:
    """Read and verify the DB path/signature from the first private stdin frame."""

    raw = sys.stdin.readline(_MAX_OPEN_ATTESTATION_BYTES + 1)
    if (
        not raw
        or len(raw.encode("utf-8")) > _MAX_OPEN_ATTESTATION_BYTES
        or not raw.endswith("\n")
    ):
        raise _HelperRefusal("open_attestation_invalid")
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _HelperRefusal("open_attestation_invalid") from exc
    expected_fields = {
        "op",
        "protocol",
        "database_path",
        "wrapper_size",
        "lock_page_no",
        "pending_byte",
    }
    if not isinstance(request, dict) or set(request) != expected_fields:
        raise _HelperRefusal("open_attestation_invalid")
    if (
        request.get("op") != "open"
        or request.get("protocol") != _OPEN_PROTOCOL
        or request.get("wrapper_size") != _NTQQ_WRAPPER_SIZE
        or request.get("lock_page_no") != _NTQQ_WRAPPED_LOCK_PAGE_NO
        or request.get("pending_byte") != _NTQQ_STRIPPED_PENDING_BYTE
    ):
        raise _HelperRefusal("open_attestation_invalid")
    raw_path = request.get("database_path")
    if not isinstance(raw_path, str) or not raw_path or "\0" in raw_path:
        raise _HelperRefusal("open_attestation_invalid")
    database_path = Path(raw_path)
    if not database_path.is_absolute() or not database_path.is_file():
        raise _HelperRefusal("database_path_invalid")
    database_path = database_path.resolve()
    lock_page_offset = (_NTQQ_WRAPPED_LOCK_PAGE_NO - 1) * _NTQQ_PAGE_SIZE
    try:
        with database_path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\0":
                raise _HelperRefusal("database_signature_invalid")
            stream.seek(lock_page_offset)
            lock_page = stream.read(_NTQQ_PAGE_SIZE)
    except OSError as exc:
        raise _HelperRefusal("database_signature_unavailable") from exc
    if len(lock_page) != _NTQQ_PAGE_SIZE or any(lock_page):
        raise _HelperRefusal("database_lock_page_invalid")
    return database_path


def _sql_is_allowlisted_read(sql: str) -> bool:
    """Allow only the fixed reader's SELECTs and allowlisted table-info PRAGMA."""

    if not isinstance(sql, str) or not sql.strip() or len(sql) > _MAX_SQL_CHARS:
        return False
    normalized = sql.strip()
    if any(token in normalized for token in ("\0", ";", "--", "/*", "*/")):
        return False
    table_info = _TABLE_INFO_RE.fullmatch(normalized)
    if table_info is not None:
        return table_info.group(1).lower() in _ALLOWED_TABLE_INFO_TABLES
    return (
        re.match(r"\ASELECT\b", normalized, re.IGNORECASE) is not None
        and _FORBIDDEN_SELECT_TOKENS_RE.search(normalized) is None
    )


def _install_read_only_authorizer(connection, sqlite3) -> None:
    """Default-deny every SQLite operation outside the fixed QQ readers."""

    def authorize(action, argument_1, argument_2, _database, _trigger):
        try:
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ:
                table = str(argument_1 or "").lower()
                return (
                    sqlite3.SQLITE_OK
                    if table in _ALLOWED_READ_TABLES
                    else sqlite3.SQLITE_DENY
                )
            if action == sqlite3.SQLITE_FUNCTION:
                function = str(argument_2 or "").lower()
                return (
                    sqlite3.SQLITE_OK
                    if function in _ALLOWED_SQL_FUNCTIONS
                    else sqlite3.SQLITE_DENY
                )
            if action == sqlite3.SQLITE_PRAGMA:
                pragma = str(argument_1 or "").lower()
                table = str(argument_2 or "").lower()
                return (
                    sqlite3.SQLITE_OK
                    if pragma == "table_info" and table in _ALLOWED_TABLE_INFO_TABLES
                    else sqlite3.SQLITE_DENY
                )
        except Exception:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_DENY

    connection.set_authorizer(authorize)


def _open_verified_connection(database_path: Path):
    """Set the shifted lock byte, then open and verify one immutable DB."""

    if not database_path.is_absolute() or not database_path.is_file():
        raise _HelperRefusal("database_path_invalid")
    # The process-global pending byte is changed after runtime validation and
    # before the first sqlite3.connect call below.
    sqlite3, test_control = _validated_sqlite_runtime()
    _set_shifted_pending_byte(test_control)
    uri = database_path.resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True)
        connection.execute("PRAGMA query_only=ON")
        query_only = connection.execute("PRAGMA query_only").fetchone()
        check_rows = connection.execute("PRAGMA quick_check").fetchall()
    except sqlite3.Error as exc:
        raise _HelperRefusal("sqlite_open_or_check_failed") from exc
    if query_only != (1,):
        connection.close()
        raise _HelperRefusal("sqlite_query_only_not_enforced")
    if check_rows != [("ok",)]:
        connection.close()
        raise _HelperRefusal("sqlite_quick_check_failed")
    try:
        _install_read_only_authorizer(connection, sqlite3)
    except sqlite3.Error as exc:
        connection.close()
        raise _HelperRefusal("sqlite_authorizer_failed") from exc
    return connection, sqlite3


def _serve(database_path: Path) -> int:
    try:
        connection, sqlite3 = _open_verified_connection(database_path)
    except _HelperRefusal as exc:
        _send({"ok": False, "error": str(exc)})
        return 2

    cursors: dict[int, Any] = {}
    next_cursor_id = 1
    _send(
        {
            "ok": True,
            "type": "ready",
            "pid": os.getpid(),
            "isolated": int(
                bool(sys.flags.isolated) or bool(getattr(sys, "frozen", False))
            ),
            "sqlite_version": sqlite3.sqlite_version,
            "pending_byte": _NTQQ_STRIPPED_PENDING_BYTE,
            "quick_check": "ok",
        }
    )
    try:
        for raw_line in sys.stdin:
            try:
                request = json.loads(raw_line)
                if not isinstance(request, dict):
                    raise _HelperRefusal("request_not_object")
                operation = request.get("op")
                if operation == "close":
                    _send({"ok": True, "closed": True})
                    return 0
                if operation == "cursor":
                    cursor_id = next_cursor_id
                    next_cursor_id += 1
                    cursors[cursor_id] = connection.cursor()
                    _send({"ok": True, "cursor_id": cursor_id})
                    continue
                cursor_id = request.get("cursor_id")
                if not isinstance(cursor_id, int) or cursor_id not in cursors:
                    raise _HelperRefusal("cursor_invalid")
                cursor = cursors[cursor_id]
                if operation == "execute":
                    sql = request.get("sql")
                    if not _sql_is_allowlisted_read(sql):
                        raise _HelperRefusal("sql_not_allowlisted")
                    params = _decode_value(request.get("params", []))
                    if not isinstance(params, tuple):
                        raise _HelperRefusal("params_invalid")
                    cursor.execute(sql, params)
                    _send({"ok": True})
                elif operation == "fetchone":
                    _send({"ok": True, "row": _encode_value(cursor.fetchone())})
                elif operation == "fetchmany":
                    size = request.get("size", 1)
                    if not isinstance(size, int) or size < 0 or size > 100000:
                        raise _HelperRefusal("fetch_size_invalid")
                    _send({"ok": True, "rows": _encode_value(cursor.fetchmany(size))})
                elif operation == "fetchall":
                    _send({"ok": True, "rows": _encode_value(cursor.fetchall())})
                elif operation == "close_cursor":
                    cursor.close()
                    del cursors[cursor_id]
                    _send({"ok": True})
                else:
                    raise _HelperRefusal("operation_invalid")
            except sqlite3.Error:
                _send({"ok": False, "error": "sqlite_query_failed"})
            except (json.JSONDecodeError, _HelperRefusal, TypeError, ValueError) as exc:
                reason = str(exc) if isinstance(exc, _HelperRefusal) else "protocol_invalid"
                _send({"ok": False, "error": reason})
    finally:
        for cursor in cursors.values():
            try:
                cursor.close()
            except sqlite3.Error:
                pass
        connection.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--probe"]:
        _send(
            {
                "ok": True,
                "type": "probe",
                "pid": os.getpid(),
                "isolated": int(
                    bool(sys.flags.isolated) or bool(getattr(sys, "frozen", False))
                ),
            }
        )
        return 0
    if arguments == ["--runtime-probe"]:
        try:
            sqlite3, test_control = _validated_sqlite_runtime()
            _set_shifted_pending_byte(test_control)
            shifted_pending_byte = _pending_byte(test_control)
            if shifted_pending_byte != _NTQQ_STRIPPED_PENDING_BYTE:
                raise _HelperRefusal("sqlite3_pending_byte_readback_failed")
        except _HelperRefusal as exc:
            _send({"ok": False, "error": str(exc)})
            return 2
        _send(
            {
                "ok": True,
                "type": "runtime_probe",
                "pid": os.getpid(),
                "isolated": int(
                    bool(sys.flags.isolated) or bool(getattr(sys, "frozen", False))
                ),
                "sqlite_version": sqlite3.sqlite_version,
                "pending_byte": shifted_pending_byte,
            }
        )
        return 0
    if arguments:
        _send({"ok": False, "error": "usage_invalid"})
        return 2
    try:
        database_path = _read_open_attestation()
    except _HelperRefusal as exc:
        _send({"ok": False, "error": str(exc)})
        return 2
    return _serve(database_path)


if __name__ == "__main__":
    raise SystemExit(main())
