"""Parent-side proxy for the isolated NTQQ shifted-pending-byte helper."""

from __future__ import annotations

import base64
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Optional


_NTQQ_STRIPPED_PENDING_BYTE = 0x3FFFFC00
_NTQQ_WRAPPER_SIZE = 1024
_NTQQ_WRAPPED_LOCK_PAGE_NO = 262144
_SUPPORTED_SQLITE_VERSIONS = frozenset({"3.53.2"})
_BYTES_TAG = "__chatlog_keeper_bytes_b64__"
_OPEN_PROTOCOL = "ntqq-shifted-sqlite-v1"
_START_TIMEOUT_SECONDS = 600.0
_QUERY_TIMEOUT_SECONDS = 600.0


class QQShiftedSQLiteError(RuntimeError):
    """The isolated shifted-pending-byte reader refused or stopped."""


def _helper_command(*arguments: str) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--_qq-sqlite-helper", *arguments]
    helper = Path(__file__).with_name("_qq_sqlite_helper.py").resolve()
    return [sys.executable, "-I", "-u", str(helper), *arguments]


def _readline_with_timeout(stream, timeout: float) -> str:
    result: queue.Queue[object] = queue.Queue(maxsize=1)

    def read() -> None:
        try:
            result.put(stream.readline())
        except BaseException as exc:  # noqa: BLE001 - forwarded to owner thread
            result.put(exc)

    thread = threading.Thread(target=read, name="qq-sqlite-helper-read", daemon=True)
    thread.start()
    try:
        value = result.get(timeout=timeout)
    except queue.Empty as exc:
        raise QQShiftedSQLiteError("isolated QQ SQLite helper timed out") from exc
    if isinstance(value, BaseException):
        raise QQShiftedSQLiteError("isolated QQ SQLite helper pipe failed") from value
    if not isinstance(value, str) or not value:
        raise QQShiftedSQLiteError("isolated QQ SQLite helper stopped unexpectedly")
    return value


def _encode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {_BYTES_TAG: base64.b64encode(value).decode("ascii")}
    if isinstance(value, (tuple, list)):
        return [_encode_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("unsupported SQLite parameter type")


def _decode_value(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) != {_BYTES_TAG} or not isinstance(value[_BYTES_TAG], str):
            raise QQShiftedSQLiteError("isolated QQ SQLite response is invalid")
        try:
            return base64.b64decode(value[_BYTES_TAG], validate=True)
        except ValueError as exc:
            raise QQShiftedSQLiteError("isolated QQ SQLite response is invalid") from exc
    if isinstance(value, list):
        return tuple(_decode_value(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise QQShiftedSQLiteError("isolated QQ SQLite response is invalid")


def _spawn_helper(arguments: list[str]) -> subprocess.Popen[str]:
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    working_directory = Path(
        getattr(sys, "_MEIPASS", sys.prefix)
    ).resolve()
    try:
        return subprocess.Popen(
            _helper_command(*arguments),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            cwd=str(working_directory),
            creationflags=creationflags,
        )
    except OSError:
        raise QQShiftedSQLiteError(
            "isolated QQ SQLite helper launch failed"
        ) from None


def probe_isolated_helper() -> dict[str, Any]:
    """Run a data-free helper probe; used by cross-platform isolation tests."""

    process = _spawn_helper(["--probe"])
    try:
        stdout, _stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise QQShiftedSQLiteError("isolated QQ SQLite probe timed out") from exc
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise QQShiftedSQLiteError("isolated QQ SQLite probe is invalid") from exc
    if process.returncode != 0 or not isinstance(payload, dict) or not payload.get("ok"):
        raise QQShiftedSQLiteError("isolated QQ SQLite probe failed")
    return payload


def probe_sqlite_runtime() -> dict[str, Any]:
    """Validate DLL/ABI and shifted pending-byte set/readback without a DB."""

    process = _spawn_helper(["--runtime-probe"])
    try:
        stdout, _stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise QQShiftedSQLiteError("isolated QQ SQLite runtime probe timed out") from exc
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise QQShiftedSQLiteError("isolated QQ SQLite runtime probe is invalid") from exc
    if (
        process.returncode != 0
        or not isinstance(payload, dict)
        or not payload.get("ok")
        or payload.get("type") != "runtime_probe"
        or payload.get("isolated") != 1
        or payload.get("pid") == os.getpid()
        or payload.get("sqlite_version") not in _SUPPORTED_SQLITE_VERSIONS
        or payload.get("pending_byte") != _NTQQ_STRIPPED_PENDING_BYTE
        or "sqlite_dll" in payload
    ):
        raise QQShiftedSQLiteError("isolated QQ SQLite runtime probe failed")
    return payload


class _IsolatedCursor:
    def __init__(self, connection: "IsolatedQQSQLiteConnection", cursor_id: int):
        self._connection = connection
        self._cursor_id = cursor_id
        self._closed = False

    def execute(self, sql: str, parameters=()):
        if self._closed:
            raise QQShiftedSQLiteError("isolated QQ SQLite cursor is closed")
        self._connection._request(  # noqa: SLF001 - private paired proxy types
            {
                "op": "execute",
                "cursor_id": self._cursor_id,
                "sql": sql,
                "params": _encode_value(parameters),
            }
        )
        return self

    def fetchone(self):
        response = self._connection._request(  # noqa: SLF001
            {"op": "fetchone", "cursor_id": self._cursor_id}
        )
        return _decode_value(response.get("row"))

    def fetchmany(self, size: Optional[int] = None):
        response = self._connection._request(  # noqa: SLF001
            {
                "op": "fetchmany",
                "cursor_id": self._cursor_id,
                "size": 1 if size is None else int(size),
            }
        )
        rows = _decode_value(response.get("rows"))
        if not isinstance(rows, tuple):
            raise QQShiftedSQLiteError("isolated QQ SQLite rows are invalid")
        return list(rows)

    def fetchall(self):
        response = self._connection._request(  # noqa: SLF001
            {"op": "fetchall", "cursor_id": self._cursor_id}
        )
        rows = _decode_value(response.get("rows"))
        if not isinstance(rows, tuple):
            raise QQShiftedSQLiteError("isolated QQ SQLite rows are invalid")
        return list(rows)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._connection._request(  # noqa: SLF001
                {"op": "close_cursor", "cursor_id": self._cursor_id}
            )
        finally:
            self._closed = True

    def __iter__(self):
        return self

    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row


class IsolatedQQSQLiteConnection:
    """Small sqlite3-compatible, read-only connection backed by a subprocess."""

    def __init__(self, database_path: Path):
        path = Path(database_path).resolve()
        if not path.is_file():
            raise QQShiftedSQLiteError("isolated QQ SQLite database is unavailable")
        self._lock = threading.Lock()
        self._closed = False
        self._process = _spawn_helper([])
        if self._process.stdin is None or self._process.stdout is None:
            self._terminate()
            raise QQShiftedSQLiteError("isolated QQ SQLite pipes are unavailable")
        try:
            self._write_frame(
                {
                    "op": "open",
                    "protocol": _OPEN_PROTOCOL,
                    "database_path": str(path),
                    "wrapper_size": _NTQQ_WRAPPER_SIZE,
                    "lock_page_no": _NTQQ_WRAPPED_LOCK_PAGE_NO,
                    "pending_byte": _NTQQ_STRIPPED_PENDING_BYTE,
                }
            )
            ready = self._read_response(_START_TIMEOUT_SECONDS)
            self._validate_ready(ready)
            self._verification = {
                "pid": ready["pid"],
                "sqlite_version": ready["sqlite_version"],
                "pending_byte": ready["pending_byte"],
                "quick_check": ready["quick_check"],
            }
        except BaseException:
            self._terminate()
            raise

    def _validate_ready(self, response: dict[str, Any]) -> None:
        if not response.get("ok"):
            raise QQShiftedSQLiteError("isolated QQ SQLite helper refused the database")
        if (
            response.get("type") != "ready"
            or response.get("isolated") != 1
            or response.get("pid") == os.getpid()
            or response.get("sqlite_version") not in _SUPPORTED_SQLITE_VERSIONS
            or response.get("pending_byte") != _NTQQ_STRIPPED_PENDING_BYTE
            or response.get("quick_check") != "ok"
            or "sqlite_dll" in response
        ):
            raise QQShiftedSQLiteError("isolated QQ SQLite helper self-check failed")

    def _write_frame(self, request: dict[str, Any]) -> None:
        if self._process.stdin is None:
            raise QQShiftedSQLiteError("isolated QQ SQLite input is unavailable")
        try:
            self._process.stdin.write(
                json.dumps(request, ensure_ascii=True, separators=(",", ":")) + "\n"
            )
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise QQShiftedSQLiteError("isolated QQ SQLite helper pipe failed") from exc

    def _read_response(self, timeout: float) -> dict[str, Any]:
        if self._process.stdout is None:
            raise QQShiftedSQLiteError("isolated QQ SQLite output is unavailable")
        raw = _readline_with_timeout(self._process.stdout, timeout)
        try:
            response = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise QQShiftedSQLiteError("isolated QQ SQLite response is invalid") from exc
        if not isinstance(response, dict):
            raise QQShiftedSQLiteError("isolated QQ SQLite response is invalid")
        return response

    def _request(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._closed or self._process.poll() is not None:
                raise QQShiftedSQLiteError("isolated QQ SQLite helper is closed")
            try:
                self._write_frame(request)
            except QQShiftedSQLiteError:
                self._terminate()
                raise
            try:
                response = self._read_response(_QUERY_TIMEOUT_SECONDS)
            except BaseException:
                self._terminate()
                raise
            if not response.get("ok"):
                import sqlite3

                raise sqlite3.DatabaseError("isolated QQ SQLite query failed")
            return response

    def cursor(self) -> _IsolatedCursor:
        response = self._request({"op": "cursor"})
        cursor_id = response.get("cursor_id")
        if not isinstance(cursor_id, int) or cursor_id <= 0:
            raise QQShiftedSQLiteError("isolated QQ SQLite cursor is invalid")
        return _IsolatedCursor(self, cursor_id)

    def execute(self, sql: str, parameters=()) -> _IsolatedCursor:
        return self.cursor().execute(sql, parameters)

    @property
    def verification(self) -> dict[str, Any]:
        """Sanitized helper self-check evidence; contains no database values."""

        return dict(self._verification)

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._process.poll() is None:
                self._request({"op": "close"})
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._terminate()
        finally:
            self._closed = True
            for stream in (
                self._process.stdin,
                self._process.stdout,
                self._process.stderr,
            ):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass

    def _terminate(self) -> None:
        if self._process.poll() is None:
            self._process.kill()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except BaseException:
            pass


def open_shifted_pending_connection(database_path: Path) -> IsolatedQQSQLiteConnection:
    return IsolatedQQSQLiteConnection(database_path)
