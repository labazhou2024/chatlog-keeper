"""Frozen local IPC contract for ``message-stream-v1``.

The request arrives as one bounded JSON value on stdin. Responses are compact
NDJSON frames written and flushed one at a time. Diagnostic frames deliberately
use only a process-local ``scope_index``; native account/conversation IDs are
allowed only inside the requested record payload.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional, TextIO, Tuple


PROTOCOL = "message-stream-v1"
VERSION = 1
SOURCES = ("qq", "wechat")
FRAME_TYPES = (
    "capabilities",
    "ready",
    "scope_begin",
    "record",
    "checkpoint",
    "scope_end",
    "complete",
    "error",
)

MAX_REQUEST_BYTES = 262_144
MAX_FRAME_BYTES = 1_048_576
MAX_CURSOR_BYTES = 65_536
MAX_CURSOR_POSITIONS = 256
MAX_ID_CHARS = 512
MAX_SCOPES = 128
MIN_PAGE_SIZE = 1
DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 1000
MAX_TOTAL_RECORDS = 2_000_000
MAX_TOTAL_PAGES = 200_000
MAX_PAGES_PER_SCOPE = 50_000

REQUEST_FIELDS = frozenset({
    "protocol",
    "version",
    "source",
    "since_ts",
    "until_ts",
    "page_size",
    "scopes",
})
SCOPE_REQUIRED_FIELDS = frozenset({
    "account_id",
    "conversation_id",
    "conversation_type",
})
SCOPE_OPTIONAL_FIELDS = frozenset({"page_cursor"})
CONVERSATION_TYPES = frozenset({"direct", "group"})
SAFE_ERROR_CODES = frozenset({
    "cancelled",
    "frame_too_large",
    "invalid_cursor",
    "invalid_record",
    "invalid_request",
    "page_limit_exceeded",
    "read_failed",
    "record_limit_exceeded",
    "request_too_large",
    "scope_mismatch",
    "source_unavailable",
})

_QQ_CURSOR_FIELDS = frozenset({
    "version",
    "since_ts",
    "until_ts",
    "msg_time",
    "table_rank",
    "rowid",
})
_WECHAT_CURSOR_FIELDS = frozenset({
    "version",
    "scope",
    "topology",
    "positions",
})
_WECHAT_CURSOR_POSITION_FIELDS = frozenset({
    "shard",
    "create_time",
    "row_id",
})
_OPAQUE_CURSOR_ID = re.compile(r"[0-9a-f]{24}")


class MessageStreamProtocolError(ValueError):
    """A safe protocol failure represented only by a frozen error code."""

    def __init__(self, code: str):
        if code not in SAFE_ERROR_CODES:
            code = "read_failed"
        self.code = code
        super().__init__(code)


class MessageStreamBrokenPipe(RuntimeError):
    """The local NDJSON consumer closed its pipe and upstream must stop."""


@dataclass(frozen=True)
class MessageStreamScope:
    """One exact, typed local conversation scope."""

    account_id: str
    conversation_id: str
    conversation_type: str
    page_cursor: Optional[dict] = None


@dataclass(frozen=True)
class MessageStreamRequest:
    """Validated source/window/page contract in canonical scope order."""

    source: str
    since_ts: float
    until_ts: float
    page_size: int
    scopes: Tuple[MessageStreamScope, ...]


class MessageStreamCancellation:
    """Small callback-compatible cancellation token for bounded readers."""

    def __init__(self) -> None:
        self._requested = False

    def __call__(self) -> bool:
        return self._requested

    def cancel(self) -> None:
        self._requested = True


def _finite_number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MessageStreamProtocolError("invalid_request")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise MessageStreamProtocolError("invalid_request")
    return normalized


def _positive_int(value: Any, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MessageStreamProtocolError("invalid_request")
    if value < 1 or value > maximum:
        raise MessageStreamProtocolError("invalid_request")
    return value


def _native_id(value: Any) -> str:
    if not isinstance(value, str):
        raise MessageStreamProtocolError("invalid_request")
    if (
        not value
        or value != value.strip()
        or len(value) > MAX_ID_CHARS
        or any(ord(char) < 32 for char in value)
    ):
        raise MessageStreamProtocolError("invalid_request")
    return value


def _cursor_json_size(value: Mapping[str, Any]) -> int:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise MessageStreamProtocolError("invalid_cursor") from None
    return len(encoded)


def _validated_qq_cursor(
    value: Mapping[str, Any],
    *,
    conversation_type: str,
    since_ts: float,
    until_ts: float,
) -> dict:
    if set(value) != _QQ_CURSOR_FIELDS or _cursor_json_size(value) > MAX_CURSOR_BYTES:
        raise MessageStreamProtocolError("invalid_cursor")
    version = value.get("version")
    table_rank = value.get("table_rank")
    rowid = value.get("rowid")
    if version != VERSION or isinstance(version, bool):
        raise MessageStreamProtocolError("invalid_cursor")
    expected_rank = 0 if conversation_type == "direct" else 1
    if (
        isinstance(table_rank, bool)
        or not isinstance(table_rank, int)
        or table_rank != expected_rank
        or isinstance(rowid, bool)
        or not isinstance(rowid, int)
        or rowid < 1
    ):
        raise MessageStreamProtocolError("invalid_cursor")
    cursor_since = _finite_cursor_number(value.get("since_ts"))
    cursor_until = _finite_cursor_number(value.get("until_ts"))
    msg_time = _finite_cursor_number(value.get("msg_time"))
    if cursor_since != since_ts or cursor_until != until_ts:
        raise MessageStreamProtocolError("invalid_cursor")
    return {
        "version": VERSION,
        "since_ts": cursor_since,
        "until_ts": cursor_until,
        "msg_time": msg_time,
        "table_rank": table_rank,
        "rowid": rowid,
    }


def _finite_cursor_number(value: Any) -> float:
    try:
        return _finite_number(value)
    except MessageStreamProtocolError:
        raise MessageStreamProtocolError("invalid_cursor") from None


def _validated_wechat_cursor(value: Mapping[str, Any]) -> dict:
    if set(value) != _WECHAT_CURSOR_FIELDS or _cursor_json_size(value) > MAX_CURSOR_BYTES:
        raise MessageStreamProtocolError("invalid_cursor")
    version = value.get("version")
    scope = value.get("scope")
    topology = value.get("topology")
    positions = value.get("positions")
    if version != VERSION or isinstance(version, bool):
        raise MessageStreamProtocolError("invalid_cursor")
    if not isinstance(scope, str) or not _OPAQUE_CURSOR_ID.fullmatch(scope):
        raise MessageStreamProtocolError("invalid_cursor")
    if not isinstance(topology, str) or not _OPAQUE_CURSOR_ID.fullmatch(topology):
        raise MessageStreamProtocolError("invalid_cursor")
    if not isinstance(positions, list) or len(positions) > MAX_CURSOR_POSITIONS:
        raise MessageStreamProtocolError("invalid_cursor")
    normalized_positions = []
    seen = set()
    for position in positions:
        if not isinstance(position, dict) or set(position) != _WECHAT_CURSOR_POSITION_FIELDS:
            raise MessageStreamProtocolError("invalid_cursor")
        shard = position.get("shard")
        create_time = position.get("create_time")
        row_id = position.get("row_id")
        if not isinstance(shard, str) or not _OPAQUE_CURSOR_ID.fullmatch(shard):
            raise MessageStreamProtocolError("invalid_cursor")
        if shard in seen:
            raise MessageStreamProtocolError("invalid_cursor")
        if (
            isinstance(create_time, bool)
            or not isinstance(create_time, int)
            or isinstance(row_id, bool)
            or not isinstance(row_id, int)
            or row_id < 0
        ):
            raise MessageStreamProtocolError("invalid_cursor")
        seen.add(shard)
        normalized_positions.append({
            "shard": shard,
            "create_time": create_time,
            "row_id": row_id,
        })
    normalized_positions.sort(key=lambda item: item["shard"])
    return {
        "version": VERSION,
        "scope": scope,
        "topology": topology,
        "positions": normalized_positions,
    }


def _validated_scope(
    value: Any,
    *,
    source: str,
    since_ts: float,
    until_ts: float,
) -> MessageStreamScope:
    if not isinstance(value, dict):
        raise MessageStreamProtocolError("invalid_request")
    keys = set(value)
    if not SCOPE_REQUIRED_FIELDS.issubset(keys):
        raise MessageStreamProtocolError("invalid_request")
    if not keys.issubset(SCOPE_REQUIRED_FIELDS | SCOPE_OPTIONAL_FIELDS):
        raise MessageStreamProtocolError("invalid_request")
    account_id = _native_id(value.get("account_id"))
    conversation_id = _native_id(value.get("conversation_id"))
    conversation_type = value.get("conversation_type")
    if conversation_type not in CONVERSATION_TYPES:
        raise MessageStreamProtocolError("invalid_request")
    raw_cursor = value.get("page_cursor")
    if raw_cursor is None:
        page_cursor = None
    elif not isinstance(raw_cursor, dict):
        raise MessageStreamProtocolError("invalid_cursor")
    elif source == "qq":
        page_cursor = _validated_qq_cursor(
            raw_cursor,
            conversation_type=conversation_type,
            since_ts=since_ts,
            until_ts=until_ts,
        )
    else:
        page_cursor = _validated_wechat_cursor(raw_cursor)
    return MessageStreamScope(
        account_id=account_id,
        conversation_id=conversation_id,
        conversation_type=conversation_type,
        page_cursor=page_cursor,
    )


def normalize_page_cursor(
    source: str,
    value: Any,
    *,
    conversation_type: str,
    since_ts: float,
    until_ts: float,
) -> Optional[dict]:
    """Validate one JSON-safe source cursor for a request or checkpoint frame."""

    if value is None:
        return None
    if source not in SOURCES or conversation_type not in CONVERSATION_TYPES:
        raise MessageStreamProtocolError("invalid_cursor")
    if not isinstance(value, Mapping):
        raise MessageStreamProtocolError("invalid_cursor")
    if source == "qq":
        return _validated_qq_cursor(
            value,
            conversation_type=conversation_type,
            since_ts=since_ts,
            until_ts=until_ts,
        )
    return _validated_wechat_cursor(value)


def parse_message_stream_request(value: Any) -> MessageStreamRequest:
    """Validate the exact v1 request and canonicalize its scope order."""

    if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
        raise MessageStreamProtocolError("invalid_request")
    if value.get("protocol") != PROTOCOL or value.get("version") != VERSION:
        raise MessageStreamProtocolError("invalid_request")
    if isinstance(value.get("version"), bool):
        raise MessageStreamProtocolError("invalid_request")
    source = value.get("source")
    if source not in SOURCES:
        raise MessageStreamProtocolError("invalid_request")
    since_ts = _finite_number(value.get("since_ts"))
    until_ts = _finite_number(value.get("until_ts"))
    if since_ts > until_ts:
        raise MessageStreamProtocolError("invalid_request")
    page_size = _positive_int(value.get("page_size"), maximum=MAX_PAGE_SIZE)
    raw_scopes = value.get("scopes")
    if not isinstance(raw_scopes, list) or len(raw_scopes) > MAX_SCOPES:
        raise MessageStreamProtocolError("invalid_request")
    scopes = tuple(
        _validated_scope(
            scope,
            source=source,
            since_ts=since_ts,
            until_ts=until_ts,
        )
        for scope in raw_scopes
    )
    identities = [
        (scope.account_id, scope.conversation_id, scope.conversation_type)
        for scope in scopes
    ]
    if len(identities) != len(set(identities)):
        raise MessageStreamProtocolError("invalid_request")
    scopes = tuple(sorted(
        scopes,
        key=lambda scope: (
            scope.account_id,
            scope.conversation_id,
            scope.conversation_type,
        ),
    ))
    return MessageStreamRequest(
        source=source,
        since_ts=since_ts,
        until_ts=until_ts,
        page_size=page_size,
        scopes=scopes,
    )


def read_message_stream_request(stream: TextIO) -> MessageStreamRequest:
    """Read one bounded stdin JSON request without retaining malformed values."""

    try:
        raw = stream.read(MAX_REQUEST_BYTES + 1)
    except (OSError, UnicodeError):
        raise MessageStreamProtocolError("invalid_request") from None
    if not isinstance(raw, str):
        raise MessageStreamProtocolError("invalid_request")
    try:
        encoded_size = len(raw.encode("utf-8"))
    except UnicodeError:
        raise MessageStreamProtocolError("invalid_request") from None
    if len(raw) > MAX_REQUEST_BYTES or encoded_size > MAX_REQUEST_BYTES:
        raise MessageStreamProtocolError("request_too_large")
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise MessageStreamProtocolError("invalid_request") from None
    return parse_message_stream_request(payload)


def message_stream_capabilities_frame() -> dict:
    """Return the single source-of-truth capability negotiation payload."""

    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "frame": "capabilities",
        "sources": list(SOURCES),
        "frames": list(FRAME_TYPES[1:]),
        "ordering": "scope_index,page_index,record_order",
        "checkpoint": "after_each_page",
        "limits": {
            "max_request_bytes": MAX_REQUEST_BYTES,
            "max_frame_bytes": MAX_FRAME_BYTES,
            "max_cursor_bytes": MAX_CURSOR_BYTES,
            "max_scopes": MAX_SCOPES,
            "max_page_size": MAX_PAGE_SIZE,
            "max_total_records": MAX_TOTAL_RECORDS,
            "max_total_pages": MAX_TOTAL_PAGES,
            "max_pages_per_scope": MAX_PAGES_PER_SCOPE,
        },
    }


def error_frame(code: str) -> dict:
    """Return a diagnostic frame that cannot carry native IDs or exception text."""

    if code not in SAFE_ERROR_CODES:
        code = "read_failed"
    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "frame": "error",
        "code": code,
    }


class NDJSONFrameWriter:
    """Serialize, size-check, write, and flush exactly one frame at a time."""

    def __init__(self, stream: TextIO):
        self.stream = stream

    def emit(self, frame: str, **fields: Any) -> None:
        if frame not in FRAME_TYPES:
            raise MessageStreamProtocolError("read_failed")
        payload = {
            "protocol": PROTOCOL,
            "version": VERSION,
            "frame": frame,
            **fields,
        }
        self.emit_payload(payload)

    def emit_payload(self, payload: Mapping[str, Any]) -> None:
        try:
            line = json.dumps(
                dict(payload),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError):
            raise MessageStreamProtocolError("invalid_record") from None
        if len(line.encode("utf-8")) > MAX_FRAME_BYTES:
            raise MessageStreamProtocolError("frame_too_large")
        try:
            self.stream.write(line + "\n")
            self.stream.flush()
        except (BrokenPipeError, ConnectionError, OSError):
            raise MessageStreamBrokenPipe() from None
