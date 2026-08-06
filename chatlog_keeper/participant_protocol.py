"""Strict local-only contract for ``participant-directory-v1``.

Native account, conversation, and participant identifiers are private IPC
values.  Requests therefore arrive as one bounded JSON object on stdin and
callers must never place those values in argv, logs, or error text.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional


PROTOCOL = "participant-directory-v1"
VERSION = 1
SOURCES = frozenset({"qq", "wechat"})
VIEWS = frozenset({"member", "sender"})
CONVERSATION_TYPES = frozenset({"direct", "group"})
MAX_REQUEST_BYTES = 65_536
MAX_ID_CHARS = 512
MIN_PAGE_SIZE = 1
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 200
MAX_PARTICIPANTS = 50_000
MAX_LABEL_CHARS = 240
MAX_CURSOR_BYTES = 2_048
LABEL_PROVENANCE = frozenset(
    {
        "anonymous",
        "current_contact_fallback",
        "current_membership",
        "historical_message",
    }
)
VIEW_LABEL_PROVENANCE = {
    "member": frozenset({"anonymous", "current_membership"}),
    "sender": frozenset(
        {"anonymous", "current_contact_fallback", "historical_message"}
    ),
}
SAFE_ERROR_CODES = frozenset(
    {
        "bad_schema",
        "conversation_not_found",
        "cursor_stale",
        "invalid_cursor",
        "invalid_request",
        "read_failed",
        "result_limit_exceeded",
        "source_unavailable",
        "unsupported_view",
    }
)

REQUEST_FIELDS = frozenset(
    {
        "protocol",
        "version",
        "source",
        "account_id",
        "conversation_id",
        "conversation_type",
        "view",
        "page_size",
        "cursor",
    }
)
CURSOR_FIELDS = frozenset({"version", "offset", "snapshot"})


class ParticipantProtocolError(ValueError):
    """Protocol failure carrying only an allowlisted, non-private code."""

    def __init__(self, code: str):
        self.code = code if code in SAFE_ERROR_CODES else "read_failed"
        super().__init__(self.code)


@dataclass(frozen=True)
class ParticipantCursor:
    """Connector-private offset bound to one exact metadata snapshot."""

    offset: int
    snapshot: str

    def to_dict(self) -> dict[str, Any]:
        return {"version": VERSION, "offset": self.offset, "snapshot": self.snapshot}


@dataclass(frozen=True)
class ParticipantRequest:
    """Validated native chat scope and requested directory view."""

    source: str
    account_id: str
    conversation_id: str
    conversation_type: str
    view: str
    page_size: int
    cursor: Optional[ParticipantCursor]


def _native_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ParticipantProtocolError("invalid_request")
    if (
        not value
        or value != value.strip()
        or len(value) > MAX_ID_CHARS
        or any(ord(character) < 32 for character in value)
        or "/" in value
        or "\\" in value
        or value in {".", ".."}
    ):
        raise ParticipantProtocolError("invalid_request")
    return value


def _page_size(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ParticipantProtocolError("invalid_request")
    if not MIN_PAGE_SIZE <= value <= MAX_PAGE_SIZE:
        raise ParticipantProtocolError("invalid_request")
    return value


def _cursor(value: Any) -> Optional[ParticipantCursor]:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != CURSOR_FIELDS:
        raise ParticipantProtocolError("invalid_cursor")
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ParticipantProtocolError("invalid_cursor") from None
    version = value.get("version")
    offset = value.get("offset")
    snapshot = value.get("snapshot")
    if (
        len(encoded) > MAX_CURSOR_BYTES
        or version != VERSION
        or isinstance(version, bool)
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 1
        or not isinstance(snapshot, str)
        or len(snapshot) != 32
        or any(character not in "0123456789abcdef" for character in snapshot)
    ):
        raise ParticipantProtocolError("invalid_cursor")
    return ParticipantCursor(offset=offset, snapshot=snapshot)


def parse_request(raw: Any) -> ParticipantRequest:
    """Validate an already-decoded request without echoing private values."""

    if not isinstance(raw, Mapping) or set(raw) != REQUEST_FIELDS:
        raise ParticipantProtocolError("invalid_request")
    if raw.get("protocol") != PROTOCOL or raw.get("version") != VERSION:
        raise ParticipantProtocolError("invalid_request")
    source = raw.get("source")
    conversation_type = raw.get("conversation_type")
    view = raw.get("view")
    if source not in SOURCES or conversation_type not in CONVERSATION_TYPES or view not in VIEWS:
        raise ParticipantProtocolError("invalid_request")
    return ParticipantRequest(
        source=str(source),
        account_id=_native_id(raw.get("account_id")),
        conversation_id=_native_id(raw.get("conversation_id")),
        conversation_type=str(conversation_type),
        view=str(view),
        page_size=_page_size(raw.get("page_size")),
        cursor=_cursor(raw.get("cursor")),
    )


def read_request(stream) -> ParticipantRequest:
    """Read one bounded JSON value from a text stream."""

    try:
        raw_text = stream.read(MAX_REQUEST_BYTES + 1)
    except (OSError, TypeError, ValueError):
        raise ParticipantProtocolError("invalid_request") from None
    if not isinstance(raw_text, str) or len(raw_text.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ParticipantProtocolError("invalid_request")
    try:
        payload = json.loads(raw_text)
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise ParticipantProtocolError("invalid_request") from None
    return parse_request(payload)


def normalize_participants(values: Any) -> tuple[dict[str, Any], ...]:
    """Validate, de-duplicate, and native-ID-sort metadata-only participants."""

    if not isinstance(values, (list, tuple)) or len(values) > MAX_PARTICIPANTS:
        raise ParticipantProtocolError("result_limit_exceeded")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, Mapping) or set(value) != {
            "participant_id",
            "label",
            "label_provenance",
            "observed_message_count",
        }:
            raise ParticipantProtocolError("bad_schema")
        participant_id = _native_id(value.get("participant_id"))
        if participant_id in seen:
            raise ParticipantProtocolError("bad_schema")
        label = value.get("label")
        label_provenance = value.get("label_provenance")
        count = value.get("observed_message_count")
        if (
            not isinstance(label, str)
            or not isinstance(label_provenance, str)
            or label_provenance not in LABEL_PROVENANCE
        ):
            raise ParticipantProtocolError("bad_schema")
        label = " ".join(label.split()).strip()[:MAX_LABEL_CHARS]
        if (not label and label_provenance != "anonymous") or (
            label and label_provenance == "anonymous"
        ):
            raise ParticipantProtocolError("bad_schema")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ParticipantProtocolError("bad_schema")
        seen.add(participant_id)
        normalized.append(
            {
                "participant_id": participant_id,
                "label": label,
                "label_provenance": label_provenance,
                "observed_message_count": count,
            }
        )
    normalized.sort(key=lambda item: item["participant_id"])
    return tuple(normalized)


def snapshot_token(
    request: ParticipantRequest,
    participants: tuple[dict[str, Any], ...],
    *,
    coverage: str,
) -> str:
    """Fingerprint one exact metadata snapshot without exposing native values."""

    body = json.dumps(
        {
            "protocol": PROTOCOL,
            "source": request.source,
            "account_id": request.account_id,
            "conversation_id": request.conversation_id,
            "conversation_type": request.conversation_type,
            "view": request.view,
            "coverage": coverage,
            "participants": participants,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()[:32]


def build_page(
    request: ParticipantRequest,
    values: Any,
    *,
    coverage: str,
) -> dict[str, Any]:
    """Build one bounded connector page and reject stale private cursors."""

    participants = normalize_participants(values)
    if any(
        item["label_provenance"] not in VIEW_LABEL_PROVENANCE[request.view]
        for item in participants
    ):
        raise ParticipantProtocolError("bad_schema")
    snapshot = snapshot_token(request, participants, coverage=coverage)
    offset = request.cursor.offset if request.cursor is not None else 0
    if request.cursor is not None and request.cursor.snapshot != snapshot:
        raise ParticipantProtocolError("cursor_stale")
    if offset < 0 or offset > len(participants):
        raise ParticipantProtocolError("invalid_cursor")
    page = participants[offset : offset + request.page_size]
    next_offset = offset + len(page)
    complete = next_offset >= len(participants)
    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "source": request.source,
        "view": request.view,
        "conversation_type": request.conversation_type,
        "participants": list(page),
        "coverage": coverage,
        "snapshot_token": snapshot,
        "next_cursor": (
            None
            if complete
            else ParticipantCursor(offset=next_offset, snapshot=snapshot).to_dict()
        ),
        "complete": complete,
    }


def error_payload(code: str) -> dict[str, Any]:
    """Return the only allowed failure shape; it contains no request values."""

    safe_code = code if code in SAFE_ERROR_CODES else "read_failed"
    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "available": False,
        "error": safe_code,
    }


def capabilities_payload() -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "sources": sorted(SOURCES),
        "views": sorted(VIEWS),
        "limits": {
            "max_request_bytes": MAX_REQUEST_BYTES,
            "max_page_size": MAX_PAGE_SIZE,
            "max_participants": MAX_PARTICIPANTS,
        },
    }


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_SIZE",
    "PROTOCOL",
    "ParticipantProtocolError",
    "ParticipantRequest",
    "VERSION",
    "build_page",
    "capabilities_payload",
    "error_payload",
    "parse_request",
    "read_request",
]
