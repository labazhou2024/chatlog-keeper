"""Contract tests for the local-only ``message-stream-v1`` NDJSON CLI."""

from __future__ import annotations

import io
import json
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from chatlog_keeper import cli, stream_protocol


def _request(source: str, scopes: list[dict], **overrides) -> dict:
    payload = {
        "protocol": "message-stream-v1",
        "version": 1,
        "source": source,
        "since_ts": 1_800_000_000.0,
        "until_ts": 1_800_000_100.0,
        "page_size": 2,
        "scopes": scopes,
    }
    payload.update(overrides)
    return payload


def _scope(
    account_id: str = "account-a",
    conversation_id: str = "conversation-a",
    conversation_type: str = "direct",
    *,
    page_cursor=None,
) -> dict:
    payload = {
        "account_id": account_id,
        "conversation_id": conversation_id,
        "conversation_type": conversation_type,
    }
    if page_cursor is not None:
        payload["page_cursor"] = page_cursor
    return payload


def _run(monkeypatch: pytest.MonkeyPatch, payload, *, stdout=None):
    stdin = io.StringIO(
        payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
    )
    stdout = stdout or io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(cli.sys, "stdin", stdin)
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)
    code = cli.main(["message-stream-v1", "--selection-stdin"])
    lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
    return code, lines, stderr.getvalue()


def _qq_cursor(account_id: str, conversation_id: str, conversation_type: str, rowid: int):
    return SimpleNamespace(
        account_id=account_id,
        conversation_id=conversation_id,
        conversation_type=conversation_type,
        since_ts=1_800_000_000.0,
        until_ts=1_800_000_100.0,
        msg_time=1_800_000_001.0,
        table_rank=0 if conversation_type == "direct" else 1,
        rowid=rowid,
    )


def _qq_cursor_payload(conversation_type: str = "direct", rowid: int = 1) -> dict:
    return {
        "version": 1,
        "since_ts": 1_800_000_000.0,
        "until_ts": 1_800_000_100.0,
        "msg_time": 1_800_000_001.0,
        "table_rank": 0 if conversation_type == "direct" else 1,
        "rowid": rowid,
    }


def _wechat_cursor_payload(row_id: int = 1) -> dict:
    return {
        "version": 1,
        "scope": "a" * 24,
        "topology": "b" * 24,
        "positions": [{
            "shard": "c" * 24,
            "create_time": 1_800_000_001,
            "row_id": row_id,
        }],
    }


def _unreadable_qq_record(
    *,
    conversation_id: str = "conversation-a",
    failure_code: str = "qq_message_body_unavailable",
    rowid: int = 2,
) -> dict:
    return {
        "account_id": "account-a",
        "conversation_id": conversation_id,
        "conversation_type": "group",
        "thread_id": f"account-a::{conversation_id}",
        "ts": 1_800_000_001.0,
        "ts_iso": "2027-01-15T08:00:01+00:00",
        "msg_id": None,
        "source_offset": f"qq_db:{conversation_id}:group:{rowid}",
        "decode_status": "unreadable",
        "decode_error_code": failure_code,
        "recoverable": True,
    }


def test_capability_negotiation_is_one_bounded_versioned_frame(monkeypatch, capsys) -> None:
    assert cli.main(["message-stream-v1", "--capabilities"]) == 0
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 1
    frame = json.loads(lines[0])
    assert frame == {
        "protocol": "message-stream-v1",
        "version": 1,
        "frame": "capabilities",
        "sources": ["qq", "wechat"],
        "frames": [
            "ready",
            "scope_begin",
            "record",
            "checkpoint",
            "scope_end",
            "complete",
            "error",
        ],
        "ordering": "scope_index,page_index,record_order",
        "checkpoint": "after_each_page",
        "unreadable_record_policy": "quarantine-v1",
        "limits": {
            "max_request_bytes": 262_144,
            "max_frame_bytes": 1_048_576,
            "max_cursor_bytes": 65_536,
            "max_scopes": 128,
            "max_page_size": 1_000,
            "max_total_records": 2_000_000,
            "max_total_pages": 200_000,
            "max_pages_per_scope": 50_000,
        },
    }
    assert frame == stream_protocol.message_stream_capabilities_frame()
    assert len(lines[0].encode("utf-8")) <= stream_protocol.MAX_FRAME_BYTES
    assert captured.err == ""


def test_zero_scopes_emit_a_clean_ready_complete_stream_without_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "_message_stream_reader",
        lambda *_args, **_kwargs: pytest.fail("zero scopes must not initialize a reader"),
    )

    code, frames, stderr = _run(monkeypatch, _request("qq", []))

    assert code == 0
    assert stderr == ""
    assert frames == [
        {
            "protocol": "message-stream-v1",
            "version": 1,
            "frame": "ready",
            "source": "qq",
            "scope_count": 0,
            "page_size": 2,
        },
        {
            "protocol": "message-stream-v1",
            "version": 1,
            "frame": "complete",
            "scope_count": 0,
            "page_count": 0,
            "record_count": 0,
        },
    ]


def test_qq_records_flush_before_iterator_resumes_and_each_page_checkpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"resumed": False, "closed": False, "record_flushed": False}
    calls = []

    class ObservedStdout(io.StringIO):
        def __init__(self):
            super().__init__()
            self.seen = 0

        def flush(self):
            lines = self.getvalue().splitlines()
            for raw in lines[self.seen:]:
                frame = json.loads(raw)
                if frame["frame"] == "record" and not state["record_flushed"]:
                    assert state["resumed"] is False
                    state["record_flushed"] = True
            self.seen = len(lines)

    class FakeQQReader:
        def __init__(self, *, data_root=None, account_id=None):
            calls.append(("reader", data_root, account_id))

        def iter_message_dict_pages(self, since_ts, until_ts, **kwargs):
            calls.append(("iter", since_ts, until_ts, kwargs))
            account_id = kwargs["account_id"]
            conversation_id = kwargs["conversation_id"]
            conversation_type = kwargs["conversation_type"]
            try:
                yield SimpleNamespace(
                    records=({
                        "account_id": account_id,
                        "conversation_id": conversation_id,
                        "conversation_type": conversation_type,
                        "content": "synthetic first",
                        "ts": 1_800_000_001.0,
                    },),
                    cursor_after=_qq_cursor(
                        account_id, conversation_id, conversation_type, 1
                    ),
                    has_more=True,
                )
                state["resumed"] = True
                assert state["record_flushed"] is True
                yield SimpleNamespace(
                    records=({
                        "account_id": account_id,
                        "conversation_id": conversation_id,
                        "conversation_type": conversation_type,
                        "content": "synthetic second",
                        "ts": 1_800_000_002.0,
                    },),
                    cursor_after=_qq_cursor(
                        account_id, conversation_id, conversation_type, 2
                    ),
                    has_more=False,
                )
            finally:
                state["closed"] = True

    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeQQReader)
    monkeypatch.setattr(
        cli,
        "export_json",
        lambda *_args, **_kwargs: pytest.fail("stream must not export JSON files"),
    )
    monkeypatch.setattr(
        cli,
        "export_html",
        lambda *_args, **_kwargs: pytest.fail("stream must not export HTML files"),
    )

    code, frames, stderr = _run(
        monkeypatch,
        _request("qq", [_scope()]),
        stdout=ObservedStdout(),
    )

    assert code == 0
    assert stderr == ""
    assert state == {"resumed": True, "closed": True, "record_flushed": True}
    assert [frame["frame"] for frame in frames] == [
        "ready",
        "scope_begin",
        "record",
        "checkpoint",
        "record",
        "checkpoint",
        "scope_end",
        "complete",
    ]
    checkpoints = [frame for frame in frames if frame["frame"] == "checkpoint"]
    assert [(item["page_index"], item["record_count"], item["has_more"]) for item in checkpoints] == [
        (0, 1, True),
        (1, 2, False),
    ]
    assert all("account_id" not in item["cursor"] for item in checkpoints)
    assert frames[-2]["page_count"] == 2
    assert frames[-2]["record_count"] == 2
    assert frames[-1]["page_count"] == 2
    assert frames[-1]["record_count"] == 2
    assert all(
        frame["protocol"] == "message-stream-v1" and frame["version"] == 1
        for frame in frames
    )
    assert calls[1][3]["page_size"] == 2
    assert callable(calls[1][3]["cancel_requested"])
    assert calls[1][3]["recover_unreadable_rows"] is False


def test_opt_in_unreadable_record_continues_current_and_later_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recover_flags: list[bool] = []

    class RecoveringQQReader:
        def __init__(self, **_kwargs):
            pass

        def iter_message_dict_pages(self, _since_ts, _until_ts, **kwargs):
            recover_flags.append(kwargs["recover_unreadable_rows"])
            conversation_id = kwargs["conversation_id"]
            if conversation_id == "conversation-a":
                records = (
                    {
                        "account_id": "account-a",
                        "conversation_id": conversation_id,
                        "conversation_type": "group",
                        "content": "valid before",
                        "ts": 1_800_000_000.0,
                    },
                    _unreadable_qq_record(conversation_id=conversation_id),
                    {
                        "account_id": "account-a",
                        "conversation_id": conversation_id,
                        "conversation_type": "group",
                        "content": "valid after",
                        "ts": 1_800_000_002.0,
                    },
                )
                rowid = 3
            else:
                records = ({
                    "account_id": "account-a",
                    "conversation_id": conversation_id,
                    "conversation_type": "group",
                    "content": "later scope",
                    "ts": 1_800_000_003.0,
                },)
                rowid = 1
            yield SimpleNamespace(
                records=records,
                cursor_after=_qq_cursor(
                    "account-a", conversation_id, "group", rowid
                ),
                has_more=False,
            )

    monkeypatch.setattr(cli.qq_db, "QQDBReader", RecoveringQQReader)
    request = _request(
        "qq",
        [
            _scope("account-a", "conversation-b", "group"),
            _scope("account-a", "conversation-a", "group"),
        ],
        page_size=3,
        unreadable_record_policy="quarantine-v1",
    )

    code, frames, stderr = _run(monkeypatch, request)

    assert code == 0
    assert stderr == ""
    assert recover_flags == [True, True]
    assert all(frame["frame"] != "error" for frame in frames)
    records = [frame["record"] for frame in frames if frame["frame"] == "record"]
    assert [record.get("content") for record in records] == [
        "valid before",
        None,
        "valid after",
        "later scope",
    ]
    assert records[1]["decode_error_code"] == "qq_message_body_unavailable"
    checkpoints = [frame for frame in frames if frame["frame"] == "checkpoint"]
    assert [frame["record_count"] for frame in checkpoints] == [3, 1]
    assert frames[-1]["frame"] == "complete"
    assert frames[-1]["scope_count"] == 2
    assert frames[-1]["record_count"] == 4


def test_unreadable_marker_without_request_opt_in_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnexpectedUnreadableReader:
        def __init__(self, **_kwargs):
            pass

        def iter_message_dict_pages(self, _since_ts, _until_ts, **kwargs):
            assert kwargs["recover_unreadable_rows"] is False
            yield SimpleNamespace(
                records=(_unreadable_qq_record(),),
                cursor_after=_qq_cursor("account-a", "conversation-a", "group", 2),
                has_more=False,
            )

    monkeypatch.setattr(cli.qq_db, "QQDBReader", UnexpectedUnreadableReader)
    code, frames, stderr = _run(
        monkeypatch,
        _request("qq", [_scope(conversation_type="group")]),
    )

    assert code == 1
    assert stderr == ""
    assert frames[-1]["frame"] == "error"
    assert frames[-1]["code"] == "invalid_record"
    assert all(frame["frame"] != "checkpoint" for frame in frames)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(thread_id="account-a::wrong-scope"),
        lambda value: value.update(ts_iso="2027-01-15T08:00:02+00:00"),
        lambda value: value.update(source_offset="qq_db:wrong-scope:group:2"),
        lambda value: value.update(ts=0),
        lambda value: value.update(decode_error_code="private_exception_text"),
        lambda value: value.update(content="not a real message"),
    ],
)
def test_unreadable_record_exact_schema_and_identity_invariants_fail_closed(
    mutate,
) -> None:
    record = _unreadable_qq_record()
    mutate(record)

    with pytest.raises(stream_protocol.MessageStreamProtocolError) as error:
        stream_protocol.validate_message_stream_record(record)

    assert error.value.code == "invalid_record"
    assert "private_exception_text" not in str(error.value)


def test_normal_record_shape_remains_open_and_invalid_policy_is_rejected() -> None:
    normal = {
        "account_id": "account-a",
        "conversation_id": "conversation-a",
        "conversation_type": "direct",
        "content": "normal record remains additive",
        "future_field": {"nested": True},
    }
    assert stream_protocol.validate_message_stream_record(normal) is normal

    request = _request(
        "qq",
        [_scope()],
        unreadable_record_policy="silent-drop",
    )
    with pytest.raises(stream_protocol.MessageStreamProtocolError) as error:
        stream_protocol.parse_message_stream_request(request)
    assert error.value.code == "invalid_request"


def test_qq_bounded_page_content_round_trips_to_ndjson_without_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    long_content = "  long-message:" + ("内容" * 2_000) + ":tail  "
    connection = sqlite3.connect(":memory:")
    connection.execute(
        'CREATE TABLE c2c_msg_table ('
        '"40001" INTEGER, "40050" REAL NOT NULL, "40090" TEXT, '
        '"40033" INTEGER, "40800" BLOB NOT NULL, "40030" TEXT NOT NULL)'
    )
    connection.execute(
        'CREATE TABLE group_msg_table ('
        '"40001" INTEGER, "40050" REAL NOT NULL, "40090" TEXT, '
        '"40033" INTEGER, "40800" BLOB NOT NULL, "40021" TEXT NOT NULL)'
    )
    connection.execute(
        'INSERT INTO c2c_msg_table '
        '("40001", "40050", "40090", "40033", "40800", "40030") '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (
            1,
            1_800_000_001.0,
            "Synthetic sender",
            10001,
            long_content.encode("utf-8"),
            "conversation-a",
        ),
    )
    monkeypatch.setattr(
        cli.qq_db,
        "_extract_msg_text",
        lambda value: bytes(value).decode("utf-8") if value else "",
    )
    monkeypatch.setattr(
        cli.qq_db,
        "_extract_qq_attachment_meta",
        lambda _value: None,
    )

    class BoundedPageQQReader:
        def __init__(self, **_kwargs):
            pass

        def iter_message_dict_pages(self, since_ts, until_ts, **kwargs):
            yield cli.qq_db._query_message_dict_page(
                connection,
                account_id=kwargs["account_id"],
                conversation_id=kwargs["conversation_id"],
                conversation_type=kwargs["conversation_type"],
                since_ts=since_ts,
                until_ts=until_ts,
                page_size=kwargs["page_size"],
                cursor=kwargs["cursor"],
            )

    monkeypatch.setattr(cli.qq_db, "QQDBReader", BoundedPageQQReader)
    try:
        code, frames, stderr = _run(monkeypatch, _request("qq", [_scope()]))
    finally:
        connection.close()

    records = [frame["record"] for frame in frames if frame["frame"] == "record"]
    assert code == 0
    assert stderr == ""
    assert len(records) == 1
    assert records[0]["content"] == long_content
    assert records[0]["content"].endswith(":tail  ")


def test_empty_scopes_are_canonical_and_still_emit_a_terminal_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = []

    class EmptyQQReader:
        def __init__(self, *, data_root=None, account_id=None):
            self.account_id = account_id

        def iter_message_dict_pages(self, since_ts, until_ts, **kwargs):
            observed.append(
                (
                    kwargs["account_id"],
                    kwargs["conversation_id"],
                    kwargs["conversation_type"],
                )
            )
            return iter(())

    monkeypatch.setattr(cli.qq_db, "QQDBReader", EmptyQQReader)
    scopes = [
        _scope("account-b", "conversation-z", "group"),
        _scope("account-a", "conversation-z", "direct"),
        _scope("account-a", "conversation-a", "group"),
    ]

    code, frames, stderr = _run(monkeypatch, _request("qq", scopes))

    assert code == 0
    assert stderr == ""
    assert observed == [
        ("account-a", "conversation-a", "group"),
        ("account-a", "conversation-z", "direct"),
        ("account-b", "conversation-z", "group"),
    ]
    checkpoints = [frame for frame in frames if frame["frame"] == "checkpoint"]
    assert [(frame["scope_index"], frame["page_index"]) for frame in checkpoints] == [
        (0, 0),
        (1, 0),
        (2, 0),
    ]
    assert all(frame["cursor"] is None and frame["has_more"] is False for frame in checkpoints)
    diagnostic_frames = [frame for frame in frames if frame["frame"] != "record"]
    diagnostics = "\n".join(json.dumps(frame) for frame in diagnostic_frames)
    assert "account-a" not in diagnostics
    assert "conversation-a" not in diagnostics


def test_wechat_uses_bounded_pages_and_preserves_existing_record_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    class Cursor:
        def __init__(self, position):
            self.position = position

        def to_dict(self):
            return {
                "version": 1,
                "scope": "a" * 24,
                "topology": "b" * 24,
                "positions": [{
                    "shard": "c" * 24,
                    "create_time": 1_800_000_001,
                    "row_id": self.position,
                }],
            }

    class FakeWeChatReader:
        def __init__(self, *, data_root=None, account_id=None):
            self.account_id = account_id
            self.wxid_dir = SimpleNamespace(name=account_id)

        def read_conversation_page(self, **kwargs):
            calls.append(kwargs)
            position = len(calls)
            message = SimpleNamespace(
                timestamp=datetime.fromtimestamp(
                    1_800_000_000 + position,
                    tz=timezone.utc,
                ),
                sender="sender-wxid",
                sender_display_name="Sender nickname",
                chat_name=kwargs["conversation_id"],
                chat_display_name="Chat display name",
                content=f"synthetic {position}",
                msg_type=1,
                is_group_chat=True,
                server_id=f"server-{position}",
            )
            return SimpleNamespace(
                messages=(message,),
                next_cursor=Cursor(position),
                has_more=position == 1,
                scanned_rows=1,
            )

    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", FakeWeChatReader)
    code, frames, stderr = _run(
        monkeypatch,
        _request(
            "wechat",
            [_scope("wechat-account", "room@chatroom", "group")],
        ),
    )

    assert code == 0
    assert stderr == ""
    assert len(calls) == 2
    assert calls[0]["page_size"] == 2
    assert calls[0]["cursor"] is None
    assert calls[1]["cursor"].to_dict()["positions"][0]["row_id"] == 1
    assert callable(calls[0]["cancel_requested"])
    records = [frame["record"] for frame in frames if frame["frame"] == "record"]
    assert [record["content"] for record in records] == ["synthetic 1", "synthetic 2"]
    assert all(record["account_id"] == "wechat-account" for record in records)
    assert all(record["conversation_id"] == "room@chatroom" for record in records)
    assert all(record["conversation_type"] == "group" for record in records)
    assert frames[-2]["page_count"] == 2
    assert frames[-1]["record_count"] == 2


def test_wechat_reader_initializes_only_once_for_multiple_scopes_on_one_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"initialize": 0, "reader": 0, "pages": 0}

    class FakeWeChatReader:
        def __init__(self, *, data_root=None, account_id=None):
            state["reader"] += 1
            self.account_id = account_id
            self.wxid_dir = SimpleNamespace(name=account_id)
            self.enc_keys = {}
            self._initialized = False

        def initialize(self):
            state["initialize"] += 1
            self.enc_keys = {"synthetic": b"key"}
            self._initialized = True
            return True

        def read_conversation_page(self, **_kwargs):
            state["pages"] += 1
            return SimpleNamespace(
                messages=(),
                next_cursor=None,
                has_more=False,
                scanned_rows=0,
            )

    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", FakeWeChatReader)
    code, frames, stderr = _run(
        monkeypatch,
        _request(
            "wechat",
            [
                _scope("wechat-account", "conversation-b", "direct"),
                _scope("wechat-account", "conversation-a", "direct"),
            ],
        ),
    )

    assert code == 0
    assert stderr == ""
    assert state == {"initialize": 1, "reader": 1, "pages": 2}
    assert [frame["frame"] for frame in frames].count("checkpoint") == 2


@pytest.mark.parametrize(
    ("conversation_id", "conversation_type"),
    [("room@chatroom", "direct"), ("direct-user", "group")],
)
def test_wechat_scope_type_suffix_mismatch_fails_before_page_read(
    monkeypatch: pytest.MonkeyPatch,
    conversation_id: str,
    conversation_type: str,
) -> None:
    class GuardedReader:
        def __init__(self, **_kwargs):
            pass

        def read_conversation_page(self, **_kwargs):
            pytest.fail("mismatched scope must not reach the database page")

    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", GuardedReader)

    code, frames, stderr = _run(
        monkeypatch,
        _request(
            "wechat",
            [_scope("wechat-account", conversation_id, conversation_type)],
        ),
    )

    assert code == 1
    assert stderr == ""
    assert frames[-1]["frame"] == "error"
    assert frames[-1]["code"] == "scope_mismatch"


def test_qq_requested_table_missing_columns_emits_read_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        'CREATE TABLE c2c_msg_table ('
        '"40050" REAL, "40033" INTEGER, "40030" TEXT)'
    )

    class BrokenSchemaReader:
        def __init__(self, **_kwargs):
            pass

        def iter_message_dict_pages(self, since_ts, until_ts, **kwargs):
            yield cli.qq_db._query_message_dict_page(
                connection,
                account_id=kwargs["account_id"],
                conversation_id=kwargs["conversation_id"],
                conversation_type=kwargs["conversation_type"],
                since_ts=since_ts,
                until_ts=until_ts,
                page_size=kwargs["page_size"],
                cursor=kwargs["cursor"],
            )

    monkeypatch.setattr(cli.qq_db, "QQDBReader", BrokenSchemaReader)
    try:
        code, frames, stderr = _run(monkeypatch, _request("qq", [_scope()]))
    finally:
        connection.close()

    assert code == 1
    assert stderr == ""
    assert frames[-1]["frame"] == "error"
    assert frames[-1]["code"] == "read_failed"
    assert all(frame["frame"] != "complete" for frame in frames)


@pytest.mark.parametrize("source", ["qq", "wechat"])
def test_has_more_rejects_a_nonadvancing_checkpoint_before_emitting_it(
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    if source == "qq":
        cursor = _qq_cursor_payload()

        class StalledReader:
            def __init__(self, **_kwargs):
                pass

            def iter_message_dict_pages(self, since_ts, until_ts, **kwargs):
                yield SimpleNamespace(
                    records=(),
                    cursor_after=_qq_cursor(
                        kwargs["account_id"],
                        kwargs["conversation_id"],
                        kwargs["conversation_type"],
                        cursor["rowid"],
                    ),
                    has_more=True,
                )

        monkeypatch.setattr(cli.qq_db, "QQDBReader", StalledReader)
    else:
        cursor = _wechat_cursor_payload()

        class StalledReader:
            def __init__(self, **_kwargs):
                pass

            def read_conversation_page(self, **_kwargs):
                return SimpleNamespace(
                    messages=(),
                    next_cursor=cursor,
                    has_more=True,
                    scanned_rows=0,
                )

        monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", StalledReader)

    code, frames, stderr = _run(
        monkeypatch,
        _request(source, [_scope(page_cursor=cursor)]),
    )

    assert code == 1
    assert stderr == ""
    assert [frame["frame"] for frame in frames] == [
        "ready",
        "scope_begin",
        "error",
    ]
    assert frames[-1]["code"] == "invalid_cursor"


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ("{not-json", "invalid_request"),
        ({"protocol": "message-stream-v1"}, "invalid_request"),
        (_request("qq", [_scope()], extra=True), "invalid_request"),
        (_request("qq", [_scope()], page_size=0), "invalid_request"),
        (
            _request(
                "qq",
                [_scope(account_id=f"account-{index}") for index in range(
                    stream_protocol.MAX_SCOPES + 1
                )],
            ),
            "invalid_request",
        ),
    ],
)
def test_malformed_requests_fail_closed_without_reader_or_stderr(
    monkeypatch: pytest.MonkeyPatch,
    payload,
    code: str,
) -> None:
    monkeypatch.setattr(
        cli.qq_db,
        "QQDBReader",
        lambda **_kwargs: pytest.fail("invalid request reached QQ reader"),
    )

    exit_code, frames, stderr = _run(monkeypatch, payload)

    assert exit_code == 2
    assert frames == [{
        "protocol": "message-stream-v1",
        "version": 1,
        "frame": "error",
        "code": code,
    }]
    assert stderr == ""


def test_oversized_input_and_record_frames_fail_with_safe_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_marker = "private-native-id"
    oversized = "{" + "x" * stream_protocol.MAX_REQUEST_BYTES + private_marker
    exit_code, frames, stderr = _run(monkeypatch, oversized)
    assert exit_code == 2
    assert frames[-1]["code"] == "request_too_large"
    assert private_marker not in json.dumps(frames)
    assert private_marker not in stderr

    class HugeQQReader:
        def __init__(self, **_kwargs):
            pass

        def iter_message_dict_pages(self, since_ts, until_ts, **kwargs):
            yield SimpleNamespace(
                records=({
                    "account_id": kwargs["account_id"],
                    "conversation_id": kwargs["conversation_id"],
                    "conversation_type": kwargs["conversation_type"],
                    "content": "x" * stream_protocol.MAX_FRAME_BYTES,
                },),
                cursor_after=_qq_cursor(
                    kwargs["account_id"],
                    kwargs["conversation_id"],
                    kwargs["conversation_type"],
                    1,
                ),
                has_more=False,
            )

    monkeypatch.setattr(cli.qq_db, "QQDBReader", HugeQQReader)
    exit_code, frames, stderr = _run(monkeypatch, _request("qq", [_scope()]))
    assert exit_code == 1
    assert frames[-1]["frame"] == "error"
    assert frames[-1]["code"] == "frame_too_large"
    assert all(len(json.dumps(frame).encode("utf-8")) <= stream_protocol.MAX_FRAME_BYTES for frame in frames)
    assert stderr == ""


def test_broken_pipe_closes_the_upstream_iterator_without_more_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"closed": False, "second_page": False}

    class BrokenOutput(io.StringIO):
        def write(self, value):
            if '"frame":"record"' in value:
                raise BrokenPipeError()
            return super().write(value)

    class FakeQQReader:
        def __init__(self, **_kwargs):
            pass

        def iter_message_dict_pages(self, since_ts, until_ts, **kwargs):
            try:
                yield SimpleNamespace(
                    records=({
                        "account_id": kwargs["account_id"],
                        "conversation_id": kwargs["conversation_id"],
                        "conversation_type": kwargs["conversation_type"],
                        "content": "first",
                    },),
                    cursor_after=_qq_cursor(
                        kwargs["account_id"],
                        kwargs["conversation_id"],
                        kwargs["conversation_type"],
                        1,
                    ),
                    has_more=True,
                )
                state["second_page"] = True
                yield pytest.fail("broken pipe consumed a second page")
            finally:
                state["closed"] = True

    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeQQReader)
    code, _frames, stderr = _run(
        monkeypatch,
        _request("qq", [_scope()]),
        stdout=BrokenOutput(),
    )

    assert code == 0
    assert state == {"closed": True, "second_page": False}
    assert stderr == ""


def test_legacy_probe_output_and_dispatch_are_unchanged(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_probe_qq", lambda: {"source": "qq", "available": True})
    monkeypatch.setattr(
        cli,
        "_probe_wechat",
        lambda: {"source": "wechat", "available": False},
    )

    assert cli.main(["probe"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "qq": {"source": "qq", "available": True},
        "wechat": {"source": "wechat", "available": False},
    }
    assert "message-stream-v1" not in captured.out
    assert captured.err == ""
