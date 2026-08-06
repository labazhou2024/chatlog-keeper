from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from chatlog_keeper import wechat_db


class _DisplayNames:
    def resolve_display_name(self, value):
        return value or ""

    def is_group(self, value):
        return bool(value and str(value).endswith("@chatroom"))


def _message_table(conversation_id: str) -> str:
    suffix = hashlib.md5(conversation_id.encode("utf-8")).hexdigest()
    return f"Msg_{suffix}"


def _create_message_database(
    path: Path,
    *,
    conversation_id: str,
    rows: list[tuple[int, int, int, str, str]],
    distractor_rows: list[tuple[int, int, int, str, str]] | None = None,
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
        connection.executemany(
            "INSERT INTO Name2Id(rowid, user_name) VALUES (?, ?)",
            [(1, "sender-one"), (2, "sender-two")],
        )
        for table, table_rows in (
            (_message_table(conversation_id), rows),
            (_message_table("unselected-conversation"), distractor_rows or []),
        ):
            connection.execute(
                f'CREATE TABLE "{table}" ('
                "local_type INTEGER NOT NULL, "
                "create_time INTEGER NOT NULL, "
                "real_sender_id INTEGER NOT NULL, "
                "message_content BLOB, "
                "server_id TEXT, "
                "packed_info_data BLOB"
                ")"
            )
            connection.executemany(
                f'INSERT INTO "{table}"('
                "rowid, local_type, create_time, real_sender_id, "
                "message_content, server_id, packed_info_data"
                ") VALUES (?, ?, ?, ?, ?, ?, NULL)",
                [
                    (row_id, msg_type, timestamp, sender_id, content, server_id)
                    for row_id, msg_type, timestamp, content, server_id in table_rows
                    for sender_id in [1 if row_id % 2 else 2]
                ],
            )
        connection.commit()
    finally:
        connection.close()


def _reader(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    databases: list[Path],
) -> wechat_db.WeChatDBReader:
    reader = wechat_db.WeChatDBReader(data_root=root)
    reader._initialized = True
    reader.wxid_dir = root
    reader.account_id = "synthetic-account"
    reader.enc_keys = {path: b"k" * 32 for path in databases}
    reader.contacts = _DisplayNames()
    monkeypatch.setattr(wechat_db, "find_msg_databases", lambda _root: list(databases))
    monkeypatch.setattr(
        wechat_db,
        "_decrypt_with_cache",
        lambda database, _key: database,
    )
    return reader


def _message_ids(page: wechat_db.WeChatMessagePage) -> list[str]:
    return [message.server_id for message in page.messages]


def test_query_page_pushes_exact_conversation_window_keyset_and_limit_into_sql(
    tmp_path: Path,
):
    conversation_id = "selected-conversation"
    database = tmp_path / "message-a.db"
    _create_message_database(
        database,
        conversation_id=conversation_id,
        rows=[
            (1, 1, 99, "before", "before"),
            (2, 1, 100, "at-since", "at-since"),
            (3, 1, 101, "first", "first"),
            (4, 1, 101, "second", "second"),
            (5, 1, 102, "third", "third"),
            (6, 1, 103, "after", "after"),
        ],
        distractor_rows=[(1, 1, 101, "not-selected", "not-selected")],
    )
    connection = sqlite3.connect(database)
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    try:
        rows = wechat_db._query_conversation_page_rows(
            connection,
            conversation_id=conversation_id,
            since_ts=100,
            until_ts=102,
            position=(101, 3),
            limit=2,
            shard_id="a" * 24,
        )
    finally:
        connection.close()

    assert [(row.create_time, row.row_id, row.server_id) for row in rows] == [
        (101, 4, "second"),
        (102, 5, "third"),
    ]
    message_selects = [
        statement
        for statement in statements
        if "message_content" in statement.casefold()
    ]
    assert len(message_selects) == 1
    normalized = " ".join(message_selects[0].split()).casefold()
    assert f'from "{_message_table(conversation_id).casefold()}"' in normalized
    assert _message_table("unselected-conversation").casefold() not in normalized
    assert "create_time > 100" in normalized
    assert "create_time <= 102" in normalized
    assert "create_time = 101" in normalized
    assert "rowid > 3" in normalized
    assert "order by create_time asc, rowid asc" in normalized
    assert "limit 2" in normalized
    selects = [
        " ".join(statement.split()).casefold()
        for statement in statements
        if statement.lstrip().casefold().startswith("select")
    ]
    assert selects
    assert all(" limit " in statement for statement in selects)


def test_unmapped_sender_uses_the_same_stable_shard_bound_identity() -> None:
    conversation_id = "selected-conversation"
    shard_id = "a" * 24
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
    connection.execute("INSERT INTO Name2Id(rowid, user_name) VALUES (7, '')")
    table = _message_table(conversation_id)
    connection.execute(
        f'CREATE TABLE "{table}" ('
        "local_type INTEGER NOT NULL, create_time INTEGER NOT NULL, "
        "real_sender_id INTEGER NOT NULL, message_content BLOB, "
        "server_id TEXT, packed_info_data BLOB)"
    )
    connection.execute(
        f'INSERT INTO "{table}"('
        "local_type, create_time, real_sender_id, message_content, server_id) "
        "VALUES (1, 101, 7, 'body', 'server')"
    )
    try:
        rows = wechat_db._query_conversation_page_rows(
            connection,
            conversation_id=conversation_id,
            since_ts=100,
            until_ts=102,
            position=None,
            limit=1,
            shard_id=shard_id,
        )
    finally:
        connection.close()

    assert len(rows) == 1
    assert rows[0].sender == wechat_db._wechat_shard_bound_sender_id(shard_id, 7)
    assert rows[0].sender != "7"


def test_reader_pages_across_shards_in_stable_order_without_same_time_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    conversation_id = "selected-conversation"
    first_database = tmp_path / "message-a.db"
    second_database = tmp_path / "message-b.db"
    _create_message_database(
        first_database,
        conversation_id=conversation_id,
        rows=[
            (1, 1, 101, "a-one", "a-one"),
            (2, 1, 101, "a-two", "a-two"),
            (3, 1, 103, "a-three", "a-three"),
        ],
    )
    _create_message_database(
        second_database,
        conversation_id=conversation_id,
        rows=[
            (1, 1, 101, "b-one", "b-one"),
            (2, 1, 102, "b-two", "b-two"),
            (3, 1, 103, "b-three", "b-three"),
        ],
    )
    reader = _reader(
        monkeypatch,
        tmp_path,
        [second_database, first_database],
    )

    expected = [
        (
            timestamp,
            wechat_db._wechat_message_shard_id(database, root=tmp_path),
            row_id,
            server_id,
        )
        for database, rows in (
            (
                first_database,
                [(1, 101, "a-one"), (2, 101, "a-two"), (3, 103, "a-three")],
            ),
            (
                second_database,
                [(1, 101, "b-one"), (2, 102, "b-two"), (3, 103, "b-three")],
            ),
        )
        for row_id, timestamp, server_id in rows
    ]
    expected_ids = [item[3] for item in sorted(expected)]

    cursor = None
    observed_ids: list[str] = []
    for _ in range(10):
        page = reader.read_conversation_page(
            conversation_id=conversation_id,
            since_ts=100,
            until_ts=103,
            page_size=2,
            cursor=cursor,
        )
        assert len(page.messages) <= 2
        assert page.scanned_rows <= 2
        observed_ids.extend(_message_ids(page))
        cursor = (
            wechat_db.WeChatMessagePageCursor.from_value(page.next_cursor.to_dict())
            if page.next_cursor is not None
            else None
        )
        if not page.has_more:
            break
    else:
        pytest.fail("paged reader did not reach the end")

    assert observed_ids == expected_ids
    assert len(observed_ids) == len(set(observed_ids)) == 6


def test_reader_result_and_cursor_do_not_depend_on_database_enumeration_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    conversation_id = "selected-conversation"
    first_database = tmp_path / "message-a.db"
    second_database = tmp_path / "message-b.db"
    _create_message_database(
        first_database,
        conversation_id=conversation_id,
        rows=[(1, 1, 101, "first", "first")],
    )
    _create_message_database(
        second_database,
        conversation_id=conversation_id,
        rows=[(1, 1, 101, "second", "second")],
    )
    reader = _reader(monkeypatch, tmp_path, [first_database, second_database])

    first = reader.read_conversation_page(
        conversation_id=conversation_id,
        since_ts=100,
        page_size=1,
    )
    monkeypatch.setattr(
        wechat_db,
        "find_msg_databases",
        lambda _root: [second_database, first_database],
    )
    reordered = reader.read_conversation_page(
        conversation_id=conversation_id,
        since_ts=100,
        page_size=1,
    )

    assert _message_ids(first) == _message_ids(reordered)
    assert first.next_cursor == reordered.next_cursor
    assert first.has_more is reordered.has_more is True


def test_cancelled_page_does_not_consume_cursor_and_resume_is_lossless(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    conversation_id = "selected-conversation"
    database = tmp_path / "message-a.db"
    _create_message_database(
        database,
        conversation_id=conversation_id,
        rows=[
            (1, 1, 101, "one", "one"),
            (2, 1, 101, "two", "two"),
            (3, 1, 102, "three", "three"),
        ],
    )
    reader = _reader(monkeypatch, tmp_path, [database])
    first = reader.read_conversation_page(
        conversation_id=conversation_id,
        since_ts=100,
        page_size=1,
    )
    saved_cursor = first.next_cursor

    with pytest.raises(wechat_db.WeChatMessagePageCancelled):
        reader.read_conversation_page(
            conversation_id=conversation_id,
            since_ts=100,
            page_size=1,
            cursor=saved_cursor,
            cancel_requested=lambda: True,
        )

    resumed_ids: list[str] = []
    cursor = saved_cursor
    while True:
        page = reader.read_conversation_page(
            conversation_id=conversation_id,
            since_ts=100,
            page_size=1,
            cursor=cursor,
            cancel_requested=lambda: False,
        )
        resumed_ids.extend(_message_ids(page))
        cursor = page.next_cursor
        if not page.has_more:
            break

    assert [*_message_ids(first), *resumed_ids] == ["one", "two", "three"]


def test_cancelled_after_query_does_not_publish_the_computed_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    conversation_id = "selected-conversation"
    database = tmp_path / "message-a.db"
    _create_message_database(
        database,
        conversation_id=conversation_id,
        rows=[
            (1, 1, 101, "one", "one"),
            (2, 1, 102, "two", "two"),
        ],
    )
    reader = _reader(monkeypatch, tmp_path, [database])
    cancelled = False

    def decorate(messages):
        nonlocal cancelled
        cancelled = True
        return messages

    monkeypatch.setattr(reader, "_decorate_with_displays", decorate)
    with pytest.raises(wechat_db.WeChatMessagePageCancelled):
        reader.read_conversation_page(
            conversation_id=conversation_id,
            since_ts=100,
            page_size=1,
            cursor=None,
            cancel_requested=lambda: cancelled,
        )

    cancelled = False
    monkeypatch.setattr(reader, "_decorate_with_displays", lambda messages: messages)
    retried = reader.read_conversation_page(
        conversation_id=conversation_id,
        since_ts=100,
        page_size=1,
        cursor=None,
        cancel_requested=lambda: cancelled,
    )
    assert _message_ids(retried) == ["one"]


def test_filtered_raw_row_advances_cursor_without_unbounded_refetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    conversation_id = "selected-conversation"
    database = tmp_path / "message-a.db"
    _create_message_database(
        database,
        conversation_id=conversation_id,
        rows=[
            (1, 999, 101, "unsupported", "unsupported"),
            (2, 1, 102, "supported", "supported"),
        ],
    )
    reader = _reader(monkeypatch, tmp_path, [database])

    first = reader.read_conversation_page(
        conversation_id=conversation_id,
        since_ts=100,
        page_size=1,
    )
    assert first.messages == ()
    assert first.scanned_rows == 1
    assert first.has_more is True
    assert first.next_cursor is not None

    second = reader.read_conversation_page(
        conversation_id=conversation_id,
        since_ts=100,
        page_size=1,
        cursor=first.next_cursor,
    )
    assert _message_ids(second) == ["supported"]
    assert second.has_more is False


def test_cursor_fails_closed_when_readable_shard_topology_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    conversation_id = "selected-conversation"
    first_database = tmp_path / "message-a.db"
    second_database = tmp_path / "message-b.db"
    _create_message_database(
        first_database,
        conversation_id=conversation_id,
        rows=[(1, 1, 101, "first", "first")],
    )
    _create_message_database(
        second_database,
        conversation_id=conversation_id,
        rows=[(1, 1, 102, "second", "second")],
    )
    reader = _reader(monkeypatch, tmp_path, [first_database])
    page = reader.read_conversation_page(
        conversation_id=conversation_id,
        since_ts=100,
        page_size=1,
    )

    reader.enc_keys[second_database] = b"k" * 32
    monkeypatch.setattr(
        wechat_db,
        "find_msg_databases",
        lambda _root: [first_database, second_database],
    )
    with pytest.raises(ValueError, match="database topology"):
        reader.read_conversation_page(
            conversation_id=conversation_id,
            since_ts=100,
            page_size=1,
            cursor=page.next_cursor,
        )


@pytest.mark.parametrize(
    "request_change",
    [
        {"conversation_id": "unselected-conversation"},
        {"since_ts": 99},
        {"until_ts": 104},
    ],
)
def test_cursor_fails_closed_when_request_scope_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request_change,
):
    conversation_id = "selected-conversation"
    database = tmp_path / "message-a.db"
    _create_message_database(
        database,
        conversation_id=conversation_id,
        rows=[
            (1, 1, 101, "first", "first"),
            (2, 1, 102, "second", "second"),
        ],
    )
    reader = _reader(monkeypatch, tmp_path, [database])
    page = reader.read_conversation_page(
        conversation_id=conversation_id,
        since_ts=100,
        until_ts=103,
        page_size=1,
    )
    request = {
        "conversation_id": conversation_id,
        "since_ts": 100,
        "until_ts": 103,
        "page_size": 1,
        "cursor": page.next_cursor,
    }
    request.update(request_change)

    with pytest.raises(ValueError, match="request scope"):
        reader.read_conversation_page(**request)


@pytest.mark.parametrize("page_size", [0, -1, 1001, True])
def test_reader_rejects_unbounded_or_invalid_page_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    page_size,
):
    database = tmp_path / "message-a.db"
    _create_message_database(
        database,
        conversation_id="selected-conversation",
        rows=[],
    )
    reader = _reader(monkeypatch, tmp_path, [database])

    with pytest.raises(ValueError, match="page_size"):
        reader.read_conversation_page(
            conversation_id="selected-conversation",
            since_ts=100,
            page_size=page_size,
        )


def test_reader_rejects_an_inverted_time_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    database = tmp_path / "message-a.db"
    _create_message_database(
        database,
        conversation_id="selected-conversation",
        rows=[],
    )
    reader = _reader(monkeypatch, tmp_path, [database])

    with pytest.raises(ValueError, match="until_ts"):
        reader.read_conversation_page(
            conversation_id="selected-conversation",
            since_ts=101,
            until_ts=100,
        )


def test_existing_read_after_contract_remains_full_list_and_time_sorted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    first_database = tmp_path / "message-a.db"
    second_database = tmp_path / "message-b.db"
    reader = _reader(monkeypatch, tmp_path, [second_database, first_database])
    calls = []

    def read(database, since, key, chat_name=None, until_ts=None):
        calls.append((database, since, key, chat_name, until_ts))
        timestamp = 102 if database == first_database else 101
        return [
            wechat_db.WxMessage(
                timestamp=datetime.fromtimestamp(timestamp),
                sender="sender",
                content="synthetic",
                chat_name="selected-conversation",
                server_id=database.stem,
            )
        ]

    monkeypatch.setattr(wechat_db, "_query_messages_since", read)
    messages = reader.read_after(
        100,
        chat_name="selected-conversation",
        until_ts=103,
    )

    assert [message.server_id for message in messages] == [
        second_database.stem,
        first_database.stem,
    ]
    assert calls == [
        (
            second_database,
            100,
            b"k" * 32,
            "selected-conversation",
            103,
        ),
        (
            first_database,
            100,
            b"k" * 32,
            "selected-conversation",
            103,
        ),
    ]
