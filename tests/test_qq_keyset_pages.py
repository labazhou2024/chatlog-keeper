"""Bounded/keyset contracts for the NTQQ message-table reader.

The fixtures are synthetic and in-memory: these tests never inspect a real QQ
database, account identifier, key, or message body.
"""

from __future__ import annotations

import inspect
import shutil
import sqlite3

import pytest

from chatlog_keeper import qq_db


_BASE_TS = 1_800_000_000


def _connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    common_columns = (
        '"40001" INTEGER, "40050" REAL NOT NULL, "40090" TEXT, '
        '"40033" INTEGER, "40020" TEXT, "40800" BLOB NOT NULL'
    )
    conn.execute(
        f'CREATE TABLE c2c_msg_table ({common_columns}, "40030" TEXT NOT NULL)'
    )
    conn.execute(
        f'CREATE TABLE group_msg_table ({common_columns}, "40021" TEXT NOT NULL)'
    )
    return conn


def _insert(
    conn: sqlite3.Connection,
    *,
    conversation_type: str,
    conversation_id: str,
    msg_uid: int,
    timestamp: float,
    body: str,
    sender_uin: int = 10001,
    sender_uid: str = "",
) -> None:
    if conversation_type == "direct":
        table = "c2c_msg_table"
        conversation_column = "40030"
    else:
        table = "group_msg_table"
        conversation_column = "40021"
    conn.execute(
        f'INSERT INTO "{table}" '
        f'("40001", "40050", "40090", "40033", "40020", "40800", '
        f'"{conversation_column}") VALUES (?, ?, ?, ?, ?, ?, ?)',
        (
            msg_uid,
            timestamp,
            "Synthetic sender",
            sender_uin,
            sender_uid,
            body.encode(),
            conversation_id,
        ),
    )


@pytest.fixture(autouse=True)
def _synthetic_body_decoder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        qq_db,
        "_extract_msg_text",
        lambda value: bytes(value).decode("utf-8") if value else "",
    )
    monkeypatch.setattr(qq_db, "_extract_qq_attachment_meta", lambda _value: None)


def _page(
    conn: sqlite3.Connection,
    *,
    conversation_type: str | None = "direct",
    conversation_id: str = "scope-a",
    page_size: int = 2,
    cursor=None,
    recover_unreadable_rows: bool = False,
):
    return qq_db._query_message_dict_page(
        conn,
        account_id="account-a",
        conversation_id=conversation_id,
        conversation_type=conversation_type,
        since_ts=_BASE_TS,
        until_ts=_BASE_TS + 10,
        page_size=page_size,
        cursor=cursor,
        recover_unreadable_rows=recover_unreadable_rows,
    )


def test_exact_scope_and_time_window_are_pushed_into_a_limited_query() -> None:
    conn = _connection()
    try:
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=1,
            timestamp=_BASE_TS,
            body="first",
        )
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=2,
            timestamp=_BASE_TS + 1,
            body="second",
        )
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-b",
            msg_uid=3,
            timestamp=_BASE_TS + 1,
            body="wrong conversation",
        )
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=4,
            timestamp=_BASE_TS - 1,
            body="too early",
        )
        _insert(
            conn,
            conversation_type="group",
            conversation_id="scope-a",
            msg_uid=5,
            timestamp=_BASE_TS + 1,
            body="wrong type",
        )
        statements: list[str] = []
        conn.set_trace_callback(statements.append)

        page = _page(conn)

        assert [record["msg_id"] for record in page.records] == [1, 2]
        assert {record["account_id"] for record in page.records} == {"account-a"}
        assert {record["conversation_id"] for record in page.records} == {"scope-a"}
        assert {record["conversation_type"] for record in page.records} == {"direct"}
        message_selects = [
            statement
            for statement in statements
            if "FROM \"c2c_msg_table\"" in statement
            or "FROM \"group_msg_table\"" in statement
        ]
        assert len(message_selects) == 1
        sql = message_selects[0]
        assert 'FROM "c2c_msg_table"' in sql
        assert 'FROM "group_msg_table"' not in sql
        assert '"40030" = ' in sql
        assert '"40050" >= ' in sql
        assert '"40050" <= ' in sql
        assert '"40050" > 0' in sql
        assert "ORDER BY" in sql
        # One extra row is a bounded lookahead used only to make has_more exact.
        assert "LIMIT 3" in sql
    finally:
        conn.close()


def test_nonpositive_timestamp_placeholder_is_excluded_even_when_since_is_zero() -> None:
    conn = _connection()
    try:
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=1,
            timestamp=0,
            body="invalid-time-placeholder",
        )
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=2,
            timestamp=1,
            body="valid",
        )

        page = qq_db._query_message_dict_page(
            conn,
            account_id="account-a",
            conversation_id="scope-a",
            conversation_type="direct",
            since_ts=0,
            until_ts=10,
            page_size=10,
        )

        assert [record["msg_id"] for record in page.records] == [2]
        assert page.has_more is False
    finally:
        conn.close()


def test_zero_uin_uses_sender_uid_and_never_merges_distinct_senders() -> None:
    conn = _connection()
    try:
        for msg_uid, sender_uid in ((1, "u_sender_a"), (2, "u_sender_b")):
            _insert(
                conn,
                conversation_type="direct",
                conversation_id="scope-a",
                msg_uid=msg_uid,
                timestamp=_BASE_TS + msg_uid,
                body=f"message {msg_uid}",
                sender_uin=0,
                sender_uid=sender_uid,
            )

        page = _page(conn, page_size=2)

        assert [record["sender_qq"] for record in page.records] == [0, 0]
        assert [record["sender_uid"] for record in page.records] == [
            "u_sender_a",
            "u_sender_b",
        ]
        assert len({record["wxid_hash"] for record in page.records}) == 2
    finally:
        conn.close()


def test_zero_uin_without_sender_uid_fails_closed() -> None:
    conn = _connection()
    try:
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=1,
            timestamp=_BASE_TS,
            body="message",
            sender_uin=0,
            sender_uid="",
        )

        with pytest.raises(RuntimeError, match="sender identity"):
            _page(conn, page_size=1)
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("case", "failure_code"),
    [
        ("missing_sender", "qq_sender_identity_unavailable"),
        ("unsupported_body", "qq_message_body_unsupported"),
        ("missing_body", "qq_message_body_unavailable"),
    ],
)
def test_opt_in_preserves_unreadable_row_identity_without_private_payload(
    case: str,
    failure_code: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _connection()
    try:
        _insert(
            conn,
            conversation_type="group",
            conversation_id="scope-a",
            msg_uid=7,
            timestamp=_BASE_TS + 1,
            body="" if case == "missing_body" else "opaque-body",
            sender_uin=0 if case == "missing_sender" else 10001,
            sender_uid="",
        )
        if case == "unsupported_body":
            monkeypatch.setattr(qq_db, "_extract_msg_text", lambda _value: "")

        page = _page(
            conn,
            conversation_type="group",
            page_size=1,
            recover_unreadable_rows=True,
        )

        assert page.has_more is False
        assert page.cursor_after is not None and page.cursor_after.rowid == 1
        assert len(page.records) == 1
        record = page.records[0]
        assert record == {
            "account_id": "account-a",
            "conversation_id": "scope-a",
            "conversation_type": "group",
            "thread_id": "account-a::scope-a",
            "ts": float(_BASE_TS + 1),
            "ts_iso": "2027-01-15T08:00:01+00:00",
            "msg_id": 7,
            "source_offset": "qq_db:scope-a:group:1",
            "decode_status": "unreadable",
            "decode_error_code": failure_code,
            "recoverable": True,
        }
        assert not {
            "content",
            "sender_name",
            "sender_uid",
            "sender_qq",
            "attachment_meta",
            "msg_body",
            "path",
            "key",
        }.intersection(record)
    finally:
        conn.close()


def test_valid_unreadable_valid_rows_continue_across_keyset_pages() -> None:
    conn = _connection()
    try:
        for msg_uid, sender_uin in ((1, 10001), (2, 0), (3, 10001)):
            _insert(
                conn,
                conversation_type="group",
                conversation_id="scope-a",
                msg_uid=msg_uid,
                timestamp=_BASE_TS + msg_uid,
                body=f"message {msg_uid}",
                sender_uin=sender_uin,
                sender_uid="",
            )

        first = _page(
            conn,
            conversation_type="group",
            page_size=2,
            recover_unreadable_rows=True,
        )
        second = _page(
            conn,
            conversation_type="group",
            page_size=2,
            cursor=first.cursor_after,
            recover_unreadable_rows=True,
        )

        assert [record["msg_id"] for record in first.records] == [1, 2]
        assert first.records[1]["decode_error_code"] == "qq_sender_identity_unavailable"
        assert [record["msg_id"] for record in second.records] == [3]
        assert first.has_more is True
        assert second.has_more is False
        assert first.cursor_after is not None and first.cursor_after.rowid == 2
        assert second.cursor_after is not None and second.cursor_after.rowid == 3
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("row_index", "replacement"),
    [
        (1, float("nan")),
        (5, "different-scope"),
        (6, 0),
        (7, 0),
    ],
)
def test_unstable_time_scope_or_locator_never_becomes_an_unreadable_marker(
    row_index: int,
    replacement,
) -> None:
    row = [
        7,
        float(_BASE_TS + 1),
        "Synthetic sender",
        10001,
        b"message",
        "scope-a",
        1,
        1,
        "group",
        "",
    ]
    row[row_index] = replacement

    with pytest.raises(RuntimeError):
        qq_db._qq_message_page_record(
            tuple(row),
            account_id="account-a",
            conversation_id="scope-a",
            buddy_map={},
            group_map={},
            group_name_map={},
            recover_unreadable_rows=True,
        )


def test_requested_existing_table_with_missing_columns_fails_closed() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute(
            'CREATE TABLE c2c_msg_table ('
            '"40050" REAL, "40033" INTEGER, "40030" TEXT)'
        )

        with pytest.raises(RuntimeError, match="schema is incompatible"):
            qq_db._query_message_dict_page(
                conn,
                account_id="account-a",
                conversation_id="scope-a",
                conversation_type="direct",
                since_ts=_BASE_TS,
                until_ts=_BASE_TS + 10,
                page_size=1,
            )
    finally:
        conn.close()


def test_message_page_never_calls_fetchall_for_history_rows() -> None:
    raw_conn = _connection()
    try:
        for msg_uid in range(1, 6):
            _insert(
                raw_conn,
                conversation_type="direct",
                conversation_id="scope-a",
                msg_uid=msg_uid,
                timestamp=_BASE_TS,
                body=f"message {msg_uid}",
            )

        class GuardedCursor:
            def __init__(self, wrapped):
                self.wrapped = wrapped
                self.statement = ""

            def execute(self, statement, parameters=()):
                self.statement = statement
                self.wrapped.execute(statement, parameters)
                return self

            def fetchall(self):
                if "AS _qq_message_page" in self.statement:
                    raise AssertionError("message history must not use fetchall")
                return self.wrapped.fetchall()

            def fetchmany(self, size=None):
                return self.wrapped.fetchmany(size)

        class GuardedConnection:
            def cursor(self):
                return GuardedCursor(raw_conn.cursor())

        page = _page(GuardedConnection(), page_size=2)

        assert [record["msg_id"] for record in page.records] == [1, 2]
        assert page.has_more is True
    finally:
        raw_conn.close()


def test_same_timestamp_keyset_resume_is_stable_without_duplicates_or_gaps() -> None:
    conn = _connection()
    try:
        for msg_uid in range(1, 7):
            _insert(
                conn,
                conversation_type="direct",
                conversation_id="scope-a",
                msg_uid=msg_uid,
                timestamp=_BASE_TS,
                body=f"message {msg_uid}",
            )
        cursor = None
        collected: list[int] = []
        pages = []
        while True:
            page = _page(conn, page_size=2, cursor=cursor)
            pages.append(page)
            collected.extend(record["msg_id"] for record in page.records)
            if not page.has_more:
                break
            assert page.cursor_after is not None
            cursor = page.cursor_after

        assert collected == [1, 2, 3, 4, 5, 6]
        assert len(collected) == len(set(collected))
        assert pages[0].cursor_after.msg_time == _BASE_TS
        assert pages[0].cursor_after.table_rank == 0
        assert pages[0].cursor_after.rowid == 2
        repeated = _page(conn, page_size=2)
        assert repeated.records == pages[0].records
        assert repeated.cursor_after == pages[0].cursor_after
    finally:
        conn.close()


def test_untyped_scope_merges_message_tables_in_deterministic_order() -> None:
    conn = _connection()
    try:
        _insert(
            conn,
            conversation_type="group",
            conversation_id="scope-a",
            msg_uid=21,
            timestamp=_BASE_TS,
            body="group one",
        )
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=11,
            timestamp=_BASE_TS,
            body="direct one",
        )
        _insert(
            conn,
            conversation_type="group",
            conversation_id="scope-a",
            msg_uid=22,
            timestamp=_BASE_TS,
            body="group two",
        )
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=12,
            timestamp=_BASE_TS,
            body="direct two",
        )

        cursor = None
        observed: list[tuple[str, int]] = []
        while True:
            page = _page(
                conn,
                conversation_type=None,
                page_size=1,
                cursor=cursor,
            )
            observed.extend(
                (record["conversation_type"], record["msg_id"])
                for record in page.records
            )
            if not page.has_more:
                break
            cursor = page.cursor_after

        assert observed == [
            ("direct", 11),
            ("direct", 12),
            ("group", 21),
            ("group", 22),
        ]
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("replacement", "field"),
    [
        ({"account_id": "account-b"}, "account_id"),
        ({"conversation_id": "scope-b"}, "conversation_id"),
        ({"conversation_type": "group"}, "conversation_type"),
        ({"since_ts": _BASE_TS + 1}, "since_ts"),
        ({"until_ts": _BASE_TS + 9}, "until_ts"),
    ],
)
def test_cursor_from_another_scope_fails_closed(replacement, field: str) -> None:
    conn = _connection()
    try:
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=1,
            timestamp=_BASE_TS,
            body="first",
        )
        cursor = _page(conn, page_size=1).cursor_after
        kwargs = {
            "account_id": "account-a",
            "conversation_id": "scope-a",
            "conversation_type": "direct",
            "since_ts": _BASE_TS,
            "until_ts": _BASE_TS + 10,
            "page_size": 1,
            "cursor": cursor,
        }
        kwargs.update(replacement)

        with pytest.raises(ValueError, match=field):
            qq_db._query_message_dict_page(conn, **kwargs)
    finally:
        conn.close()


def test_empty_page_and_page_size_boundaries_are_explicit() -> None:
    conn = _connection()
    try:
        empty = _page(conn, page_size=1)
        assert empty.records == ()
        assert empty.cursor_after is None
        assert empty.has_more is False

        accepted = _page(conn, page_size=qq_db._QQ_MESSAGE_PAGE_MAX_SIZE)
        assert accepted.records == ()

        for invalid in (False, 0, -1, qq_db._QQ_MESSAGE_PAGE_MAX_SIZE + 1):
            with pytest.raises(ValueError, match="page_size"):
                _page(conn, page_size=invalid)
    finally:
        conn.close()


def test_legacy_read_recent_dicts_signature_remains_unchanged() -> None:
    assert list(inspect.signature(qq_db.QQDBReader.read_recent_dicts).parameters) == [
        "self",
        "since_ts",
        "until_ts",
    ]


def test_reader_stream_keeps_one_decrypted_snapshot_and_exact_account_scope(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "synthetic.db"
    conn = sqlite3.connect(db_path)
    common_columns = (
        '"40001" INTEGER, "40050" REAL NOT NULL, "40090" TEXT, '
        '"40033" INTEGER, "40020" TEXT, "40800" BLOB NOT NULL'
    )
    conn.execute(
        f'CREATE TABLE c2c_msg_table ({common_columns}, "40030" TEXT NOT NULL)'
    )
    conn.execute(
        f'CREATE TABLE group_msg_table ({common_columns}, "40021" TEXT NOT NULL)'
    )
    for msg_uid in range(1, 6):
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=msg_uid,
            timestamp=_BASE_TS,
            body=f"message {msg_uid}",
        )
    conn.commit()
    conn.close()

    snapshots = []

    def copy_plaintext(source, target):
        snapshots.append((source, target))
        shutil.copyfile(source, target)
        return True

    monkeypatch.setattr(qq_db, "_skip_header", copy_plaintext)
    monkeypatch.setattr(qq_db, "_decrypt_db_qq", lambda *_args, **_kwargs: False)
    reader = qq_db.QQDBReader(data_root=tmp_path, account_id="account-a")
    reader._initialized = True
    reader.db_path = db_path
    reader.account_id = "account-a"
    reader.key = b"synthetic-key"

    pages = list(
        reader.iter_message_dict_pages(
            _BASE_TS,
            _BASE_TS + 10,
            account_id="account-a",
            conversation_id="scope-a",
            conversation_type="direct",
            page_size=2,
        )
    )

    assert [record["msg_id"] for page in pages for record in page.records] == [
        1,
        2,
        3,
        4,
        5,
    ]
    assert len(snapshots) == 1
    with pytest.raises(ValueError, match="account_id"):
        list(
            reader.iter_message_dict_pages(
                _BASE_TS,
                _BASE_TS + 10,
                account_id="account-b",
                conversation_id="scope-a",
                conversation_type="direct",
                page_size=2,
            )
        )


def test_reader_cancellation_after_yield_does_not_query_the_next_page(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "synthetic.db"
    conn = sqlite3.connect(db_path)
    common_columns = (
        '"40001" INTEGER, "40050" REAL NOT NULL, "40090" TEXT, '
        '"40033" INTEGER, "40020" TEXT, "40800" BLOB NOT NULL'
    )
    conn.execute(
        f'CREATE TABLE c2c_msg_table ({common_columns}, "40030" TEXT NOT NULL)'
    )
    conn.execute(
        f'CREATE TABLE group_msg_table ({common_columns}, "40021" TEXT NOT NULL)'
    )
    for msg_uid in range(1, 5):
        _insert(
            conn,
            conversation_type="direct",
            conversation_id="scope-a",
            msg_uid=msg_uid,
            timestamp=_BASE_TS,
            body=f"message {msg_uid}",
        )
    conn.commit()
    conn.close()

    monkeypatch.setattr(
        qq_db,
        "_skip_header",
        lambda source, target: shutil.copyfile(source, target) is not None,
    )
    monkeypatch.setattr(qq_db, "_decrypt_db_qq", lambda *_args, **_kwargs: False)
    original_query = qq_db._query_message_dict_page
    query_calls = 0

    def counted_query(*args, **kwargs):
        nonlocal query_calls
        query_calls += 1
        return original_query(*args, **kwargs)

    monkeypatch.setattr(qq_db, "_query_message_dict_page", counted_query)
    reader = qq_db.QQDBReader(data_root=tmp_path, account_id="account-a")
    reader._initialized = True
    reader.db_path = db_path
    reader.account_id = "account-a"
    reader.key = b"synthetic-key"
    cancelled = False
    pages = reader.iter_message_dict_pages(
        _BASE_TS,
        _BASE_TS + 10,
        account_id="account-a",
        conversation_id="scope-a",
        conversation_type="direct",
        page_size=2,
        cancel_requested=lambda: cancelled,
    )

    first = next(pages)
    assert [record["msg_id"] for record in first.records] == [1, 2]
    assert query_calls == 1
    cancelled = True
    with pytest.raises(qq_db.QQMessagePageCancelled, match="read cancelled"):
        next(pages)
    assert query_calls == 1
