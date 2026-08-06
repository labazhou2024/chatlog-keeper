"""Synthetic contracts for metadata-only participant-directory-v1."""

from __future__ import annotations

import io
import json
import logging
import sqlite3
from types import SimpleNamespace

import pytest

from chatlog_keeper import (
    cli,
    participant_directory,
    participant_protocol,
    wechat_contacts,
    wechat_db,
)


def _request(**overrides):
    value = {
        "protocol": "participant-directory-v1",
        "version": 1,
        "source": "qq",
        "account_id": "account-native",
        "conversation_id": "conversation-native",
        "conversation_type": "group",
        "view": "member",
        "page_size": 100,
        "cursor": None,
    }
    value.update(overrides)
    return value


def _participant(
    index: int,
    *,
    label: str | None = None,
    count: int = 0,
    provenance: str = "current_membership",
):
    return {
        "participant_id": f"native-{index:04d}",
        "label": label if label is not None else f"Person {index}",
        "label_provenance": provenance,
        "observed_message_count": count,
    }


def test_protocol_pages_more_than_two_hundred_without_duplicates() -> None:
    values = [_participant(index) for index in range(451)]
    first_request = participant_protocol.parse_request(_request(page_size=200))
    first = participant_protocol.build_page(
        first_request,
        values,
        coverage="current_members_complete",
    )
    second_request = participant_protocol.parse_request(
        _request(page_size=200, cursor=first["next_cursor"])
    )
    second = participant_protocol.build_page(
        second_request,
        list(reversed(values)),
        coverage="current_members_complete",
    )
    third_request = participant_protocol.parse_request(
        _request(page_size=200, cursor=second["next_cursor"])
    )
    third = participant_protocol.build_page(
        third_request,
        values,
        coverage="current_members_complete",
    )

    ids = [
        item["participant_id"]
        for page in (first, second, third)
        for item in page["participants"]
    ]
    assert len(ids) == 451
    assert len(set(ids)) == 451
    assert third["complete"] is True
    assert third["next_cursor"] is None


def test_cursor_rejects_snapshot_rename_and_bad_schema() -> None:
    first_request = participant_protocol.parse_request(_request(page_size=1))
    first = participant_protocol.build_page(
        first_request,
        [_participant(1), _participant(2)],
        coverage="current_members_complete",
    )
    continued = participant_protocol.parse_request(
        _request(page_size=1, cursor=first["next_cursor"])
    )
    with pytest.raises(participant_protocol.ParticipantProtocolError) as raised:
        participant_protocol.build_page(
            continued,
            [_participant(1, label="Renamed"), _participant(2)],
            coverage="current_members_complete",
        )
    assert raised.value.code == "cursor_stale"

    with pytest.raises(participant_protocol.ParticipantProtocolError) as invalid:
        participant_protocol.normalize_participants(
            [{"participant_id": "x", "label": "X", "body": "forbidden"}]
        )
    assert invalid.value.code == "bad_schema"

    with pytest.raises(participant_protocol.ParticipantProtocolError) as mismatch:
        participant_protocol.normalize_participants(
            [
                {
                    "participant_id": "x",
                    "label": "Alice",
                    "label_provenance": "anonymous",
                    "observed_message_count": 0,
                }
            ]
        )
    assert mismatch.value.code == "bad_schema"

    with pytest.raises(participant_protocol.ParticipantProtocolError) as wrong_view:
        participant_protocol.build_page(
            participant_protocol.parse_request(_request(view="member")),
            [
                _participant(
                    1,
                    provenance="current_contact_fallback",
                )
            ],
            coverage="current_members_complete",
        )
    assert wrong_view.value.code == "bad_schema"


def test_protocol_rejects_unbounded_participants_and_page_size() -> None:
    with pytest.raises(participant_protocol.ParticipantProtocolError) as oversized:
        participant_protocol.normalize_participants(
            [{}] * (participant_protocol.MAX_PARTICIPANTS + 1)
        )
    assert oversized.value.code == "result_limit_exceeded"

    with pytest.raises(participant_protocol.ParticipantProtocolError) as page_size:
        participant_protocol.parse_request(
            _request(page_size=participant_protocol.MAX_PAGE_SIZE + 1)
        )
    assert page_size.value.code == "invalid_request"


def test_qq_current_members_keep_missing_nickname() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute('CREATE TABLE group_member3 ("60001" INTEGER, "1002" INTEGER, "20002" TEXT)')
    connection.executemany(
        'INSERT INTO group_member3 ("60001", "1002", "20002") VALUES (?, ?, ?)',
        [(888, 10001, "Named"), (888, 10002, ""), (999, 10003, "Elsewhere")],
    )
    rows = participant_directory._qq_group_members(
        connection,
        conversation_id="888",
        profile_identities={},
    )
    assert rows == [
        {
            "participant_id": "10001",
            "label": "Named",
            "label_provenance": "current_membership",
            "observed_message_count": 0,
        },
        {
            "participant_id": "10002",
            "label": "",
            "label_provenance": "anonymous",
            "observed_message_count": 0,
        },
    ]


def test_qq_sender_view_keeps_departed_and_orphan_and_never_selects_body() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        'CREATE TABLE group_msg_table ('
        '"40021" INTEGER, "40033" INTEGER, "40090" TEXT, "40800" BLOB)'
    )
    connection.executemany(
        'INSERT INTO group_msg_table ("40021", "40033", "40090", "40800") '
        'VALUES (?, ?, ?, ?)',
        [
            (888, 10001, "Current", b"body-a"),
            (888, 10009, "Departed", b"body-b"),
            (888, 10009, "Departed", b"body-c"),
            (888, 10077, "", b"body-d"),
        ],
    )
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    rows = participant_directory._qq_observed_senders(
        connection,
        conversation_id="888",
        conversation_type="group",
        profile_identities={
            10001: SimpleNamespace(directory_label="Current profile name")
        },
        group_labels={
            (888, 10001): "Current group name",
            (888, 10077): "Current group fallback",
        },
    )
    assert {item["participant_id"] for item in rows} == {"10001", "10009", "10077"}
    assert next(item for item in rows if item["participant_id"] == "10009")[
        "observed_message_count"
    ] == 2
    assert next(item for item in rows if item["participant_id"] == "10001")[
        "label"
    ] == "Current"
    assert next(item for item in rows if item["participant_id"] == "10001")[
        "label_provenance"
    ] == "historical_message"
    assert next(item for item in rows if item["participant_id"] == "10077")[
        "label_provenance"
    ] == "current_contact_fallback"
    selects = "\n".join(statement for statement in statements if statement.lstrip().upper().startswith("SELECT"))
    assert "40800" not in selects
    assert "body-a" not in selects


def test_sender_historical_label_wins_current_directory_fallback() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        'CREATE TABLE group_msg_table ('
        '"40021" INTEGER, "40033" INTEGER, "40090" TEXT)'
    )
    connection.execute(
        'INSERT INTO group_msg_table ("40021", "40033", "40090") '
        "VALUES (888, 10001, 'Historical sender name')"
    )

    rows = participant_directory._qq_observed_senders(
        connection,
        conversation_id="888",
        conversation_type="group",
        profile_identities={
            10001: SimpleNamespace(directory_label="Current profile name")
        },
        group_labels={(888, 10001): "Current group name"},
    )

    assert rows == [
        {
            "participant_id": "10001",
            "label": "Historical sender name",
            "label_provenance": "historical_message",
            "observed_message_count": 1,
        }
    ]


def test_qq_sender_zero_uses_stable_uid_and_never_merges_distinct_people() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        'CREATE TABLE group_msg_table ('
        '"40021" INTEGER, "40033" INTEGER, "40020" TEXT, '
        '"40090" TEXT, "40800" BLOB)'
    )
    connection.executemany(
        'INSERT INTO group_msg_table '
        '("40021", "40033", "40020", "40090", "40800") '
        'VALUES (?, ?, ?, ?, ?)',
        [
            (888, 0, "u_sender_a", "Historical A", b"private-zero-a"),
            (888, 0, "u_sender_a", "Historical A", b"private-zero-a-2"),
            (888, 0, "u_sender_b", "", b"private-zero-b"),
            (888, 10001, "u_internal", "Named", b"private-person"),
        ],
    )
    statements: list[str] = []
    connection.set_trace_callback(statements.append)

    rows = participant_directory._qq_observed_senders(
        connection,
        conversation_id="888",
        conversation_type="group",
        profile_identities={0: SimpleNamespace(directory_label="Not allowed")},
        group_labels={(888, 0): "Not allowed"},
    )

    by_id = {item["participant_id"]: item for item in rows}
    assert set(by_id) == {"u_sender_a", "u_sender_b", "10001"}
    assert by_id["u_sender_a"] == {
        "participant_id": "u_sender_a",
        "label": "Historical A",
        "label_provenance": "historical_message",
        "observed_message_count": 2,
    }
    assert by_id["u_sender_b"]["observed_message_count"] == 1
    selects = "\n".join(
        statement
        for statement in statements
        if statement.lstrip().upper().startswith("SELECT")
    )
    assert "40800" not in selects
    assert "private-zero" not in selects

    for invalid_sender in (None, ""):
        invalid = sqlite3.connect(":memory:")
        invalid.execute(
            'CREATE TABLE group_msg_table ('
            '"40021" INTEGER, "40033", "40090" TEXT)'
        )
        invalid.execute(
            'INSERT INTO group_msg_table ("40021", "40033", "40090") '
            "VALUES (888, ?, '')",
            (invalid_sender,),
        )
        with pytest.raises(participant_protocol.ParticipantProtocolError) as raised:
            participant_directory._qq_observed_senders(
                invalid,
                conversation_id="888",
                conversation_type="group",
                profile_identities={},
                group_labels={},
            )
        assert raised.value.code == "bad_schema"


@pytest.mark.parametrize("include_uid_column", [False, True])
def test_qq_sender_zero_without_stable_uid_uses_one_anonymous_bucket(
    include_uid_column: bool,
) -> None:
    connection = sqlite3.connect(":memory:")
    uid_column = ', "40020" TEXT' if include_uid_column else ""
    connection.execute(
        'CREATE TABLE group_msg_table ('
        f'"40021" INTEGER, "40033" INTEGER, "40090" TEXT, '
        f'"40800" BLOB{uid_column})'
    )
    if include_uid_column:
        connection.executemany(
            'INSERT INTO group_msg_table '
            '("40021", "40033", "40090", "40800", "40020") '
            "VALUES (?, ?, ?, ?, ?)",
            [
                (888, 0, "", b"private-system-a", None),
                (888, 0, "Must not become identity", b"private-system-b", ""),
                (888, 10001, "Known", b"private-known", None),
            ],
        )
    else:
        connection.executemany(
            'INSERT INTO group_msg_table '
            '("40021", "40033", "40090", "40800") VALUES (?, ?, ?, ?)',
            [
                (888, 0, "", b"private-system-a"),
                (888, 0, "Must not become identity", b"private-system-b"),
                (888, 10001, "Known", b"private-known"),
            ],
        )
    statements: list[str] = []
    connection.set_trace_callback(statements.append)

    rows = participant_directory._qq_observed_senders(
        connection,
        conversation_id="888",
        conversation_type="group",
        profile_identities={},
        group_labels={},
    )

    by_id = {item["participant_id"]: item for item in rows}
    assert set(by_id) == {
        participant_directory._QQ_UNATTRIBUTED_SENDER_ID,
        "10001",
    }
    assert by_id[participant_directory._QQ_UNATTRIBUTED_SENDER_ID] == {
        "participant_id": participant_directory._QQ_UNATTRIBUTED_SENDER_ID,
        "label": "",
        "label_provenance": "anonymous",
        "observed_message_count": 2,
    }
    assert by_id["10001"]["observed_message_count"] == 1
    page = participant_protocol.build_page(
        participant_protocol.parse_request(_request(view="sender")),
        rows,
        coverage="observed_senders_complete",
    )
    assert len(page["participants"]) == 2
    selects = "\n".join(
        statement
        for statement in statements
        if statement.lstrip().upper().startswith("SELECT")
    )
    assert "40800" not in selects
    assert "private-system" not in selects


def test_wechat_current_members_require_proven_join_and_keep_no_nickname() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE chat_room (id INTEGER, username TEXT)")
    connection.execute("CREATE TABLE chatroom_member (room_id INTEGER, member_id INTEGER)")
    connection.execute(
        "CREATE TABLE contact (id INTEGER, username TEXT, alias TEXT, remark TEXT, nick_name TEXT)"
    )
    connection.execute("INSERT INTO chat_room VALUES (7, 'room@chatroom')")
    connection.executemany("INSERT INTO chatroom_member VALUES (7, ?)", [(1,), (2,)])
    connection.executemany(
        "INSERT INTO contact VALUES (?, ?, ?, ?, ?)",
        [(1, "wxid_one", "alias-one", "Remark", "Nick"), (2, "wxid_two", "", "", "")],
    )
    rows = participant_directory._wechat_current_members(
        connection,
        conversation_id="room@chatroom",
    )
    assert rows == [
        {
            "participant_id": "wxid_one",
            "label": "Remark",
            "label_provenance": "current_membership",
            "observed_message_count": 0,
        },
        {
            "participant_id": "wxid_two",
            "label": "",
            "label_provenance": "anonymous",
            "observed_message_count": 0,
        },
    ]

    broken = sqlite3.connect(":memory:")
    broken.execute("CREATE TABLE chat_room (id INTEGER, username TEXT)")
    with pytest.raises(participant_protocol.ParticipantProtocolError) as raised:
        participant_directory._wechat_current_members(
            broken,
            conversation_id="room@chatroom",
        )
    assert raised.value.code == "bad_schema"


def test_wechat_sender_view_aggregates_shards_without_message_content() -> None:
    table = "Msg_" + __import__("hashlib").md5(b"room@chatroom").hexdigest()
    connections = []
    statements: list[str] = []
    for counts in ((1, 2), (1, 3)):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
        connection.executemany(
            "INSERT INTO Name2Id(rowid, user_name) VALUES (?, ?)",
            [(1, "wxid_old"), (2, "wxid_orphan"), (3, "wxid_third")],
        )
        connection.execute(
            f'CREATE TABLE "{table}" (real_sender_id INTEGER, message_content BLOB)'
        )
        connection.executemany(
            f'INSERT INTO "{table}" VALUES (?, ?)',
            [(sender_id, b"private-body") for sender_id in counts],
        )
        connection.set_trace_callback(statements.append)
        shard_id = ("a" if not connections else "b") * 24
        connections.append((shard_id, connection))
    rows = participant_directory._wechat_observed_senders(
        connections,
        conversation_id="room@chatroom",
    )
    counts = {item["participant_id"]: item["observed_message_count"] for item in rows}
    assert counts == {"wxid_old": 2, "wxid_orphan": 1, "wxid_third": 1}
    selects = "\n".join(statement for statement in statements if statement.lstrip().upper().startswith("SELECT"))
    assert "message_content" not in selects
    assert "private-body" not in selects


def test_wechat_sender_falls_back_for_zero_empty_mapping_and_positive_orphan() -> None:
    table = "Msg_" + __import__("hashlib").md5(b"room@chatroom").hexdigest()
    connections = []
    statements: list[str] = []
    for rows, mappings in (
        (
            [
                (1, b"private-valid"),
                (2, b"private-empty"),
                (3, b"private-late-map"),
                (4, b"private-orphan"),
            ],
            [(1, "wxid_valid"), (2, "")],
        ),
        (
            [
                (1, b"private-valid-2"),
                (2, b"private-empty-2"),
                (3, b"private-late-map-2"),
                (0, b"private-zero"),
            ],
            [(1, "wxid_valid"), (2, ""), (3, "wxid_late")],
        ),
    ):
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
        connection.executemany(
            "INSERT INTO Name2Id(rowid, user_name) VALUES (?, ?)",
            mappings,
        )
        connection.execute(
            f'CREATE TABLE "{table}" ('
            "real_sender_id INTEGER, message_content BLOB)"
        )
        connection.executemany(
            f'INSERT INTO "{table}" VALUES (?, ?)',
            rows,
        )
        connection.set_trace_callback(statements.append)
        shard_id = ("a" if not connections else "b") * 24
        connections.append((shard_id, connection))

    senders = participant_directory._wechat_observed_senders(
        connections,
        conversation_id="room@chatroom",
    )

    by_id = {item["participant_id"]: item for item in senders}
    shard_a = "a" * 24
    shard_b = "b" * 24
    fallback_a_2 = wechat_db._wechat_shard_bound_sender_id(shard_a, 2)
    fallback_a_3 = wechat_db._wechat_shard_bound_sender_id(shard_a, 3)
    fallback_a_4 = wechat_db._wechat_shard_bound_sender_id(shard_a, 4)
    fallback_b_2 = wechat_db._wechat_shard_bound_sender_id(shard_b, 2)
    fallback_b_0 = wechat_db._wechat_shard_bound_sender_id(shard_b, 0)
    assert set(by_id) == {
        "wxid_valid",
        "wxid_late",
        fallback_a_2,
        fallback_a_3,
        fallback_a_4,
        fallback_b_2,
        fallback_b_0,
    }
    assert by_id["wxid_valid"]["observed_message_count"] == 2
    assert by_id["wxid_late"]["observed_message_count"] == 1
    assert by_id[fallback_a_3]["observed_message_count"] == 1
    assert by_id[fallback_a_2]["observed_message_count"] == 1
    assert by_id[fallback_b_2]["observed_message_count"] == 1
    assert all(
        item["label"] == "" and item["label_provenance"] == "anonymous"
        for item in senders
    )
    selects = "\n".join(
        statement
        for statement in statements
        if statement.lstrip().upper().startswith("SELECT")
    )
    assert "message_content" not in selects
    assert "private-" not in selects


def test_wechat_sender_null_id_still_fails_closed_without_selecting_body() -> None:
    table = "Msg_" + __import__("hashlib").md5(b"room@chatroom").hexdigest()
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
    connection.execute(
        f'CREATE TABLE "{table}" ('
        "real_sender_id INTEGER, message_content BLOB)"
    )
    connection.execute(
        f'INSERT INTO "{table}" VALUES (NULL, ?)',
        (b"private-null",),
    )
    statements: list[str] = []
    connection.set_trace_callback(statements.append)

    with pytest.raises(participant_protocol.ParticipantProtocolError) as raised:
        participant_directory._wechat_observed_senders(
            [("a" * 24, connection)],
            conversation_id="room@chatroom",
        )
    assert raised.value.code == "bad_schema"
    selects = "\n".join(
        statement
        for statement in statements
        if statement.lstrip().upper().startswith("SELECT")
    )
    assert "message_content" not in selects
    assert "private-null" not in selects


@pytest.mark.parametrize(
    ("conversation_id", "conversation_type"),
    [("room@chatroom", "direct"), ("direct-user", "group")],
)
def test_wechat_participant_request_rejects_type_suffix_mismatch_before_io(
    conversation_id: str,
    conversation_type: str,
) -> None:
    request = participant_protocol.parse_request(
        _request(
            source="wechat",
            conversation_id=conversation_id,
            conversation_type=conversation_type,
            view="sender",
        )
    )

    with pytest.raises(participant_protocol.ParticipantProtocolError) as raised:
        participant_directory._read_wechat(request, None)

    assert raised.value.code == "bad_schema"


def test_wechat_reader_separates_member_data_and_optional_sender_labels(
    tmp_path,
    monkeypatch,
) -> None:
    wxid_dir = tmp_path / "wxid_account"
    message_database = wxid_dir / "message_0.db"
    contact_database = wxid_dir / "db_storage" / "contact" / "contact.db"
    message_database.parent.mkdir(parents=True)
    contact_database.parent.mkdir(parents=True)
    message_database.write_bytes(b"encrypted-message")
    contact_database.write_bytes(b"encrypted-contact")

    table = "Msg_" + __import__("hashlib").md5(b"room@chatroom").hexdigest()
    plain_message = tmp_path / "plain-message.db"
    connection = sqlite3.connect(plain_message)
    connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
    connection.execute("INSERT INTO Name2Id(rowid, user_name) VALUES (1, 'wxid_sender')")
    connection.execute(f'CREATE TABLE "{table}" (real_sender_id INTEGER)')
    connection.executemany(f'INSERT INTO "{table}" VALUES (?)', [(1,), (1,)])
    connection.commit()
    connection.close()

    plain_contact = tmp_path / "plain-contact.db"
    connection = sqlite3.connect(plain_contact)
    connection.execute("CREATE TABLE chat_room (id INTEGER, username TEXT)")
    connection.execute("CREATE TABLE chatroom_member (room_id INTEGER, member_id INTEGER)")
    connection.execute(
        "CREATE TABLE contact ("
        "id INTEGER, username TEXT, alias TEXT, remark TEXT, nick_name TEXT)"
    )
    connection.execute("INSERT INTO chat_room VALUES (7, 'room@chatroom')")
    connection.execute("INSERT INTO chatroom_member VALUES (7, 1)")
    connection.execute(
        "INSERT INTO contact VALUES (1, 'wxid_sender', '', 'Current remark', '')"
    )
    connection.commit()
    connection.close()

    class FakeReader:
        def __init__(self, **_kwargs):
            self.wxid_dir = wxid_dir
            self.account_id = "wxid_account"
            self.enc_keys = {message_database: b"message-key"}

        def initialize(self):
            return True

    find_message_calls = 0

    def find_message_databases(_wxid_dir):
        nonlocal find_message_calls
        find_message_calls += 1
        return [message_database]

    contact_decrypts = [True]

    def decrypt_snapshot(source, _key, destination):
        if source.name.endswith("contact.db"):
            if not contact_decrypts[0]:
                return False
            destination.write_bytes(plain_contact.read_bytes())
        else:
            destination.write_bytes(plain_message.read_bytes())
        return True

    monkeypatch.setattr(wechat_db, "WeChatDBReader", FakeReader)
    monkeypatch.setattr(wechat_db, "find_msg_databases", find_message_databases)
    monkeypatch.setattr(wechat_db, "_decrypt_db_v4", decrypt_snapshot)
    monkeypatch.setattr(
        wechat_contacts.WeChatContactResolver,
        "_extract_contact_key",
        lambda _self: b"contact-key",
    )

    sender_request = participant_protocol.parse_request(
        _request(
            source="wechat",
            conversation_id="room@chatroom",
            view="sender",
        )
    )
    sender_rows = participant_directory._read_wechat(sender_request, str(tmp_path))
    assert sender_rows == [
        {
            "participant_id": "wxid_sender",
            "label": "Current remark",
            "label_provenance": "current_contact_fallback",
            "observed_message_count": 2,
        }
    ]

    # Current-contact labels are optional for sender coverage.
    contact_decrypts[0] = False
    sender_without_label = participant_directory._read_wechat(
        sender_request,
        str(tmp_path),
    )
    assert sender_without_label[0]["label"] == ""
    assert sender_without_label[0]["label_provenance"] == "anonymous"

    # Current-member view reads only the contact family, not message shards.
    contact_decrypts[0] = True
    calls_before_member = find_message_calls
    member_request = participant_protocol.parse_request(
        _request(
            source="wechat",
            conversation_id="room@chatroom",
            view="member",
        )
    )
    member_rows = participant_directory._read_wechat(member_request, str(tmp_path))
    assert member_rows[0]["label"] == "Current remark"
    assert member_rows[0]["label_provenance"] == "current_membership"
    assert find_message_calls == calls_before_member


def test_cli_reads_native_scope_only_from_stdin_and_errors_never_echo_it(monkeypatch) -> None:
    private_account = "native-account-do-not-log"
    private_conversation = "native-conversation-do-not-log"
    raw_request = _request(
        account_id=private_account,
        conversation_id=private_conversation,
    )
    monkeypatch.setattr(
        participant_directory,
        "read_page",
        lambda received, **_kwargs: participant_protocol.build_page(
            received,
            [_participant(1)],
            coverage="current_members_complete",
        ),
    )
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(json.dumps(raw_request)))
    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)

    code = cli.main(["participant-directory-v1", "--selection-stdin"])

    assert code == 0
    assert stderr.getvalue() == ""
    assert private_account not in "participant-directory-v1 --selection-stdin"
    assert private_conversation not in "participant-directory-v1 --selection-stdin"
    payload = json.loads(stdout.getvalue())
    assert payload["participants"][0]["participant_id"] == "native-0001"

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("not-json-" + private_account))
    stdout = io.StringIO()
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    assert cli.main(["participant-directory-v1", "--selection-stdin"]) == 1
    failure = stdout.getvalue()
    assert failure
    assert private_account not in failure
    assert json.loads(failure)["error"] == "invalid_request"


def test_cli_suppresses_reader_logs_containing_native_scope(
    monkeypatch,
    caplog,
) -> None:
    private_account = "native-account-must-not-enter-logs"
    raw_request = _request(account_id=private_account)

    def fail_after_log(_request, **_kwargs):
        logging.getLogger("participant-private-reader").critical(private_account)
        raise participant_protocol.ParticipantProtocolError("source_unavailable")

    monkeypatch.setattr(participant_directory, "read_page", fail_after_log)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(json.dumps(raw_request)))
    stdout = io.StringIO()
    monkeypatch.setattr(cli.sys, "stdout", stdout)

    with caplog.at_level(logging.DEBUG):
        assert cli.main(["participant-directory-v1", "--selection-stdin"]) == 1

    assert private_account not in caplog.text
    assert private_account not in stdout.getvalue()
    assert json.loads(stdout.getvalue())["error"] == "source_unavailable"
