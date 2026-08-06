from __future__ import annotations

import io
import json
import sqlite3

import pytest

from chatlog_keeper import cli, qq_db

OPAQUE_UID = "u_A9f3K2m8P7q4R6s1T5u0V8w2"


def _proto_varint(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def _proto_bytes_field(field_number: int, value: bytes) -> bytes:
    return _proto_varint((field_number << 3) | 2) + _proto_varint(len(value)) + value


def _qq_message_body(*inner_fields: bytes) -> bytes:
    return _proto_bytes_field(40800, b"".join(inner_fields))


@pytest.mark.parametrize(
    "text",
    [
        OPAQUE_UID,
        f"{OPAQUE_UID}¥{OPAQUE_UID}",
        f"{OPAQUE_UID}:{OPAQUE_UID}",
        f"{OPAQUE_UID}：{OPAQUE_UID}",
        f"{OPAQUE_UID}\u200b{OPAQUE_UID}",
        "4a7d1ed4-8f22-44a8-b8e0-c9370d6f5841",
        "8c14f6dce9104e54893ca0df71bf43e8",
    ],
)
def test_qq_utf8_fallback_rejects_machine_identifier_only_text(text: str) -> None:
    assert qq_db._qq_fallback_text_is_machine_only(text) is True
    assert qq_db._extract_msg_text(b"\x00" + text.encode("utf-8")) == ""


@pytest.mark.parametrize(
    "text",
    [
        f"Please contact {OPAQUE_UID} and retry tomorrow",
        "deployment failed please retry tomorrow",
        "请明天重新确认迁移是否完成",
        "リリースを明日もう一度確認してください",
        "https://example.test/resource?id=42",
        f"https://example.test/resource/{OPAQUE_UID}",
        f"{OPAQUE_UID}@example.test",
        f"/var/tmp/{OPAQUE_UID}",
        f"./cache/{OPAQUE_UID}",
        rf"C:\Temp\{OPAQUE_UID}",
        rf"\\server\share\{OPAQUE_UID}",
        "u_documentation",
        "u_documentation_identifier",
        "HelloWorld_version2_beta_value",
    ],
)
def test_qq_utf8_fallback_keeps_human_readable_context(text: str) -> None:
    assert qq_db._qq_fallback_text_is_machine_only(text) is False
    assert qq_db._extract_msg_text(b"\x00" + text.encode("utf-8"))


def test_qq_protobuf_sender_uid_metadata_is_not_promoted_to_message_text() -> None:
    body = _qq_message_body(
        _proto_bytes_field(40020, OPAQUE_UID.encode("utf-8")),
        _proto_bytes_field(40020, OPAQUE_UID.encode("utf-8")),
    )

    assert qq_db._brute_extract_utf8_fallback(body)
    assert qq_db._extract_msg_text(body) == ""


def test_qq_structured_text_field_preserves_user_authored_identifier() -> None:
    body = _qq_message_body(
        _proto_bytes_field(45101, OPAQUE_UID.encode("utf-8")),
    )

    assert qq_db._extract_msg_text(body) == OPAQUE_UID


def test_qq_message_stream_fails_closed_on_unknown_nonempty_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE c2c_msg_table ("
        '"40001" INTEGER, "40050" REAL NOT NULL, "40090" TEXT, '
        '"40033" INTEGER, "40800" BLOB NOT NULL, "40030" TEXT NOT NULL)'
    )
    machine_body = _qq_message_body(
        _proto_bytes_field(40020, OPAQUE_UID.encode("utf-8")),
        _proto_bytes_field(40020, OPAQUE_UID.encode("utf-8")),
    )
    human_message = "release approved for tomorrow"
    human_body = _qq_message_body(
        _proto_bytes_field(45101, human_message.encode("utf-8")),
    )
    connection.executemany(
        "INSERT INTO c2c_msg_table "
        '("40001", "40050", "40090", "40033", "40800", "40030") '
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (
                1,
                1_800_000_001.0,
                "Synthetic sender",
                10001,
                machine_body,
                "conversation-a",
            ),
            (
                2,
                1_800_000_002.0,
                "Synthetic sender",
                10001,
                human_body,
                "conversation-a",
            ),
        ],
    )

    class BoundedPageQQReader:
        def __init__(self, **_kwargs):
            pass

        def iter_message_dict_pages(self, since_ts, until_ts, **kwargs):
            yield qq_db._query_message_dict_page(
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
    request = {
        "protocol": "message-stream-v1",
        "version": 1,
        "source": "qq",
        "since_ts": 1_800_000_000.0,
        "until_ts": 1_800_000_100.0,
        "page_size": 8,
        "scopes": [
            {
                "account_id": "account-a",
                "conversation_id": "conversation-a",
                "conversation_type": "direct",
            }
        ],
    }
    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setattr(cli.sys, "stdout", stdout)
    monkeypatch.setattr(cli.sys, "stderr", stderr)
    try:
        code = cli.main(["message-stream-v1", "--selection-stdin"])
    finally:
        connection.close()

    frames = [json.loads(line) for line in stdout.getvalue().splitlines()]
    records = [frame["record"] for frame in frames if frame["frame"] == "record"]
    assert code == 1
    assert stderr.getvalue() == ""
    assert records == []
    assert frames[-1] == {
        "protocol": "message-stream-v1",
        "version": 1,
        "frame": "error",
        "code": "read_failed",
    }


def test_qq_reaction_without_narrative_uses_fixed_safe_placeholder() -> None:
    private_payload = _proto_bytes_field(
        47702,
        _proto_bytes_field(47703, OPAQUE_UID.encode("utf-8")),
    )
    body = _qq_message_body(private_payload)

    narrative = qq_db._extract_msg_text(body)

    assert narrative == "[回应]"
    assert OPAQUE_UID not in narrative


def test_qq_reaction_does_not_override_structured_text() -> None:
    body = _qq_message_body(
        _proto_bytes_field(45101, "kept text".encode("utf-8")),
        _proto_bytes_field(47702, b"private-reaction-payload"),
    )

    assert qq_db._extract_msg_text(body) == "kept text"
