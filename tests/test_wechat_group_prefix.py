"""Synthetic group envelopes must not hide non-text messages or metadata."""

import sqlite3
from datetime import datetime

import pytest
import zstandard

from chatlog_keeper import wechat_db


_CONVERSATION = "synthetic-group@chatroom"
_SENDER = "wxid_synthetic_sender"
_CASES = [
    (3, '<msg><img md5="' + 'a' * 32 + '" /></msg>', "image"),
    (34, '<msg><voicemsg voicelength="1200" /></msg>', "voice"),
    (43, '<msg><videomsg md5="' + 'b' * 32 + '" playlength="3" /></msg>', "video"),
    (47, '<msg><emoji md5="' + 'c' * 32 + '" /></msg>', None),
    (48, '<msg><location x="1" y="2" label="Synthetic place" /></msg>', None),
    (49, '<msg><appmsg><type>6</type><title>synthetic.txt</title></appmsg></msg>', None),
]


def _read(connection, reader):
    names = wechat_db._load_name_map(connection)
    if reader == "date":
        return wechat_db._query_messages_by_date(
            connection, datetime.fromtimestamp(1700000000).date(), names,
        )
    if reader == "since":
        return wechat_db._query_messages_since_inner(connection, 0, names)
    rows = wechat_db._query_conversation_page_rows(
        connection, conversation_id=_CONVERSATION, since_ts=0, until_ts=None,
        position=None, limit=10, shard_id="a" * 24,
    )
    return [
        message for row in rows
        if (message := wechat_db._wechat_message_from_page_row(
            row, conversation_id=_CONVERSATION,
        )) is not None
    ]


@pytest.mark.parametrize("reader", ["date", "since", "page"])
@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("kind,xml,attachment_kind", _CASES)
def test_group_nontext_messages_survive_every_reader(reader, compressed, kind, xml, attachment_kind):
    connection = sqlite3.connect(":memory:")
    table = wechat_db._wechat_conversation_table_name(_CONVERSATION)
    original = (_SENDER + ":\n" + xml).encode("utf-8")
    if compressed:
        original = zstandard.ZstdCompressor().compress(original)
    try:
        connection.execute("CREATE TABLE Name2Id (user_name TEXT)")
        connection.executemany("INSERT INTO Name2Id VALUES (?)", [(_SENDER,), (_CONVERSATION,)])
        connection.execute(
            f'CREATE TABLE "{table}" (local_type INTEGER, create_time INTEGER, '
            'real_sender_id INTEGER, message_content BLOB, server_id TEXT, packed_info_data BLOB)'
        )
        connection.execute(f'INSERT INTO "{table}" VALUES (?, ?, ?, ?, ?, NULL)',
                           (kind, 1700000000, 1, original, "synthetic-message"))
        messages = _read(connection, reader)
        assert len(messages) == 1
        assert messages[0].content == wechat_db._extract_wechat_xml(xml, kind)
        assert messages[0].sender == _SENDER
        assert messages[0].attachment_meta == wechat_db._extract_attachment_meta(xml, kind)
        if attachment_kind:
            assert messages[0].attachment_meta["kind"] == attachment_kind
        assert connection.execute(f'SELECT message_content FROM "{table}"').fetchone()[0] == original
    finally:
        connection.close()


@pytest.mark.parametrize("sender", [_SENDER, "90000007@openim", "synthetic.sender-1"])
def test_group_xml_declarations_and_identifier_forms(sender):
    xml = '<?xml version="1.0"?><msg><img /></msg>'
    assert wechat_db._extract_wechat_xml(sender + ":\n" + xml, 3) == "[图片]"


@pytest.mark.parametrize("body", [
    "ordinary note:\n<msg><img /></msg>",
    ":\n<msg><img /></msg>",
    "x" * 65 + ":\n<msg><img /></msg>",
    "synthetic_sender:\nordinary prose",
    "synthetic_sender:\n",
])
def test_invalid_or_non_markup_envelopes_are_not_accepted_as_images(body):
    assert wechat_db._extract_wechat_xml(body, 3) == ""


def test_bare_xml_and_plain_text_keep_their_existing_behavior():
    assert wechat_db._extract_wechat_xml("<msg><img /></msg>", 3) == "[图片]"
    assert wechat_db._extract_wechat_xml("ordinary note:\nkeep this text", 10000) == (
        "ordinary note:\nkeep this text"
    )
