"""Directory and scoped-export contracts using synthetic data only."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from chatlog_keeper import cli, qq_db, wechat_contacts, wechat_db


def test_selection_stdin_is_strict_and_marks_empty_accounts_as_all(monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "account_ids": [],
            "conversation_ids": ["conversation-a", "conversation-a"],
        })),
    )
    args = SimpleNamespace(selection_stdin=True, account=[], conversation=[])

    selection = cli._selection_from_args(args)

    assert selection.explicit is True
    assert selection.all_accounts is True
    assert selection.account_ids == ()
    assert selection.conversation_ids == ("conversation-a",)
    assert selection.conversation_scopes == ()
    assert selection.scopes_explicit is False


def test_selection_stdin_accepts_exact_account_scoped_pairs(monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "account_ids": ["account-a", "account-b"],
            "conversation_ids": ["shared-conversation"],
            "conversation_scopes": [
                {"account_id": "account-a", "conversation_id": "shared-conversation"},
                {"account_id": "account-a", "conversation_id": "shared-conversation"},
            ],
        })),
    )
    args = SimpleNamespace(selection_stdin=True, account=[], conversation=[])

    selection = cli._selection_from_args(args)

    assert selection.scopes_explicit is True
    assert selection.conversation_ids == ("shared-conversation",)
    assert selection.conversation_scopes == (("account-a", "shared-conversation"),)


def test_selection_stdin_accepts_typed_account_scoped_conversations(monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "account_ids": ["account-a"],
            "conversation_ids": [],
            "conversation_scopes": [
                {
                    "account_id": "account-a",
                    "conversation_id": "shared-conversation",
                    "conversation_type": "direct",
                },
                {
                    "account_id": "account-a",
                    "conversation_id": "shared-conversation",
                    "conversation_type": "group",
                },
            ],
        })),
    )
    args = SimpleNamespace(selection_stdin=True, account=[], conversation=[])

    selection = cli._selection_from_args(args)

    assert selection.conversation_scopes == (
        ("account-a", "shared-conversation", "direct"),
        ("account-a", "shared-conversation", "group"),
    )


@pytest.mark.parametrize("conversation_type", ["", " direct", "direct ", "channel"])
def test_selection_stdin_rejects_invalid_typed_conversation_scope(
    monkeypatch, conversation_type
):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "account_ids": [],
            "conversation_ids": [],
            "conversation_scopes": [{
                "account_id": "account-a",
                "conversation_id": "conversation-a",
                "conversation_type": conversation_type,
            }],
        })),
    )
    args = SimpleNamespace(selection_stdin=True, account=[], conversation=[])

    with pytest.raises(cli._SelectionError):
        cli._selection_from_args(args)


def test_selection_stdin_rejects_legacy_and_typed_scope_for_the_same_pair(
    monkeypatch,
):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "account_ids": [],
            "conversation_ids": [],
            "conversation_scopes": [
                {
                    "account_id": "account-a",
                    "conversation_id": "shared-conversation",
                },
                {
                    "account_id": "account-a",
                    "conversation_id": "shared-conversation",
                    "conversation_type": "direct",
                },
            ],
        })),
    )
    args = SimpleNamespace(selection_stdin=True, account=[], conversation=[])

    with pytest.raises(cli._SelectionError):
        cli._selection_from_args(args)


def test_selection_stdin_allows_legacy_and_typed_scopes_for_different_pairs(
    monkeypatch,
):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "account_ids": [],
            "conversation_ids": [],
            "conversation_scopes": [
                {"account_id": "account-a", "conversation_id": "legacy"},
                {
                    "account_id": "account-a",
                    "conversation_id": "typed",
                    "conversation_type": "group",
                },
            ],
        })),
    )
    args = SimpleNamespace(selection_stdin=True, account=[], conversation=[])

    selection = cli._selection_from_args(args)

    assert selection.conversation_scopes == (
        ("account-a", "legacy"),
        ("account-a", "typed", "group"),
    )


def test_selection_stdin_rejects_scope_outside_selected_accounts(monkeypatch):
    private_value = "account-outside-scope"
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "account_ids": ["account-a"],
            "conversation_ids": [],
            "conversation_scopes": [
                {"account_id": private_value, "conversation_id": "conversation-a"},
            ],
        })),
    )
    args = SimpleNamespace(selection_stdin=True, account=[], conversation=[])

    with pytest.raises(cli._SelectionError) as exc_info:
        cli._selection_from_args(args)

    assert private_value not in str(exc_info.value)


@pytest.mark.parametrize("payload", [
    {
        "account_ids": [],
        "conversation_ids": [],
        "conversation_scopes": [],
        "unexpected": True,
    },
    {
        "account_ids": [],
        "conversation_ids": [],
        "conversation_scopes": [
            {"account_id": "account-a", "conversation_id": "conversation-a", "extra": "x"}
        ],
    },
])
def test_selection_stdin_accepts_only_the_two_exact_key_sets(monkeypatch, payload):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    args = SimpleNamespace(selection_stdin=True, account=[], conversation=[])

    with pytest.raises(cli._SelectionError):
        cli._selection_from_args(args)


def test_selection_stdin_rejects_mixed_cli_values_without_retaining_them(monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO('{"account_ids":[],"conversation_ids":[]}'),
    )
    args = SimpleNamespace(
        selection_stdin=True,
        account=["private-account"],
        conversation=[],
    )

    with pytest.raises(cli._SelectionError) as exc_info:
        cli._selection_from_args(args)

    assert str(exc_info.value) == ""


def test_invalid_stdin_selection_is_not_echoed_by_cli(monkeypatch, tmp_path, capsys):
    private_value = "../../private-account-value"
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({
            "account_ids": [private_value],
            "conversation_ids": [],
        })),
    )
    monkeypatch.setattr(cli.qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(
        cli.qq_db,
        "find_qq_account_databases",
        lambda _root: {"known-account": tmp_path / "nt_msg.db"},
    )

    exit_code = cli.main([
        "qq", "--days", "1", "--out", str(tmp_path / "out"), "--selection-stdin"
    ])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert private_value not in captured.out
    assert private_value not in captured.err
    assert json.loads(captured.out)["error"] == "invalid_selection"


def test_unexpected_export_error_never_echoes_selection(monkeypatch, tmp_path, capsys):
    private_value = "private-native-conversation"
    monkeypatch.setattr(
        cli,
        "_export_qq",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(private_value)),
    )

    exit_code = cli.main([
        "qq", "--out", str(tmp_path / "out"), "--conversation", private_value
    ])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert private_value not in captured.out
    assert private_value not in captured.err
    assert json.loads(captured.out)["error"] == "export_failed"


def test_cli_directory_dispatches_repeated_account_filters(monkeypatch, capsys):
    captured_scope = {}

    def fake_directory(data_root, account_ids):
        captured_scope["data_root"] = data_root
        captured_scope["account_ids"] = account_ids
        return {
            "source": "qq",
            "available": True,
            "conversation_scope_version": 2,
            "accounts": [],
            "conversations": [],
        }

    monkeypatch.setattr(cli, "_directory_qq", fake_directory)

    exit_code = cli.main([
        "directory", "--source", "qq", "--account", "10001", "--account", "10002"
    ])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert captured_scope == {"data_root": None, "account_ids": ("10001", "10002")}
    assert set(payload) == {
        "source",
        "available",
        "conversation_scope_version",
        "accounts",
        "conversations",
    }
    assert payload["conversation_scope_version"] == 2


def test_account_selection_is_exact_and_never_joined_as_a_path(tmp_path):
    qq_account = tmp_path / "10001" / "nt_qq" / "nt_db"
    qq_account.mkdir(parents=True)
    (qq_account / "nt_msg.db").write_bytes(b"fixture")
    qq_reader = qq_db.QQDBReader(data_root=tmp_path, account_id="../10001")

    wechat_account = tmp_path / "wxid_fixture_account"
    wechat_account.mkdir()
    wechat_reader = wechat_db.WeChatDBReader(
        data_root=tmp_path,
        account_id="../wxid_fixture_account",
    )

    assert qq_reader.initialize() is False
    assert qq_reader.db_path is None
    assert wechat_reader.initialize() is False
    assert wechat_reader.wxid_dir is None


def test_qq_directory_returns_exact_public_shape_for_all_accounts(monkeypatch, tmp_path):
    account_directories = {
        "u_local_account": tmp_path / "opaque.db",
        "10002": tmp_path / "10002.db",
    }
    directories = {
        "u_local_account": [
            {
                "conversation_id": "friend-a",
                "label": "Friend A",
                "conversation_type": "direct",
                "message_count": 4,
            },
            {
                "conversation_id": "group-a",
                "label": "Group A",
                "conversation_type": "group",
                "message_count": 9,
            },
        ],
        "10002": [],
    }

    class FakeReader:
        def __init__(self, data_root=None, account_id=None, *, allow_live_key_extract=True):
            self.account_id = account_id
            self.account_label = {
                "u_local_account": "123456789",
                "10002": "",
            }[account_id]
            self.key = b"key"
            assert allow_live_key_extract is False

        def initialize(self):
            return True

        def read_conversation_directory(self):
            return directories[self.account_id]

    monkeypatch.setattr(cli.qq_db, "find_qq_account_databases", lambda _root: account_directories)
    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeReader)

    result = cli._directory_qq(str(tmp_path))

    assert set(result) == {
        "source",
        "available",
        "conversation_scope_version",
        "accounts",
        "conversations",
    }
    assert result["conversation_scope_version"] == 2
    assert result["available"] is True
    assert [item["account_id"] for item in result["accounts"]] == [
        "u_local_account",
        "10002",
    ]
    assert [item["label"] for item in result["accounts"]] == [
        "123456789",
        "10002",
    ]
    assert result["accounts"][0]["label"] != result["accounts"][0]["account_id"]
    assert all(
        set(item) == {"account_id", "account_ref", "label", "conversation_count"}
        for item in result["accounts"]
    )
    assert all(
        str(item["account_ref"]).startswith("chatlog-native-account-ref-v1:")
        for item in result["accounts"]
    )
    assert all(
        set(item) == {
            "account_id", "conversation_id", "label", "conversation_type", "message_count"
        }
        for item in result["conversations"]
    )


def test_qq_directory_keeps_readable_account_when_another_account_is_unreadable(
    monkeypatch, tmp_path
):
    """一个过期账号目录不能让同机另一个可读 QQ 账号一起不可用。"""

    monkeypatch.setattr(
        cli.qq_db,
        "find_qq_account_databases",
        lambda _root: {
            "readable": tmp_path / "readable.db",
            "stale": tmp_path / "stale.db",
        },
    )

    class FakeReader:
        def __init__(self, data_root=None, account_id=None, *, allow_live_key_extract=True):
            self.account_id = account_id
            self.key = b"key"
            assert allow_live_key_extract is False

        def initialize(self):
            return True

        def read_conversation_directory(self):
            if self.account_id == "stale":
                return None
            return [{
                "conversation_id": "friend",
                "label": "Friend",
                "conversation_type": "direct",
                "message_count": 1,
            }]

    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeReader)

    result = cli._directory_qq(str(tmp_path))

    assert result["available"] is True
    assert [item["account_id"] for item in result["accounts"]] == ["readable"]
    assert [item["account_id"] for item in result["conversations"]] == ["readable"]


def test_wechat_directory_keeps_readable_account_when_another_account_is_unreadable(
    monkeypatch, tmp_path
):
    """一个失效 wxid 目录不能阻止另一个可读微信账号完成目录扫描。"""

    account_dirs = [tmp_path / "readable", tmp_path / "stale"]
    monkeypatch.setattr(cli.wechat_db, "find_wxid_dirs", lambda _root: account_dirs)

    class FakeReader:
        def __init__(self, data_root=None, account_id=None, *, allow_live_key_extract=True):
            self.account_id = account_id
            self.enc_keys = {tmp_path / "message.db": b"key"}
            assert allow_live_key_extract is False

        def initialize(self):
            return True

        def read_conversation_directory(self):
            if self.account_id == "stale":
                return None
            return [{
                "conversation_id": "friend",
                "label": "Friend",
                "conversation_type": "direct",
                "message_count": 1,
            }]

    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", FakeReader)

    result = cli._directory_wechat(str(tmp_path))

    assert result["available"] is True
    assert [item["account_id"] for item in result["accounts"]] == ["readable"]
    assert [item["label"] for item in result["accounts"]] == ["微信号：readable"]
    assert [item["account_id"] for item in result["conversations"]] == ["readable"]


def test_wechat_directory_requires_verified_message_key(monkeypatch, tmp_path):
    """联系人元数据不能把没有可验证消息库密钥的账号标成可用。"""

    account_dirs = [tmp_path / "readable", tmp_path / "missing-key"]
    monkeypatch.setattr(cli.wechat_db, "find_wxid_dirs", lambda _root: account_dirs)
    constructed = []

    class FakeReader:
        def __init__(self, data_root=None, account_id=None, *, allow_live_key_extract=True):
            self.account_id = account_id
            self.enc_keys = (
                {tmp_path / "message.db": b"verified"}
                if account_id == "readable"
                else {}
            )
            constructed.append((account_id, allow_live_key_extract))

        def initialize(self):
            return True

        def read_conversation_directory(self):
            if not self.enc_keys:
                raise AssertionError("directory must not read metadata without a message key")
            return [{
                "conversation_id": "friend",
                "label": "Friend",
                "conversation_type": "direct",
                "message_count": 1,
            }]

    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", FakeReader)

    result = cli._directory_wechat(str(tmp_path))

    assert constructed == [("readable", False), ("missing-key", False)]
    assert result["available"] is True
    assert [item["account_id"] for item in result["accounts"]] == ["readable"]
    assert [item["account_id"] for item in result["conversations"]] == ["readable"]


def test_directory_rejects_unknown_account_without_echo(monkeypatch, tmp_path):
    private_value = "../private-account"
    monkeypatch.setattr(
        cli.qq_db,
        "find_qq_account_databases",
        lambda _root: {"known-account": tmp_path / "known.db"},
    )

    result = cli._directory_qq(str(tmp_path), (private_value,))
    serialized = json.dumps(result)

    assert result == {
        "source": "qq",
        "available": False,
        "conversation_scope_version": 2,
        "accounts": [],
        "conversations": [],
    }
    assert private_value not in serialized


def test_qq_directory_query_never_selects_message_body():
    conn = sqlite3.connect(":memory:")
    conn.execute('CREATE TABLE c2c_msg_table ("40030" TEXT, "40800" TEXT)')
    conn.execute('CREATE TABLE group_msg_table ("40021" TEXT, "40800" TEXT)')
    conn.executemany(
        'INSERT INTO c2c_msg_table ("40030", "40800") VALUES (?, ?)',
        [("100", "private-direct-body"), ("100", "another-private-body")],
    )
    conn.execute(
        'INSERT INTO group_msg_table ("40021", "40800") VALUES (?, ?)',
        ("200", "private-group-body"),
    )
    statements = []
    conn.set_trace_callback(statements.append)

    directory = qq_db._query_conversation_directory(
        conn,
        buddy_map={100: "Friend"},
        group_name_map={200: "Product Group"},
    )

    assert directory == [
        {
            "conversation_id": "100",
            "label": "Friend",
            "conversation_type": "direct",
            "message_count": 2,
        },
        {
            "conversation_id": "200",
            "label": "Product Group",
            "conversation_type": "group",
            "message_count": 1,
        },
    ]
    assert all("40800" not in statement for statement in statements)
    assert all("private-" not in statement for statement in statements)
    conn.close()


def test_qq_directory_skips_bad_c2c_schema_and_keeps_good_group_without_body_read():
    """缺 peer 列不能生成字面量假会话，也不能拖垮另一张可读消息表。"""

    conn = sqlite3.connect(":memory:")
    conn.execute('CREATE TABLE c2c_msg_table ("40033" INTEGER, "40800" BLOB)')
    conn.executemany(
        'INSERT INTO c2c_msg_table ("40033", "40800") VALUES (?, ?)',
        [(10001, b"private-direct-one"), (10001, b"private-direct-two")],
    )
    conn.execute('CREATE TABLE group_msg_table ("40021" TEXT, "40800" BLOB)')
    conn.execute(
        'INSERT INTO group_msg_table ("40021", "40800") VALUES (?, ?)',
        ("real-group", b"private-group-body"),
    )
    statements = []
    conn.set_trace_callback(statements.append)

    directory = qq_db._query_conversation_directory(conn)

    assert [(item["conversation_id"], item["conversation_type"]) for item in directory] == [
        ("real-group", "group")
    ]
    assert not any(
        statement.lstrip().upper().startswith("SELECT")
        and "c2c_msg_table" in statement
        for statement in statements
    )
    assert all("private-" not in statement for statement in statements)
    conn.close()


def test_qq_directory_skips_bad_group_schema_and_keeps_good_c2c_without_body_read():
    """缺 group code 列不能生成字面量假会话，也不能拖垮可读直聊表。"""

    conn = sqlite3.connect(":memory:")
    conn.execute('CREATE TABLE c2c_msg_table ("40030" TEXT, "40800" BLOB)')
    conn.execute(
        'INSERT INTO c2c_msg_table ("40030", "40800") VALUES (?, ?)',
        ("real-friend", b"private-direct-body"),
    )
    conn.execute('CREATE TABLE group_msg_table ("40033" INTEGER, "40800" BLOB)')
    conn.execute(
        'INSERT INTO group_msg_table ("40033", "40800") VALUES (?, ?)',
        (10001, b"private-group-body"),
    )
    statements = []
    conn.set_trace_callback(statements.append)

    directory = qq_db._query_conversation_directory(conn)

    assert [(item["conversation_id"], item["conversation_type"]) for item in directory] == [
        ("real-friend", "direct")
    ]
    assert not any(
        statement.lstrip().upper().startswith("SELECT")
        and "group_msg_table" in statement
        for statement in statements
    )
    assert all("private-" not in statement for statement in statements)
    conn.close()


def test_qq_directory_includes_friends_and_groups_without_local_messages():
    """QQ 目录应与微信一致包含完整好友/群目录，并用 0 表示没有本地消息。"""

    conn = sqlite3.connect(":memory:")
    conn.execute('CREATE TABLE c2c_msg_table ("40030" TEXT, "40800" TEXT)')
    conn.execute('CREATE TABLE group_msg_table ("40021" TEXT, "40800" TEXT)')
    conn.execute(
        'INSERT INTO c2c_msg_table ("40030", "40800") VALUES (?, ?)',
        ("100", "private-direct-body"),
    )
    conn.execute(
        'INSERT INTO group_msg_table ("40021", "40800") VALUES (?, ?)',
        ("200", "private-group-body"),
    )
    statements = []
    conn.set_trace_callback(statements.append)

    directory = qq_db._query_conversation_directory(
        conn,
        buddy_map={100: "Messaged Friend", 101: "Directory Friend"},
        buddy_directory_map={100: "Messaged Friend", 101: "Directory Friend"},
        group_name_map={200: "Messaged Group", 201: "Directory Group"},
    )

    assert directory == [
        {
            "conversation_id": "100",
            "label": "Messaged Friend",
            "conversation_type": "direct",
            "message_count": 1,
        },
        {
            "conversation_id": "101",
            "label": "Directory Friend",
            "conversation_type": "direct",
            "message_count": 0,
        },
        {
            "conversation_id": "200",
            "label": "Messaged Group",
            "conversation_type": "group",
            "message_count": 1,
        },
        {
            "conversation_id": "201",
            "label": "Directory Group",
            "conversation_type": "group",
            "message_count": 0,
        },
    ]
    assert all("40800" not in statement for statement in statements)
    assert all("private-" not in statement for statement in statements)
    conn.close()


def test_qq_buddy_directory_uses_only_friend_list_members(tmp_path):
    """profile 缓存中的群成员不能冒充好友；好友即使没有消息也必须可选。"""

    db_path = tmp_path / "profile_info.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        'CREATE TABLE profile_info_v6 ('
        '"1000" TEXT, "1002" INTEGER, "20002" TEXT, "20009" TEXT)'
    )
    conn.execute('CREATE TABLE buddy_list ("1000" TEXT, "1002" INTEGER)')
    conn.executemany(
        'INSERT INTO profile_info_v6 ("1000", "1002", "20002", "20009") '
        'VALUES (?, ?, ?, ?)',
        [
            ("u_friend_a", 100, "Alice", "产品负责人"),
            ("u_friend_b", 101, "Bob", ""),
            ("u_group_member", 999, "Not a friend", ""),
        ],
    )
    conn.executemany(
        'INSERT INTO buddy_list ("1000", "1002") VALUES (?, ?)',
        [("u_friend_a", 100), ("u_friend_b", 101)],
    )
    conn.commit()
    conn.close()

    assert qq_db._build_buddy_directory_map(db_path) == {
        100: "备注：产品负责人 · 昵称：Alice",
        101: "昵称：Bob",
    }


def test_qq_buddy_identity_skips_profile_schema_without_uin(tmp_path):
    """profile 缺 UIN 时不能把 quoted column 字面量 1002 当作联系人。"""

    db_path = tmp_path / "profile_info.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        'CREATE TABLE profile_info_v6 ("20002" TEXT, "20009" TEXT)'
    )
    conn.execute(
        'INSERT INTO profile_info_v6 ("20002", "20009") VALUES (?, ?)',
        ("Fake contact", "Fake remark"),
    )
    conn.commit()
    conn.close()

    assert qq_db._build_buddy_identity_map(db_path) == {}


def test_qq_buddy_directory_skips_buddy_list_schema_without_uin(tmp_path):
    """buddy_list 缺 UIN 时不能生成 ID 为 numeric column name 的假好友。"""

    db_path = tmp_path / "profile_info.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        'CREATE TABLE profile_info_v6 ('
        '"1002" INTEGER, "20002" TEXT, "20009" TEXT)'
    )
    conn.execute(
        'INSERT INTO profile_info_v6 ("1002", "20002", "20009") '
        'VALUES (?, ?, ?)',
        (1002, "Fake contact", ""),
    )
    conn.execute('CREATE TABLE buddy_list ("1000" TEXT)')
    conn.execute('INSERT INTO buddy_list ("1000") VALUES (?)', ("u_fake",))
    conn.commit()
    conn.close()

    assert qq_db._build_buddy_directory_map(db_path) == {}


def test_qq_buddy_directory_label_keeps_remark_and_nickname(tmp_path):
    """QQ 目录必须说明联系人备注和昵称，正文展示名仍只取一个自然名称。"""

    db_path = tmp_path / "profile_info.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        'CREATE TABLE profile_info_v6 ('
        '"1002" INTEGER, "20002" TEXT, "20009" TEXT)'
    )
    conn.executemany(
        'INSERT INTO profile_info_v6 ("1002", "20002", "20009") VALUES (?, ?, ?)',
        [
            (100, "公开昵称", "我的备注"),
            (200, "只有昵称", ""),
            (300, "同名", "同名"),
        ],
    )
    conn.commit()
    conn.close()

    assert qq_db._build_buddy_directory_label_map(db_path) == {
        100: "备注：我的备注 · 昵称：公开昵称",
        200: "昵称：只有昵称",
        300: "备注/昵称：同名",
    }
    assert qq_db._build_buddy_name_map(db_path) == {
        100: "我的备注",
        200: "只有昵称",
        300: "同名",
    }


@pytest.mark.parametrize(
    ("identity", "expected_name", "expected_label"),
    [
        (
            wechat_contacts.WeChatContactIdentity(
                username="wxid_friend",
                alias="alice_wechat",
                remark="产品负责人",
                nickname="Alice",
            ),
            "产品负责人",
            "备注：产品负责人 · 昵称：Alice",
        ),
        (
            wechat_contacts.WeChatContactIdentity(
                username="wxid_friend",
                nickname="Alice",
            ),
            "Alice",
            "昵称：Alice",
        ),
        (
            wechat_contacts.WeChatContactIdentity(
                username="wxid_friend",
                alias="alice_wechat",
            ),
            "alice_wechat",
            "微信号：alice_wechat",
        ),
    ],
)
def test_wechat_contact_identity_keeps_remark_and_nickname(
    identity, expected_name, expected_label
):
    """微信目录与 QQ 一样保留备注和昵称，正文仍只使用一个自然名称。"""

    assert identity.preferred_name == expected_name
    assert identity.directory_label == expected_label


def test_wechat_account_directory_label_always_contains_wechat_id():
    identity = wechat_contacts.WeChatContactIdentity(
        username="wxid_local_account",
        alias="public_wechat_id",
        nickname="本机昵称",
    )

    assert identity.account_directory_label == "微信号：public_wechat_id · 昵称：本机昵称"


def test_wechat_contact_key_uses_selected_account_cache(monkeypatch, tmp_path):
    """多账号联系人库必须先读取当前账号的 key，不能回退到另一账号的全局值。"""

    contact_db = tmp_path / "contact.db"
    contact_db.write_bytes(b"encrypted")
    account_key = b"a" * 32
    reader = SimpleNamespace(account_id="wxid_selected_account", wxid_dir=tmp_path)
    resolver = wechat_contacts.WeChatContactResolver(reader)
    monkeypatch.setattr(resolver, "_contact_db_path", lambda: contact_db)
    seen = []
    monkeypatch.setattr(
        wechat_db,
        "load_cached_wechat_key_for_account",
        lambda account_id: seen.append(account_id) or account_key,
    )
    monkeypatch.setattr(
        wechat_db,
        "load_cached_wechat_key",
        lambda: (_ for _ in ()).throw(AssertionError("global cache bypassed account scope")),
    )
    monkeypatch.setattr(wechat_db, "_read_stable_page1", lambda _path: b"page")
    monkeypatch.setattr(wechat_db, "_verify_key_v4", lambda key, _page: key == account_key)

    assert resolver._extract_contact_key() == account_key
    assert seen == ["wxid_selected_account"]


def test_wechat_initialize_logs_no_native_account_or_data_path(monkeypatch, tmp_path, caplog):
    """微信号可以出现在授权 UI，但不能进入普通运行日志。"""

    secret_account = "wxid_private_log_value"
    account_dir = tmp_path / secret_account
    account_dir.mkdir()
    monkeypatch.setattr(wechat_db, "find_wxid_dirs", lambda _root: [account_dir])
    monkeypatch.setattr(wechat_db, "find_msg_databases", lambda _root: [])
    reader = wechat_db.WeChatDBReader(data_root=tmp_path, account_id=secret_account)

    assert reader.initialize() is True
    assert secret_account not in caplog.text
    assert str(tmp_path) not in caplog.text


def test_qq_account_number_resolves_numeric_uin_and_opaque_uid(tmp_path):
    """QQ 自身账号按 UIN 或 NT UID 都必须解析为对应 QQ 号。"""

    db_path = tmp_path / "profile_info.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        'CREATE TABLE profile_info_v6 ('
        '"1000" TEXT, "1002" INTEGER, "20002" TEXT, "20009" TEXT)'
    )
    conn.executemany(
        'INSERT INTO profile_info_v6 ("1000", "1002", "20002", "20009") '
        'VALUES (?, ?, ?, ?)',
        [
            ("u_local_account", 10001, "", ""),
            ("u_other_account", 20002, "干扰账号", ""),
        ],
    )
    conn.commit()
    conn.close()

    account_numbers = qq_db._build_account_qq_number_map(db_path)

    assert account_numbers == {
        "10001": "10001",
        "u_local_account": "10001",
        "20002": "20002",
        "u_other_account": "20002",
    }


@pytest.mark.parametrize(
    "missing_column",
    [qq_db._NTQQ_PROFILE_COL_UID, qq_db._NTQQ_PROFILE_COL_QQ_UIN],
)
def test_qq_account_number_map_skips_profile_without_required_column(
    tmp_path,
    missing_column,
):
    """账号映射缺 NT UID 或 UIN 时必须 fail closed，不能返回列名字面量。"""

    db_path = tmp_path / "profile_info.db"
    values = {
        qq_db._NTQQ_PROFILE_COL_UID: "u_local_account",
        qq_db._NTQQ_PROFILE_COL_QQ_UIN: 123456789,
    }
    columns = [column for column in values if column != missing_column]
    declaration = ", ".join(f'"{column}" TEXT' for column in columns)
    quoted_columns = ", ".join(f'"{column}"' for column in columns)
    placeholders = ", ".join("?" for _column in columns)
    conn = sqlite3.connect(str(db_path))
    conn.execute(f'CREATE TABLE profile_info_v6 ({declaration})')
    conn.execute(
        f'INSERT INTO profile_info_v6 ({quoted_columns}) VALUES ({placeholders})',
        tuple(values[column] for column in columns),
    )
    conn.commit()
    conn.close()

    assert qq_db._build_account_qq_number_map(db_path) == {}


@pytest.mark.parametrize(
    "missing_column",
    [qq_db._NTQQ_GROUP_MEMBER_COL_GROUP, qq_db._NTQQ_GROUP_MEMBER_COL_UIN],
)
def test_qq_group_member_map_skips_schema_without_required_column(
    tmp_path,
    missing_column,
):
    """群成员表缺 group/UIN 时不能以 numeric column name 组成假成员键。"""

    db_path = tmp_path / "group_info.db"
    values = {
        qq_db._NTQQ_GROUP_MEMBER_COL_GROUP: 60001,
        qq_db._NTQQ_GROUP_MEMBER_COL_UIN: 1002,
        qq_db._NTQQ_PROFILE_COL_NICKNAME: "Fake member",
    }
    columns = [column for column in values if column != missing_column]
    declaration = ", ".join(f'"{column}" TEXT' for column in columns)
    quoted_columns = ", ".join(f'"{column}"' for column in columns)
    placeholders = ", ".join("?" for _column in columns)
    conn = sqlite3.connect(str(db_path))
    conn.execute(f'CREATE TABLE group_member3 ({declaration})')
    conn.execute(
        f'INSERT INTO group_member3 ({quoted_columns}) VALUES ({placeholders})',
        tuple(values[column] for column in columns),
    )
    conn.commit()
    conn.close()

    assert qq_db._build_group_member_map(db_path) == {}


def test_qq_number_normalization_rejects_non_uin_identifiers():
    """QQ 展示号只接受不带前导零的 ASCII 十进制 UIN。"""

    assert qq_db._normalize_qq_number("12345") == "12345"
    assert qq_db._normalize_qq_number("01234") == ""
    assert qq_db._normalize_qq_number("١٢٣٤٥") == ""
    assert qq_db._normalize_qq_number("u_local_account") == ""
    assert qq_db._normalize_qq_number("1234") == ""


def test_qq_account_number_uses_unique_outgoing_c2c_sender_without_body():
    """自身 QQ 号可由直聊 sender/peer 元数据确认，且目录查询不能读取正文。"""

    conn = sqlite3.connect(":memory:")
    statements = []
    conn.set_trace_callback(statements.append)
    conn.execute(
        'CREATE TABLE c2c_msg_table ('
        '"40033" TEXT, "40030" TEXT, "40800" TEXT)'
    )
    conn.executemany(
        'INSERT INTO c2c_msg_table ("40033", "40030", "40800") '
        'VALUES (?, ?, ?)',
        [
            ("22334455", "22334455", "incoming-private-body"),
            ("123456789", "22334455", "outgoing-private-body"),
            ("123456789", "33445566", "another-private-body"),
            ("01234", "33445566", "invalid-sender"),
        ],
    )

    assert qq_db._query_account_qq_number(conn) == "123456789"
    select_statements = [
        statement for statement in statements if statement.lstrip().upper().startswith("SELECT")
    ]
    assert all('"40800"' not in statement for statement in select_statements)

    conn.execute(
        'INSERT INTO c2c_msg_table ("40033", "40030", "40800") '
        'VALUES (?, ?, ?)',
        ("987654321", "22334455", "ambiguous-private-body"),
    )
    assert qq_db._query_account_qq_number(conn) == ""
    conn.close()


@pytest.mark.parametrize(
    "missing_column",
    [qq_db._NTQQ_COL_SENDER_UIN, qq_db._NTQQ_COL_PEER_UIN],
)
def test_qq_account_number_skips_c2c_schema_without_required_column(missing_column):
    """缺 sender/peer 列时不能把 quoted column 字面量当成自身账号证据。"""

    conn = sqlite3.connect(":memory:")
    required_values = {
        qq_db._NTQQ_COL_SENDER_UIN: "123456789",
        qq_db._NTQQ_COL_PEER_UIN: "22334455",
    }
    present_columns = [
        column for column in required_values if column != missing_column
    ]
    declaration = ", ".join(f'"{column}" TEXT' for column in present_columns)
    conn.execute(f'CREATE TABLE c2c_msg_table ({declaration}, "40800" TEXT)')
    quoted_columns = ", ".join(f'"{column}"' for column in present_columns)
    placeholders = ", ".join("?" for _column in present_columns)
    conn.execute(
        f'INSERT INTO c2c_msg_table ({quoted_columns}, "40800") '
        f'VALUES ({placeholders}, ?)',
        tuple(required_values[column] for column in present_columns) + ("private-body",),
    )
    statements = []
    conn.set_trace_callback(statements.append)

    assert qq_db._query_account_qq_number(conn) == ""
    assert not any(
        statement.lstrip().upper().startswith("SELECT")
        and "c2c_msg_table" in statement
        for statement in statements
    )
    assert all("private-body" not in statement for statement in statements)
    conn.close()


@pytest.mark.parametrize(
    "missing_column",
    [
        qq_db._NTQQ_COL_PEER_UIN,
        qq_db._NTQQ_COL_SENDER_UIN,
        qq_db._NTQQ_COL_MSG_TIME,
        qq_db._NTQQ_COL_MSG_BODY,
    ],
)
def test_qq_message_query_skips_bad_c2c_schema_and_keeps_good_group(
    monkeypatch,
    missing_column,
):
    """任一关键列缺失时整张坏表应跳过，另一张好表仍可正常读取。"""

    conn = sqlite3.connect(":memory:")
    all_columns = {
        qq_db._NTQQ_COL_MSG_UID: "INTEGER",
        qq_db._NTQQ_COL_MSG_TIME: "INTEGER",
        qq_db._NTQQ_COL_SENDER_NAME: "TEXT",
        qq_db._NTQQ_COL_SENDER_UIN: "INTEGER",
        qq_db._NTQQ_COL_MSG_BODY: "BLOB",
        qq_db._NTQQ_COL_PEER_UIN: "INTEGER",
        qq_db._NTQQ_COL_GROUP_CODE: "INTEGER",
    }

    def create_table(table, *, omitted=None):
        columns = [
            (column, kind)
            for column, kind in all_columns.items()
            if column != omitted
        ]
        declaration = ", ".join(f'"{column}" {kind}' for column, kind in columns)
        conn.execute(f'CREATE TABLE "{table}" ({declaration})')
        values = {
            qq_db._NTQQ_COL_MSG_UID: 1,
            qq_db._NTQQ_COL_MSG_TIME: int(datetime.now().timestamp()),
            qq_db._NTQQ_COL_SENDER_NAME: "Sender",
            qq_db._NTQQ_COL_SENDER_UIN: 10001,
            qq_db._NTQQ_COL_MSG_BODY: b"bad-c2c" if table == "c2c_msg_table" else b"good-group",
            qq_db._NTQQ_COL_PEER_UIN: 20001 if table == "c2c_msg_table" else None,
            qq_db._NTQQ_COL_GROUP_CODE: 30001 if table == "group_msg_table" else None,
        }
        quoted = ", ".join(f'"{column}"' for column, _kind in columns)
        placeholders = ", ".join("?" for _column, _kind in columns)
        conn.execute(
            f'INSERT INTO "{table}" ({quoted}) VALUES ({placeholders})',
            tuple(values[column] for column, _kind in columns),
        )

    create_table("c2c_msg_table", omitted=missing_column)
    create_table("group_msg_table")
    decoded_bodies = []
    monkeypatch.setattr(
        qq_db,
        "_extract_msg_text",
        lambda body: decoded_bodies.append(body) or "synthetic message",
    )
    monkeypatch.setattr(qq_db, "_extract_qq_attachment_meta", lambda _body: None)
    statements = []
    conn.set_trace_callback(statements.append)

    messages = qq_db._query_messages(conn)

    assert [(message.chat_uid, message.conversation_type) for message in messages] == [
        ("30001", "group")
    ]
    assert decoded_bodies == [b"good-group"]
    assert not any(
        statement.lstrip().upper().startswith("SELECT")
        and "c2c_msg_table" in statement
        for statement in statements
    )
    conn.close()


def test_qq_message_query_skips_group_without_group_code_and_keeps_good_c2c(
    monkeypatch,
):
    """group code 缺失时不解码坏群表，直聊表仍正常产出。"""

    conn = sqlite3.connect(":memory:")
    message_time = int(datetime.now().timestamp())
    conn.execute(
        'CREATE TABLE c2c_msg_table ('
        '"40050" INTEGER, "40033" INTEGER, "40800" BLOB, "40030" INTEGER)'
    )
    conn.execute(
        'INSERT INTO c2c_msg_table ("40050", "40033", "40800", "40030") '
        'VALUES (?, ?, ?, ?)',
        (message_time, 10001, b"good-c2c", 20001),
    )
    conn.execute(
        'CREATE TABLE group_msg_table ('
        '"40050" INTEGER, "40033" INTEGER, "40800" BLOB)'
    )
    conn.execute(
        'INSERT INTO group_msg_table ("40050", "40033", "40800") '
        'VALUES (?, ?, ?)',
        (message_time, 10001, b"bad-group"),
    )
    decoded_bodies = []
    monkeypatch.setattr(
        qq_db,
        "_extract_msg_text",
        lambda body: decoded_bodies.append(body) or "synthetic message",
    )
    monkeypatch.setattr(qq_db, "_extract_qq_attachment_meta", lambda _body: None)
    statements = []
    conn.set_trace_callback(statements.append)

    messages = qq_db._query_messages(conn)

    assert [(message.chat_uid, message.conversation_type) for message in messages] == [
        ("20001", "direct")
    ]
    assert decoded_bodies == [b"good-c2c"]
    assert not any(
        statement.lstrip().upper().startswith("SELECT")
        and "group_msg_table" in statement
        for statement in statements
    )
    conn.close()


def test_qq_message_query_keeps_optional_columns_and_attachment_behavior(monkeypatch):
    """缺非关键展示列时仍读取正文，并保留附件提取行为。"""

    conn = sqlite3.connect(":memory:")
    conn.execute(
        'CREATE TABLE c2c_msg_table ('
        '"40050" INTEGER, "40033" INTEGER, "40800" BLOB, "40030" INTEGER)'
    )
    conn.execute(
        'INSERT INTO c2c_msg_table ("40050", "40033", "40800", "40030") '
        'VALUES (?, ?, ?, ?)',
        (int(datetime.now().timestamp()), 10001, b"attachment-body", 20001),
    )
    attachment = {"kind": "file", "name": "synthetic.txt"}
    monkeypatch.setattr(qq_db, "_extract_msg_text", lambda _body: "file message")
    monkeypatch.setattr(qq_db, "_extract_qq_attachment_meta", lambda _body: attachment)

    messages = qq_db._query_messages(conn, buddy_map={20001: "Friend"})

    assert len(messages) == 1
    assert messages[0].chat_uid == "20001"
    assert messages[0].chat_name == "Friend"
    assert messages[0].attachment_meta == attachment
    conn.close()


def test_qq_message_query_preserves_source_table_conversation_type(monkeypatch):
    """会话类型来自 c2c/group 表，不能由可能含 ``group`` 的展示名猜测。"""

    conn = sqlite3.connect(":memory:")
    columns = (
        '("40001" INTEGER, "40050" INTEGER, "40090" TEXT, '
        '"40033" INTEGER, "40800" BLOB, "40030" INTEGER, "40021" INTEGER)'
    )
    conn.execute(f"CREATE TABLE c2c_msg_table {columns}")
    conn.execute(f"CREATE TABLE group_msg_table {columns}")
    now = int(datetime.now().timestamp())
    conn.execute(
        'INSERT INTO c2c_msg_table '
        '("40001", "40050", "40090", "40033", "40800", "40030", "40021") '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (1, now, "", 10001, b"direct", 20001, None),
    )
    conn.execute(
        'INSERT INTO group_msg_table '
        '("40001", "40050", "40090", "40033", "40800", "40030", "40021") '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (2, now, "Teammate", 20002, b"group", None, 30001),
    )
    monkeypatch.setattr(qq_db, "_extract_msg_text", lambda _body: "synthetic message")
    monkeypatch.setattr(qq_db, "_extract_qq_attachment_meta", lambda _body: None)

    messages = qq_db._query_messages(
        conn,
        buddy_map={20001: "Study Group Partner"},
        group_name_map={30001: "Project Room"},
    )

    by_conversation = {message.chat_uid: message for message in messages}
    assert by_conversation["20001"].chat_name == "Study Group Partner"
    assert by_conversation["20001"].conversation_type == "direct"
    assert by_conversation["20001"].is_group_chat is False
    assert by_conversation["30001"].chat_name == "Project Room"
    assert by_conversation["30001"].conversation_type == "group"
    assert by_conversation["30001"].is_group_chat is True
    conn.close()


def test_qq_group_name_map_reads_metadata_tables_without_message_content(tmp_path):
    db_path = tmp_path / "group_info.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute('CREATE TABLE group_list ("60001" INTEGER, "60007" TEXT)')
    conn.execute(
        'CREATE TABLE group_detail_info_ver1 ("60001" INTEGER, "60007" TEXT)'
    )
    conn.execute('INSERT INTO group_list ("60001", "60007") VALUES (?, ?)', (100, "Old"))
    conn.execute(
        'INSERT INTO group_detail_info_ver1 ("60001", "60007") VALUES (?, ?)',
        (100, "Current"),
    )
    conn.execute(
        'INSERT INTO group_detail_info_ver1 ("60001", "60007") VALUES (?, ?)',
        (200, "Second"),
    )
    conn.commit()
    conn.close()

    assert qq_db._build_group_name_map(db_path) == {100: "Current", 200: "Second"}


def test_qq_group_name_map_tolerates_missing_metadata_tables(tmp_path):
    db_path = tmp_path / "empty.db"
    sqlite3.connect(str(db_path)).close()

    assert qq_db._build_group_name_map(db_path) == {}


def test_qq_group_name_map_keeps_unnamed_groups_and_skips_bad_schema(tmp_path):
    """无名群仍属于目录，旧表缺列时也不能生成伪 ID 或阻断有效详情表。"""

    db_path = tmp_path / "group_info.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute('CREATE TABLE group_list (legacy_id INTEGER, legacy_name TEXT)')
    conn.execute('INSERT INTO group_list VALUES (999, "legacy")')
    conn.execute(
        'CREATE TABLE group_detail_info_ver1 ("60001" INTEGER, "60007" TEXT)'
    )
    conn.executemany(
        'INSERT INTO group_detail_info_ver1 ("60001", "60007") VALUES (?, ?)',
        [(100, None), (101, "   "), (102, "Named Group")],
    )
    conn.commit()
    conn.close()

    assert qq_db._build_group_name_map(db_path) == {
        100: "",
        101: "",
        102: "Named Group",
    }


def test_qq_self_is_removed_only_from_metadata_only_buddy_directory():
    """自身好友项不应伪装成联系人，但真实消息表中的自聊会话仍保留。"""

    buddy_directory = {12345: "Self", 23456: "Friend"}
    qq_db._exclude_self_from_buddy_directory(buddy_directory, "12345")
    conn = sqlite3.connect(":memory:")
    conn.execute('CREATE TABLE c2c_msg_table ("40030" TEXT)')
    conn.execute('INSERT INTO c2c_msg_table ("40030") VALUES ("12345")')

    directory = qq_db._query_conversation_directory(
        conn,
        buddy_directory_map=buddy_directory,
    )
    by_id = {item["conversation_id"]: item for item in directory}

    assert set(by_id) == {"12345", "23456"}
    assert by_id["12345"]["message_count"] == 1
    assert by_id["23456"]["message_count"] == 0
    conn.close()


def test_qq_directory_keeps_direct_and_group_with_the_same_native_id():
    conn = sqlite3.connect(":memory:")
    conn.execute('CREATE TABLE c2c_msg_table ("40030" TEXT)')
    conn.execute('CREATE TABLE group_msg_table ("40021" TEXT)')
    conn.execute('INSERT INTO c2c_msg_table ("40030") VALUES ("shared-id")')
    conn.execute('INSERT INTO group_msg_table ("40021") VALUES ("shared-id")')

    directory = qq_db._query_conversation_directory(conn)

    assert [
        (item["conversation_id"], item["conversation_type"])
        for item in directory
    ] == [("shared-id", "direct"), ("shared-id", "group")]
    conn.close()


def test_wechat_directory_query_never_selects_message_body():
    conversation_id = "wxid_friend"
    table_name = "Msg_" + hashlib.md5(conversation_id.encode()).hexdigest()
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE Name2Id (user_name TEXT)")
    conn.execute("INSERT INTO Name2Id (rowid, user_name) VALUES (?, ?)", (1, conversation_id))
    conn.execute(f'CREATE TABLE "{table_name}" (message_content TEXT)')
    conn.executemany(
        f'INSERT INTO "{table_name}" (message_content) VALUES (?)',
        [("private-body-one",), ("private-body-two",)],
    )
    statements = []
    conn.set_trace_callback(statements.append)

    counts = wechat_db._query_conversation_counts(conn)

    assert counts == {conversation_id: 2}
    assert all("message_content" not in statement for statement in statements)
    assert all("private-body" not in statement for statement in statements)
    conn.close()


def test_wechat_reader_prefers_contacts_and_keeps_message_only_fallback(monkeypatch, tmp_path):
    message_db = tmp_path / "message_0.db"
    reader = wechat_db.WeChatDBReader()
    reader._initialized = True
    reader.wxid_dir = tmp_path
    reader.enc_keys = {message_db: b"k" * 32}

    class Contacts:
        def all_displays(self):
            return {"wxid_friend": "Friend", "room@chatroom": "Group"}

        def all_directory_labels(self):
            return {
                "wxid_friend": "备注：产品负责人 · 昵称：Friend",
                "room@chatroom": "昵称：Group",
            }

        def account_directory_label(self, _account_id):
            return "微信号：local_wechat_id"

        def is_group(self, value):
            return value.endswith("@chatroom")

    reader.contacts = Contacts()
    monkeypatch.setattr(wechat_db, "find_msg_databases", lambda _root: [message_db])
    monkeypatch.setattr(
        wechat_db,
        "_conversation_counts",
        lambda _db, _key, candidate_ids=(): {"wxid_friend": 3, "orphan@chatroom": 2},
    )

    directory = reader.read_conversation_directory()

    by_id = {item["conversation_id"]: item for item in directory}
    assert reader.account_label == "微信号：local_wechat_id"
    assert by_id["wxid_friend"]["label"] == "备注：产品负责人 · 昵称：Friend"
    assert by_id["wxid_friend"]["message_count"] == 3
    assert by_id["room@chatroom"]["conversation_type"] == "group"
    assert by_id["orphan@chatroom"]["conversation_type"] == "group"
    assert by_id["orphan@chatroom"]["message_count"] == 2


def test_exported_message_dicts_add_account_thread_and_type(monkeypatch):
    timestamp = datetime.now()
    qq_reader = qq_db.QQDBReader()
    qq_reader.account_id = "10001"
    monkeypatch.setattr(
        qq_reader,
        "read_recent",
        lambda **_kwargs: [qq_db.QQMessage(
            timestamp=timestamp,
            sender="10001",
            sender_name="Me",
            content="hello",
            chat_name="qq_group_200",
            chat_uid="200",
            conversation_type="group",
            is_group_chat=True,
        )],
    )

    qq_message = qq_reader.read_recent_dicts(timestamp.timestamp() - 1, timestamp.timestamp() + 1)[0]
    wechat_message = cli._wx_msg_to_dict(
        SimpleNamespace(
            timestamp=timestamp,
            sender="wxid_sender",
            sender_display_name="Sender",
            chat_name="room@chatroom",
            chat_display_name="Room",
            content="hello",
            msg_type=1,
            is_group_chat=True,
            server_id="server-message-1",
        ),
        self_wxid="wxid_account",
        account_id="wxid_account",
    )

    assert qq_message["chat_uid"] == "200"
    assert qq_message["account_id"] == "10001"
    assert qq_message["conversation_id"] == "200"
    assert qq_message["thread_id"] == "10001::200"
    assert qq_message["conversation_type"] == "group"
    assert qq_message["is_group_chat"] is True
    assert wechat_message["chat_room"] == "Room"
    assert wechat_message["account_id"] == "wxid_account"
    assert wechat_message["conversation_id"] == "room@chatroom"
    assert wechat_message["thread_id"] == "wxid_account::room@chatroom"
    assert wechat_message["server_id"] == "server-message-1"
    assert wechat_message["source_offset"] == "wechat_server:server-message-1"
    assert wechat_message["conversation_type"] == "group"
    assert wechat_message["is_group_chat"] is True


def test_qq_message_dict_type_does_not_depend_on_display_name(monkeypatch):
    timestamp = datetime.now()
    reader = qq_db.QQDBReader()
    reader.account_id = "opaque-account"
    monkeypatch.setattr(
        reader,
        "read_recent",
        lambda **_kwargs: [
            qq_db.QQMessage(
                timestamp=timestamp,
                sender="10001",
                sender_name="Me",
                content="direct message",
                chat_name="Study Group Partner",
                chat_uid="20001",
                conversation_type="direct",
                is_group_chat=False,
            ),
            qq_db.QQMessage(
                timestamp=timestamp,
                sender="20002",
                sender_name="Teammate",
                content="group message",
                chat_name="Project Room",
                chat_uid="30001",
                conversation_type="group",
                is_group_chat=True,
            ),
        ],
    )

    messages = reader.read_recent_dicts(
        timestamp.timestamp() - 1,
        timestamp.timestamp() + 1,
    )
    by_conversation = {message["conversation_id"]: message for message in messages}

    assert by_conversation["20001"]["conversation_type"] == "direct"
    assert by_conversation["20001"]["chat_kind"] == "friend"
    assert by_conversation["20001"]["is_group_chat"] is False
    assert by_conversation["30001"]["conversation_type"] == "group"
    assert by_conversation["30001"]["chat_kind"] == "group"
    assert by_conversation["30001"]["is_group_chat"] is True


def test_qq_export_supports_legacy_and_account_scoped_conversation_filters(
    monkeypatch, tmp_path
):
    constructed_accounts = []

    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id
            self.key = b"key"
            constructed_accounts.append(account_id)

        def initialize(self):
            return True

        def read_conversation_directory(self):
            return [
                {"conversation_id": "keep", "label": "Keep",
                 "conversation_type": "direct", "message_count": 1},
                {"conversation_id": "drop", "label": "Drop",
                 "conversation_type": "group", "message_count": 1},
            ]

        def read_recent_dicts(self, _since, _until):
            return [
                {"ts": 1, "chat_uid": "keep", "account_id": self.account_id,
                 "sender_qq": int(self.account_id), "sender_name": "Me", "content": "kept"},
                {"ts": 2, "chat_uid": "drop", "account_id": self.account_id,
                 "sender_qq": 999, "sender_name": "Other", "content": "dropped"},
            ]

    monkeypatch.setattr(cli.qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(
        cli.qq_db,
        "find_qq_account_databases",
        lambda _root: {"10001": tmp_path / "one.db", "10002": tmp_path / "two.db"},
    )
    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeReader)
    selection = cli._ExportSelection(
        account_ids=("10001", "10002"),
        conversation_ids=("keep",),
        explicit=True,
    )

    result = cli._export_qq(1, str(tmp_path / "out"), selection=selection)
    exported = json.loads((tmp_path / "out" / "qq_messages.json").read_text(encoding="utf-8"))

    assert result["available"] is True
    assert result["n_messages"] == 2
    assert constructed_accounts == ["10001", "10002"]
    assert {item["account_id"] for item in exported} == {"10001", "10002"}
    assert {item["chat_uid"] for item in exported} == {"keep"}
    assert all(item["is_self"] is True for item in exported)

    constructed_accounts.clear()
    scoped_selection = cli._ExportSelection(
        account_ids=("10001", "10002"),
        conversation_ids=("keep",),
        conversation_scopes=(("10001", "keep"),),
        scopes_explicit=True,
        explicit=True,
    )
    scoped_result = cli._export_qq(
        1,
        str(tmp_path / "scoped-out"),
        selection=scoped_selection,
    )
    scoped_export = json.loads(
        (tmp_path / "scoped-out" / "qq_messages.json").read_text(encoding="utf-8")
    )

    assert scoped_result["n_messages"] == 1
    assert constructed_accounts == ["10001"]
    assert [(item["account_id"], item["chat_uid"]) for item in scoped_export] == [
        ("10001", "keep")
    ]


def test_qq_precise_scope_never_initializes_or_reads_unselected_account(
    monkeypatch,
    tmp_path,
):
    """B 缺 key 不能阻断只选择 A 的精确 scope，且 B 不能被构造或解码。"""

    events = []

    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id
            self.account_label = account_id
            self.key = b"key" if account_id == "10001" else None
            events.append(("construct", account_id))

        def initialize(self):
            events.append(("initialize", self.account_id))
            return True

        def read_conversation_directory(self):
            events.append(("directory", self.account_id))
            return [{
                "conversation_id": "keep",
                "label": "Keep",
                "conversation_type": "direct",
                "message_count": 1,
            }]

        def read_recent_dicts(self, _since, _until):
            events.append(("read", self.account_id))
            return [{
                "ts": 1,
                "chat_uid": "keep",
                "conversation_id": "keep",
                "conversation_type": "direct",
                "account_id": self.account_id,
                "sender_qq": 10001,
                "sender_name": "Me",
                "content": "kept",
            }]

    monkeypatch.setattr(cli.qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(
        cli.qq_db,
        "find_qq_account_databases",
        lambda _root: {"10001": tmp_path / "one.db", "10002": tmp_path / "two.db"},
    )
    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeReader)
    selection = cli._ExportSelection(
        account_ids=("10001", "10002"),
        conversation_scopes=(("10001", "keep", "direct"),),
        scopes_explicit=True,
        explicit=True,
    )

    result = cli._export_qq(1, str(tmp_path / "out"), selection=selection)

    assert result["available"] is True
    assert result["n_messages"] == 1
    assert events == [
        ("construct", "10001"),
        ("initialize", "10001"),
        ("directory", "10001"),
        ("read", "10001"),
    ]


def test_qq_legacy_pair_scope_rejects_direct_group_native_id_collision(
    monkeypatch, tmp_path
):
    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id
            self.account_label = "10001"
            self.key = b"key"

        def initialize(self):
            return True

        def read_conversation_directory(self):
            return [
                {"conversation_id": "shared", "label": "Friend",
                 "conversation_type": "direct", "message_count": 1},
                {"conversation_id": "shared", "label": "Group",
                 "conversation_type": "group", "message_count": 1},
            ]

        def read_recent_dicts(self, _since, _until):
            raise AssertionError("ambiguous selection must fail before reading messages")

    monkeypatch.setattr(cli.qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(
        cli.qq_db,
        "find_qq_account_databases",
        lambda _root: {"10001": tmp_path / "account.db"},
    )
    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeReader)
    selection = cli._ExportSelection(
        account_ids=("10001",),
        conversation_scopes=(("10001", "shared"),),
        scopes_explicit=True,
        explicit=True,
    )

    result = cli._export_qq(1, str(tmp_path / "out"), selection=selection)

    assert result == {
        "source": "qq",
        "available": False,
        "error": "invalid_selection",
    }
    assert not (tmp_path / "out").exists()


def test_qq_typed_scope_filters_collision_and_isolates_message_identity(
    monkeypatch, tmp_path
):
    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id
            self.account_label = "10001"
            self.key = b"key"

        def initialize(self):
            return True

        def read_conversation_directory(self):
            return [
                {"conversation_id": "shared", "label": "Friend",
                 "conversation_type": "direct", "message_count": 1},
                {"conversation_id": "shared", "label": "Group",
                 "conversation_type": "group", "message_count": 1},
                {"conversation_id": "stable", "label": "Stable",
                 "conversation_type": "direct", "message_count": 1},
            ]

        def read_recent_dicts(self, _since, _until):
            common = {
                "ts": 1,
                "account_id": self.account_id,
                "sender_qq": 10001,
                "sender_name": "Me",
                "content": "content",
            }
            return [
                {
                    **common,
                    "chat_uid": "shared",
                    "conversation_id": "shared",
                    "conversation_type": "direct",
                    "is_group_chat": False,
                    "thread_id": "10001::shared",
                    "source_offset": "qq_db:shared:1",
                },
                {
                    **common,
                    "chat_uid": "shared",
                    "conversation_id": "shared",
                    "conversation_type": "group",
                    "is_group_chat": True,
                    "thread_id": "10001::shared",
                    "source_offset": "qq_db:shared:1",
                },
                {
                    **common,
                    "ts": 2,
                    "chat_uid": "stable",
                    "conversation_id": "stable",
                    "conversation_type": "direct",
                    "is_group_chat": False,
                    "thread_id": "10001::stable",
                    "source_offset": "qq_db:stable:2",
                },
            ]

    monkeypatch.setattr(cli.qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(
        cli.qq_db,
        "find_qq_account_databases",
        lambda _root: {"10001": tmp_path / "account.db"},
    )
    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeReader)

    typed_selection = cli._ExportSelection(
        account_ids=("10001",),
        conversation_scopes=(("10001", "shared", "group"),),
        scopes_explicit=True,
        explicit=True,
    )
    typed_result = cli._export_qq(
        1, str(tmp_path / "typed-out"), selection=typed_selection
    )
    typed_export = json.loads(
        (tmp_path / "typed-out" / "qq_messages.json").read_text(encoding="utf-8")
    )

    assert typed_result["n_messages"] == 1
    assert typed_export[0]["conversation_type"] == "group"
    assert typed_export[0]["thread_id"] == "10001::group::shared"
    assert typed_export[0]["source_offset"] == "qq_db:shared:1:group"

    all_selection = cli._ExportSelection(
        account_ids=("10001",),
        explicit=True,
    )
    all_result = cli._export_qq(
        1, str(tmp_path / "all-out"), selection=all_selection
    )
    all_export = json.loads(
        (tmp_path / "all-out" / "qq_messages.json").read_text(encoding="utf-8")
    )
    by_scope = {
        (item["conversation_id"], item["conversation_type"]): item
        for item in all_export
    }

    assert all_result["n_messages"] == 3
    assert by_scope[("shared", "direct")]["thread_id"] == "10001::direct::shared"
    assert by_scope[("shared", "group")]["thread_id"] == "10001::group::shared"
    assert by_scope[("shared", "direct")]["source_offset"] != (
        by_scope[("shared", "group")]["source_offset"]
    )
    assert by_scope[("stable", "direct")]["thread_id"] == "10001::stable"
    assert by_scope[("stable", "direct")]["source_offset"] == "qq_db:stable:2"


def test_qq_all_accounts_export_uses_verified_uin_for_opaque_account_id(
    monkeypatch, tmp_path
):
    """全选读取元数据判定碰撞，但自身 UIN 仍以消息读取后的结果为准。"""

    directory_called = False

    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id
            self.account_label = ""
            self.key = b"key"

        def initialize(self):
            return True

        def read_conversation_directory(self):
            nonlocal directory_called
            directory_called = True
            return []

        def read_recent_dicts(self, _since, _until):
            self.account_label = "123456789"
            return [
                {
                    "ts": 1,
                    "chat_uid": "conversation-a",
                    "account_id": self.account_id,
                    "sender_qq": 123456789,
                    "sender_name": "Me",
                    "content": "self message",
                },
                {
                    "ts": 2,
                    "chat_uid": "conversation-a",
                    "account_id": self.account_id,
                    "sender_qq": 987654321,
                    "sender_name": "Other",
                    "content": "other message",
                },
            ]

    monkeypatch.setattr(cli.qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(
        cli.qq_db,
        "find_qq_account_databases",
        lambda _root: {"opaque-account": tmp_path / "account.db"},
    )
    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeReader)
    selection = cli._ExportSelection(
        explicit=True,
        all_accounts=True,
    )

    result = cli._export_qq(1, str(tmp_path / "all-out"), selection=selection)
    exported = json.loads(
        (tmp_path / "all-out" / "qq_messages.json").read_text(encoding="utf-8")
    )

    assert result["available"] is True
    assert directory_called is True
    assert [message["account_id"] for message in exported] == [
        "opaque-account",
        "opaque-account",
    ]
    assert [message["is_self"] for message in exported] == [True, False]


def test_wechat_export_supports_legacy_and_account_scoped_conversation_filters(
    monkeypatch, tmp_path
):
    account_dirs = [tmp_path / "wxid_one", tmp_path / "wxid_two"]
    constructed_accounts = []
    requested_chat_names = []

    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id
            self.wxid_dir = Path(account_id)
            self.enc_keys = {Path("message.db"): b"key"}
            constructed_accounts.append(account_id)

        def initialize(self):
            return True

        def read_conversation_directory(self):
            return [
                {"conversation_id": "keep@chatroom", "label": "Keep",
                 "conversation_type": "group", "message_count": 1},
                {"conversation_id": "drop", "label": "Drop",
                 "conversation_type": "direct", "message_count": 1},
            ]

        def read_after(self, _since, chat_name=None):
            requested_chat_names.append((self.account_id, chat_name))
            common = {
                "timestamp": datetime.now(),
                "sender": "sender",
                "sender_display_name": "Sender",
                "chat_display_name": "Chat",
                "content": "content",
                "msg_type": 1,
            }
            return [
                SimpleNamespace(**common, chat_name="keep@chatroom", is_group_chat=True),
                SimpleNamespace(**common, chat_name="drop", is_group_chat=False),
            ]

    monkeypatch.setattr(cli.wechat_db, "find_weixin_data_root", lambda: tmp_path)
    monkeypatch.setattr(cli.wechat_db, "find_wxid_dirs", lambda _root: account_dirs)
    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", FakeReader)
    selection = cli._ExportSelection(
        account_ids=("wxid_one", "wxid_two"),
        conversation_ids=("keep@chatroom",),
        explicit=True,
    )

    result = cli._export_wechat(1, str(tmp_path / "out"), selection=selection)
    exported = json.loads(
        (tmp_path / "out" / "wechat_messages.json").read_text(encoding="utf-8")
    )

    assert result["available"] is True
    assert result["n_messages"] == 2
    assert constructed_accounts == ["wxid_one", "wxid_two"]
    assert requested_chat_names == [
        ("wxid_one", "keep@chatroom"),
        ("wxid_two", "keep@chatroom"),
    ]
    assert {item["account_id"] for item in exported} == {"wxid_one", "wxid_two"}
    assert {item["conversation_id"] for item in exported} == {"keep@chatroom"}
    assert all(item["conversation_type"] == "group" for item in exported)

    constructed_accounts.clear()
    requested_chat_names.clear()
    scoped_selection = cli._ExportSelection(
        account_ids=("wxid_one", "wxid_two"),
        conversation_ids=("keep@chatroom",),
        conversation_scopes=(("wxid_two", "keep@chatroom"),),
        scopes_explicit=True,
        explicit=True,
    )
    scoped_result = cli._export_wechat(
        1,
        str(tmp_path / "scoped-out"),
        selection=scoped_selection,
    )
    scoped_export = json.loads(
        (tmp_path / "scoped-out" / "wechat_messages.json").read_text(encoding="utf-8")
    )

    assert scoped_result["n_messages"] == 1
    assert constructed_accounts == ["wxid_two"]
    assert requested_chat_names == [("wxid_two", "keep@chatroom")]
    assert [
        (item["account_id"], item["conversation_id"]) for item in scoped_export
    ] == [("wxid_two", "keep@chatroom")]

    constructed_accounts.clear()
    requested_chat_names.clear()
    typed_selection = cli._ExportSelection(
        account_ids=("wxid_two",),
        conversation_scopes=(("wxid_two", "keep@chatroom", "group"),),
        scopes_explicit=True,
        explicit=True,
    )
    typed_result = cli._export_wechat(
        1,
        str(tmp_path / "typed-out"),
        selection=typed_selection,
    )
    typed_export = json.loads(
        (tmp_path / "typed-out" / "wechat_messages.json").read_text(
            encoding="utf-8"
        )
    )

    assert typed_result["n_messages"] == 1
    assert constructed_accounts == ["wxid_two"]
    assert requested_chat_names == [("wxid_two", "keep@chatroom")]
    assert typed_export[0]["conversation_type"] == "group"


def test_wechat_precise_scope_never_initializes_or_reads_unselected_account(
    monkeypatch,
    tmp_path,
):
    """B 缺 key 不能阻断只选择 A 的精确 scope，且 B reader 不得被触碰。"""

    events = []
    account_dirs = [tmp_path / "wxid_one", tmp_path / "wxid_two"]

    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id
            self.wxid_dir = Path(account_id)
            self.enc_keys = {Path("message.db"): b"key"} if account_id == "wxid_one" else {}
            events.append(("construct", account_id))

        def initialize(self):
            events.append(("initialize", self.account_id))
            return True

        def read_conversation_directory(self):
            events.append(("directory", self.account_id))
            return [{
                "conversation_id": "keep@chatroom",
                "label": "Keep",
                "conversation_type": "group",
                "message_count": 1,
            }]

        def read_after(self, _since, chat_name=None):
            events.append(("read", self.account_id, chat_name))
            return [SimpleNamespace(
                timestamp=datetime.now(),
                sender="sender",
                sender_display_name="Sender",
                chat_name="keep@chatroom",
                chat_display_name="Keep",
                content="kept",
                msg_type=1,
                is_group_chat=True,
            )]

    monkeypatch.setattr(cli.wechat_db, "find_weixin_data_root", lambda: tmp_path)
    monkeypatch.setattr(cli.wechat_db, "find_wxid_dirs", lambda _root: account_dirs)
    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", FakeReader)
    selection = cli._ExportSelection(
        account_ids=("wxid_one", "wxid_two"),
        conversation_scopes=(("wxid_one", "keep@chatroom", "group"),),
        scopes_explicit=True,
        explicit=True,
    )

    result = cli._export_wechat(1, str(tmp_path / "out"), selection=selection)

    assert result["available"] is True
    assert result["n_messages"] == 1
    assert events == [
        ("construct", "wxid_one"),
        ("initialize", "wxid_one"),
        ("directory", "wxid_one"),
        ("read", "wxid_one", "keep@chatroom"),
    ]


def test_unscoped_export_keeps_single_legacy_reader(monkeypatch, tmp_path):
    constructed_accounts = []

    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id or "legacy"
            self.key = b"key"
            constructed_accounts.append(account_id)

        def initialize(self):
            return True

        def read_recent_dicts(self, _since, _until):
            return []

    monkeypatch.setattr(cli.qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(cli.qq_db, "QQDBReader", FakeReader)

    result = cli._export_qq(1, str(tmp_path / "out"))

    assert result["available"] is True
    assert constructed_accounts == [None]


def test_unscoped_wechat_export_keeps_single_legacy_reader(monkeypatch, tmp_path):
    constructed_accounts = []

    class FakeReader:
        def __init__(self, data_root=None, account_id=None):
            self.account_id = account_id or "legacy-wxid"
            self.wxid_dir = Path("legacy-wxid")
            self.enc_keys = {Path("message.db"): b"key"}
            constructed_accounts.append(account_id)

        def initialize(self):
            return True

        def read_after(self, _since, chat_name=None):
            return []

    monkeypatch.setattr(cli.wechat_db, "find_weixin_data_root", lambda: tmp_path)
    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", FakeReader)

    result = cli._export_wechat(1, str(tmp_path / "out"))

    assert result["available"] is True
    assert constructed_accounts == [None]
