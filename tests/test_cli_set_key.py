import io
import json
from pathlib import Path

import pytest

from chatlog_keeper import cli, native_account_binding, wechat_key_identity


def test_set_key_can_be_read_from_stdin_without_argv_secret(monkeypatch):
    seen = {}

    def fake_set_key(source, key, data_root=None):
        seen.update(source=source, key=key, data_root=data_root)
        return {"source": source, "ok": True}

    monkeypatch.setattr(cli, "_set_key", fake_set_key)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("0123456789abcdef\n"))

    assert cli.main(["set-key", "--source", "qq", "--key-stdin"]) == 0
    assert seen == {
        "source": "qq",
        "key": "0123456789abcdef\n",
        "data_root": None,
    }


def test_key_identity_set_key_request_passes_expected_ref_only_through_stdin(
    monkeypatch,
):
    seen = {}
    expected = "chatlog-account-ref-v1:" + ("a" * 64)

    def fake_set_key(
        source,
        key,
        data_root=None,
        *,
        expected_account_ref,
    ):
        seen.update(
            source=source,
            key=key,
            data_root=data_root,
            expected_account_ref=expected_account_ref,
        )
        return {"source": source, "ok": True}

    request = json.dumps(
        {
            "schema": "chatlog-keeper.set-key-identity.v1",
            "source": "wechat",
            "key": "ab" * 32,
            "expected_account_ref": expected,
        },
        separators=(",", ":"),
    )
    monkeypatch.setattr(cli, "_set_key", fake_set_key)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(request))

    argv = ["set-key", "--source", "wechat", "--key-identity-stdin"]
    assert expected not in repr(argv)
    assert "ab" * 32 not in repr(argv)
    assert cli.main(argv) == 0
    assert seen == {
        "source": "wechat",
        "key": "ab" * 32,
        "data_root": None,
        "expected_account_ref": expected,
    }


@pytest.mark.parametrize(
    "payload_text",
    [
        "{}",
        '{"schema":"chatlog-keeper.set-key-identity.v1",'
        '"source":"wechat","key":"aa","key":"bb",'
        '"expected_account_ref":null}',
        json.dumps(
            {
                "schema": "chatlog-keeper.set-key-identity.v1",
                "source": "wechat",
                "key": "ab" * 32,
                "expected_account_ref": "chatlog-account-ref-v1:" + ("A" * 64),
            }
        ),
    ],
)
def test_key_identity_set_key_request_rejects_schema_or_type_drift(
    monkeypatch,
    capsys,
    payload_text,
):
    monkeypatch.setattr(
        cli,
        "_set_key",
        lambda *_args, **_kwargs: pytest.fail("invalid request reached set-key"),
    )
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(payload_text))

    assert cli.main(
        ["set-key", "--source", "wechat", "--key-identity-stdin"]
    ) == 1
    assert "invalid key input" in capsys.readouterr().out


@pytest.mark.parametrize(
    "supplied",
    [
        "",
        " \n\t\n",
        "0123456789abcdef\nextra\n",
        "x" * (cli._MAX_KEY_STDIN_CHARS + 1),
    ],
)
def test_set_key_stdin_rejects_empty_extra_or_oversized_content(
    monkeypatch, capsys, supplied
):
    monkeypatch.setattr(
        cli,
        "_set_key",
        lambda *_args, **_kwargs: pytest.fail("invalid stdin reached key parser"),
    )
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(supplied))

    assert cli.main(["set-key", "--source", "qq", "--key-stdin"]) == 1
    result = capsys.readouterr().out
    assert "invalid key input" in result
    if supplied.strip():
        assert supplied.strip() not in result


def test_set_key_stdin_allows_trailing_blank_lines(monkeypatch):
    seen = {}

    def fake_set_key(source, key, data_root=None):
        seen.update(source=source, key=key, data_root=data_root)
        return {"source": source, "ok": True}

    monkeypatch.setattr(cli, "_set_key", fake_set_key)
    monkeypatch.setattr(
        cli.sys, "stdin", io.StringIO("0123456789abcdef\n \n\t\n")
    )

    assert cli.main(["set-key", "--source", "qq", "--key-stdin"]) == 0
    assert seen["key"] == "0123456789abcdef\n \n\t\n"


def test_set_key_passes_data_root_without_exposing_stdin_key(monkeypatch, tmp_path):
    seen = {}

    def fake_set_key(source, key, data_root=None):
        seen.update(source=source, key=key, data_root=data_root)
        return {"source": source, "ok": True}

    monkeypatch.setattr(cli, "_set_key", fake_set_key)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("ab" * 32 + "\n"))
    monkeypatch.setenv("CHATLOG_WECHAT_DATA_ROOT", "restore-after-test")

    assert cli.main([
        "set-key",
        "--source",
        "wechat",
        "--key-stdin",
        "--data-root",
        str(tmp_path),
    ]) == 0
    assert seen == {
        "source": "wechat",
        "key": "ab" * 32 + "\n",
        "data_root": str(tmp_path),
    }


@pytest.mark.parametrize(
    "supplied",
    [
        "a" * 63,
        "a" * 65,
        "g" * 64,
        ("ab " * 21) + "a",
    ],
)
def test_wechat_set_key_rejects_any_value_that_is_not_exactly_64_hex(
    monkeypatch, supplied
):
    monkeypatch.setattr(
        cli,
        "_wechat_verification_databases",
        lambda data_root=None: pytest.fail("invalid input must not read databases"),
        raising=False,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key",
        lambda key: pytest.fail("invalid input must not touch the key cache"),
    )

    result = cli._set_key("wechat", supplied)

    assert result == {
        "source": "wechat",
        "ok": False,
        "error": "invalid WeChat key (expect 64 hex chars)",
    }


def _message_db(account_root: Path, name: str = "message_0.db") -> Path:
    db = account_root / "db_storage" / "message" / name
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_bytes(b"page" * 1024)
    return db


def test_wechat_verification_databases_selects_one_oracle_per_account(tmp_path):
    root = tmp_path / "xwechat_files"
    first = _message_db(root / "wxid_primary_test")
    _message_db(root / "wxid_primary_test", "message_1.db")
    second = _message_db(root / "wxid_secondary_test", "message_2.db")

    found = cli._wechat_verification_databases(str(root))

    assert set(found) == {first, second}
    assert len(found) == 2


def test_wechat_verification_databases_accepts_direct_account_root(tmp_path):
    account_root = tmp_path / "wxid_direct_test"
    db = _message_db(account_root)

    assert cli._wechat_verification_databases(str(account_root)) == [db]


def test_wechat_set_key_fails_closed_without_a_message_database(monkeypatch):
    monkeypatch.setattr(
        cli,
        "_wechat_verification_databases",
        lambda data_root=None: [],
        raising=False,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key",
        lambda key: pytest.fail("an unverifiable key must not overwrite the cache"),
    )

    result = cli._set_key("wechat", "01" * 32)

    assert set(result) == {"source", "ok", "saved_to", "error"}
    assert result["ok"] is False
    assert result["saved_to"] is None
    assert result["error"] == (
        "could not locate a WeChat message database for key verification"
    )


def test_wechat_set_key_fails_closed_when_all_database_pages_are_unstable(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    monkeypatch.setattr(
        cli, "_wechat_verification_databases", lambda data_root=None: [db], raising=False
    )
    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", lambda path: None)
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda key, page: pytest.fail("an unstable page must not be verified"),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key",
        lambda key: pytest.fail("an unverifiable key must not overwrite the cache"),
    )

    result = cli._set_key("wechat", "02" * 32)

    assert set(result) == {"source", "ok", "saved_to", "error"}
    assert result["ok"] is False
    assert result["saved_to"] is None
    assert result["error"] == (
        "could not read a stable WeChat database page for key verification"
    )


def test_wechat_set_key_fails_closed_on_hmac_mismatch(monkeypatch, tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"fixture")
    monkeypatch.setattr(
        cli, "_wechat_verification_databases", lambda data_root=None: [db], raising=False
    )
    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", lambda path: b"p" * 4096)
    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", lambda key, page: False)
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key",
        lambda key: pytest.fail("a mismatched key must not overwrite the cache"),
    )

    result = cli._set_key("wechat", "03" * 32)

    assert set(result) == {"source", "ok", "saved_to", "error"}
    assert result["ok"] is False
    assert result["saved_to"] is None
    assert result["error"] == "WeChat key did not pass local database verification"


def test_wechat_set_key_reads_verifies_then_saves_after_any_account_matches(
    monkeypatch, tmp_path
):
    first = tmp_path / "first.db"
    second = tmp_path / "second.db"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    candidate = bytes.fromhex("04" * 32)
    events = []

    monkeypatch.setattr(
        cli,
        "_wechat_verification_databases",
        lambda data_root=None: [first, second],
        raising=False,
    )

    def fake_read(path):
        events.append(("read", path.name))
        return path.name.encode().ljust(4096, b".")

    def fake_verify(key, page):
        events.append(("verify", page[:9].rstrip(b".").decode()))
        return page.startswith(b"second.db") and key == candidate

    def fake_save(key):
        events.append(("save", key == candidate))
        return True

    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", fake_read)
    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", fake_verify)
    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key", fake_save)
    monkeypatch.setattr(
        wechat_key_identity, "write_selected_key", lambda key: key == candidate
    )
    monkeypatch.setattr(
        cli.wechat_db, "_wechat_key_cache_path", lambda: Path("wechat_db.key")
    )

    result = cli._set_key("wechat", "04" * 32 + "\n", data_root="configured-root")

    expected = wechat_key_identity.protocol_payload(
        {
            "source": "wechat",
            "ok": True,
            "saved_to": "wechat_db.key",
            "error": None,
        },
        key=candidate,
    )
    expected["native_account_binding"] = native_account_binding.envelope(
        "wechat",
        state="unavailable",
    )
    assert result == expected
    assert events == [
        ("read", "first.db"),
        ("read", "second.db"),
        ("verify", "first.db"),
        ("verify", "second.db"),
        ("read", "first.db"),
        ("verify", "first.db"),
        ("read", "second.db"),
        ("verify", "second.db"),
        ("save", True),
        ("read", "first.db"),
        ("verify", "first.db"),
        ("read", "second.db"),
        ("verify", "second.db"),
        ("read", "first.db"),
        ("verify", "first.db"),
        ("read", "second.db"),
        ("verify", "second.db"),
    ]


def test_wechat_set_key_reports_verified_cache_write_failure(monkeypatch, tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"fixture")
    monkeypatch.setattr(
        cli, "_wechat_verification_databases", lambda data_root=None: [db], raising=False
    )
    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", lambda path: b"p" * 4096)
    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", lambda key, page: True)
    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key", lambda key: False)

    result = cli._set_key("wechat", "05" * 32)

    assert result == {
        "source": "wechat",
        "ok": False,
        "saved_to": None,
        "error": "verified WeChat key could not be stored",
    }


def test_wechat_set_key_writes_only_the_hmac_matching_account(monkeypatch, tmp_path):
    root = tmp_path / "xwechat_files"
    first = _message_db(root / "wxid_first")
    second = _message_db(root / "wxid_second")
    candidate = bytes.fromhex("06" * 32)
    saves = []

    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda path: path.parent.parent.parent.name.encode().ljust(4096, b"."),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda key, page: key == candidate and page.startswith(b"wxid_second"),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key_for_account",
        lambda key, account_id, verification_db: saves.append(
            (key, account_id, verification_db)
        ) or True,
        raising=False,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_wechat_account_key_cache_path",
        lambda account_id: Path("wechat_accounts") / f"{account_id}.key",
        raising=False,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key",
        lambda _key: pytest.fail("a discovered account key must not overwrite global cache"),
    )
    monkeypatch.setattr(
        wechat_key_identity, "write_selected_key", lambda key: key == candidate
    )

    result = cli._set_key("wechat", "06" * 32, data_root=str(root))

    expected = wechat_key_identity.protocol_payload(
        {
            "source": "wechat",
            "ok": True,
            "saved_to": "wechat_accounts/wxid_second.key",
            "error": None,
        },
        key=candidate,
    )
    assert {
        key: result[key]
        for key in expected
    } == expected
    binding = result["native_account_binding"]
    assert binding["state"] == "verified"
    assert binding["account_ref"] == wechat_key_identity.envelope(candidate)[
        "account_ref"
    ]
    assert "wxid_second" not in json.dumps(binding)
    assert saves == [(candidate, "wxid_second", second)]
    assert first != second


def test_qq_set_key_behavior_is_unchanged_when_data_root_is_supplied(monkeypatch):
    monkeypatch.setattr(cli.qq_db, "save_cached_key", lambda key: key == "q" * 16)
    monkeypatch.setattr(cli.qq_db, "_key_cache_path", lambda: Path("qq_db.key"))

    result = cli._set_key("qq", "q" * 16, data_root="ignored-for-qq")

    assert {
        key: result[key]
        for key in ("source", "ok", "saved_to", "error")
    } == {
        "source": "qq",
        "ok": True,
        "saved_to": "qq_db.key",
        "error": None,
    }
    assert result["native_account_binding"] == native_account_binding.envelope(
        "qq",
        state="unavailable",
    )
