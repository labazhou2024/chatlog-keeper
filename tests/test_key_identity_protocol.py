"""Security contract for the additive WeChat ``key-identity-v1`` producer.

All fixtures are synthetic.  Native account directory names are routing hints
only; an opaque ref is emitted solely after a 32-byte key authenticates a
frozen SQLCipher page target.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from chatlog_keeper import cli, wechat_key_identity


_EXPECTED_CAPABILITY = {
    "capability": "key-identity-v1",
    "schema": "chatlog-keeper.key-identity.v1",
    "source": "wechat",
    "authority": "database-master-key-proof",
    "account_ref_format": "chatlog-account-ref-v1-sha256",
}


def test_capability_payload_exactly_matches_the_frozen_consumer_contract() -> None:
    payload = wechat_key_identity.capabilities_payload()

    assert payload == _EXPECTED_CAPABILITY
    assert set(payload) == set(_EXPECTED_CAPABILITY)

    payload["capability"] = "drifted-by-caller"
    assert wechat_key_identity.capabilities_payload() == _EXPECTED_CAPABILITY


def test_capability_cli_reads_no_input_scans_no_database_and_writes_no_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class ForbiddenInput:
        def read(self, *_args, **_kwargs):
            pytest.fail("capability command must not read stdin")

        def readline(self, *_args, **_kwargs):
            pytest.fail("capability command must not read stdin")

    def forbidden_scan(*_args, **_kwargs):
        pytest.fail("capability command must not inspect a database")

    monkeypatch.setattr(sys, "stdin", ForbiddenInput())
    monkeypatch.setattr(cli, "_probe_wechat", forbidden_scan)
    monkeypatch.setattr(cli, "_wechat_key_target_snapshots", forbidden_scan)
    monkeypatch.setattr(cli.wechat_db, "find_weixin_data_root", forbidden_scan)
    monkeypatch.setattr(cli.wechat_db, "find_msg_databases", forbidden_scan)
    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", forbidden_scan)

    assert cli.main(["key-identity-v1", "--capabilities"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out) == _EXPECTED_CAPABILITY
    assert captured.err == ""


def _message_db(root: Path, account: str, name: str = "message_0.db") -> Path:
    database = root / account / "db_storage" / "message" / name
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_bytes((account + ":" + name).encode().ljust(4096, b"."))
    return database


def _expected_ref(key: bytes) -> str:
    return "chatlog-account-ref-v1:" + hashlib.sha256(
        wechat_key_identity.ACCOUNT_REF_DOMAIN + key
    ).hexdigest()


def _patch_single_account(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    database: Path,
    *,
    key: bytes,
    cache: dict[str, bytes],
) -> None:
    account = database.parents[2].name
    page = b"stable-salt-0001" + b"p" * (4096 - 16)
    monkeypatch.setattr(cli.wechat_db, "_get_weixin_pids", lambda: [901])
    monkeypatch.setattr(cli.wechat_db, "find_weixin_data_root", lambda: root)
    monkeypatch.setattr(
        cli.wechat_db,
        "find_wxid_dirs",
        lambda _root: [database.parents[2]],
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "find_msg_databases",
        lambda _account_root: [database],
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda path: page if Path(path) == database.resolve() else None,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda candidate, observed: candidate == key and observed == page,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "load_cached_wechat_key_for_account",
        lambda account_id: cache.get(account_id),
    )
    monkeypatch.setattr(cli.wechat_db, "load_cached_wechat_key", lambda: None)

    def save(candidate: bytes, account_id: str, target: Path) -> bool:
        if candidate != key or account_id != account or Path(target) != database.resolve():
            return False
        cache[account_id] = candidate
        return True

    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key_for_account", save)
    monkeypatch.setattr(
        cli.wechat_db,
        "_wechat_account_key_cache_path",
        lambda account_id: Path("wechat_accounts") / f"{account_id}.key",
    )
    marker = root.parent / "app-data" / "secrets" / "wechat_key_identity.ref"
    monkeypatch.setattr(
        wechat_key_identity,
        "_selection_marker_path",
        lambda: marker,
    )


def _patch_two_accounts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path, bytes, bytes, dict[str, bytes], Path]:
    root = tmp_path / "xwechat_files"
    first = _message_db(root, "wxid_a_private")
    second = _message_db(root, "wxid_b_private")
    first_key = b"1" * 32
    second_key = b"2" * 32
    pages = {
        first.resolve(): b"first-salt-page1" + b"a" * (4096 - 16),
        second.resolve(): b"second-salt-page" + b"b" * (4096 - 16),
    }
    cache = {
        "wxid_a_private": first_key,
        "wxid_b_private": second_key,
    }
    marker = tmp_path / "app-data" / "secrets" / "wechat_key_identity.ref"
    monkeypatch.setattr(cli.wechat_db, "_get_weixin_pids", lambda: [1])
    monkeypatch.setattr(cli.wechat_db, "find_weixin_data_root", lambda: root)
    monkeypatch.setattr(
        cli.wechat_db,
        "load_cached_wechat_key_for_account",
        lambda account_id: cache.get(account_id),
    )
    monkeypatch.setattr(cli.wechat_db, "load_cached_wechat_key", lambda: None)
    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda path: pages[Path(path)],
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda key, page: (key, page) in {
            (first_key, pages[first.resolve()]),
            (second_key, pages[second.resolve()]),
        },
    )

    def save(candidate: bytes, account_id: str, target: Path) -> bool:
        expected = {
            "wxid_a_private": (first_key, first.resolve()),
            "wxid_b_private": (second_key, second.resolve()),
        }.get(account_id)
        if expected != (candidate, Path(target)):
            return False
        cache[account_id] = candidate
        return True

    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key_for_account", save)
    monkeypatch.setattr(
        cli.wechat_db,
        "_wechat_account_key_cache_path",
        lambda account_id: Path("wechat_accounts") / f"{account_id}.key",
    )
    monkeypatch.setattr(
        wechat_key_identity,
        "_selection_marker_path",
        lambda: marker,
    )
    return first, second, first_key, second_key, cache, marker


def test_needs_key_probe_declares_capability_without_guessing_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    account = "wxid_path_is_not_identity"
    database = _message_db(root, account)
    cache: dict[str, bytes] = {}
    _patch_single_account(
        monkeypatch,
        root,
        database,
        key=b"k" * 32,
        cache=cache,
    )

    result = cli._probe_wechat()

    assert result["available"] is False
    assert result["needs_key"] is True
    assert result["protocol_capabilities"] == ["key-identity-v1"]
    assert "key_identity" not in result
    assert "account_ref" not in result


def test_set_key_bootstraps_exact_identity_and_ready_probe_repeats_same_ref(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    private_account = "wxid_private_native_value"
    database = _message_db(root, private_account)
    key = bytes(range(32))
    cache: dict[str, bytes] = {}
    _patch_single_account(
        monkeypatch,
        root,
        database,
        key=key,
        cache=cache,
    )

    before = cli._probe_wechat()
    configured = cli._set_key("wechat", key.hex(), data_root=str(root))
    ready = cli._probe_wechat()

    assert "key_identity" not in before
    assert configured["ok"] is True
    assert ready["available"] is True
    assert configured["protocol_capabilities"] == ["key-identity-v1"]
    assert configured["key_identity"] == ready["key_identity"]
    assert configured["key_identity"] == {
        "schema": "chatlog-keeper.key-identity.v1",
        "source": "wechat",
        "authority": "database-master-key-proof",
        "account_ref": _expected_ref(key),
    }
    envelope_text = json.dumps(configured["key_identity"], sort_keys=True)
    assert private_account not in envelope_text
    assert str(database) not in envelope_text
    assert key.hex() not in envelope_text


def test_active_extract_bootstraps_identity_and_ready_probe_repeats_same_ref(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    database = _message_db(root, "wxid_extract_private")
    key = b"e" * 32
    cache: dict[str, bytes] = {}
    _patch_single_account(
        monkeypatch,
        root,
        database,
        key=key,
        cache=cache,
    )
    monkeypatch.setattr(
        cli.active_key,
        "extract_wechat_key_active",
        lambda *, db_path: key if Path(db_path) == database else None,
    )

    extracted = cli._extract_key("wechat", "active", data_root=str(root))
    ready = cli._probe_wechat()

    assert extracted["ok"] is True
    assert extracted["fresh_extraction"] is True
    assert extracted["key_identity"] == ready["key_identity"]
    assert extracted["key_identity"]["account_ref"] == _expected_ref(key)
    assert key.hex() not in json.dumps(extracted["key_identity"], sort_keys=True)


def test_passive_extract_bootstraps_identity_and_ready_probe_repeats_same_ref(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    database = _message_db(root, "wxid_passive_private")
    key = b"p" * 32
    cache: dict[str, bytes] = {}
    _patch_single_account(
        monkeypatch,
        root,
        database,
        key=key,
        cache=cache,
    )

    class Reader:
        def __init__(self, *, data_root=None, client_executable=None) -> None:
            assert data_root == root.resolve()
            assert client_executable is None
            self.enc_keys: dict[Path, bytes] = {}

        def initialize(self) -> bool:
            self.enc_keys[database] = key
            return True

    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", Reader)

    extracted = cli._extract_key("wechat", "passive", data_root=str(root))
    ready = cli._probe_wechat()

    assert extracted["ok"] is True
    assert extracted["key_identity"] == ready["key_identity"]
    assert extracted["key_identity"]["account_ref"] == _expected_ref(key)


def test_set_key_rejects_cross_account_multi_match_without_touching_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    first = _message_db(root, "wxid_first_private")
    second = _message_db(root, "wxid_second_private")
    key = b"m" * 32
    saves: list[object] = []
    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda _path: b"same-salt-page1" + b"p" * (4096 - 15),
    )
    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", lambda candidate, _page: candidate == key)
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key_for_account",
        lambda *_args: saves.append(object()) or True,
    )

    result = cli._set_key("wechat", key.hex(), data_root=str(root))

    assert result["ok"] is False
    assert result["error"] == "WeChat key matched multiple local accounts"
    assert "key_identity" not in result
    assert saves == []
    assert {first.parents[2].name, second.parents[2].name} == {
        "wxid_first_private",
        "wxid_second_private",
    }


def test_probe_rejects_two_ready_accounts_instead_of_selecting_by_path_order(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_two_accounts(monkeypatch, tmp_path)

    result = cli._probe_wechat()

    assert result["available"] is False
    assert result["needs_key"] is True
    assert result["protocol_capabilities"] == ["key-identity-v1"]
    assert "key_identity" not in result


def test_expected_candidate_ref_allows_internal_second_account_switch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first, _second, first_key, second_key, _cache, _marker = _patch_two_accounts(
        monkeypatch, tmp_path
    )
    root = first.parents[3]
    assert wechat_key_identity.write_selected_key(first_key) is True
    first_ready = cli._probe_wechat()

    configured = cli._set_key(
        "wechat",
        second_key.hex(),
        data_root=str(root),
        expected_account_ref=_expected_ref(second_key),
    )
    second_ready = cli._probe_wechat()

    assert first_ready["key_identity"]["account_ref"] == _expected_ref(first_key)
    assert configured["ok"] is True
    assert configured["key_identity"]["account_ref"] == _expected_ref(second_key)
    assert second_ready["key_identity"] == configured["key_identity"]


def test_expected_ref_mismatch_preserves_cache_and_marker_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first, _second, first_key, second_key, _cache, marker = _patch_two_accounts(
        monkeypatch,
        tmp_path,
    )
    root = first.parents[3]
    cache_file = tmp_path / "app-data" / "secrets" / "wechat_accounts" / "second.key"
    cache_file.parent.mkdir(parents=True, mode=0o700)
    cache_file.write_bytes(b"original-account-cache-bytes")
    assert wechat_key_identity.write_selected_key(first_key) is True
    cache_before = cache_file.read_bytes()
    marker_before = marker.read_bytes()
    cache_writes = 0

    def forbidden_save(*_args) -> bool:
        nonlocal cache_writes
        cache_writes += 1
        cache_file.write_bytes(b"unexpected-cache-mutation")
        return True

    monkeypatch.setattr(
        cli.wechat_db,
        "_wechat_account_key_cache_path",
        lambda _account_id: cache_file,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key_for_account",
        forbidden_save,
    )

    result = cli._set_key(
        "wechat",
        second_key.hex(),
        data_root=str(root),
        expected_account_ref=_expected_ref(first_key),
    )

    assert result == {
        "source": "wechat",
        "ok": False,
        "saved_to": None,
        "error": "WeChat key did not match expected account identity",
    }
    assert cache_writes == 0
    assert cache_file.read_bytes() == cache_before
    assert marker.read_bytes() == marker_before


def test_explicit_bootstrap_ref_rejects_existing_proven_selection_before_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first, _second, first_key, second_key, _cache, marker = _patch_two_accounts(
        monkeypatch,
        tmp_path,
    )
    root = first.parents[3]
    assert wechat_key_identity.write_selected_key(first_key) is True
    marker_before = marker.read_bytes()
    cache_writes = 0

    def forbidden_save(*_args) -> bool:
        nonlocal cache_writes
        cache_writes += 1
        return True

    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key_for_account",
        forbidden_save,
    )

    result = cli._set_key(
        "wechat",
        second_key.hex(),
        data_root=str(root),
        expected_account_ref=None,
    )

    assert result["ok"] is False
    assert result["error"] == "WeChat key did not match expected account identity"
    assert cache_writes == 0
    assert marker.read_bytes() == marker_before


def test_probe_selection_never_limits_two_account_directory_reads(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first, second, first_key, _second_key, _cache, _marker = _patch_two_accounts(
        monkeypatch, tmp_path
    )
    root = first.parents[3]
    databases = {
        "wxid_a_private": first.resolve(),
        "wxid_b_private": second.resolve(),
    }
    constructed: list[str] = []
    assert wechat_key_identity.write_selected_key(first_key) is True

    class Reader:
        def __init__(
            self,
            data_root: Path,
            account_id: str,
            allow_live_key_extract: bool,
        ) -> None:
            assert data_root == root
            assert allow_live_key_extract is False
            self.account_id = account_id
            self.account_label = f"label-{account_id}"
            self.enc_keys: dict[Path, bytes] = {}
            constructed.append(account_id)

        def initialize(self) -> bool:
            key = cli.wechat_db.load_cached_wechat_key_for_account(self.account_id)
            database = databases[self.account_id]
            page = cli.wechat_db._read_stable_page1(database)
            if key and page and cli.wechat_db._verify_key_v4(key, page):
                self.enc_keys[database] = key
            return True

        def read_conversation_directory(self) -> list[dict[str, object]]:
            return [{
                "conversation_id": f"conversation-{self.account_id}",
                "label": "Conversation",
                "conversation_type": "direct",
                "message_count": 1,
            }]

    monkeypatch.setattr(cli.wechat_db, "WeChatDBReader", Reader)

    result = cli._directory_wechat(str(root))

    assert result["available"] is True
    assert set(constructed) == {"wxid_a_private", "wxid_b_private"}
    assert len(constructed) == 2
    assert {item["account_id"] for item in result["accounts"]} == {
        "wxid_a_private",
        "wxid_b_private",
    }
    assert {item["account_id"] for item in result["conversations"]} == {
        "wxid_a_private",
        "wxid_b_private",
    }


@pytest.mark.parametrize(
    "marker_value",
    [
        "corrupt-marker",
        "chatlog-account-ref-v1:" + ("f" * 64),
        "chatlog-account-ref-v1:" + ("A" * 64),
    ],
)
def test_corrupt_or_forged_selection_cannot_choose_between_two_accounts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    marker_value: str,
) -> None:
    _first, _second, _first_key, _second_key, _cache, marker = (
        _patch_two_accounts(monkeypatch, tmp_path)
    )
    from chatlog_keeper.core._secrets import write_secret_text

    assert write_secret_text(marker, marker_value) is True

    result = cli._probe_wechat()

    assert result["available"] is False
    assert "key_identity" not in result
    assert marker_value not in repr(result)


def test_selection_marker_is_private_atomic_and_contains_only_opaque_ref(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _first, _second, first_key, _second_key, _cache, marker = _patch_two_accounts(
        monkeypatch, tmp_path
    )

    assert wechat_key_identity.write_selected_key(first_key) is True

    assert wechat_key_identity.selected_ref() == _expected_ref(first_key)
    assert marker.read_text(encoding="utf-8").strip() == _expected_ref(first_key)
    assert first_key.hex() not in marker.read_text(encoding="utf-8")
    assert "wxid_" not in marker.read_text(encoding="utf-8")
    assert not list(marker.parent.glob(f".{marker.name}.*"))
    if os.name != "nt":
        assert marker.stat().st_mode & 0o777 == 0o600
        assert marker.parent.stat().st_mode & 0o777 == 0o700


def test_failed_marker_replace_preserves_previous_selection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _first, _second, first_key, second_key, _cache, _marker = _patch_two_accounts(
        monkeypatch, tmp_path
    )
    assert wechat_key_identity.write_selected_key(first_key) is True
    monkeypatch.setattr(wechat_key_identity, "write_secret_text", lambda *_args: False)

    assert wechat_key_identity.write_selected_key(second_key) is False
    assert wechat_key_identity.selected_ref() == _expected_ref(first_key)


def test_crash_leftover_temp_marker_is_never_read_as_selection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _first, _second, first_key, second_key, _cache, marker = _patch_two_accounts(
        monkeypatch, tmp_path
    )
    assert wechat_key_identity.write_selected_key(first_key) is True
    crash_temp = marker.parent / f".{marker.name}.crash"
    crash_temp.write_text(_expected_ref(second_key), encoding="utf-8")

    assert wechat_key_identity.selected_ref() == _expected_ref(first_key)


def test_marker_write_failure_never_returns_action_success_or_ref(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    database = _message_db(root, "wxid_marker_failure_private")
    key = b"w" * 32
    cache: dict[str, bytes] = {}
    _patch_single_account(
        monkeypatch,
        root,
        database,
        key=key,
        cache=cache,
    )
    monkeypatch.setattr(wechat_key_identity, "write_selected_key", lambda _key: False)

    result = cli._set_key("wechat", key.hex(), data_root=str(root))

    assert result == {
        "source": "wechat",
        "ok": False,
        "saved_to": None,
        "error": "verified WeChat key identity could not be stored",
    }
    assert _expected_ref(key) not in repr(result)
    assert key.hex() not in repr(result)


def test_second_account_becoming_match_during_action_fails_before_marker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    first = _message_db(root, "wxid_first_private")
    second = _message_db(root, "wxid_second_private")
    key = b"d" * 32
    pages = {
        first.resolve(): b"first-action-salt" + b"a" * (4096 - 17),
        second.resolve(): b"second-action-sal" + b"b" * (4096 - 17),
    }
    second_matches = False
    marker_writes = 0

    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda path: pages[Path(path)],
    )

    def verify(candidate: bytes, page: bytes) -> bool:
        return candidate == key and (
            page == pages[first.resolve()]
            or (second_matches and page == pages[second.resolve()])
        )

    def save(*_args) -> bool:
        nonlocal second_matches
        second_matches = True
        return True

    def write_marker(_key: bytes) -> bool:
        nonlocal marker_writes
        marker_writes += 1
        return True

    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", verify)
    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key_for_account", save)
    monkeypatch.setattr(wechat_key_identity, "write_selected_key", write_marker)

    result = cli._set_key("wechat", key.hex(), data_root=str(root))

    assert result["ok"] is False
    assert result["error"] == "WeChat database changed during key configuration"
    assert "key_identity" not in result
    assert marker_writes == 0


def test_same_account_multiple_database_targets_are_not_cross_account_ambiguity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    first = _message_db(root, "wxid_same_private", "message_0.db")
    second = _message_db(root, "wxid_same_private", "message_1.db")
    key = b"s" * 32
    monkeypatch.setattr(
        cli,
        "_wechat_verification_databases",
        lambda _data_root=None: [first, second],
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda path: Path(path).name.encode().ljust(4096, b"."),
    )
    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", lambda candidate, _page: candidate == key)

    snapshots = cli._wechat_key_target_snapshots(str(root))
    target = wechat_key_identity.matching_target(key, snapshots)

    assert target.account_id == "wxid_same_private"
    assert target.path == min(first.resolve(), second.resolve(), key=lambda path: os.path.normcase(str(path)))


def test_partial_account_discovery_fails_before_hmac_or_cache_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    first = _message_db(root, "wxid_first_private")
    _message_db(root, "wxid_hidden_private")
    monkeypatch.setattr(
        cli.wechat_db,
        "find_wxid_dirs",
        lambda _root: [first.parents[2]],
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda *_args: pytest.fail("partial discovery reached HMAC verification"),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key_for_account",
        lambda *_args: pytest.fail("partial discovery reached cache write"),
    )

    result = cli._set_key("wechat", (b"u" * 32).hex(), data_root=str(root))

    assert result["ok"] is False
    assert result["error"] == (
        "could not read a stable WeChat database page for key verification"
    )
    assert "key_identity" not in result


def test_one_unreadable_account_discovery_invalidates_complete_target_set(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    first = _message_db(root, "wxid_first_private")
    second = _message_db(root, "wxid_second_private")

    def find_databases(account_root: Path) -> list[Path]:
        if Path(account_root) == second.parents[2]:
            raise PermissionError("synthetic unreadable account")
        return [first]

    monkeypatch.setattr(cli.wechat_db, "find_msg_databases", find_databases)
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda *_args: pytest.fail("incomplete target set reached HMAC verification"),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key_for_account",
        lambda *_args: pytest.fail("incomplete target set reached cache write"),
    )

    result = cli._set_key("wechat", (b"v" * 32).hex(), data_root=str(root))

    assert result["ok"] is False
    assert result["error"] == (
        "could not read a stable WeChat database page for key verification"
    )
    assert "key_identity" not in result


def test_final_symlink_target_is_rejected_before_hmac_or_cache_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    real = _message_db(tmp_path, "wxid_real_private")
    link = tmp_path / "message_link.db"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    monkeypatch.setattr(cli, "_wechat_verification_databases", lambda _root=None: [link])
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda *_args: pytest.fail("unsafe target reached HMAC verification"),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key",
        lambda *_args: pytest.fail("unsafe target reached cache write"),
    )

    result = cli._set_key("wechat", (b"x" * 32).hex())

    assert result["ok"] is False
    assert "key_identity" not in result


def test_target_replacement_before_cache_write_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database = _message_db(tmp_path, "wxid_switch_private")
    key = b"r" * 32
    original_page = b"original-salt-01" + b"o" * (4096 - 16)
    replacement_page = b"replaced-salt-01" + b"r" * (4096 - 16)
    reads = 0
    saves = 0

    def read(path: Path) -> bytes:
        nonlocal reads
        reads += 1
        if reads == 2:
            replacement = database.with_name("replacement.db")
            replacement.write_bytes(b"replacement")
            os.replace(replacement, database)
            return replacement_page
        return original_page

    def save(*_args) -> bool:
        nonlocal saves
        saves += 1
        return True

    monkeypatch.setattr(cli, "_wechat_verification_databases", lambda _root=None: [database])
    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", read)
    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", lambda candidate, _page: candidate == key)
    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key_for_account", save)

    result = cli._set_key("wechat", key.hex())

    assert result["ok"] is False
    assert result["error"] == "WeChat database changed during key configuration"
    assert "key_identity" not in result
    assert saves == 0


def test_target_replacement_after_cache_write_never_returns_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database = _message_db(tmp_path, "wxid_postsave_private")
    key = b"z" * 32
    page = b"original-salt-02" + b"o" * (4096 - 16)
    reads = 0
    saves = 0

    def read(_path: Path) -> bytes:
        nonlocal reads
        reads += 1
        if reads == 3:
            replacement = database.with_name("replacement.db")
            replacement.write_bytes(b"replacement")
            os.replace(replacement, database)
        return page

    def save(*_args) -> bool:
        nonlocal saves
        saves += 1
        return True

    monkeypatch.setattr(cli, "_wechat_verification_databases", lambda _root=None: [database])
    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", read)
    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", lambda candidate, _page: candidate == key)
    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key_for_account", save)

    result = cli._set_key("wechat", key.hex())

    assert result["ok"] is False
    assert result["error"] == "WeChat database changed during key configuration"
    assert "key_identity" not in result
    assert saves == 1


def test_target_change_during_marker_publish_never_returns_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database = _message_db(tmp_path, "wxid_marker_race_private")
    key = b"y" * 32
    page = b"marker-race-salt" + b"o" * (4096 - 16)
    marker_writes = 0

    monkeypatch.setattr(cli, "_wechat_verification_databases", lambda _root=None: [database])
    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", lambda _path: page)
    monkeypatch.setattr(cli.wechat_db, "_verify_key_v4", lambda candidate, _page: candidate == key)
    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key_for_account", lambda *_args: True)

    def publish_then_replace(_key: bytes) -> bool:
        nonlocal marker_writes
        marker_writes += 1
        replacement = database.with_name("replacement.db")
        replacement.write_bytes(b"replacement")
        os.replace(replacement, database)
        return True

    monkeypatch.setattr(wechat_key_identity, "write_selected_key", publish_then_replace)

    result = cli._set_key("wechat", key.hex())

    assert result["ok"] is False
    assert result["error"] == "WeChat database changed during key configuration"
    assert "key_identity" not in result
    assert marker_writes == 1


def test_target_limit_fails_before_read_verify_or_save(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    targets = [tmp_path / f"message_{index}.db" for index in range(65)]
    monkeypatch.setattr(cli, "_wechat_verification_databases", lambda _root=None: targets)
    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda *_args: pytest.fail("oversized target set reached a database read"),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key",
        lambda *_args: pytest.fail("oversized target set reached a cache write"),
    )

    result = cli._set_key("wechat", (b"l" * 32).hex())

    assert result["ok"] is False
    assert "key_identity" not in result


def test_identity_ref_is_domain_separated_deterministic_and_key_sensitive() -> None:
    first = b"a" * 32
    second = b"b" * 32

    first_envelope = wechat_key_identity.envelope(first)

    assert first_envelope == wechat_key_identity.envelope(first)
    assert first_envelope != wechat_key_identity.envelope(second)
    assert first_envelope["account_ref"] == _expected_ref(first)
    assert first.hex() not in repr(first_envelope)
    assert set(first_envelope) == {"schema", "source", "authority", "account_ref"}
