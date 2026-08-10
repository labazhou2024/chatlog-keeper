"""Contract tests for the additive opaque native-account binding protocol."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from chatlog_keeper import cli, native_account_binding, wechat_key_identity


_EXPECTED_CAPABILITY = {
    "capability": "native-account-binding-v1",
    "schema": "chatlog-keeper.native-account-binding.v1",
    "authority": "device-local-canonical-account-binding",
    "account_ref_formats": [
        "chatlog-account-ref-v1-sha256",
        "chatlog-native-account-ref-v1-hmac-sha256",
    ],
    "sources": ["qq", "wechat"],
    "states": [
        "verified",
        "verified_unpersisted",
        "restored",
        "single_account",
        "current_account",
        "selection_required",
        "unavailable",
    ],
}


@pytest.fixture
def binding_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    root = tmp_path / "private-state" / "secrets"
    monkeypatch.setattr(native_account_binding, "_state_root", lambda: root)
    monkeypatch.setattr(
        wechat_key_identity,
        "_selection_marker_path",
        lambda: root / "wechat_key_identity.ref",
    )
    return root


def _message_db(root: Path, account_id: str) -> Path:
    database = root / account_id / "db_storage" / "message" / "message_0.db"
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_bytes((account_id + ":page").encode().ljust(4096, b"."))
    return database


def _patch_wechat_probe(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    databases: list[Path],
    cache: dict[str, bytes] | None = None,
) -> None:
    cache = cache if cache is not None else {}
    pages = {
        database.resolve(): database.read_bytes()
        for database in databases
    }
    monkeypatch.setattr(cli.wechat_db, "_get_weixin_pids", lambda: [])
    monkeypatch.setattr(cli.wechat_db, "find_weixin_data_root", lambda: root)
    monkeypatch.setattr(
        cli.wechat_db,
        "find_wxid_dirs",
        lambda _root: [database.parents[2] for database in databases],
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "find_msg_databases",
        lambda account_root: [
            database
            for database in databases
            if database.parents[2] == Path(account_root)
        ],
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda path: pages.get(Path(path).resolve()),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "load_cached_wechat_key_for_account",
        lambda account_id: cache.get(account_id),
    )
    monkeypatch.setattr(cli.wechat_db, "load_cached_wechat_key", lambda: None)
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda key, page: any(
            cache.get(database.parents[2].name) == key
            and pages[database.resolve()] == page
            for database in databases
        ),
    )


def test_capability_is_exact_and_cli_does_not_create_private_state(
    binding_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert native_account_binding.capabilities_payload() == _EXPECTED_CAPABILITY

    assert cli.main(["native-account-binding-v1", "--capabilities"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out) == _EXPECTED_CAPABILITY
    assert captured.err == ""
    assert not binding_root.exists()


def test_refs_are_stable_opaque_and_domain_separated(
    binding_root: Path,
) -> None:
    private_id = "wxid_private_value_123"

    first = native_account_binding.account_ref("wechat", private_id)
    second = native_account_binding.account_ref("wechat", private_id)
    qq_ref = native_account_binding.account_ref("qq", private_id)

    assert first == second
    assert first != qq_ref
    assert first.startswith("chatlog-native-account-ref-v1:")
    assert private_id not in first
    assert binding_root.joinpath("native_account_binding.secret").is_file()
    assert private_id not in binding_root.joinpath(
        "native_account_binding.secret"
    ).read_text(encoding="utf-8")
    if os.name != "nt":
        assert binding_root.stat().st_mode & 0o777 == 0o700
        assert (
            binding_root.joinpath("native_account_binding.secret").stat().st_mode
            & 0o777
            == 0o600
        )


def test_selected_record_contains_no_raw_id_path_or_key_and_resolves_exactly(
    binding_root: Path,
) -> None:
    private_id = "wxid_private_selected"
    other_id = "wxid_other"

    selected = native_account_binding.select_account(
        "wechat",
        private_id,
        proof="database-key-proof",
    )
    resolved = native_account_binding.resolve_selected(
        "wechat",
        (other_id, private_id),
    )

    assert selected is not None
    assert resolved is not None
    assert resolved.account_id == private_id
    assert resolved.account_ref == selected
    stored = binding_root.joinpath("wechat_native_account_binding.json").read_text(
        encoding="utf-8"
    )
    stored_payload = json.loads(stored)
    assert private_id not in stored
    assert other_id not in stored
    assert "/" not in stored_payload["native_account_hash"]
    assert stored_payload["native_account_hash"] != selected.rsplit(":", 1)[-1]
    assert "key" not in stored_payload
    if os.name != "nt":
        assert (
            binding_root.joinpath("wechat_native_account_binding.json").stat().st_mode
            & 0o777
            == 0o600
        )


def test_single_wechat_needs_key_gets_stable_opaque_ref_and_recovery_order(
    monkeypatch: pytest.MonkeyPatch,
    binding_root: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    account_id = "wxid_single_private"
    database = _message_db(root, account_id)
    _patch_wechat_probe(monkeypatch, root, [database])

    first = cli._probe_wechat()
    second = cli._probe_wechat()

    first_binding = first["native_account_binding"]
    second_binding = second["native_account_binding"]
    assert first["needs_key"] is True
    assert first_binding["state"] == "single_account"
    assert second_binding["state"] == "restored"
    assert first_binding["account_ref"] == second_binding["account_ref"]
    assert first_binding["account_selection_required"] is False
    assert account_id not in json.dumps(first_binding, ensure_ascii=False)
    assert first["key_recovery_flow"] == {
        "schema": "chatlog-keeper.key-recovery-flow.v1",
        "source": "wechat",
        "sequence": ["passive", "active", "manual"],
        "active_authentication": ["saved_session", "qr"],
        "account_switch_required": False,
    }


def test_first_multi_account_wechat_never_guesses_a_scalar_ref(
    monkeypatch: pytest.MonkeyPatch,
    binding_root: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    account_ids = ("wxid_first_private", "wxid_second_private")
    databases = [_message_db(root, account_id) for account_id in account_ids]
    _patch_wechat_probe(monkeypatch, root, databases)

    first = cli._probe_wechat()
    second = cli._probe_wechat()

    for result in (first, second):
        binding = result["native_account_binding"]
        assert result["needs_key"] is True
        assert binding["state"] == "selection_required"
        assert binding["account_ref"] is None
        assert binding["account_selection_required"] is True
        assert len(binding["account_refs"]) == 2
        serialized = json.dumps(binding, ensure_ascii=False)
        assert all(account_id not in serialized for account_id in account_ids)
    assert (
        first["native_account_binding"]["account_refs"]
        == second["native_account_binding"]["account_refs"]
    )
    assert not binding_root.joinpath("wechat_native_account_binding.json").exists()


def test_verified_selection_restores_without_account_switch_or_key_cache(
    monkeypatch: pytest.MonkeyPatch,
    binding_root: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    first_id = "wxid_first_private"
    selected_id = "wxid_selected_private"
    databases = [_message_db(root, first_id), _message_db(root, selected_id)]
    _patch_wechat_probe(monkeypatch, root, databases)
    selected_ref = native_account_binding.select_account(
        "wechat",
        selected_id,
        proof="database-key-proof",
    )

    result = cli._probe_wechat()

    binding = result["native_account_binding"]
    assert result["needs_key"] is True
    assert binding["state"] == "restored"
    assert binding["account_ref"] == selected_ref
    assert binding["account_selection_required"] is False
    assert selected_id not in json.dumps(binding, ensure_ascii=False)


def test_upgrade_restores_proven_key_ref_before_native_binding_exists(
    monkeypatch: pytest.MonkeyPatch,
    binding_root: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    first_id = "wxid_first_private"
    selected_id = "wxid_selected_private"
    first = _message_db(root, first_id)
    selected = _message_db(root, selected_id)
    key = bytes(range(32))
    cache: dict[str, bytes] = {}
    _patch_wechat_probe(monkeypatch, root, [first, selected], cache)
    assert wechat_key_identity.write_selected_key(key) is True
    key_ref = wechat_key_identity.envelope(key)["account_ref"]

    needs_key = cli._probe_wechat()

    binding = needs_key["native_account_binding"]
    assert needs_key["needs_key"] is True
    assert binding["state"] == "restored"
    assert binding["account_ref_format"] == "chatlog-account-ref-v1-sha256"
    assert binding["account_ref"] == key_ref
    assert binding["account_refs"] == [key_ref]
    assert binding["account_selection_required"] is False
    serialized = json.dumps(binding, ensure_ascii=False)
    assert first_id not in serialized
    assert selected_id not in serialized
    assert not binding_root.joinpath("wechat_native_account_binding.json").exists()

    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda candidate, page: candidate == key and page == selected.read_bytes(),
    )

    def save(candidate: bytes, account_id: str, target: Path) -> bool:
        if candidate != key or account_id != selected_id or Path(target) != selected:
            return False
        cache[account_id] = candidate
        return True

    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key_for_account", save)
    monkeypatch.setattr(
        cli.wechat_db,
        "_wechat_account_key_cache_path",
        lambda _account: binding_root / "wechat_accounts" / "selected.key",
    )

    configured = cli._set_key("wechat", key.hex(), data_root=str(root))

    assert configured["ok"] is True
    assert configured["native_account_binding"]["state"] == "verified"
    assert configured["native_account_binding"]["account_ref"] == key_ref
    selected_binding = native_account_binding.selected_binding("wechat")
    assert selected_binding is not None
    assert selected_binding.account_ref == key_ref
    assert selected_binding.account_ref_format == "chatlog-account-ref-v1-sha256"


def test_wechat_set_key_success_and_later_needs_key_share_binding_ref(
    monkeypatch: pytest.MonkeyPatch,
    binding_root: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "xwechat_files"
    account_id = "wxid_verified_private"
    database = _message_db(root, account_id)
    key = bytes(range(32))
    cache: dict[str, bytes] = {}
    _patch_wechat_probe(monkeypatch, root, [database], cache)
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda candidate, page: candidate == key and page == database.read_bytes(),
    )

    def save(candidate: bytes, selected: str, target: Path) -> bool:
        if candidate != key or selected != account_id or Path(target) != database.resolve():
            return False
        cache[selected] = candidate
        return True

    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key_for_account", save)
    monkeypatch.setattr(
        cli.wechat_db,
        "_wechat_account_key_cache_path",
        lambda _account: binding_root / "wechat_accounts" / "selected.key",
    )
    monkeypatch.setattr(
        wechat_key_identity,
        "_selection_marker_path",
        lambda: binding_root / "wechat_key_identity.ref",
    )

    configured = cli._set_key("wechat", key.hex(), data_root=str(root))
    configured_ref = configured["native_account_binding"]["account_ref"]
    cache.clear()
    needs_key = cli._probe_wechat()

    assert configured["ok"] is True
    assert configured["native_account_binding"]["state"] == "verified"
    assert configured_ref == wechat_key_identity.envelope(key)["account_ref"]
    assert needs_key["needs_key"] is True
    assert needs_key["native_account_binding"]["state"] == "restored"
    assert needs_key["native_account_binding"]["account_ref"] == configured_ref
    assert account_id not in json.dumps(
        configured["native_account_binding"], ensure_ascii=False
    )


def test_qq_needs_key_prefers_once_then_restores_same_opaque_ref(
    monkeypatch: pytest.MonkeyPatch,
    binding_root: Path,
) -> None:
    from chatlog_keeper import qq_db

    root = Path("X:/private/Tencent Files")
    first_db = Path("X:/private/Tencent Files/10001/nt_msg.db")
    current_db = Path("X:/private/Tencent Files/10002/nt_msg.db")
    monkeypatch.setattr(qq_db, "_get_qq_pids", lambda: [])
    monkeypatch.setattr(qq_db, "find_qq_data_root", lambda: root)
    monkeypatch.setattr(qq_db, "find_msg_database", lambda _root: current_db)
    monkeypatch.setattr(
        qq_db,
        "find_qq_account_databases",
        lambda _root: {"10001": first_db, "10002": current_db},
    )
    monkeypatch.setattr(qq_db, "detect_current_qq_account", lambda: 10002)
    monkeypatch.setattr(qq_db, "load_cached_key_for_account", lambda _account: None)

    first = cli._probe_qq()
    second = cli._probe_qq()

    assert first["needs_key"] is True
    assert first["native_account_binding"]["state"] == "current_account"
    assert second["native_account_binding"]["state"] == "restored"
    assert (
        first["native_account_binding"]["account_ref"]
        == second["native_account_binding"]["account_ref"]
    )
    assert "10002" not in json.dumps(first["native_account_binding"])


def test_qq_passive_success_includes_verified_opaque_ref(
    monkeypatch: pytest.MonkeyPatch,
    binding_root: Path,
) -> None:
    from chatlog_keeper import qq_db

    key = b"q" * 16

    class Reader:
        def __init__(self) -> None:
            self.account_id = "10001234"
            self.key_source = "live"
            self.key = key
            self._passive_key_error_code = None

        def initialize(self) -> bool:
            return True

    monkeypatch.setattr(qq_db, "QQDBReader", Reader)
    monkeypatch.setattr(qq_db, "save_cached_key_for_account", lambda *_args: True)
    monkeypatch.setattr(
        qq_db,
        "_account_key_cache_path",
        lambda _account: binding_root / "qq_accounts" / "selected.key",
    )

    result = cli._extract_key("qq", "passive")

    binding = result["native_account_binding"]
    assert result["ok"] is True
    assert binding["state"] == "verified"
    assert binding["account_ref"] is not None
    assert "10001234" not in json.dumps(binding)


def test_corrupt_binding_never_selects_an_account(
    binding_root: Path,
) -> None:
    assert native_account_binding.account_ref("wechat", "wxid_private") is not None
    binding_root.joinpath("wechat_native_account_binding.json").write_text(
        '{"schema":"wrong"}\n',
        encoding="utf-8",
    )
    if os.name != "nt":
        binding_root.joinpath("wechat_native_account_binding.json").chmod(0o600)

    assert native_account_binding.resolve_selected(
        "wechat",
        ("wxid_private",),
    ) is None


def test_missing_device_secret_never_resolves_private_routing_hmac(
    binding_root: Path,
) -> None:
    private_id = "wxid_private"
    key_ref = "chatlog-account-ref-v1:" + "a" * 64
    assert native_account_binding.select_account(
        "wechat",
        private_id,
        proof="database-key-proof",
        account_ref_value=key_ref,
    ) == key_ref

    binding_root.joinpath("native_account_binding.secret").unlink()

    assert native_account_binding.resolve_selected(
        "wechat",
        (private_id,),
    ) is None


def test_envelope_rejects_raw_or_path_shaped_refs() -> None:
    with pytest.raises(ValueError):
        native_account_binding.envelope(
            "wechat",
            state="verified",
            account_ref_value="wxid_private",
        )
    with pytest.raises(ValueError):
        native_account_binding.envelope(
            "wechat",
            state="verified",
            account_ref_value="C:/private/message.db",
        )
    valid_ref = "chatlog-native-account-ref-v1:" + "b" * 64
    with pytest.raises(ValueError):
        native_account_binding.envelope(
            "wechat",
            state="selection_required",
            account_refs=(valid_ref, valid_ref),
        )
    with pytest.raises(ValueError):
        native_account_binding.envelope(
            "wechat",
            state="restored",
        )
