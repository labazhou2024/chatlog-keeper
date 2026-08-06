from pathlib import Path

from chatlog_keeper import cli, macos_debug_app, macos_wechat_capture, wechat_db
from chatlog_keeper.core import _paths


def _mk_message_db(root: Path) -> Path:
    db = root / "wxid_user_1234" / "db_storage" / "message" / "message_0.db"
    db.parent.mkdir(parents=True)
    db.write_bytes(b"x" * 4096)
    return db


def test_wechat_active_db_path_resolves_parent_data_root(tmp_path):
    db = _mk_message_db(tmp_path / "xwechat_files")

    assert cli._wechat_message_db_for_active(str(tmp_path / "xwechat_files")) == str(db)


def test_wechat_active_db_path_resolves_wxid_data_root(tmp_path):
    db = _mk_message_db(tmp_path / "xwechat_files")

    assert cli._wechat_message_db_for_active(str(db.parents[2])) == str(db)


def test_wechat_active_passes_db_path_to_debugger(monkeypatch, tmp_path):
    db = _mk_message_db(tmp_path / "xwechat_files")
    seen = {}

    def fake_extract_wechat_key_active(**kwargs):
        seen.update(kwargs)
        return bytes(range(32))

    monkeypatch.setattr(cli.active_key, "extract_wechat_key_active", fake_extract_wechat_key_active)
    monkeypatch.setattr(cli.wechat_db, "_read_stable_page1", lambda path: b"page")
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda key, page: key == bytes(range(32)),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key_for_account",
        lambda key, account_id, verification_db: (
            key == bytes(range(32))
            and account_id == "wxid_user_1234"
            and verification_db == db
        ),
        raising=False,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_wechat_account_key_cache_path",
        lambda account_id: Path("wechat_accounts") / f"{account_id}.key",
        raising=False,
    )

    result = cli._extract_key("wechat", "active", data_root=str(tmp_path / "xwechat_files"))

    assert result["ok"] is True
    assert result["db_path"] == str(db)
    assert result["saved_to"] == "wechat_accounts/wxid_user_1234.key"
    assert seen["db_path"] == str(db)


def test_wechat_active_saves_key_for_matching_account_not_seed(
    monkeypatch, tmp_path
):
    root = tmp_path / "xwechat_files"
    seed = _mk_message_db(root)
    matching = (
        root
        / "wxid_z_matching_account"
        / "db_storage"
        / "message"
        / "message_0.db"
    )
    matching.parent.mkdir(parents=True)
    matching.write_bytes(b"y" * 4096)
    key = bytes(range(32))
    saved = []
    active_args = {}

    monkeypatch.setattr(
        cli.active_key,
        "extract_wechat_key_active",
        lambda **kwargs: active_args.update(kwargs) or key,
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_read_stable_page1",
        lambda path: b"matching" if Path(path) == matching else b"seed",
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_verify_key_v4",
        lambda candidate, page: candidate == key and page == b"matching",
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "save_cached_wechat_key_for_account",
        lambda candidate, account_id, database: (
            saved.append((account_id, Path(database))) or True
        ),
    )
    monkeypatch.setattr(
        cli.wechat_db,
        "_wechat_account_key_cache_path",
        lambda account_id: Path("wechat_accounts") / "matching.key",
    )

    result = cli._extract_key("wechat", "active", data_root=str(root))

    assert result["ok"] is True
    assert Path(active_args["db_path"]) == seed
    assert Path(result["db_path"]) == matching
    assert saved == [("wxid_z_matching_account", matching)]
    assert seed != matching


def test_wechat_active_reports_running_daily_client_without_new_fields(
    monkeypatch, tmp_path
):
    db = _mk_message_db(tmp_path / "xwechat_files")
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(
        cli.active_key,
        "extract_wechat_key_active",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "last_error",
        lambda: "daily_client_single_instance_conflict",
    )

    result = cli._extract_key(
        "wechat",
        "active",
        data_root=str(tmp_path / "xwechat_files"),
    )

    assert set(result) == {"source", "method", "ok", "error", "db_path"}
    assert result["ok"] is False
    assert result["db_path"] == str(db)
    assert "quit WeChat normally" in result["error"]
    assert "do not force-quit" in result["error"]


def test_wechat_active_reports_library_validation_block_without_new_fields(
    monkeypatch, tmp_path
):
    db = _mk_message_db(tmp_path / "xwechat_files")
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(
        cli.active_key,
        "extract_wechat_key_active",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "last_error",
        lambda: "debug_copy_library_validation_incompatible",
    )

    result = cli._extract_key(
        "wechat",
        "active",
        data_root=str(tmp_path / "xwechat_files"),
    )

    assert set(result) == {"source", "method", "ok", "error", "db_path"}
    assert result["ok"] is False
    assert result["db_path"] == str(db)
    assert "required embedded libraries" in result["error"]
    assert "manual master key" in result["error"]


def test_wechat_active_reports_unverifiable_library_validation_without_new_fields(
    monkeypatch, tmp_path
):
    db = _mk_message_db(tmp_path / "xwechat_files")
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(
        cli.active_key,
        "extract_wechat_key_active",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "last_error",
        lambda: "debug_copy_library_validation_unverifiable",
    )

    result = cli._extract_key(
        "wechat",
        "active",
        data_root=str(tmp_path / "xwechat_files"),
    )

    assert set(result) == {"source", "method", "ok", "error", "db_path"}
    assert result["ok"] is False
    assert result["db_path"] == str(db)
    assert "could not safely verify" in result["error"]
    assert "not launched" in result["error"]


def test_wechat_active_reports_capture_preflight_without_contract_drift(
    monkeypatch, tmp_path
):
    db = _mk_message_db(tmp_path / "xwechat_files")
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(
        cli.active_key,
        "extract_wechat_key_active",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(macos_debug_app, "last_error", lambda: "")
    monkeypatch.setattr(
        macos_wechat_capture,
        "last_error",
        lambda: "capture_validation_failed",
    )

    result = cli._extract_key(
        "wechat",
        "active",
        data_root=str(tmp_path / "xwechat_files"),
    )

    assert set(result) == {"source", "method", "ok", "error", "db_path"}
    assert result["ok"] is False
    assert result["db_path"] == str(db)
    assert "startup capture helper" in result["error"]
    assert "reinstall the connector" in result["error"]


def test_wechat_data_root_discovers_root_level_relocation(monkeypatch, tmp_path):
    relocated = tmp_path / "xwechat_files"
    relocated.mkdir()
    monkeypatch.delenv("CHATLOG_WECHAT_DATA_ROOT", raising=False)
    monkeypatch.setattr(wechat_db.sys, "platform", "win32")
    monkeypatch.setattr(_paths, "all_drive_roots", lambda: [tmp_path])
    monkeypatch.setattr(_paths, "candidate_documents_roots", lambda: [])

    assert wechat_db.find_weixin_data_root() == relocated
