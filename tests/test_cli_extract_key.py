from pathlib import Path

from chatlog_keeper import cli, wechat_db
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
    monkeypatch.setattr(cli.wechat_db, "save_cached_wechat_key", lambda key: key == bytes(range(32)))
    monkeypatch.setattr(cli.wechat_db, "_wechat_key_cache_path", lambda: Path("wechat_db.key"))

    result = cli._extract_key("wechat", "active", data_root=str(tmp_path / "xwechat_files"))

    assert result["ok"] is True
    assert result["db_path"] == str(db)
    assert seen["db_path"] == str(db)


def test_wechat_data_root_discovers_root_level_relocation(monkeypatch, tmp_path):
    relocated = tmp_path / "xwechat_files"
    relocated.mkdir()
    monkeypatch.delenv("CHATLOG_WECHAT_DATA_ROOT", raising=False)
    monkeypatch.setattr(_paths, "all_drive_roots", lambda: [tmp_path])
    monkeypatch.setattr(_paths, "candidate_documents_roots", lambda: [])

    assert wechat_db.find_weixin_data_root() == relocated
