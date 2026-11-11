"""Discover synthetic Windows stores from WeChat's own path records."""

from pathlib import Path
import sys

import pytest

from chatlog_keeper import wechat_db
from chatlog_keeper.core import _paths


@pytest.fixture
def configured_store(tmp_path, monkeypatch):
    appdata = tmp_path / "appdata"
    config = appdata / "Tencent" / "xwechat" / "config"
    config.mkdir(parents=True)
    base = tmp_path / "relocated"
    store = base / "xwechat_files"
    store.mkdir(parents=True)
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.delenv("CHATLOG_WECHAT_DATA_ROOT", raising=False)
    monkeypatch.setattr(wechat_db.sys, "platform", "win32")
    monkeypatch.setattr(_paths, "all_drive_roots", lambda: [])
    monkeypatch.setattr(_paths, "candidate_documents_roots", lambda: [])
    return config, base, store


@pytest.mark.parametrize("direct,bom", [(False, False), (True, False), (False, True)])
def test_config_finds_the_relocated_base_or_store(configured_store, direct, bom):
    config, base, store = configured_store
    value = str(store if direct else base)
    (config / "path.ini").write_bytes(value.encode("utf-8-sig" if bom else "utf-8"))
    assert wechat_db.find_weixin_data_root() == store


def test_utf8_non_ascii_path_and_mode_marker(configured_store, tmp_path):
    config, _, _ = configured_store
    base = tmp_path / "synthetic-资料"
    store = base / "xwechat_files"
    store.mkdir(parents=True)
    (config / "00-mode.ini").write_text("MyDocument:", encoding="utf-8")
    (config / "01-path.ini").write_text(str(base) + "\n", encoding="utf-8")
    assert wechat_db.find_weixin_data_root() == store


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ANSI codec")
def test_windows_ansi_path(configured_store, tmp_path):
    config, _, _ = configured_store
    # U+00E9 is representable in both Western ANSI and common Chinese code pages.
    base = tmp_path / "synthetic-café"
    store = base / "xwechat_files"
    store.mkdir(parents=True)
    (config / "path.ini").write_bytes(str(base).encode("mbcs"))
    assert wechat_db.find_weixin_data_root() == store


def test_explicit_environment_override_wins(configured_store, tmp_path, monkeypatch):
    config, base, _ = configured_store
    (config / "path.ini").write_text(str(base), encoding="utf-8")
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    monkeypatch.setenv("CHATLOG_WECHAT_DATA_ROOT", str(explicit))
    assert wechat_db.find_weixin_data_root() == explicit


@pytest.mark.parametrize("record", ["MyDocument:", "missing", "relative/path", "", "a\nb", "x" * 5000])
def test_invalid_records_fall_back_to_existing_candidates(configured_store, tmp_path, monkeypatch, record):
    config, _, _ = configured_store
    fallback = tmp_path / "documents" / "xwechat_files"
    fallback.mkdir(parents=True)
    (config / "path.ini").write_text(record, encoding="utf-8")
    monkeypatch.setattr(_paths, "candidate_documents_roots", lambda: [fallback.parent])
    assert wechat_db.find_weixin_data_root() == fallback


def test_unreadable_record_does_not_hide_a_later_record(configured_store, monkeypatch):
    config, base, store = configured_store
    bad = config / "00-bad.ini"
    bad.write_text("synthetic", encoding="utf-8")
    (config / "01-good.ini").write_text(str(base), encoding="utf-8")
    original_open = Path.open

    def open_path(path, *args, **kwargs):
        if path == bad:
            raise PermissionError("synthetic denial")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_path)
    assert wechat_db.find_weixin_data_root() == store


def test_missing_appdata_keeps_fallback_behavior(configured_store, tmp_path, monkeypatch):
    monkeypatch.delenv("APPDATA")
    fallback = tmp_path / "documents" / "xwechat_files"
    fallback.mkdir(parents=True)
    monkeypatch.setattr(_paths, "candidate_documents_roots", lambda: [fallback.parent])
    assert wechat_db.find_weixin_data_root() == fallback


def test_missing_config_directory_keeps_fallback_behavior(configured_store, tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "absent"))
    fallback = tmp_path / "documents" / "xwechat_files"
    fallback.mkdir(parents=True)
    monkeypatch.setattr(_paths, "candidate_documents_roots", lambda: [fallback.parent])
    assert wechat_db.find_weixin_data_root() == fallback


def test_unreadable_config_directory_keeps_fallback_behavior(configured_store, tmp_path, monkeypatch):
    fallback = tmp_path / "documents" / "xwechat_files"
    fallback.mkdir(parents=True)

    def refused(*_args):
        raise PermissionError("synthetic denial")

    monkeypatch.setattr(Path, "glob", refused)
    monkeypatch.setattr(_paths, "candidate_documents_roots", lambda: [fallback.parent])
    assert wechat_db.find_weixin_data_root() == fallback


def test_constructor_override_does_not_consult_auto_discovery(configured_store, tmp_path, monkeypatch):
    explicit = tmp_path / "explicit-root"
    (explicit / "wxid_synthetic_account" / "db_storage").mkdir(parents=True)

    def unexpected():
        pytest.fail("explicit data_root must bypass auto-discovery")

    monkeypatch.setattr(wechat_db, "find_weixin_data_root", unexpected)
    reader = wechat_db.WeChatDBReader(data_root=explicit, allow_live_key_extract=False)
    assert reader.initialize()
    assert reader.data_root == explicit


def test_non_windows_discovery_ignores_windows_config(configured_store, monkeypatch):
    config, base, _ = configured_store
    (config / "path.ini").write_text(str(base), encoding="utf-8")
    from chatlog_keeper.core import _macos
    monkeypatch.setattr(wechat_db.sys, "platform", "darwin")
    monkeypatch.setattr(_macos, "wechat_data_roots", lambda: [])
    assert wechat_db.find_weixin_data_root() is None
