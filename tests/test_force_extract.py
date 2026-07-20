from chatlog_keeper import cli, qq_db


def test_force_qq_rejects_cached_fallback(monkeypatch):
    class CachedReader:
        key = b"1234567890abcdef"
        key_source = "cache"

        def initialize(self):
            return True

    monkeypatch.setenv("CHATLOG_FORCE_EXTRACT", "1")
    monkeypatch.setattr(cli.qq_db, "QQDBReader", CachedReader)

    result = cli._extract_key("qq", "passive")

    assert result["ok"] is False
    assert "fresh extraction" in result["error"]


def test_force_qq_marks_live_key_fresh(monkeypatch):
    class LiveReader:
        key = b"1234567890abcdef"
        key_source = "live"

        def initialize(self):
            return True

    monkeypatch.setenv("CHATLOG_FORCE_EXTRACT", "1")
    monkeypatch.setattr(cli.qq_db, "QQDBReader", LiveReader)
    monkeypatch.setattr(cli.qq_db, "save_cached_key", lambda key: True)
    monkeypatch.setattr(cli.qq_db, "_key_cache_path", lambda: "qq_db.key")

    result = cli._extract_key("qq", "passive")

    assert result["ok"] is True
    assert result["fresh_extraction"] is True


def test_qq_reader_disables_cache_fallback_when_live_is_required(monkeypatch, tmp_path):
    monkeypatch.setenv("CHATLOG_QQ_FORCE_LIVE_KEY", "1")
    monkeypatch.setenv("CHATLOG_QQ_REQUIRE_LIVE_KEY", "1")
    monkeypatch.setattr(qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(qq_db, "find_msg_database", lambda root: tmp_path / "nt_msg.db")
    monkeypatch.setattr(qq_db, "_get_qq_pids", lambda: [])
    monkeypatch.setattr(qq_db, "load_cached_key", lambda: b"1234567890abcdef")

    reader = qq_db.QQDBReader()
    reader.initialize()

    assert reader.key is None
    assert reader.key_source is None
