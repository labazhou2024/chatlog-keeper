import inspect
import time

from chatlog_keeper import qq_db


def test_qq_pid_ranking_puts_earliest_root_before_newer_helpers(monkeypatch):
    created = {23464: 300, 23116: 100, 22276: 200, 15924: 250}
    monkeypatch.setattr(qq_db, "_qq_process_creation_ticks", created.get)

    assert qq_db._rank_qq_pids([23464, 23116, 22276, 15924]) == [
        23116,
        22276,
        15924,
        23464,
    ]


def test_qq_pid_ranking_keeps_unknown_metadata_after_known_processes(monkeypatch):
    created = {40: None, 30: 200, 20: 100}
    monkeypatch.setattr(qq_db, "_qq_process_creation_ticks", created.get)

    assert qq_db._rank_qq_pids([40, 30, 20]) == [20, 30, 40]


def test_qq_initialize_uses_one_total_passive_budget(monkeypatch, tmp_path):
    db_path = tmp_path / "nt_msg.db"
    db_path.write_bytes(b"x" * 8192)
    monkeypatch.setenv("CHATLOG_QQ_SCAN_TIMEOUT_S", "120")
    monkeypatch.setenv("CHATLOG_QQ_SCAN_TOTAL_S", "120")
    monkeypatch.setattr(qq_db, "find_qq_data_root", lambda: tmp_path)
    monkeypatch.setattr(qq_db, "find_msg_database", lambda root: db_path)
    monkeypatch.setattr(qq_db, "load_cached_key", lambda: None)
    monkeypatch.setattr(qq_db, "_get_qq_pids", lambda: [10, 20, 30])

    clock = {"value": 0.0}
    calls = []

    def fake_scan(pid, db_path=None, timeout_s=None):
        calls.append((pid, timeout_s))
        clock["value"] += timeout_s
        return None

    monkeypatch.setattr(qq_db, "extract_key_from_qq", fake_scan)
    monkeypatch.setattr(time, "monotonic", lambda: clock["value"])

    reader = qq_db.QQDBReader()
    assert reader.initialize() is True
    assert calls == [(10, 120.0)]
    assert reader.key is None


def test_qq_passive_logs_never_include_key_preview():
    source = inspect.getsource(qq_db)
    assert "preview={candidate" not in source
    assert "Passphrase extracted: len={len(key)} preview=" not in source
