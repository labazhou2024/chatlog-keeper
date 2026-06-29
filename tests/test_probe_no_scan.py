"""Probe must stay cache-first and NEVER scan process memory.

Regression for the "检测微信检测不到 / passive 超时" hang: the status probe
(``chatlog-keeper probe``, used by the GUI 检测 button via memexa
``detect_wechat_status``) used to call ``reader.initialize()``, which runs the
passive memory scan — 120s/pid on WeChat 4.1.10.31+ where the key is no longer
in the heap, multiplied across DB×pid into minutes. These tests pin that the
probe only *locates* data + checks the *cached* key, reports the actionable
``needs_key`` state, and never touches the scanner; and that ``initialize()``'s
scan is bounded by a TOTAL budget so a never-succeeding scan can't run forever.

No real chat data — everything is monkeypatched. Safe in CI.

Run:  python -m pytest tests/test_probe_no_scan.py -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ─── probe is cache-first, never scans ────────────────────────────────────────

def test_probe_wechat_never_scans(monkeypatch):
    from chatlog_keeper import cli, wechat_db

    def _no_initialize(self):
        raise AssertionError("probe must not call WeChatDBReader.initialize() (it scans)")

    def _no_scan(*a, **k):
        raise AssertionError("probe must not run extract_key_from_weixin (passive scan)")

    monkeypatch.setattr(wechat_db.WeChatDBReader, "initialize", _no_initialize)
    monkeypatch.setattr(wechat_db, "extract_key_from_weixin", _no_scan)
    monkeypatch.setattr(wechat_db, "_get_weixin_pids", lambda: [4321])
    monkeypatch.setattr(wechat_db, "find_weixin_data_root", lambda: Path("X:/fake/xwechat_files"))
    monkeypatch.setattr(wechat_db, "find_wxid_dirs", lambda root: [Path("X:/fake/xwechat_files/wxid_demo")])
    monkeypatch.setattr(wechat_db, "load_cached_wechat_key", lambda: None)

    r = cli._probe_wechat()
    assert r["source"] == "wechat"
    assert r["available"] is False        # no cached key → can't decrypt yet
    assert r["client_running"] is True    # process located
    assert r["needs_key"] is True         # running + data + no key → guide to 取密钥


def test_probe_wechat_available_with_cached_key(monkeypatch):
    from chatlog_keeper import cli, wechat_db

    monkeypatch.setattr(wechat_db.WeChatDBReader, "initialize",
                        lambda self: (_ for _ in ()).throw(AssertionError("no scan in probe")))
    monkeypatch.setattr(wechat_db, "_get_weixin_pids", lambda: [1])
    monkeypatch.setattr(wechat_db, "find_weixin_data_root", lambda: Path("X:/fake"))
    monkeypatch.setattr(wechat_db, "find_wxid_dirs", lambda root: [Path("X:/fake/wxid_demo")])
    monkeypatch.setattr(wechat_db, "load_cached_wechat_key", lambda: b"\x11" * 32)

    r = cli._probe_wechat()
    assert r["available"] is True         # 32-byte cached key → ready now
    assert r["needs_key"] is False


def test_probe_qq_never_scans(monkeypatch):
    from chatlog_keeper import cli, qq_db

    def _no_initialize(self):
        raise AssertionError("probe must not call QQDBReader.initialize() (it scans)")

    monkeypatch.setattr(qq_db.QQDBReader, "initialize", _no_initialize)
    monkeypatch.setattr(qq_db, "_get_qq_pids", lambda: [777])
    monkeypatch.setattr(qq_db, "find_qq_data_root", lambda: Path("X:/fake/Tencent Files"))
    monkeypatch.setattr(qq_db, "find_msg_database", lambda root: Path("X:/fake/nt_msg.db"))
    monkeypatch.setattr(qq_db, "detect_current_qq_account", lambda: 10001)
    monkeypatch.setattr(qq_db, "load_cached_key", lambda: None)

    r = cli._probe_qq()
    assert r["source"] == "qq"
    assert r["available"] is False
    assert r["client_running"] is True
    assert r["needs_key"] is True
    assert r["account"] == 10001


# ─── WeChat passive scan is bounded by a TOTAL budget ─────────────────────────

def test_wechat_initialize_total_budget_early_stop(monkeypatch, tmp_path):
    """A never-succeeding scan (4.1.10.31+) must stop at the TOTAL budget, not
    run DB×pid×per-budget. Simulate 8 DBs × 3 pids, every scan failing and
    "costing" 10 simulated seconds; assert it breaks after ~total_budget worth
    of scans (~3), NOT all 24."""
    from chatlog_keeper import wechat_db

    dbs = [tmp_path / f"message_{i}.db" for i in range(8)]
    for db in dbs:
        db.write_bytes(b"\x00" * 4096)

    monkeypatch.setattr(wechat_db, "find_weixin_data_root", lambda: tmp_path)
    monkeypatch.setattr(wechat_db, "find_wxid_dirs", lambda root: [tmp_path])
    monkeypatch.setattr(wechat_db, "find_msg_databases", lambda d: dbs)
    monkeypatch.setattr(wechat_db, "load_cached_wechat_key", lambda: None)
    monkeypatch.setattr(wechat_db, "_get_weixin_pids", lambda: [11, 22, 33])

    scan_calls = {"n": 0}
    clock = {"t": 0.0}

    def fake_scan(pid, db_path=None, timeout_s=None):
        scan_calls["n"] += 1
        clock["t"] += 10.0          # each failing scan "costs" 10 simulated s
        return None

    monkeypatch.setattr(wechat_db, "extract_key_from_weixin", fake_scan)
    # initialize() does a local `import time as _time`, so _time IS the global
    # time module — patch its monotonic to drive a deterministic fake clock.
    import time as _time_mod
    monkeypatch.setattr(_time_mod, "monotonic", lambda: clock["t"])

    reader = wechat_db.WeChatDBReader()
    ok = reader.initialize()
    assert ok is True
    # total budget 25s / 10s per scan → ~3 scans. Old code (no total budget)
    # would run 8 DBs × 3 pids = 24. Pin the early stop.
    assert scan_calls["n"] <= 4, f"expected early stop, got {scan_calls['n']} scans"
    assert reader.enc_keys == {}          # all scans failed → nothing unlocked


def test_wechat_scan_defaults_are_fast():
    """The shipped per-pid + total budget defaults must be the fast ones (the
    120s/pid default was the 超时 root cause)."""
    import inspect
    from chatlog_keeper import wechat_db
    src = inspect.getsource(wechat_db.WeChatDBReader.initialize)
    assert 'CHATLOG_WECHAT_SCAN_TIMEOUT_S", "10"' in src or 'CHATLOG_WECHAT_SCAN_TIMEOUT_S","10"' in src
    assert "CHATLOG_WECHAT_SCAN_TOTAL_S" in src


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
