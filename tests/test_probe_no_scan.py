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
    monkeypatch.setattr(wechat_db, "load_cached_wechat_key_for_account", lambda _account: None)

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
    account_dir = Path("X:/fake/wxid_demo")
    database = account_dir / "db_storage" / "message" / "message_0.db"
    monkeypatch.setattr(wechat_db, "find_wxid_dirs", lambda root: [account_dir])
    monkeypatch.setattr(wechat_db, "find_msg_databases", lambda _root: [database])
    monkeypatch.setattr(
        wechat_db,
        "load_cached_wechat_key_for_account",
        lambda account: b"\x11" * 32 if account == "wxid_demo" else None,
    )
    monkeypatch.setattr(wechat_db, "_read_stable_page1", lambda path: b"page")
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda key, page: key == b"\x11" * 32 and page == b"page",
    )

    r = cli._probe_wechat()
    assert r["available"] is True         # 32-byte cached key → ready now
    assert r["needs_key"] is False


def test_probe_wechat_rejects_a_cached_key_for_the_wrong_account(monkeypatch):
    from chatlog_keeper import cli, wechat_db

    account_dir = Path("X:/fake/wxid_current")
    database = account_dir / "db_storage" / "message" / "message_0.db"
    monkeypatch.setattr(wechat_db, "_get_weixin_pids", lambda: [1])
    monkeypatch.setattr(wechat_db, "find_weixin_data_root", lambda: Path("X:/fake"))
    monkeypatch.setattr(wechat_db, "find_wxid_dirs", lambda _root: [account_dir])
    monkeypatch.setattr(wechat_db, "find_msg_databases", lambda _root: [database])
    monkeypatch.setattr(
        wechat_db,
        "load_cached_wechat_key_for_account",
        lambda _account: b"\x22" * 32,
    )
    monkeypatch.setattr(wechat_db, "_read_stable_page1", lambda _path: b"page")
    monkeypatch.setattr(wechat_db, "_verify_key_v4", lambda _key, _page: False)

    result = cli._probe_wechat()

    assert result["available"] is False
    assert result["enc_keys_present"] is False
    assert result["needs_key"] is True


def test_wechat_directory_reader_never_scans_without_cached_key(monkeypatch, tmp_path):
    """Directory mode is cache-only even while a WeChat process is running."""
    from chatlog_keeper import wechat_db

    account_dir = tmp_path / "account"
    message_db = account_dir / "message.db"
    monkeypatch.setattr(wechat_db, "find_wxid_dirs", lambda _root: [account_dir])
    monkeypatch.setattr(wechat_db, "find_msg_databases", lambda _root: [message_db])
    monkeypatch.setattr(wechat_db, "load_cached_wechat_key", lambda: None)
    monkeypatch.setattr(
        wechat_db,
        "_get_weixin_pids",
        lambda: (_ for _ in ()).throw(
            AssertionError("directory reader must not inspect running processes")
        ),
    )
    monkeypatch.setattr(
        wechat_db,
        "extract_key_from_weixin",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("directory reader must not extract a live key")
        ),
    )

    reader = wechat_db.WeChatDBReader(
        data_root=tmp_path,
        account_id="account",
        allow_live_key_extract=False,
    )

    assert reader.initialize() is True
    assert reader.enc_keys == {}


def test_wechat_reader_loads_cache_for_selected_account(monkeypatch, tmp_path):
    """A reader must never try another account's scoped key first."""
    from chatlog_keeper import wechat_db

    account_dir = tmp_path / "wxid_selected"
    message_db = account_dir / "db_storage" / "message" / "message_0.db"
    message_db.parent.mkdir(parents=True)
    message_db.write_bytes(b"fixture")
    selected_key = b"\x44" * 32
    seen = []

    monkeypatch.setattr(wechat_db, "find_wxid_dirs", lambda _root: [account_dir])
    monkeypatch.setattr(wechat_db, "find_msg_databases", lambda _root: [message_db])
    monkeypatch.setattr(
        wechat_db,
        "load_cached_wechat_key_for_account",
        lambda account_id: seen.append(account_id) or selected_key,
        raising=False,
    )
    monkeypatch.setattr(wechat_db, "_read_stable_page1", lambda _path: b"page")
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda key, page: key == selected_key and page == b"page",
    )

    reader = wechat_db.WeChatDBReader(
        data_root=tmp_path,
        account_id="wxid_selected",
        allow_live_key_extract=False,
    )

    assert reader.initialize() is True
    assert seen == ["wxid_selected"]
    assert reader.enc_keys == {message_db: selected_key}


def test_wechat_contact_directory_respects_no_live_extract(monkeypatch, tmp_path):
    """Contact labels cannot re-enter live extraction after reader init skipped it."""
    from types import SimpleNamespace

    from chatlog_keeper import wechat_contacts, wechat_db

    contact_db = tmp_path / "db_storage" / "contact" / "contact.db"
    contact_db.parent.mkdir(parents=True)
    contact_db.write_bytes(b"fixture")
    reader = SimpleNamespace(
        wxid_dir=tmp_path,
        _allow_live_key_extract=False,
    )
    monkeypatch.setattr(wechat_db, "load_cached_wechat_key", lambda: None)
    monkeypatch.setattr(
        wechat_db,
        "_get_weixin_pids",
        lambda: (_ for _ in ()).throw(
            AssertionError("contact directory must not inspect running processes")
        ),
    )
    monkeypatch.setattr(
        wechat_db,
        "extract_key_from_weixin",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("contact directory must not extract a live key")
        ),
    )

    resolver = wechat_contacts.WeChatContactResolver(reader)

    assert resolver._extract_contact_key() is None


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
    monkeypatch.setattr(qq_db, "load_cached_key_for_account", lambda _account: None)

    r = cli._probe_qq()
    assert r["source"] == "qq"
    assert r["available"] is False
    assert r["client_running"] is True
    assert r["needs_key"] is True
    assert r["account"] == 10001


def test_probe_qq_requires_cached_key_to_unlock_active_database(monkeypatch):
    from chatlog_keeper import cli, qq_db

    db = Path("X:/fake/nt_msg.db")
    monkeypatch.setattr(
        qq_db.QQDBReader,
        "initialize",
        lambda self: (_ for _ in ()).throw(AssertionError("no scan in probe")),
    )
    monkeypatch.setattr(qq_db, "_get_qq_pids", lambda: [777])
    monkeypatch.setattr(qq_db, "find_qq_data_root", lambda: Path("X:/fake/Tencent Files"))
    monkeypatch.setattr(qq_db, "find_msg_database", lambda _root: db)
    monkeypatch.setattr(qq_db, "detect_current_qq_account", lambda: 10001)
    monkeypatch.setattr(
        qq_db,
        "load_cached_key_for_account",
        lambda _account: b"cached-key-value",
    )
    monkeypatch.setattr(
        qq_db,
        "_read_qq_verification_bytes",
        lambda path: b"page" if path == db else None,
    )
    monkeypatch.setattr(
        qq_db,
        "_verify_key_qq",
        lambda key, page: key == b"cached-key-value" and page == b"page",
    )

    ready = cli._probe_qq()
    assert ready["available"] is True
    assert ready["key_present"] is True
    assert ready["needs_key"] is False

    monkeypatch.setattr(qq_db, "_verify_key_qq", lambda _key, _page: False)
    stale = cli._probe_qq()
    assert stale["available"] is False
    assert stale["key_present"] is False
    assert stale["needs_key"] is True


def test_probe_qq_accepts_a_readable_non_active_account(monkeypatch):
    from chatlog_keeper import cli, qq_db

    active_db = Path("X:/fake/active/nt_msg.db")
    readable_db = Path("X:/fake/readable/nt_msg.db")
    monkeypatch.setattr(
        qq_db.QQDBReader,
        "initialize",
        lambda self: (_ for _ in ()).throw(AssertionError("no scan in probe")),
    )
    monkeypatch.setattr(qq_db, "_get_qq_pids", lambda: [777])
    monkeypatch.setattr(qq_db, "find_qq_data_root", lambda: Path("X:/fake/Tencent Files"))
    monkeypatch.setattr(qq_db, "find_msg_database", lambda _root: active_db)
    monkeypatch.setattr(
        qq_db,
        "find_qq_account_databases",
        lambda _root: {"10001": readable_db, "10002": active_db},
    )
    monkeypatch.setattr(qq_db, "detect_current_qq_account", lambda: 10002)
    monkeypatch.setattr(
        qq_db,
        "load_cached_key_for_account",
        lambda account: b"readable-key-value" if account == "10001" else b"stale-key-value!!",
    )
    monkeypatch.setattr(
        qq_db,
        "_read_qq_verification_bytes",
        lambda path: b"readable-page" if path == readable_db else b"active-page",
    )
    monkeypatch.setattr(
        qq_db,
        "_verify_key_qq",
        lambda key, page: key == b"readable-key-value" and page == b"readable-page",
    )

    result = cli._probe_qq()

    assert result["available"] is True
    assert result["key_present"] is True
    assert result["needs_key"] is False
    assert result["account"] == "10001"
    assert result["db_path"] == str(readable_db)


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

    def fake_scan(pid, db_path=None, timeout_s=None, account_id=None):
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
