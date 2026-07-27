"""Unit tests for active_key parsing / version-selection logic.

Pure logic only — no QQ/WeChat client, no debugger, no admin rights — so these
run anywhere (CI included). The debugger run itself can't be unit-tested without
a live client; what we lock down here is everything around it: how a key line is
recognized, how the newest install is chosen, and that the scripts are bundled.
"""
from chatlog_keeper import macos_debug_app, macos_key, qq_db, wechat_db
from chatlog_keeper import active_key as ak


# ── QQ key-line validation ────────────────────────────────────────────────────

def test_validate_qq_accepts_16_and_32():
    assert ak._validate_qq("ABCDEFGHIJKLMNOP") == "ABCDEFGHIJKLMNOP"      # 16
    assert ak._validate_qq("Ab3!Xy9@Qw5#Zk1$") == "Ab3!Xy9@Qw5#Zk1$"      # 16, mixed ASCII
    assert ak._validate_qq("A" * 32) == "A" * 32                          # 32


def test_validate_qq_rejects_bad_length():
    assert ak._validate_qq("tooshort") is None
    assert ak._validate_qq("") is None
    assert ak._validate_qq("A" * 20) is None


def test_validate_qq_stops_at_non_ascii():
    # only the leading printable-ASCII run counts; a NUL terminator ends it
    assert ak._validate_qq("ABCDEFGHIJKLMNOP\x00trailing") == "ABCDEFGHIJKLMNOP"


# ── WeChat key-line validation ────────────────────────────────────────────────

def test_validate_wechat_accepts_64_hex_lowercased():
    h = "AB" * 32  # 64 hex chars, uppercase
    assert ak._validate_wechat(h) == h.lower()


def test_validate_wechat_rejects_bad():
    assert ak._validate_wechat("abc") is None        # too short
    assert ak._validate_wechat("zz" * 32) is None    # not hex
    assert ak._validate_wechat("ab" * 31) is None    # 62 chars


# ── transcript parsing ────────────────────────────────────────────────────────

def test_parse_key_qq_marker():
    transcript = "\n".join([
        "some log line",
        "加密密钥:      ABCDEFGHIJKLMNOP",
        "more log",
    ])
    assert ak._parse_key(transcript, ak._QQ_MARKERS, ak._validate_qq) == "ABCDEFGHIJKLMNOP"


def test_parse_key_wechat_marker():
    h = "ab" * 32
    transcript = f"master key: {h}\n(verified locally)"
    assert ak._parse_key(transcript, ak._WX_MARKERS, ak._validate_wechat) == h


def test_parse_key_none_when_absent():
    assert ak._parse_key("nothing here", ak._QQ_MARKERS, ak._validate_qq) is None


# ── version selection (the multi-version auto-detect fix) ─────────────────────

def test_version_key_orders_qq_builds():
    assert ak._version_key("9.9.31-49738") > ak._version_key("9.9.28-46928")
    # an upgrade-leftover mixed dir sorts BELOW the clean newest build
    assert ak._version_key("9.9.28-46928-9.9.31-49738") < ak._version_key("9.9.31-49738")


def test_version_key_handles_nonnumeric():
    assert ak._version_key("foo") == (0,)


# ── bundled scripts present (so `extract-key --method active` works) ──────────

def test_debugger_scripts_are_bundled():
    qq = ak.qq_key_script()
    wx = ak.wechat_key_script()
    assert qq is not None and qq.exists()
    assert wx is not None and wx.exists()
    assert qq.name == "windows_ntqq_get_key.ps1"
    assert wx.name == "windows_wechat_get_key.ps1"


def test_macos_wechat_does_not_fallback_to_sip_protected_daily_app(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    called = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source: None,
    )
    monkeypatch.setattr(
        macos_key,
        "extract_verified",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) is None
    assert called == []


def test_macos_wechat_rechecks_page1_after_scan(monkeypatch, tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))
    pages = iter((b"A" * 4096, b"B" * 4096, b"C" * 4096, b"C" * 4096))
    scans = []
    rechecks = iter((False, True))

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source: 42,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: next(pages),
    )
    monkeypatch.setattr(
        macos_key,
        "extract_verified",
        lambda *args, **kwargs: scans.append(args[1]) or key,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: next(rechecks),
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) == key
    assert scans == [42, 42]


def test_macos_qq_rechecks_oracle_after_scan_and_retries(
    monkeypatch, tmp_path
):
    db = tmp_path / "nt_msg.db"
    db.write_bytes(b"x" * 5120)
    key = b"0123456789abcdef"
    pages = iter((b"A" * 5120, b"B" * 5120, b"C" * 5120, b"C" * 5120))
    scans = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source: 42,
    )
    monkeypatch.setattr(
        qq_db,
        "_read_qq_verification_bytes",
        lambda path: next(pages),
    )
    monkeypatch.setattr(
        macos_key,
        "extract_verified",
        lambda *args, **kwargs: scans.append(args[1]) or key,
    )
    monkeypatch.setattr(
        qq_db,
        "_verify_key_qq",
        lambda candidate, page: page == b"C" * 5120,
    )

    assert ak.extract_qq_key_active(db_path=str(db), timeout=1) == key
    assert scans == [42, 42]
