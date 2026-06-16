"""Unit tests for active_key parsing / version-selection logic.

Pure logic only — no QQ/WeChat client, no debugger, no admin rights — so these
run anywhere (CI included). The debugger run itself can't be unit-tested without
a live client; what we lock down here is everything around it: how a key line is
recognized, how the newest install is chosen, and that the scripts are bundled.
"""
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
