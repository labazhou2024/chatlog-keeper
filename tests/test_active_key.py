"""Unit tests for active_key parsing / version-selection logic.

Pure logic only — no QQ/WeChat client, no debugger, no admin rights — so these
run anywhere (CI included). The debugger run itself can't be unit-tested without
a live client; what we lock down here is everything around it: how a key line is
recognized, how the newest install is chosen, and that the scripts are bundled.
"""
import os
from pathlib import Path

import pytest

from chatlog_keeper import (
    macos_debug_app,
    macos_key,
    macos_wechat_capture,
    qq_db,
    wechat_db,
)
from chatlog_keeper import active_key as ak


class _EmptyCaptureChannel:
    def __init__(self, path: Path):
        self.path = path
        self.identity = (1, 2)
        self.library_path = path.with_suffix(".dylib")
        self.library_identity = (3, 4)
        self.invalid = False
        self.closed = False

    def read_candidates(self):
        return []

    def close(self):
        self.closed = True
        return True


@pytest.fixture(autouse=True)
def _stub_macos_helper_preflight(monkeypatch, tmp_path):
    """Keep active-flow tests pure while production prewarms both observers."""
    monkeypatch.setattr(
        macos_key,
        "ensure_helper",
        lambda: Path("/private/tmp/chatlog-keeper-test-helper"),
    )
    monkeypatch.setattr(
        macos_wechat_capture,
        "ensure_capture_library",
        lambda: Path("/private/tmp/chatlog-keeper-test-capture.dylib"),
    )
    monkeypatch.setattr(
        macos_wechat_capture,
        "create_capture_channel",
        lambda db_path, **kwargs: _EmptyCaptureChannel(tmp_path / "capture.fifo"),
    )


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


def test_privileged_script_discovery_ignores_environment_override(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("CHATLOG_KEEPER_SCRIPTS_DIR", str(tmp_path))
    assert ak._scripts_dir() != tmp_path
    assert ak.qq_key_script() is not None
    assert ak.wechat_key_script() is not None


@pytest.mark.parametrize("script_getter", (ak.qq_key_script, ak.wechat_key_script))
def test_bundled_active_scripts_match_pinned_content(script_getter, tmp_path):
    script = script_getter()
    assert script is not None
    assert ak._verified_script_digest(script) is not None

    tampered = tmp_path / script.name
    tampered.write_bytes(script.read_bytes() + b"\n# tampered")
    assert ak._verified_script_digest(tampered) is None


def test_active_bootstrap_verifies_once_then_executes_in_memory(tmp_path):
    script = ak.wechat_key_script()
    assert script is not None
    digest = ak._verified_script_digest(script)
    assert digest is not None
    bootstrap = ak._active_bootstrap(
        script=script,
        script_digest=digest,
        args=["-NoDebugForKey", "-DbPath", r"C:\private\message_0.db"],
        out_path=tmp_path / "result.txt",
    )

    assert bootstrap.index("ComputeHash") < bootstrap.index("ScriptBlock]::Create")
    assert bootstrap.index("-cne $expectedHash") < bootstrap.index("ScriptBlock]::Create")
    assert "& $scriptBlock @scriptArgs" in bootstrap
    assert r"C:\private\message_0.db" not in bootstrap


def test_windows_active_environment_drops_injection_overrides(monkeypatch):
    monkeypatch.setenv("PATH", r"C:\Windows\System32")
    monkeypatch.setenv("CHATLOG_KEEPER_SCRIPTS_DIR", r"C:\attacker")
    monkeypatch.setenv("CHATLOG_CALIBRATE_KEY", "ab" * 32)
    monkeypatch.setenv("PSModulePath", r"C:\attacker\modules")
    monkeypatch.setenv("PYTHONPATH", r"C:\attacker\python")

    env = ak._windows_active_environment()
    assert env["PATH"] == r"C:\Windows\System32"
    assert "CHATLOG_KEEPER_SCRIPTS_DIR" not in env
    assert "CHATLOG_CALIBRATE_KEY" not in env
    assert "PSModulePath" not in env
    assert "PYTHONPATH" not in env


def test_active_transcript_read_is_bounded_and_rejects_symlink(tmp_path):
    transcript = tmp_path / "result.txt"
    transcript.write_text("safe transcript", encoding="utf-8")
    assert ak._read_active_transcript(transcript) == "safe transcript"

    transcript.write_bytes(b"X" * (ak._MAX_ACTIVE_TRANSCRIPT_BYTES + 1))
    assert ak._read_active_transcript(transcript) == ""

    if hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"):
        target = tmp_path / "target.txt"
        target.write_text("must not follow", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        assert ak._read_active_transcript(link) == ""


def test_windows_scripts_pin_tencent_signatures_and_internal_timeout():
    qq = ak.qq_key_script()
    wx = ak.wechat_key_script()
    assert qq is not None and wx is not None
    qq_text = qq.read_text(encoding="utf-8-sig")
    wx_text = wx.read_text(encoding="utf-8-sig")

    for source in (qq_text, wx_text):
        assert "Get-AuthenticodeSignature" in source
        assert "SignerCertificate.Subject" in source
        assert "TimeoutSeconds" in source
        assert "DateTime.UtcNow" in source
    active_source = Path(ak.__file__).read_text(encoding="utf-8")
    assert "-Verb RunAs" not in active_source
    assert "DEBUG_PROCESS" in active_source


@pytest.mark.parametrize("verified", [True, False])
def test_windows_qq_transcript_key_is_rechecked_against_selected_database(
    monkeypatch,
    tmp_path,
    verified,
):
    database = tmp_path / "nt_msg.db"
    database.write_bytes(b"encrypted")
    candidate = "0123456789abcdef"
    monkeypatch.setattr(ak, "_is_macos_host", lambda: False)
    monkeypatch.setattr(ak, "_is_windows_host", lambda: True)
    monkeypatch.setattr(ak, "qq_key_script", lambda: tmp_path / "bundled.ps1")
    monkeypatch.setattr(
        ak,
        "_run_active",
        lambda *_args, **_kwargs: f"加密密钥: {candidate}",
    )
    monkeypatch.setattr(qq_db, "_read_qq_verification_bytes", lambda _path: b"page")
    monkeypatch.setattr(qq_db, "_verify_key_qq", lambda key, page: verified)

    result = ak.extract_qq_key_active(db_path=str(database), timeout=30)
    assert result == (candidate.encode("ascii") if verified else None)


@pytest.mark.parametrize(
    "extractor",
    (ak.extract_qq_key_active, ak.extract_wechat_key_active),
)
def test_macos_active_analyze_only_clears_stale_errors_without_launch(
    monkeypatch, extractor
):
    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(macos_debug_app, "_LAST_ERROR", "stale_debug_error")
    monkeypatch.setattr(macos_key, "_LAST_ERROR", "stale_key_error")
    monkeypatch.setattr(macos_key, "ensure_helper", lambda: None)
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: pytest.fail(f"analyze-only launched {source}"),
    )

    assert extractor(analyze_only=True, timeout=1) is None
    assert macos_debug_app.last_error() == ""
    assert macos_key.last_error() == ""


@pytest.mark.parametrize(
    "extractor",
    (ak.extract_qq_key_active, ak.extract_wechat_key_active),
)
def test_macos_active_missing_db_clears_stale_errors_without_launch(
    monkeypatch, tmp_path, extractor
):
    missing_db = tmp_path / "missing.db"
    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(macos_debug_app, "_LAST_ERROR", "stale_debug_error")
    monkeypatch.setattr(macos_key, "_LAST_ERROR", "stale_key_error")
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: pytest.fail(f"missing-DB attempt launched {source}"),
    )

    assert extractor(db_path=str(missing_db), timeout=1) is None
    assert macos_debug_app.last_error() == ""
    assert macos_key.last_error() == ""


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
        lambda source, **kwargs: None,
    )
    monkeypatch.setattr(
        macos_key,
        "extract_verified",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) is None
    assert called == []


def test_macos_wechat_prepares_scanner_before_launch(monkeypatch, tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    events = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_key,
        "ensure_helper",
        lambda: events.append("helper") or Path("/private/tmp/helper"),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: events.append(f"launch:{source}"),
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) is None
    assert events == ["helper", "launch:wechat"]


def test_macos_wechat_helper_preflight_failure_does_not_launch(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    launched = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(macos_key, "ensure_helper", lambda: None)
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: launched.append(source),
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) is None
    assert launched == []


def test_macos_wechat_accepts_startup_candidate_before_memory_scan(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))
    events = []
    launch_kwargs = {}

    class BufferedChannel(_EmptyCaptureChannel):
        def __init__(self, path):
            super().__init__(path)
            self.pending = [[key], []]

        def read_candidates(self):
            return self.pending.pop(0) if self.pending else []

        def close(self):
            events.append("channel-close")
            return super().close()

    channel = BufferedChannel(tmp_path / "capture.fifo")
    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_wechat_capture,
        "create_capture_channel",
        lambda db_path, **kwargs: channel,
    )

    def launch(source, **kwargs):
        launch_kwargs.update(kwargs)
        return 42

    monkeypatch.setattr(macos_debug_app, "launch_debug_copy", launch)
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: events.append("process-close") or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: candidate == key,
    )
    monkeypatch.setattr(
        macos_key,
        "extract_verified",
        lambda *args, **kwargs: pytest.fail("startup candidate fell back to scan"),
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=5) == key
    assert launch_kwargs == {
        "capture_library": channel.library_path,
        "capture_library_identity": channel.library_identity,
        "capture_fifo": channel.path,
        "capture_fifo_identity": channel.identity,
    }
    assert events == ["process-close", "channel-close"]


def test_macos_wechat_never_returns_unverified_startup_candidate(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    candidate = bytes(range(32))
    clock = {"now": 0.0}

    class BufferedChannel(_EmptyCaptureChannel):
        def __init__(self, path):
            super().__init__(path)
            self.first = True

        def read_candidates(self):
            if self.first:
                self.first = False
                return [candidate]
            return []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_wechat_capture,
        "create_capture_channel",
        lambda db_path, **kwargs: BufferedChannel(tmp_path / "capture.fifo"),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: 42,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(wechat_db, "_verify_key_v4", lambda key, page: False)
    monkeypatch.setattr(macos_key, "extract_verified", lambda *args, **kwargs: None)
    monkeypatch.setattr(ak.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(
        ak.time,
        "sleep",
        lambda seconds: clock.__setitem__("now", clock["now"] + seconds),
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) is None


def test_macos_wechat_fifo_cleanup_failure_rejects_captured_key(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))

    class UncleanChannel(_EmptyCaptureChannel):
        def read_candidates(self):
            return [key]

        def close(self):
            return False

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_wechat_capture,
        "create_capture_channel",
        lambda db_path, **kwargs: UncleanChannel(tmp_path / "capture.fifo"),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: 42,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: candidate == key,
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) is None


def test_macos_wechat_capture_verifier_exception_cleans_both_resources(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))
    events = []

    class BufferedChannel(_EmptyCaptureChannel):
        def read_candidates(self):
            return [key]

        def close(self):
            events.append("channel-close")
            return True

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_wechat_capture,
        "create_capture_channel",
        lambda db_path, **kwargs: BufferedChannel(tmp_path / "capture.fifo"),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: 42,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: events.append("process-close") or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: (_ for _ in ()).throw(RuntimeError("verify")),
    )

    with pytest.raises(RuntimeError, match="verify"):
        ak.extract_wechat_key_active(db_path=str(db), timeout=1)
    assert events == ["process-close", "channel-close"]


def test_macos_wechat_rechecks_page1_after_scan(monkeypatch, tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))
    pages = iter((b"A" * 4096, b"B" * 4096, b"C" * 4096, b"C" * 4096))
    scans = []
    scan_elevation = []
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: 42,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: next(pages),
    )
    def scan(*args, **kwargs):
        scans.append(args[1])
        scan_elevation.append(kwargs["elevate"])
        return key if args[2](key) else None

    monkeypatch.setattr(macos_key, "extract_verified", scan)
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: page[:1] != b"B",
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) == key
    assert scans == [42, 42]
    assert scan_elevation == [False, False]
    assert terminated == [("wechat", 42)]


def test_macos_wechat_checks_all_discovered_account_oracles_in_one_scan(
    monkeypatch, tmp_path
):
    root = tmp_path / "xwechat_files"
    first = root / "wxid_first_account" / "db_storage" / "message" / "message_0.db"
    matching = root / "wxid_matching_account" / "db_storage" / "message" / "message_0.db"
    for database in (first, matching):
        database.parent.mkdir(parents=True)
        database.write_bytes(b"x" * 4096)

    key = bytes(range(32))
    page_by_path = {
        first: b"A" * 4096,
        matching: b"B" * 4096,
    }
    page_reads = []
    checks = []
    scans = []
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app, "launch_debug_copy", lambda source, **kwargs: 42
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )

    def read_page(database):
        database = type(first)(database)
        page_reads.append(database)
        return page_by_path[database]

    def verify(candidate, page):
        checks.append(page[:1])
        return candidate == key and page[:1] == b"B"

    def scan(source, pid, verify_candidate, **kwargs):
        scans.append((source, pid, kwargs["elevate"]))
        return key if verify_candidate(key) else None

    monkeypatch.setattr(wechat_db, "_read_stable_page1", read_page)
    monkeypatch.setattr(wechat_db, "_verify_key_v4", verify)
    monkeypatch.setattr(macos_key, "extract_verified", scan)

    assert ak.extract_wechat_key_active(db_path=str(first), timeout=5) == key
    assert scans == [("wechat", 42, False)]
    assert checks == [b"A", b"B", b"B"]
    assert page_reads == [first, matching, matching]
    assert terminated == [("wechat", 42)]


def test_macos_wechat_oracle_discovery_is_bounded(monkeypatch, tmp_path):
    root = tmp_path / "xwechat_files"
    databases = []
    for index in range(3):
        database = (
            root
            / f"wxid_account_{index}"
            / "db_storage"
            / "message"
            / "message_0.db"
        )
        database.parent.mkdir(parents=True)
        database.write_bytes(b"x" * 4096)
        databases.append(database)

    monkeypatch.setattr(ak, "_MACOS_WECHAT_MAX_ORACLES", 2)

    assert ak._wechat_active_oracle_paths(databases[0], wechat_db) == databases[:2]


def test_macos_wechat_refreshes_oracles_created_during_login(
    monkeypatch, tmp_path
):
    root = tmp_path / "xwechat_files"
    first = root / "wxid_first_account" / "db_storage" / "message" / "message_0.db"
    matching = root / "wxid_new_account" / "db_storage" / "message" / "message_0.db"
    first.parent.mkdir(parents=True)
    first.write_bytes(b"x" * 4096)

    key = bytes(range(32))
    clock = {"now": 0.0}
    scans = []
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app, "launch_debug_copy", lambda source, **kwargs: 42
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda database: (
            b"B" * 4096 if type(first)(database) == matching else b"A" * 4096
        ),
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: candidate == key and page[:1] == b"B",
    )

    def scan(source, pid, verify_candidate, **kwargs):
        scans.append((source, pid))
        return key if verify_candidate(key) else None

    def sleep(seconds):
        matching.parent.mkdir(parents=True, exist_ok=True)
        matching.write_bytes(b"x" * 4096)
        clock["now"] += seconds

    monkeypatch.setattr(macos_key, "extract_verified", scan)
    monkeypatch.setattr(macos_key, "last_error", lambda: "")
    monkeypatch.setattr(ak.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(ak.time, "sleep", sleep)

    assert ak.extract_wechat_key_active(db_path=str(first), timeout=5) == key
    assert scans == [("wechat", 42), ("wechat", 42)]
    assert terminated == [("wechat", 42)]


def test_macos_wechat_waits_for_first_login_candidate(monkeypatch, tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))
    scans = iter((None, None, key))
    clock = {"now": 0.0}
    slept = []
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app, "launch_debug_copy", lambda source, **kwargs: 42
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: candidate == key,
    )
    def scan(*args, **kwargs):
        candidate = next(scans)
        if candidate is None:
            return None
        return candidate if args[2](candidate) else None

    monkeypatch.setattr(macos_key, "extract_verified", scan)
    monkeypatch.setattr(macos_key, "last_error", lambda: "")
    monkeypatch.setattr(ak.time, "monotonic", lambda: clock["now"])

    def sleep(seconds):
        slept.append(seconds)
        clock["now"] += seconds

    monkeypatch.setattr(ak.time, "sleep", sleep)

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=10) == key
    assert slept == [2.0, 2.0]
    assert terminated == [("wechat", 42)]


def test_macos_wechat_uses_timeout_as_polling_bound_and_cleans(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    clock = {"now": 0.0}
    scan_timeouts = []
    slept = []
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app, "launch_debug_copy", lambda source, **kwargs: 42
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )

    def scan(*args, **kwargs):
        scan_timeouts.append(kwargs["timeout"])
        return None

    monkeypatch.setattr(macos_key, "extract_verified", scan)
    monkeypatch.setattr(macos_key, "last_error", lambda: "")
    monkeypatch.setattr(ak.time, "monotonic", lambda: clock["now"])

    def sleep(seconds):
        slept.append(seconds)
        clock["now"] += seconds

    monkeypatch.setattr(ak.time, "sleep", sleep)

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=5) is None
    assert scan_timeouts == [5, 3, 1]
    assert slept == [2.0, 2.0, 1.0]
    assert clock["now"] == 5.0
    assert terminated == [("wechat", 42)]


def test_macos_wechat_retries_a_timed_out_scan_slice(monkeypatch, tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))
    clock = {"now": 0.0}
    scans = []
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app, "launch_debug_copy", lambda source, **kwargs: 42
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: candidate == key,
    )

    def scan(source, pid, verify_candidate, **kwargs):
        scans.append((source, pid))
        if len(scans) == 1:
            macos_key._LAST_ERROR = "helper_timeout"
            return None
        macos_key._LAST_ERROR = ""
        return key if verify_candidate(key) else None

    def sleep(seconds):
        clock["now"] += seconds

    monkeypatch.setattr(macos_key, "extract_verified", scan)
    monkeypatch.setattr(ak.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(ak.time, "sleep", sleep)

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=5) == key
    assert scans == [("wechat", 42), ("wechat", 42)]
    assert terminated == [("wechat", 42)]


def test_macos_wechat_terminates_debug_copy_when_scan_fails(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app, "launch_debug_copy", lambda source, **kwargs: 42
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(macos_key, "extract_verified", lambda *args, **kwargs: None)
    monkeypatch.setattr(macos_key, "last_error", lambda: "process_access_denied")

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) is None
    assert terminated == [("wechat", 42)]


def test_macos_wechat_cleanup_failure_rejects_verified_key(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app, "launch_debug_copy", lambda source, **kwargs: 42
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: False,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: True,
    )
    monkeypatch.setattr(
        macos_key,
        "extract_verified",
        lambda *args, **kwargs: key if args[2](key) else None,
    )

    assert ak.extract_wechat_key_active(db_path=str(db), timeout=1) is None


def test_macos_wechat_verifier_exception_still_cleans(
    monkeypatch, tmp_path
):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x" * 4096)
    key = bytes(range(32))
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app, "launch_debug_copy", lambda source, **kwargs: 42
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-wechat", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )
    monkeypatch.setattr(
        wechat_db,
        "_read_stable_page1",
        lambda path: b"A" * 4096,
    )
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, page: (_ for _ in ()).throw(RuntimeError("verify")),
    )
    monkeypatch.setattr(
        macos_key,
        "extract_verified",
        lambda *args, **kwargs: key if args[2](key) else None,
    )

    with pytest.raises(RuntimeError, match="verify"):
        ak.extract_wechat_key_active(db_path=str(db), timeout=1)
    assert terminated == [("wechat", 42)]


def test_macos_qq_rechecks_oracle_after_scan_and_retries(
    monkeypatch, tmp_path
):
    db = tmp_path / "nt_msg.db"
    db.write_bytes(b"x" * 5120)
    key = b"0123456789abcdef"
    pages = iter((b"A" * 5120, b"B" * 5120, b"C" * 5120, b"C" * 5120))
    scans = []
    scan_elevation = []
    terminated = []

    monkeypatch.setattr(ak.sys, "platform", "darwin")
    monkeypatch.setattr(
        macos_debug_app,
        "launch_debug_copy",
        lambda source, **kwargs: 42,
    )
    monkeypatch.setattr(
        qq_db,
        "_read_qq_verification_bytes",
        lambda path: next(pages),
    )
    monkeypatch.setattr(
        macos_key,
        "extract_verified",
        lambda *args, **kwargs: (
            scans.append(args[1]),
            scan_elevation.append(kwargs["elevate"]),
            key,
        )[-1],
    )
    monkeypatch.setattr(
        macos_debug_app,
        "validate_debug_copy_process",
        lambda source, pid: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "debug_copy_process_identity",
        lambda source, pid: (b"/tmp/isolated-qq", 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_debug_copy",
        lambda source, pid: terminated.append((source, pid)) or True,
    )
    monkeypatch.setattr(
        qq_db,
        "_verify_key_qq",
        lambda candidate, page: page == b"C" * 5120,
    )

    assert ak.extract_qq_key_active(db_path=str(db), timeout=1) == key
    assert scans == [42, 42]
    assert scan_elevation == [False, False]
    assert terminated == [("qq", 42)]
