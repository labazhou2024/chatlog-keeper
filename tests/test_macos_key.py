import subprocess
import plistlib

from chatlog_keeper import macos_key


def _debugger_entitlements_xml():
    return plistlib.dumps(
        {"com.apple.security.cs.debugger": True},
        fmt=plistlib.FMT_XML,
    ).decode("utf-8")


def test_parse_candidates_deduplicates_and_rejects_noise():
    text = "QQ:31323334353637383930616263646566\nbad\nQQ:zz\nQQ:31323334353637383930616263646566"
    assert list(macos_key._parse_candidates(text, "QQ")) == [b"1234567890abcdef"]


def test_qq_candidates_rank_16_byte_frequency_before_legacy_32_byte():
    frequent = b"B" * 16
    rare = b"A" * 16
    legacy = b"C" * 32
    text = "\n".join(
        [
            "QQ:" + legacy.hex(),
            "QQ:" + rare.hex(),
            "QQ:" + frequent.hex(),
            "QQ:" + frequent.hex(),
            "QQ:" + frequent.hex(),
            "QQ:" + (b"bad-length").hex(),
        ]
    )
    assert macos_key._rank_candidates(text, "QQ", (16, 32)) == [
        frequent,
        rare,
        legacy,
    ]


def test_qq_primary_oracle_is_ranked_then_full_confirmed(monkeypatch):
    target = b"T" * 16
    noise = b"N" * 16
    transcript = "\n".join(
        [
            "QQ:" + noise.hex(),
            "QQ:" + target.hex(),
            "QQ:" + target.hex(),
            "QQ:" + target.hex(),
        ]
    )
    monkeypatch.setattr(
        macos_key,
        "_run_helper",
        lambda *args, **kwargs: transcript,
    )
    calls = []

    def primary(candidate):
        calls.append(("primary", candidate))
        return candidate == target

    def full(candidate):
        calls.append(("full", candidate))
        return candidate == target

    assert macos_key.extract_verified(
        "qq", 42, full, primary_verify=primary
    ) == target
    assert calls == [("primary", target), ("full", target)]


def test_qq_primary_miss_falls_back_to_full_oracle(monkeypatch):
    target = b"T" * 32
    noise = b"N" * 16
    monkeypatch.setattr(
        macos_key,
        "_run_helper",
        lambda *args, **kwargs: "\n".join(
            ["QQ:" + target.hex(), "QQ:" + noise.hex()]
        ),
    )
    primary_calls = []
    full_calls = []
    result = macos_key.extract_verified(
        "qq",
        42,
        lambda candidate: full_calls.append(candidate) is None
        and candidate == target,
        primary_verify=lambda candidate: primary_calls.append(candidate) is None
        and False,
    )
    assert result == target
    assert primary_calls == [noise, target]
    assert full_calls == [noise, target]


def test_candidate_values_are_never_written_to_output_or_logs(
    monkeypatch, capsys, caplog
):
    secret = b"do-not-log-this!"
    monkeypatch.setattr(
        macos_key,
        "_run_helper",
        lambda *args, **kwargs: "QQ:" + secret.hex(),
    )
    assert macos_key.extract_verified(
        "qq", 42, lambda candidate: candidate == secret
    ) == secret
    captured = capsys.readouterr()
    assert secret.decode() not in captured.out
    assert secret.decode() not in captured.err
    assert secret.decode() not in caplog.text


def test_extract_verified_never_returns_unverified(monkeypatch):
    monkeypatch.setattr(
        macos_key,
        "_run_helper",
        lambda *args, **kwargs: "WX:" + ("11" * 32) + "\nWX:" + ("22" * 32),
    )
    assert macos_key.extract_verified(
        "wechat", 42, lambda key: key == b"\x22" * 32
    ) == b"\x22" * 32
    assert macos_key.extract_verified("wechat", 42, lambda key: False) is None


def test_elevated_helper_uses_valid_applescript_string(monkeypatch, tmp_path):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)
    macos_key._run_helper("wechat", 42, elevate=True, timeout=10)
    assert seen["argv"][:2] == ["osascript", "-e"]
    assert seen["argv"][2].startswith('do shell script "')
    assert seen["argv"][2].endswith('" with administrator privileges')


def test_last_error_normalizes_access_and_cancel(monkeypatch):
    monkeypatch.setattr(macos_key, "_LAST_ERROR", "task_for_pid:5")
    assert macos_key.last_error() == "process_access_denied"
    monkeypatch.setattr(
        macos_key,
        "_LAST_ERROR",
        "0:157: execution error: task_for_pid:5 (3)",
    )
    assert macos_key.last_error() == "process_access_denied"
    monkeypatch.setattr(macos_key, "_LAST_ERROR", "execution error: User canceled. (-128)")
    assert macos_key.last_error() == "authorization_cancelled"
    monkeypatch.setattr(macos_key, "_LAST_ERROR", "execution error (-60007)")
    assert macos_key.last_error() == "authorization_interaction_unavailable"


def test_helper_timeout_is_reported_without_traceback(monkeypatch, tmp_path):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout", 1))

    monkeypatch.setattr(macos_key.subprocess, "run", timeout)
    assert macos_key._run_helper("wechat", 42, elevate=False, timeout=1) == ""
    assert macos_key.last_error() == "helper_timeout"


def test_helper_nonzero_exit_discards_candidate_stdout(
    monkeypatch, tmp_path
):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    candidate = "QQ:" + (b"A" * 16).hex()

    def failed(*args, **kwargs):
        return type(
            "Result",
            (),
            {"returncode": 7, "stdout": candidate, "stderr": "scan_failed"},
        )()

    monkeypatch.setattr(macos_key.subprocess, "run", failed)
    for elevate in (False, True):
        assert (
            macos_key._run_helper(
                "qq", 42, elevate=elevate, timeout=10
            )
            == ""
        )
        assert macos_key.last_error() == "scan_failed"


def test_prebuilt_helper_avoids_runtime_compiler(monkeypatch, tmp_path):
    prebuilt = tmp_path / "bundle" / "macos_memory_scan"
    prebuilt.parent.mkdir()
    prebuilt.write_bytes(b"prebuilt-mach-helper")
    data_root = tmp_path / "data"
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        stdout = _debugger_entitlements_xml() if "--entitlements" in argv and "-d" in argv else ""
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": ""},
        )()

    monkeypatch.setattr(macos_key.sys, "platform", "darwin")
    monkeypatch.setattr(macos_key, "_prebuilt_path", lambda: prebuilt)
    monkeypatch.setattr(macos_key, "data_dir", lambda: data_root)
    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)

    helper = macos_key.ensure_helper()
    assert helper is not None
    assert helper.read_bytes() == b"prebuilt-mach-helper"
    assert all(argv[0] != "xcrun" for argv in calls)
    signing_calls = [
        argv for argv in calls
        if argv[0] == "codesign" and "--force" in argv
    ]
    assert len(signing_calls) == 1
    assert "--entitlements" in signing_calls[0]


def test_existing_helper_without_debugger_entitlement_is_replaced(
    monkeypatch, tmp_path
):
    prebuilt = tmp_path / "bundle" / "macos_memory_scan"
    prebuilt.parent.mkdir()
    prebuilt.write_bytes(b"new-prebuilt-mach-helper")
    data_root = tmp_path / "data"
    calls = []

    monkeypatch.setattr(macos_key.sys, "platform", "darwin")
    monkeypatch.setattr(macos_key, "_prebuilt_path", lambda: prebuilt)
    monkeypatch.setattr(macos_key, "data_dir", lambda: data_root)

    helper = macos_key._helper_path()
    helper.parent.mkdir(parents=True)
    helper.write_bytes(b"stale-helper")
    helper.chmod(0o700)

    describe_count = 0

    def fake_run(argv, **kwargs):
        nonlocal describe_count
        calls.append(argv)
        stdout = ""
        if "--entitlements" in argv and "-d" in argv:
            describe_count += 1
            if describe_count >= 2:
                stdout = _debugger_entitlements_xml()
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": ""},
        )()

    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)
    rebuilt = macos_key.ensure_helper()
    assert rebuilt == helper
    assert rebuilt.read_bytes() == b"new-prebuilt-mach-helper"
    assert any(argv[0] == "codesign" and "--force" in argv for argv in calls)
