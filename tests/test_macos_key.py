import plistlib
import subprocess
import sys
from pathlib import Path

import pytest

from chatlog_keeper import macos_key


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS key-helper tests require Darwin ownership and code-signing semantics",
)


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
        "_run_helper_candidates",
        lambda *args, **kwargs: macos_key._rank_candidates(
            transcript, "QQ", (16, 32)
        ),
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
        "_run_helper_candidates",
        lambda *args, **kwargs: [noise, target],
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
        "_run_helper_candidates",
        lambda *args, **kwargs: [secret],
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
        "_run_helper_candidates",
        lambda *args, **kwargs: [b"\x11" * 32, b"\x22" * 32],
    )
    assert macos_key.extract_verified(
        "wechat", 42, lambda key: key == b"\x22" * 32
    ) == b"\x22" * 32
    assert macos_key.extract_verified("wechat", 42, lambda key: False) is None


def test_privileged_helper_is_disabled_without_launching_subprocess(
    monkeypatch, tmp_path
):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)
    assert macos_key._run_helper("wechat", 42, elevate=True, timeout=10) == ""
    assert macos_key.last_error() == "privileged_helper_disabled"
    assert seen == []


def test_macos_key_module_contains_no_privileged_launcher():
    source = Path(macos_key.__file__).read_text(encoding="utf-8")
    assert "osascript" not in source
    assert "administrator privileges" not in source


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


def test_process_identity_timeout_is_reported_without_traceback(
    monkeypatch, tmp_path
):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout", 1))

    monkeypatch.setattr(macos_key.subprocess, "run", timeout)
    assert macos_key._run_helper("wechat", 42, elevate=False, timeout=1) == ""
    assert macos_key.last_error() == "process_identity_timeout"


def test_helper_nonzero_exit_discards_candidate_stdout(
    monkeypatch, tmp_path
):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    class FailedProcess:
        stdout = iter(["QQ:" + (b"A" * 16).hex() + "\n"])
        stderr = iter(["scan_failed\n"])

        def wait(self, timeout=None):
            return 7

        def terminate(self):
            return None

        def kill(self):
            return None

    monkeypatch.setattr(
        macos_key.subprocess,
        "Popen",
        lambda *args, **kwargs: FailedProcess(),
    )
    assert macos_key._run_helper(
        "qq",
        42,
        elevate=False,
        timeout=10,
        expected_identity=(b"/tmp/target", 1, 2),
    ) == ""
    assert macos_key.last_error() == "helper_exit_7"
    assert macos_key._run_helper("qq", 42, elevate=True, timeout=10) == ""
    assert macos_key.last_error() == "privileged_helper_disabled"


def test_streaming_candidates_are_ranked_without_retaining_transcript(
    monkeypatch, tmp_path
):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    frequent = b"F" * 16
    rare = b"R" * 16

    class SuccessfulProcess:
        def __init__(self):
            self.stdout = iter(
                [
                    f"QQ:{rare.hex()}\n",
                    f"QQ:{frequent.hex()}\n",
                    f"QQ:{frequent.hex()}\n",
                ]
            )
            self.stderr = iter(())

        def wait(self, timeout=None):
            return 0

        def terminate(self):
            return None

        def kill(self):
            return None

    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    monkeypatch.setattr(
        macos_key.subprocess,
        "Popen",
        lambda *args, **kwargs: SuccessfulProcess(),
    )

    assert macos_key._run_helper_candidates(
        "qq",
        42,
        elevate=False,
        timeout=10,
        expected_identity=(b"/tmp/target", 1, 2),
    ) == [frequent, rare]


def test_streaming_candidate_limit_terminates_and_discards_output(
    monkeypatch, tmp_path
):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    terminated = []

    class ExcessProcess:
        def __init__(self):
            self.stdout = iter(
                [
                    "WX:" + ("11" * 32) + "\n",
                    "WX:" + ("22" * 32) + "\n",
                ]
            )
            self.stderr = iter(())

        def wait(self, timeout=None):
            return 0

        def terminate(self):
            terminated.append(True)

        def kill(self):
            return None

    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    monkeypatch.setattr(macos_key, "_MAX_CANDIDATE_LINES", 1)
    monkeypatch.setattr(
        macos_key.subprocess,
        "Popen",
        lambda *args, **kwargs: ExcessProcess(),
    )

    assert macos_key._run_helper_candidates(
        "wechat",
        42,
        elevate=False,
        timeout=10,
        expected_identity=(b"/tmp/target", 1, 2),
    ) == []
    assert terminated
    assert macos_key.last_error() == "candidate_output_limit_exceeded"


def test_streaming_timeout_kills_and_reaps_helper(monkeypatch, tmp_path):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    state = {"waits": 0, "killed": False}

    class TimedOutProcess:
        stdout = iter(())
        stderr = iter(())

        def wait(self, timeout=None):
            state["waits"] += 1
            if state["waits"] == 1:
                raise subprocess.TimeoutExpired("scanner", timeout)
            return -9

        def terminate(self):
            return None

        def kill(self):
            state["killed"] = True

    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    monkeypatch.setattr(
        macos_key.subprocess,
        "Popen",
        lambda *args, **kwargs: TimedOutProcess(),
    )

    assert macos_key._run_helper_candidates(
        "wechat",
        42,
        elevate=False,
        timeout=1,
        expected_identity=(b"/tmp/target", 1, 2),
    ) == []
    assert state == {"waits": 2, "killed": True}
    assert macos_key.last_error() == "helper_timeout"


def test_streaming_timeout_keeps_identity_checked_partial_candidate(
    monkeypatch, tmp_path
):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    key = bytes(range(32))
    expected_identity = (b"/tmp/target", 1, 2)
    state = {"waits": 0, "killed": False}

    class TimedOutProcess:
        stdout = iter((f"WX:{key.hex()}\n",))
        stderr = iter(())

        def wait(self, timeout=None):
            state["waits"] += 1
            if state["waits"] == 1:
                raise subprocess.TimeoutExpired("scanner", timeout)
            return -9

        def terminate(self):
            return None

        def kill(self):
            state["killed"] = True

    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    monkeypatch.setattr(
        macos_key.subprocess,
        "Popen",
        lambda *args, **kwargs: TimedOutProcess(),
    )
    monkeypatch.setattr(
        macos_key,
        "process_identity",
        lambda pid, **kwargs: expected_identity,
    )

    assert macos_key._run_helper_candidates(
        "wechat",
        42,
        elevate=False,
        timeout=1,
        expected_identity=expected_identity,
    ) == [key]
    assert state == {"waits": 2, "killed": True}
    assert macos_key.last_error() == ""


def test_streaming_timeout_discards_partial_candidate_when_identity_changes(
    monkeypatch, tmp_path
):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    key = bytes(range(32))
    expected_identity = (b"/tmp/target", 1, 2)
    state = {"waits": 0}

    class TimedOutProcess:
        stdout = iter((f"WX:{key.hex()}\n",))
        stderr = iter(())

        def wait(self, timeout=None):
            state["waits"] += 1
            if state["waits"] == 1:
                raise subprocess.TimeoutExpired("scanner", timeout)
            return -9

        def terminate(self):
            return None

        def kill(self):
            return None

    monkeypatch.setattr(macos_key, "ensure_helper", lambda: helper)
    monkeypatch.setattr(
        macos_key.subprocess,
        "Popen",
        lambda *args, **kwargs: TimedOutProcess(),
    )
    monkeypatch.setattr(
        macos_key,
        "process_identity",
        lambda pid, **kwargs: (b"/tmp/replaced", 3, 4),
    )

    assert macos_key._run_helper_candidates(
        "wechat",
        42,
        elevate=False,
        timeout=1,
        expected_identity=expected_identity,
    ) == []
    assert macos_key.last_error() == "process_identity_mismatch"


def test_process_identity_parser_keeps_path_internal(monkeypatch, tmp_path):
    helper = tmp_path / "scanner"
    helper.write_text("", encoding="utf-8")
    expected_path = b"/tmp/isolated-client"
    monkeypatch.setattr(
        macos_key.subprocess,
        "run",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": f"IDENTITY:100:200:{expected_path.hex()}\n",
                "stderr": "",
            },
        )(),
    )

    assert macos_key.process_identity(42, helper=helper) == (
        expected_path,
        100,
        200,
    )


def test_mach_helper_enforces_kernel_path_and_start_generation():
    source = macos_key._source_path().read_text(encoding="utf-8")
    assert "proc_pidpath" in source
    assert "PROC_PIDTBSDINFO" in source
    assert source.count("identity_matches(pid, &expected)") >= 3
    assert source.index("identity_matches(pid, &expected)") < source.index(
        "task_for_pid"
    )


def test_runtime_flag_parser_rejects_path_only_runtime_word(
    monkeypatch, tmp_path
):
    binary = tmp_path / "runtime-helper"
    monkeypatch.setattr(
        macos_key.subprocess,
        "run",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "",
                "stderr": (
                    f"Executable={binary}\n"
                    "CodeDirectory v=20500 flags=0x2(adhoc)"
                ),
            },
        )(),
    )

    assert macos_key._has_hardened_runtime(binary) is False


def test_helper_entitlement_verifier_rejects_extra_entitlements(
    monkeypatch, tmp_path
):
    helper = tmp_path / "macos-memory-scan"
    entitlement_xml = plistlib.dumps(
        {
            "com.apple.security.cs.debugger": True,
            "com.apple.security.cs.disable-library-validation": True,
        },
        fmt=plistlib.FMT_XML,
    ).decode("utf-8")

    def fake_run(argv, **kwargs):
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": entitlement_xml if "--entitlements" in argv else "",
                "stderr": "",
            },
        )()

    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)
    monkeypatch.setattr(macos_key, "_has_hardened_runtime", lambda path: True)

    assert macos_key._has_debugger_entitlement(helper) is False


def test_prebuilt_helper_avoids_runtime_compiler(monkeypatch, tmp_path):
    prebuilt = tmp_path / "bundle" / "macos_memory_scan"
    prebuilt.parent.mkdir()
    prebuilt.write_bytes(b"prebuilt-mach-helper")
    data_root = tmp_path / "data"
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        stdout = _debugger_entitlements_xml() if "--entitlements" in argv and "-d" in argv else ""
        stderr = (
            "CodeDirectory v=20500 flags=0x10002(adhoc,runtime)\n"
            "TeamIdentifier=not set\n"
            if "--verbose=4" in argv
            else ""
        )
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
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
    assert signing_calls[0][signing_calls[0].index("--options") + 1] == "runtime"


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

    def fake_run(argv, **kwargs):
        calls.append(argv)
        stdout = (
            _debugger_entitlements_xml()
            if "--entitlements" in argv and "-d" in argv
            else ""
        )
        stderr = (
            "CodeDirectory v=20500 flags=0x10002(adhoc,runtime)\n"
            "TeamIdentifier=not set\n"
            if "--verbose=4" in argv
            else ""
        )
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
        )()

    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)
    rebuilt = macos_key.ensure_helper()
    assert rebuilt == helper
    assert rebuilt.read_bytes() == b"new-prebuilt-mach-helper"
    assert any(argv[0] == "codesign" and "--force" in argv for argv in calls)


def test_ad_hoc_resigned_cached_helper_is_rebuilt_from_trusted_input(
    monkeypatch, tmp_path
):
    prebuilt = tmp_path / "bundle" / "macos_memory_scan"
    prebuilt.parent.mkdir()
    prebuilt.write_bytes(b"trusted-prebuilt-helper")
    data_root = tmp_path / "data"
    signing_calls = []

    def fake_run(argv, **kwargs):
        if argv[0] == "codesign" and "--force" in argv:
            signing_calls.append(argv)
        stdout = (
            _debugger_entitlements_xml()
            if "--entitlements" in argv and "-d" in argv
            else ""
        )
        stderr = (
            "CodeDirectory v=20500 flags=0x10002(adhoc,runtime)\n"
            "TeamIdentifier=not set\n"
            if "--verbose=4" in argv
            else ""
        )
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
        )()

    monkeypatch.setattr(macos_key.sys, "platform", "darwin")
    monkeypatch.setattr(macos_key, "_prebuilt_path", lambda: prebuilt)
    monkeypatch.setattr(macos_key, "data_dir", lambda: data_root)
    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)
    monkeypatch.setattr(macos_key, "_TRUSTED_HELPER", None)

    helper = macos_key.ensure_helper()
    assert helper is not None
    first_identity = helper.lstat().st_ino
    helper.unlink()
    helper.write_bytes(b"attacker-helper-with-valid-ad-hoc-signature")
    helper.chmod(0o700)
    monkeypatch.setattr(macos_key, "_TRUSTED_HELPER", None)

    rebuilt = macos_key.ensure_helper()
    assert rebuilt == helper
    assert rebuilt.read_bytes() == b"trusted-prebuilt-helper"
    assert rebuilt.lstat().st_ino != first_identity
    assert len(signing_calls) == 2


def test_helper_build_rejects_non_ad_hoc_team_id(monkeypatch, tmp_path):
    prebuilt = tmp_path / "bundle" / "macos_memory_scan"
    prebuilt.parent.mkdir()
    prebuilt.write_bytes(b"prebuilt-mach-helper")
    data_root = tmp_path / "data"

    def fake_run(argv, **kwargs):
        stdout = (
            _debugger_entitlements_xml()
            if "--entitlements" in argv and "-d" in argv
            else ""
        )
        stderr = (
            "CodeDirectory v=20500 flags=0x10000(runtime)\n"
            "TeamIdentifier=ATTACKER1\n"
            if "--verbose=4" in argv
            else ""
        )
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
        )()

    monkeypatch.setattr(macos_key.sys, "platform", "darwin")
    monkeypatch.setattr(macos_key, "_prebuilt_path", lambda: prebuilt)
    monkeypatch.setattr(macos_key, "data_dir", lambda: data_root)
    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)
    monkeypatch.setattr(macos_key, "_TRUSTED_HELPER", None)

    assert macos_key.ensure_helper() is None
    assert macos_key.last_error() == "helper_signature_validation_failed"


def test_helper_permission_tamper_is_rebuilt(monkeypatch, tmp_path):
    prebuilt = tmp_path / "bundle" / "macos_memory_scan"
    prebuilt.parent.mkdir()
    prebuilt.write_bytes(b"prebuilt-mach-helper")
    data_root = tmp_path / "data"
    signing_calls = []

    def fake_run(argv, **kwargs):
        if argv[0] == "codesign" and "--force" in argv:
            signing_calls.append(argv)
        stdout = (
            _debugger_entitlements_xml()
            if "--entitlements" in argv and "-d" in argv
            else ""
        )
        stderr = (
            "CodeDirectory v=20500 flags=0x10002(adhoc,runtime)\n"
            "TeamIdentifier=not set\n"
            if "--verbose=4" in argv
            else ""
        )
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
        )()

    monkeypatch.setattr(macos_key.sys, "platform", "darwin")
    monkeypatch.setattr(macos_key, "_prebuilt_path", lambda: prebuilt)
    monkeypatch.setattr(macos_key, "data_dir", lambda: data_root)
    monkeypatch.setattr(macos_key.subprocess, "run", fake_run)
    monkeypatch.setattr(macos_key, "_TRUSTED_HELPER", None)

    helper = macos_key.ensure_helper()
    assert helper is not None
    first_identity = helper.lstat().st_ino
    helper.chmod(0o755)

    rebuilt = macos_key.ensure_helper()
    assert rebuilt == helper
    assert (rebuilt.stat().st_mode & 0o777) == 0o700
    assert rebuilt.lstat().st_ino != first_identity
    assert len(signing_calls) == 2
