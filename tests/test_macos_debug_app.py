import os
import plistlib
import shutil
from pathlib import Path

from chatlog_keeper import macos_debug_app, macos_wechat_capture


def test_prepare_debug_copy_is_macos_only(monkeypatch):
    monkeypatch.setattr(macos_debug_app.sys, "platform", "win32")
    assert macos_debug_app.prepare_debug_copy("wechat") is None


def test_launch_debug_copy_returns_exact_copy_pid(monkeypatch, tmp_path):
    app = tmp_path / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(macos_debug_app, "_ACTIVE_DEBUG_PROCESSES", {})

    def fake_run(argv, **kwargs):
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "", "stderr": ""},
        )()

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)
    exact_calls = {"count": 0}

    def exact_pids(path):
        if path != executable:
            return []
        exact_calls["count"] += 1
        return [] if exact_calls["count"] == 1 else [314]

    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", exact_pids)
    monkeypatch.setattr(
        macos_debug_app,
        "_kernel_process_identity",
        lambda pid: (os.fsencode(executable), 100, 200),
    )
    monkeypatch.setattr(macos_debug_app, "_same_user_process", lambda pid: True)
    assert macos_debug_app.launch_debug_copy("wechat", wait_s=0) == 314
    assert macos_debug_app.validate_debug_copy_process("wechat", 314) is True
    assert macos_debug_app.last_error() == ""
    token = macos_debug_app._ACTIVE_DEBUG_PROCESSES.pop(("wechat", 314))
    macos_debug_app._release_launch_lock(token.lock_file)


def test_wechat_capture_is_passed_to_private_launch_before_target(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "WeChat.app"
    app = tmp_path / "private" / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    capture_library = tmp_path / "capture.dylib"
    capture_fifo = tmp_path / "capture.fifo"
    library_identity = (33, 44)
    fifo_identity = (11, 22)
    token = macos_debug_app._DebugProcessToken(
        "wechat", 314, executable, os.fsencode(executable), 100, 200
    )
    launches = []
    fifo_validations = []

    monkeypatch.setitem(
        macos_debug_app._APPS,
        "wechat",
        (original, "WeChat"),
    )
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(
        macos_debug_app,
        "_runtime_library_validation_compatible",
        lambda target, main: True,
    )
    monkeypatch.setattr(macos_debug_app, "_acquire_launch_lock", lambda *args: object())
    monkeypatch.setattr(macos_debug_app, "_release_launch_lock", lambda handle: None)
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: ())
    monkeypatch.setattr(
        macos_debug_app,
        "_wait_for_stable_pid",
        lambda *args, **kwargs: (token, True, (token,)),
    )
    monkeypatch.setattr(macos_debug_app, "_process_matches", lambda candidate: True)
    monkeypatch.setattr(macos_debug_app, "_ACTIVE_DEBUG_PROCESSES", {})
    monkeypatch.setattr(
        macos_wechat_capture,
        "validate_launch_capture_library",
        lambda path, *, expected_identity: (
            path == capture_library and expected_identity == library_identity
        ),
    )

    def validate_fifo(path, *, expected_identity=None):
        fifo_validations.append((path, expected_identity))
        return path == capture_fifo and expected_identity == fifo_identity

    monkeypatch.setattr(
        macos_wechat_capture,
        "validate_capture_fifo",
        validate_fifo,
    )

    def run(argv, **kwargs):
        if argv[:2] == ["/usr/bin/open", "-n"]:
            launches.append(argv)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(macos_debug_app, "_run", run)

    assert macos_debug_app.launch_debug_copy(
        "wechat",
        capture_library=capture_library,
        capture_library_identity=library_identity,
        capture_fifo=capture_fifo,
        capture_fifo_identity=fifo_identity,
    ) == 314
    assert launches == [[
        "/usr/bin/open",
        "-n",
        "--env",
        f"DYLD_INSERT_LIBRARIES={capture_library}",
        "--env",
        f"CHATLOG_KEEPER_WECHAT_KEY_FIFO={capture_fifo}",
        str(app),
    ]]
    assert fifo_validations == [
        (capture_fifo, fifo_identity),
        (capture_fifo, fifo_identity),
    ]


def test_capture_launch_requires_complete_fixed_configuration(monkeypatch, tmp_path):
    prepared = []
    launched = []
    monkeypatch.setattr(
        macos_debug_app,
        "prepare_debug_copy",
        lambda source: prepared.append(source),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: launched.append((args, kwargs)),
    )

    assert macos_debug_app.launch_debug_copy(
        "wechat",
        capture_library=tmp_path / "capture.dylib",
    ) is None
    assert macos_debug_app.last_error() == "capture_launch_configuration_invalid"
    assert prepared == []
    assert launched == []


def test_capture_launch_revalidates_fifo_generation_immediately_before_open(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "WeChat.app"
    app = tmp_path / "private" / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    capture_library = tmp_path / "capture.dylib"
    capture_fifo = tmp_path / "capture.fifo"
    validations = {"fifo": 0}
    launched = []

    monkeypatch.setitem(
        macos_debug_app._APPS,
        "wechat",
        (original, "WeChat"),
    )
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(
        macos_debug_app,
        "_runtime_library_validation_compatible",
        lambda target, main: True,
    )
    monkeypatch.setattr(macos_debug_app, "_acquire_launch_lock", lambda *args: object())
    monkeypatch.setattr(macos_debug_app, "_release_launch_lock", lambda handle: None)
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: ())
    monkeypatch.setattr(
        macos_wechat_capture,
        "validate_launch_capture_library",
        lambda path, *, expected_identity: True,
    )

    def validate_fifo(path, *, expected_identity=None):
        validations["fifo"] += 1
        return validations["fifo"] == 1

    monkeypatch.setattr(
        macos_wechat_capture,
        "validate_capture_fifo",
        validate_fifo,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: launched.append((args, kwargs)),
    )

    assert macos_debug_app.launch_debug_copy(
        "wechat",
        capture_library=capture_library,
        capture_library_identity=(3, 4),
        capture_fifo=capture_fifo,
        capture_fifo_identity=(1, 2),
    ) is None
    assert macos_debug_app.last_error() == "capture_launch_configuration_invalid"
    assert validations["fifo"] == 2
    assert launched == []


def test_launch_debug_copy_wechat_returns_without_settle_delay(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "WeChat.app"
    app = tmp_path / "private" / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    token = macos_debug_app._DebugProcessToken(
        "wechat", 314, executable, os.fsencode(executable), 100, 200
    )
    wait_args = {}

    monkeypatch.setitem(
        macos_debug_app._APPS,
        "wechat",
        (original, "WeChat"),
    )
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(
        macos_debug_app,
        "_runtime_library_validation_compatible",
        lambda target, main: True,
    )
    monkeypatch.setattr(macos_debug_app, "_acquire_launch_lock", lambda *args: object())
    monkeypatch.setattr(macos_debug_app, "_release_launch_lock", lambda handle: None)
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: ())
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 0})(),
    )

    def wait_for_pid(source, target, *, wait_s, settle_s):
        wait_args.update(wait_s=wait_s, settle_s=settle_s)
        return token, True, (token,)

    monkeypatch.setattr(macos_debug_app, "_wait_for_stable_pid", wait_for_pid)
    monkeypatch.setattr(macos_debug_app, "_process_matches", lambda candidate: True)
    monkeypatch.setattr(macos_debug_app, "_ACTIVE_DEBUG_PROCESSES", {})

    assert macos_debug_app.launch_debug_copy("wechat") == 314
    assert wait_args == {"wait_s": 15.0, "settle_s": 0.0}


def test_launch_debug_copy_qq_keeps_requested_settle_delay(monkeypatch, tmp_path):
    original = tmp_path / "Applications" / "QQ.app"
    app = tmp_path / "private" / "QQ.app"
    executable = app / "Contents" / "MacOS" / "QQ"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    token = macos_debug_app._DebugProcessToken(
        "qq", 2718, executable, os.fsencode(executable), 100, 200
    )
    wait_args = {}

    monkeypatch.setitem(macos_debug_app._APPS, "qq", (original, "QQ"))
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(
        macos_debug_app,
        "_runtime_library_validation_compatible",
        lambda target, main: True,
    )
    monkeypatch.setattr(macos_debug_app, "_acquire_launch_lock", lambda *args: object())
    monkeypatch.setattr(macos_debug_app, "_release_launch_lock", lambda handle: None)
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: ())
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 0})(),
    )

    def wait_for_pid(source, target, *, wait_s, settle_s):
        wait_args.update(wait_s=wait_s, settle_s=settle_s)
        return token, True, (token,)

    monkeypatch.setattr(macos_debug_app, "_wait_for_stable_pid", wait_for_pid)
    monkeypatch.setattr(macos_debug_app, "_process_matches", lambda candidate: True)
    monkeypatch.setattr(macos_debug_app, "_ACTIVE_DEBUG_PROCESSES", {})

    assert macos_debug_app.launch_debug_copy("qq", settle_s=2.75) == 2718
    assert wait_args == {"wait_s": 15.0, "settle_s": 2.75}


def test_generation_for_pid_rejects_process_owned_by_another_user(
    monkeypatch, tmp_path
):
    executable = tmp_path / "WeChat.app" / "Contents" / "MacOS" / "WeChat"
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: (314,))
    monkeypatch.setattr(
        macos_debug_app,
        "_kernel_process_identity",
        lambda pid: (os.fsencode(executable), 100, 200),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_same_user_process",
        lambda pid: False,
        raising=False,
    )

    assert (
        macos_debug_app._generation_for_pid("wechat", executable, 314)
        is None
    )


def test_same_user_process_accepts_only_one_matching_effective_uid(monkeypatch):
    monkeypatch.setattr(
        macos_debug_app.os,
        "geteuid",
        lambda: 501,
        raising=False,
    )

    def result(stdout, returncode=0):
        return type(
            "Result",
            (),
            {"returncode": returncode, "stdout": stdout, "stderr": ""},
        )()

    monkeypatch.setattr(macos_debug_app, "_run", lambda *args, **kwargs: result("501\n"))
    assert macos_debug_app._same_user_process(314) is True

    monkeypatch.setattr(macos_debug_app, "_run", lambda *args, **kwargs: result("502\n"))
    assert macos_debug_app._same_user_process(314) is False

    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: result("501\n501\n"),
    )
    assert macos_debug_app._same_user_process(314) is False

    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: result("", returncode=1),
    )
    assert macos_debug_app._same_user_process(314) is False

    monkeypatch.setattr(
        macos_debug_app.os,
        "geteuid",
        lambda: None,
        raising=False,
    )
    assert macos_debug_app._same_user_process(314) is False


def test_launch_debug_copy_rejects_running_daily_wechat_before_prepare(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "WeChat.app"
    daily_executable = original / "Contents" / "MacOS" / "WeChat"
    prepared = []
    launched = []

    monkeypatch.setitem(
        macos_debug_app._APPS,
        "wechat",
        (original, "WeChat"),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "prepare_debug_copy",
        lambda source: prepared.append(source),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: launched.append((args, kwargs)),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_exact_process_pids",
        lambda path: [2718] if path == daily_executable else [],
    )

    assert macos_debug_app.launch_debug_copy("wechat", wait_s=0) is None
    assert macos_debug_app.last_error() == "daily_client_single_instance_conflict"
    assert prepared == []
    assert launched == []


def test_launch_debug_copy_fails_closed_when_enumeration_is_unavailable(
    monkeypatch
):
    prepared = []
    launched = []
    monkeypatch.setattr(
        macos_debug_app,
        "prepare_debug_copy",
        lambda source: prepared.append(source),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: launched.append((args, kwargs)),
    )
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: None)

    assert macos_debug_app.launch_debug_copy("wechat", wait_s=0) is None
    assert macos_debug_app.last_error() == "process_enumeration_failed"
    assert prepared == []
    assert launched == []


def test_launch_debug_copy_rejects_ephemeral_pid(monkeypatch, tmp_path):
    app = tmp_path / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 0})(),
    )
    states = iter(([], [314], [], [], []))
    monkeypatch.setattr(
        macos_debug_app,
        "_exact_process_pids",
        lambda path: next(states, []) if path == executable else [],
    )
    clock = {"now": 0.0}

    def monotonic():
        clock["now"] += 0.25
        return clock["now"]

    monkeypatch.setattr(macos_debug_app.time, "monotonic", monotonic)
    monkeypatch.setattr(macos_debug_app.time, "sleep", lambda seconds: None)

    assert macos_debug_app.launch_debug_copy(
        "wechat", wait_s=1.0, settle_s=0.5
    ) is None
    assert macos_debug_app.last_error() == "debug_copy_ephemeral_exit"


def test_launch_debug_copy_distinguishes_launch_failure(monkeypatch, tmp_path):
    app = tmp_path / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    entitlement_xml = plistlib.dumps({}, fmt=plistlib.FMT_XML).decode("utf-8")

    def failed_copy(argv, **kwargs):
        if argv[:3] == ["codesign", "-d", "--entitlements"]:
            return type(
                "Result",
                (),
                {"returncode": 0, "stdout": entitlement_xml, "stderr": ""},
            )()
        return type(
            "Result",
            (),
            {"returncode": 1, "stdout": "", "stderr": ""},
        )()

    monkeypatch.setattr(macos_debug_app, "_run", failed_copy)
    monkeypatch.setattr(
        macos_debug_app,
        "_runtime_library_validation_compatible",
        lambda app, main: True,
    )
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: ())

    assert macos_debug_app.launch_debug_copy("wechat", wait_s=0) is None
    assert macos_debug_app.last_error() == "debug_copy_launch_failed"


def test_runtime_library_validation_preflight_rejects_mismatched_team_ids(
    monkeypatch, tmp_path
):
    app = tmp_path / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    dependency = (
        app
        / "Contents"
        / "Frameworks"
        / "WCDYWrapper.framework"
        / "Versions"
        / "A"
        / "WCDYWrapper"
    )
    executable.parent.mkdir(parents=True)
    dependency.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    dependency.write_bytes(b"framework")

    def fake_run(argv, **kwargs):
        if argv[:2] == ["otool", "-L"]:
            return type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": (
                        f"{executable}:\n"
                        "\t@rpath/WCDYWrapper.framework/Versions/A/"
                        "WCDYWrapper (compatibility version 0.0.0, "
                        "current version 0.0.0)\n"
                    ),
                    "stderr": "",
                },
            )()
        if argv[:3] == ["codesign", "-d", "--entitlements"]:
            return type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": plistlib.dumps({}, fmt=plistlib.FMT_XML).decode(),
                    "stderr": "",
                },
            )()
        team = "not set" if Path(argv[-1]) == executable else "5A4RE8SF68"
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "",
                "stderr": (
                    "CodeDirectory v=20500 flags=0x10002(adhoc,runtime)\n"
                    f"TeamIdentifier={team}\n"
                ),
            },
        )()

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)

    assert (
        macos_debug_app._runtime_library_validation_compatible(app, executable)
        is False
    )


def test_runtime_library_validation_preflight_marks_unresolved_rpath_unverifiable(
    monkeypatch, tmp_path
):
    app = tmp_path / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    def fake_run(argv, **kwargs):
        if argv[:2] == ["otool", "-L"]:
            stdout = (
                f"{executable}:\n"
                "\t@rpath/Missing.framework/Versions/A/Missing "
                "(compatibility version 0.0.0, current version 0.0.0)\n"
            )
            stderr = ""
        else:
            stdout = ""
            stderr = "CodeDirectory v=20500 flags=0x10002(adhoc,runtime)\n"
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
        )()

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)

    assert (
        macos_debug_app._runtime_library_validation_compatible(app, executable)
        is None
    )


def test_embedded_dependency_parser_canonicalizes_system_prefix_before_trust(
    monkeypatch, tmp_path
):
    app = tmp_path / "Client.app"
    executable = app / "Contents" / "MacOS" / "Client"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda argv, **kwargs: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": (
                    f"{executable}:\n"
                    "\t/usr/lib/../../tmp/external.dylib "
                    "(compatibility version 0.0.0, current version 0.0.0)\n"
                ),
                "stderr": "",
            },
        )(),
    )

    assert (
        macos_debug_app._direct_embedded_dependencies(app, executable)
        is None
    )


def test_runtime_library_validation_preflight_accepts_matching_team_ids(
    monkeypatch, tmp_path
):
    app = tmp_path / "Client.app"
    executable = app / "Contents" / "MacOS" / "Client"
    dependency = app / "Contents" / "Frameworks" / "ClientCore.dylib"
    executable.parent.mkdir(parents=True)
    dependency.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    dependency.write_bytes(b"library")

    def fake_run(argv, **kwargs):
        if argv[:2] == ["otool", "-L"]:
            stdout = (
                f"{executable}:\n"
                "\t@rpath/ClientCore.dylib (compatibility version 0.0.0, "
                "current version 0.0.0)\n"
            )
        elif argv[:3] == ["codesign", "-d", "--entitlements"]:
            stdout = plistlib.dumps({}, fmt=plistlib.FMT_XML).decode()
        else:
            stdout = ""
        stderr = (
            "CodeDirectory v=20500 flags=0x10002(adhoc,runtime)\n"
            "TeamIdentifier=LOCALTEAM1\n"
            if not stdout
            else ""
        )
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
        )()

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)

    assert (
        macos_debug_app._runtime_library_validation_compatible(app, executable)
        is True
    )


def test_runtime_library_validation_is_not_applied_without_hardened_runtime(
    monkeypatch, tmp_path
):
    app = tmp_path / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "",
                "stderr": "CodeDirectory v=20500 flags=0x2(adhoc)\n",
            },
        )()

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)

    assert (
        macos_debug_app._runtime_library_validation_compatible(app, executable)
        is True
    )
    assert not any(argv[:2] == ["otool", "-L"] for argv in calls)


def test_non_runtime_library_preflight_rejects_invalid_bundle_signature(
    monkeypatch, tmp_path
):
    app = tmp_path / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")

    def fake_run(argv, **kwargs):
        returncode = 1 if argv[:2] == ["codesign", "--verify"] else 0
        return type(
            "Result",
            (),
            {
                "returncode": returncode,
                "stdout": "",
                "stderr": "CodeDirectory v=20500 flags=0x2(adhoc)\n",
            },
        )()

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)

    assert (
        macos_debug_app._runtime_library_validation_compatible(app, executable)
        is None
    )


def test_launch_debug_copy_stops_before_open_on_library_validation_mismatch(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "WeChat.app"
    daily_executable = original / "Contents" / "MacOS" / "WeChat"
    app = tmp_path / "private" / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    launched = []

    monkeypatch.setitem(
        macos_debug_app._APPS,
        "wechat",
        (original, "WeChat"),
    )
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(
        macos_debug_app,
        "_runtime_library_validation_compatible",
        lambda target, main: False,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_exact_process_pids",
        lambda path: [] if path == daily_executable else [],
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: launched.append((args, kwargs)),
    )

    assert macos_debug_app.launch_debug_copy("wechat", wait_s=0) is None
    assert (
        macos_debug_app.last_error()
        == "debug_copy_library_validation_incompatible"
    )
    assert launched == []


def test_launch_debug_copy_stops_before_open_when_library_validation_unverifiable(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "WeChat.app"
    daily_executable = original / "Contents" / "MacOS" / "WeChat"
    app = tmp_path / "private" / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    launched = []

    monkeypatch.setitem(
        macos_debug_app._APPS,
        "wechat",
        (original, "WeChat"),
    )
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(
        macos_debug_app,
        "_runtime_library_validation_compatible",
        lambda target, main: None,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_exact_process_pids",
        lambda path: [] if path == daily_executable else [],
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: launched.append((args, kwargs)),
    )

    assert macos_debug_app.launch_debug_copy("wechat", wait_s=0) is None
    assert (
        macos_debug_app.last_error()
        == "debug_copy_library_validation_unverifiable"
    )
    assert launched == []


def test_launch_debug_copy_rejects_unowned_existing_copy(
    monkeypatch, tmp_path
):
    app = tmp_path / "WeChat.app"
    executable = app / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    launched = []
    monkeypatch.setattr(macos_debug_app, "prepare_debug_copy", lambda source: app)
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: launched.append((args, kwargs)),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_runtime_library_validation_compatible",
        lambda target, main: True,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_exact_process_pids",
        lambda path: [314] if path == executable else [],
    )

    assert macos_debug_app.launch_debug_copy("wechat", wait_s=0) is None
    assert macos_debug_app.last_error() == "debug_copy_already_running"
    assert launched == []


def test_failed_debug_copy_leaves_no_partial_canonical_app(monkeypatch, tmp_path):
    original = tmp_path / "Applications" / "WeChat.app"
    info = original / "Contents" / "Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleExecutable": "WeChat"}))
    executable = original / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    private_root = tmp_path / "private"
    monkeypatch.setattr(macos_debug_app.sys, "platform", "darwin")
    monkeypatch.setitem(macos_debug_app._APPS, "wechat", (original, "WeChat"))
    monkeypatch.setattr(macos_debug_app, "data_dir", lambda: private_root)
    entitlement_xml = plistlib.dumps({}, fmt=plistlib.FMT_XML).decode("utf-8")

    def failed_copy(argv, **kwargs):
        if argv[:3] == ["codesign", "-d", "--entitlements"]:
            return type(
                "Result",
                (),
                {"returncode": 0, "stdout": entitlement_xml, "stderr": ""},
            )()
        return type(
            "Result",
            (),
            {"returncode": 1, "stdout": "", "stderr": ""},
        )()

    monkeypatch.setattr(macos_debug_app, "_run", failed_copy)

    assert macos_debug_app.prepare_debug_copy("wechat") is None
    debug_root = private_root / "debug-apps"
    assert debug_root.is_dir()
    assert list(debug_root.iterdir()) == []


def test_prepare_debug_copy_does_not_deep_resign_nested_helpers(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "QQ.app"
    info = original / "Contents" / "Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleExecutable": "QQ"}))
    executable = original / "Contents" / "MacOS" / "QQ"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    private_root = tmp_path / "private"
    signing_calls = []
    entitlement_xml = plistlib.dumps(
        {"com.apple.security.get-task-allow": True},
        fmt=plistlib.FMT_XML,
    ).decode("utf-8")

    monkeypatch.setattr(macos_debug_app.sys, "platform", "darwin")
    monkeypatch.setitem(macos_debug_app._APPS, "qq", (original, "QQ"))
    monkeypatch.setattr(macos_debug_app, "data_dir", lambda: private_root)

    def fake_run(argv, timeout=300):
        if argv[0] == "/usr/bin/ditto":
            shutil.copytree(argv[1], argv[2])
        if argv[0] == "codesign" and "--force" in argv:
            signing_calls.append(argv)
        stdout = entitlement_xml if argv[:3] == [
            "codesign", "-d", "--entitlements"
        ] else ""
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

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)

    target = macos_debug_app.prepare_debug_copy("qq")
    assert target is not None
    assert len(signing_calls) == 1
    assert "--deep" not in signing_calls[0]
    assert "--entitlements" in signing_calls[0]
    assert signing_calls[0][signing_calls[0].index("--options") + 1] == "runtime"


def test_prepare_wechat_debug_copy_uses_upstream_compatibility_signature(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "WeChat.app"
    info = original / "Contents" / "Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleExecutable": "WeChat"}))
    executable = original / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    private_root = tmp_path / "private"
    signing_calls = []
    entitlement_xml = plistlib.dumps(
        {"com.apple.security.get-task-allow": True},
        fmt=plistlib.FMT_XML,
    ).decode("utf-8")

    monkeypatch.setattr(macos_debug_app.sys, "platform", "darwin")
    monkeypatch.setitem(
        macos_debug_app._APPS, "wechat", (original, "WeChat")
    )
    monkeypatch.setattr(macos_debug_app, "data_dir", lambda: private_root)

    def fake_run(argv, timeout=300):
        if argv[0] == "/usr/bin/ditto":
            shutil.copytree(argv[1], argv[2])
        if argv[0] == "codesign" and "--force" in argv:
            signing_calls.append(argv)
        stdout = entitlement_xml if argv[:3] == [
            "codesign", "-d", "--entitlements"
        ] else ""
        stderr = (
            "CodeDirectory v=20500 flags=0x2(adhoc)\n"
            "TeamIdentifier=not set\n"
            if "--verbose=4" in argv
            else ""
        )
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
        )()

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)

    target = macos_debug_app.prepare_debug_copy("wechat")
    assert target is not None
    assert len(signing_calls) == 1
    assert "--deep" not in signing_calls[0]
    assert "--options" not in signing_calls[0]
    assert "--entitlements" in signing_calls[0]


def test_prepare_debug_copy_accepts_only_verified_concurrent_winner(
    monkeypatch, tmp_path
):
    original = tmp_path / "Applications" / "QQ.app"
    info = original / "Contents" / "Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleExecutable": "QQ"}))
    executable = original / "Contents" / "MacOS" / "QQ"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"main")
    private_root = tmp_path / "private"
    entitlement_xml = plistlib.dumps(
        {"com.apple.security.get-task-allow": True},
        fmt=plistlib.FMT_XML,
    ).decode("utf-8")

    monkeypatch.setattr(macos_debug_app.sys, "platform", "darwin")
    monkeypatch.setitem(macos_debug_app._APPS, "qq", (original, "QQ"))
    monkeypatch.setattr(macos_debug_app, "data_dir", lambda: private_root)

    def fake_run(argv, timeout=300):
        if argv[0] == "/usr/bin/ditto":
            shutil.copytree(argv[1], argv[2])
        stdout = entitlement_xml if argv[:3] == [
            "codesign", "-d", "--entitlements"
        ] else ""
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

    original_replace = Path.replace

    def concurrent_replace(stage, target):
        # Simulate another process publishing the same fully-verified staged
        # directory before this process reaches rename(2).  macOS commonly
        # reports the losing directory rename as a generic OSError.
        shutil.copytree(stage, target)
        raise OSError("directory rename race")

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)
    monkeypatch.setattr(Path, "replace", concurrent_replace)
    try:
        target = macos_debug_app.prepare_debug_copy("qq")
    finally:
        monkeypatch.setattr(Path, "replace", original_replace)
    assert target is not None
    assert (
        target / "Contents" / "Resources" / ".chatlog-keeper-debug-copy"
    ).is_file()


def test_ad_hoc_resigned_debug_cache_is_rebuilt_from_installed_bundle(
    monkeypatch,
    tmp_path,
):
    original = tmp_path / "Applications" / "WeChat.app"
    info = original / "Contents" / "Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleExecutable": "WeChat"}))
    executable = original / "Contents" / "MacOS" / "WeChat"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"trusted-main")
    resource = original / "Contents" / "Resources" / "trusted.dat"
    resource.parent.mkdir(parents=True)
    resource.write_bytes(b"trusted-resource")
    private_root = tmp_path / "private"
    signing_calls = []
    entitlement_xml = plistlib.dumps(
        {"com.apple.security.get-task-allow": True},
        fmt=plistlib.FMT_XML,
    ).decode("utf-8")

    def fake_run(argv, timeout=300):
        if argv[0] == "/usr/bin/ditto":
            shutil.copytree(argv[1], argv[2])
        if argv[0] == "codesign" and "--force" in argv:
            signing_calls.append(argv)
        stdout = (
            entitlement_xml
            if argv[:3] == ["codesign", "-d", "--entitlements"]
            else ""
        )
        stderr = (
            "CodeDirectory v=20500 flags=0x2(adhoc)\n"
            "TeamIdentifier=not set\n"
            if "--verbose=4" in argv
            else ""
        )
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": stderr},
        )()

    monkeypatch.setattr(macos_debug_app.sys, "platform", "darwin")
    monkeypatch.setitem(
        macos_debug_app._APPS,
        "wechat",
        (original, "WeChat"),
    )
    monkeypatch.setattr(macos_debug_app, "data_dir", lambda: private_root)
    monkeypatch.setattr(macos_debug_app, "_run", fake_run)
    monkeypatch.setattr(macos_debug_app, "_TRUSTED_DEBUG_COPIES", {})

    target = macos_debug_app.prepare_debug_copy("wechat")
    assert target is not None
    cached_executable = target / "Contents" / "MacOS" / "WeChat"
    cached_executable.write_bytes(b"attacker-main")
    (target / "Contents" / "Resources" / "injected.py").write_text(
        "malicious",
        encoding="utf-8",
    )
    # Simulate a fresh process with no trusted in-memory inode receipt.
    monkeypatch.setattr(macos_debug_app, "_TRUSTED_DEBUG_COPIES", {})

    rebuilt = macos_debug_app.prepare_debug_copy("wechat")
    assert rebuilt == target
    assert cached_executable.read_bytes() == b"trusted-main"
    assert not (target / "Contents" / "Resources" / "injected.py").exists()
    assert len(signing_calls) == 2


def test_verified_debug_copy_rejects_non_ad_hoc_team_id(
    monkeypatch,
    tmp_path,
):
    target = tmp_path / "WeChat.app"
    marker = target / "Contents" / "Resources" / ".chatlog-keeper-debug-copy"
    marker.parent.mkdir(parents=True)
    marker.write_text("expected", encoding="ascii")
    monkeypatch.setattr(
        macos_debug_app,
        "_entitlements",
        lambda app: {"com.apple.security.get-task-allow": True},
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "",
                "stderr": (
                    "CodeDirectory v=20500 flags=0x2(adhoc)\n"
                    "TeamIdentifier=ATTACKER1\n"
                ),
            },
        )(),
    )

    assert not macos_debug_app._verified_debug_copy(
        target,
        marker,
        "expected",
        {"com.apple.security.get-task-allow": True},
        hardened_runtime=False,
    )


def test_debug_copy_identity_changes_with_main_executable(tmp_path):
    first = tmp_path / "first.app"
    second = tmp_path / "second.app"
    for app, content in ((first, b"build-one"), (second, b"build-two")):
        info = app / "Contents" / "Info.plist"
        info.parent.mkdir(parents=True)
        info.write_bytes(plistlib.dumps({"CFBundleExecutable": "QQ"}))
        executable = app / "Contents" / "MacOS" / "QQ"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(content)
    assert macos_debug_app._app_identity(first) != macos_debug_app._app_identity(
        second
    )


def test_verified_debug_copy_rejects_wrong_marker_content(
    monkeypatch, tmp_path
):
    target = tmp_path / "QQ.app"
    marker = (
        target
        / "Contents"
        / "Resources"
        / ".chatlog-keeper-debug-copy"
    )
    marker.parent.mkdir(parents=True)
    marker.write_text("wrong", encoding="ascii")
    monkeypatch.setattr(
        macos_debug_app,
        "_entitlements",
        lambda app: {"com.apple.security.get-task-allow": True},
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type(
            "Result", (), {"returncode": 0, "stdout": "", "stderr": ""}
        )(),
    )
    assert (
            macos_debug_app._verified_debug_copy(
                target,
                marker,
                "expected",
                {"com.apple.security.get-task-allow": True},
            )
        is False
    )


def test_verified_debug_copy_rejects_missing_hardened_runtime(
    monkeypatch, tmp_path
):
    target = tmp_path / "QQ.app"
    marker = target / "Contents" / "Resources" / ".chatlog-keeper-debug-copy"
    marker.parent.mkdir(parents=True)
    marker.write_text("expected", encoding="ascii")
    monkeypatch.setattr(
        macos_debug_app,
        "_entitlements",
        lambda app: {"com.apple.security.get-task-allow": True},
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type(
            "Result", (), {"returncode": 0, "stdout": "", "stderr": ""}
        )(),
    )

    assert (
        macos_debug_app._verified_debug_copy(
            target,
            marker,
            "expected",
            {"com.apple.security.get-task-allow": True},
        )
        is False
    )


def test_verified_wechat_compatibility_copy_requires_runtime_to_be_absent(
    monkeypatch, tmp_path
):
    target = tmp_path / "WeChat.app"
    marker = target / "Contents" / "Resources" / ".chatlog-keeper-debug-copy"
    marker.parent.mkdir(parents=True)
    marker.write_text("expected", encoding="ascii")
    monkeypatch.setattr(
        macos_debug_app,
        "_entitlements",
        lambda app: {"com.apple.security.get-task-allow": True},
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "",
                    "stderr": (
                        "CodeDirectory v=20500 flags=0x2(adhoc)\n"
                        "TeamIdentifier=not set\n"
                    ),
            },
        )(),
    )

    assert macos_debug_app._verified_debug_copy(
        target,
        marker,
        "expected",
        {"com.apple.security.get-task-allow": True},
        hardened_runtime=False,
    )


def test_verified_debug_copy_rejects_extra_entitlement(
    monkeypatch, tmp_path
):
    target = tmp_path / "QQ.app"
    marker = target / "Contents" / "Resources" / ".chatlog-keeper-debug-copy"
    marker.parent.mkdir(parents=True)
    marker.write_text("expected", encoding="ascii")
    monkeypatch.setattr(
        macos_debug_app,
        "_entitlements",
        lambda app: {
            "com.apple.security.get-task-allow": True,
            "unexpected": True,
        },
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "",
                "stderr": (
                    "CodeDirectory v=20500 "
                    "flags=0x10002(adhoc,runtime)"
                ),
            },
        )(),
    )

    assert (
        macos_debug_app._verified_debug_copy(
            target,
            marker,
            "expected",
            {"com.apple.security.get-task-allow": True},
        )
        is False
    )


def test_runtime_flag_parser_rejects_runtime_word_in_path_only(
    monkeypatch, tmp_path
):
    target = tmp_path / "runtime-copy.app"
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": "",
                "stderr": (
                    f"Executable={target}\n"
                    "CodeDirectory v=20500 flags=0x2(adhoc)"
                ),
            },
        )(),
    )

    assert macos_debug_app._has_hardened_runtime(target) is False


def test_terminate_debug_copy_fails_if_replacement_at_exact_path_remains(
    monkeypatch, tmp_path
):
    executable = tmp_path / "WeChat.app" / "Contents" / "MacOS" / "WeChat"
    token = macos_debug_app._DebugProcessToken(
        "wechat", 42, executable, os.fsencode(executable), 100, 200
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_ACTIVE_DEBUG_PROCESSES",
        {("wechat", 42): token},
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_kernel_process_identity",
        lambda pid: (os.fsencode(executable), 100, 201),
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_exact_process_pids",
        lambda path: [42],
    )
    signals = []
    monkeypatch.setattr(
        macos_debug_app.os,
        "kill",
        lambda pid, sig: signals.append((pid, sig)),
    )

    assert macos_debug_app.terminate_debug_copy("wechat", 42) is False
    assert macos_debug_app.last_error() == "debug_copy_cleanup_failed"
    assert signals == []
    assert macos_debug_app._ACTIVE_DEBUG_PROCESSES == {}


def test_terminate_debug_copy_confirms_exit_after_sigkill(
    monkeypatch, tmp_path
):
    executable = tmp_path / "WeChat.app" / "Contents" / "MacOS" / "WeChat"
    token = macos_debug_app._DebugProcessToken(
        "wechat", 42, executable, os.fsencode(executable), 100, 200
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_ACTIVE_DEBUG_PROCESSES",
        {("wechat", 42): token},
    )
    states = iter(("same", "same", "same", "replaced"))
    monkeypatch.setattr(
        macos_debug_app,
        "_generation_state",
        lambda candidate: next(states, "replaced"),
    )
    ticks = iter((0.0, 0.0, 0.1, 0.2, 0.3))
    monkeypatch.setattr(
        macos_debug_app.time,
        "monotonic",
        lambda: next(ticks, 1.0),
    )
    monkeypatch.setattr(macos_debug_app.time, "sleep", lambda seconds: None)
    signals = []
    monkeypatch.setattr(
        macos_debug_app.os,
        "kill",
        lambda pid, sig: signals.append((pid, sig)),
    )
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: ())

    assert macos_debug_app.terminate_debug_copy(
        "wechat", 42, wait_s=0
    ) is True
    assert signals == [
        (42, macos_debug_app.signal.SIGTERM),
        (42, macos_debug_app.signal.SIGKILL),
    ]


def test_terminate_debug_copy_fails_closed_when_enumeration_is_unavailable(
    monkeypatch, tmp_path
):
    executable = tmp_path / "WeChat.app" / "Contents" / "MacOS" / "WeChat"
    token = macos_debug_app._DebugProcessToken(
        "wechat", 42, executable, os.fsencode(executable), 100, 200
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_ACTIVE_DEBUG_PROCESSES",
        {("wechat", 42): token},
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_generation_state",
        lambda candidate: "gone",
    )
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: None)

    assert macos_debug_app.terminate_debug_copy("wechat", 42) is False
    assert macos_debug_app.last_error() == "debug_copy_cleanup_failed"


def test_generation_state_treats_enumeration_failure_as_unknown(
    monkeypatch, tmp_path
):
    executable = tmp_path / "WeChat.app" / "Contents" / "MacOS" / "WeChat"
    token = macos_debug_app._DebugProcessToken(
        "wechat", 42, executable, os.fsencode(executable), 100, 200
    )
    identities = []
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda path: None)
    monkeypatch.setattr(
        macos_debug_app,
        "_kernel_process_identity",
        lambda pid: identities.append(pid),
    )

    assert macos_debug_app._generation_state(token) == "unknown"
    assert identities == []


def test_terminate_debug_copy_fails_closed_when_generation_is_unknown(
    monkeypatch, tmp_path
):
    executable = tmp_path / "WeChat.app" / "Contents" / "MacOS" / "WeChat"
    token = macos_debug_app._DebugProcessToken(
        "wechat", 42, executable, os.fsencode(executable), 100, 200
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_ACTIVE_DEBUG_PROCESSES",
        {("wechat", 42): token},
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_generation_state",
        lambda candidate: "unknown",
    )
    signals = []
    monkeypatch.setattr(
        macos_debug_app.os,
        "kill",
        lambda pid, sig: signals.append((pid, sig)),
    )

    assert macos_debug_app.terminate_debug_copy("wechat", 42) is False
    assert macos_debug_app.last_error() == "debug_copy_cleanup_failed"
    assert signals == []
