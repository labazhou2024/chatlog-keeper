import plistlib
import shutil
from pathlib import Path

from chatlog_keeper import macos_debug_app


def test_prepare_debug_copy_is_macos_only(monkeypatch):
    monkeypatch.setattr(macos_debug_app.sys, "platform", "win32")
    assert macos_debug_app.prepare_debug_copy("wechat") is None


def test_launch_debug_copy_returns_exact_copy_pid(monkeypatch, tmp_path):
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
    from chatlog_keeper.core import _macos
    monkeypatch.setattr(_macos, "process_pids_for_executable", lambda path: [314])
    assert macos_debug_app.launch_debug_copy("wechat", wait_s=0) == 314


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
    from chatlog_keeper.core import _macos
    states = iter(([], [314], [], [], []))
    monkeypatch.setattr(
        _macos,
        "process_pids_for_executable",
        lambda path: next(states, []),
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
    monkeypatch.setattr(
        macos_debug_app,
        "_run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 1})(),
    )

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
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": ""},
        )()

    monkeypatch.setattr(macos_debug_app, "_run", fake_run)

    target = macos_debug_app.prepare_debug_copy("qq")
    assert target is not None
    assert len(signing_calls) == 1
    assert "--deep" not in signing_calls[0]
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
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": stdout, "stderr": ""},
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
            target, marker, "expected"
        )
        is False
    )
