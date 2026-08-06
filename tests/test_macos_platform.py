import subprocess
from pathlib import Path
from types import SimpleNamespace

from chatlog_keeper.core import _macos
from chatlog_keeper import qq_db, wechat_db


def test_macos_process_pids_match_real_app_binary_only(monkeypatch):
    monkeypatch.setattr(_macos, "is_macos", lambda: True)
    stdout = "\n".join(
        [
            " 42 /Applications/WeChat.app/Contents/MacOS/WeChat",
            " 44 /Applications/WeChat.app/Contents/Frameworks/Helper",
            " 43 /Applications/QQ.app/Contents/MacOS/QQ",
            " 99 /tmp/QQ",
        ]
    )
    monkeypatch.setattr(
        _macos.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=stdout),
    )
    assert _macos.process_pids(("WeChat", "QQ")) == [42, 43]


def test_macos_exact_executable_pid_uses_comm_not_argument_substrings(
    monkeypatch,
):
    monkeypatch.setattr(_macos, "is_macos", lambda: True)
    expected = Path("/Applications/QQ.app/Contents/MacOS/QQ")
    stdout = "\n".join(
        [
            f" 43 {expected}",
            f" 44 {expected} --flag",
            f" 45 /usr/bin/python3 {expected}",
        ]
    )
    monkeypatch.setattr(
        _macos.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=stdout),
    )
    assert _macos.process_pids_for_executable(expected) == [43]


def test_macos_process_pids_fail_closed_off_macos(monkeypatch):
    monkeypatch.setattr(_macos, "is_macos", lambda: False)
    monkeypatch.setattr(
        _macos.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("ps must not run")),
    )
    assert _macos.process_pids(("WeChat",)) == []


def test_macos_exact_executable_pid_match(monkeypatch):
    monkeypatch.setattr(_macos, "is_macos", lambda: True)
    exact = Path("/tmp/WeChat-copy.app/Contents/MacOS/WeChat")
    stdout = f" 7 {exact}\n 8 {exact} --flag\n 9 /Applications/WeChat.app/Contents/MacOS/WeChat"
    monkeypatch.setattr(
        _macos.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=stdout),
    )
    assert _macos.process_pids_for_executable(exact) == [7]


def test_macos_checked_exact_enumeration_distinguishes_ps_failure(monkeypatch):
    monkeypatch.setattr(_macos, "is_macos", lambda: True)
    exact = Path("/tmp/WeChat-copy.app/Contents/MacOS/WeChat")
    monkeypatch.setattr(
        _macos.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("ps", 5)
        ),
    )

    assert _macos._process_pids_for_executable_checked(exact) == (False, [])
    assert _macos.process_pids_for_executable(exact) == []


def test_macos_checked_exact_enumeration_rejects_nonzero_ps(monkeypatch):
    monkeypatch.setattr(_macos, "is_macos", lambda: True)
    exact = Path("/tmp/WeChat-copy.app/Contents/MacOS/WeChat")
    monkeypatch.setattr(
        _macos.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
        ),
    )

    assert _macos._process_pids_for_executable_checked(exact) == (False, [])


def test_macos_container_candidates_are_bounded():
    home = Path("/Users/tester")
    wechat = _macos.wechat_data_roots(home)
    qq = _macos.qq_container_roots(home)
    assert wechat[0] == home / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
    assert "5A4RE8SF68.com.tencent.xinWeChat" in str(wechat[1])
    assert qq == [
        home / "Library/Containers/com.tencent.qq/Data",
        home / "Library/Group Containers/FN2V63AD2J.com.tencent",
    ]


def test_wechat_resolver_finds_macos_container(monkeypatch, tmp_path):
    root = tmp_path / "xwechat_files"
    root.mkdir()
    monkeypatch.delenv("CHATLOG_WECHAT_DATA_ROOT", raising=False)
    monkeypatch.setattr(wechat_db.sys, "platform", "darwin")
    monkeypatch.setattr(_macos, "wechat_data_roots", lambda: [root])
    assert wechat_db.find_weixin_data_root() == root


def test_qq_resolver_finds_macos_legacy_layout(monkeypatch, tmp_path):
    data = tmp_path / "Data"
    root = data / "Library" / "Application Support" / "QQ"
    db = root / "opaque-account" / "nt_db" / "nt_msg.db"
    db.parent.mkdir(parents=True)
    db.write_bytes(b"SQLite header 3\x00" + b"\0" * 64)
    monkeypatch.delenv("CHATLOG_QQ_DATA_ROOT", raising=False)
    monkeypatch.setattr(qq_db.sys, "platform", "darwin")
    monkeypatch.setattr(_macos, "qq_container_roots", lambda: [data])
    assert qq_db.find_qq_data_root() == root
    assert qq_db.find_msg_database(root) == db
    assert qq_db.detect_current_qq_account() == "opaque-account"
