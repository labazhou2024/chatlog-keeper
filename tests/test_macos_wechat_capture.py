import os
import sys
from pathlib import Path

import pytest

from chatlog_keeper import macos_wechat_capture


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS capture tests require Darwin FIFO, ownership, and code-signing semantics",
)


def _database_in_container(tmp_path: Path) -> tuple[Path, Path]:
    data = tmp_path / "Containers" / "com.tencent.xinWeChat" / "Data"
    database = (
        data
        / "Documents"
        / "xwechat_files"
        / "wxid_test"
        / "db_storage"
        / "message"
        / "message_0.db"
    )
    database.parent.mkdir(parents=True)
    database.write_bytes(b"x" * 4096)
    return database, data


def test_container_tmp_is_derived_from_database_ancestry(tmp_path):
    database, data = _database_in_container(tmp_path)

    assert macos_wechat_capture._container_tmp_for_database(database) == data / "tmp"


def test_container_tmp_rejects_non_wechat_layout(tmp_path):
    database = tmp_path / "archive" / "message_0.db"
    database.parent.mkdir()
    database.write_bytes(b"x" * 4096)

    assert macos_wechat_capture._container_tmp_for_database(database) is None


def test_capture_channel_reads_fixed_records_and_removes_fifo(tmp_path):
    database, _ = _database_in_container(tmp_path)
    channel = macos_wechat_capture.create_capture_channel(database)
    assert channel is not None
    key = bytes(range(32))

    write_fd = os.open(channel.path, os.O_WRONLY | os.O_NONBLOCK)
    try:
        assert os.write(write_fd, b"WXK1" + key) == 36
    finally:
        os.close(write_fd)

    assert channel.read_candidates() == [key]
    path = channel.path
    assert channel.close() is True
    assert not path.exists()


def test_capture_channel_rejects_invalid_record(tmp_path):
    database, _ = _database_in_container(tmp_path)
    channel = macos_wechat_capture.create_capture_channel(database)
    assert channel is not None

    write_fd = os.open(channel.path, os.O_WRONLY | os.O_NONBLOCK)
    try:
        os.write(write_fd, b"BAD!" + bytes(32))
    finally:
        os.close(write_fd)

    assert channel.read_candidates() == []
    assert channel.invalid is True
    assert macos_wechat_capture.last_error() == "capture_channel_invalid_record"
    assert channel.close() is True


def test_capture_cleanup_does_not_unlink_replaced_fifo(tmp_path):
    database, _ = _database_in_container(tmp_path)
    channel = macos_wechat_capture.create_capture_channel(database)
    assert channel is not None
    path = channel.path
    path.unlink()
    os.mkfifo(path, 0o600)

    assert channel.close() is False
    assert path.exists()
    assert macos_wechat_capture.last_error() == "capture_channel_identity_changed"
    path.unlink()


def test_capture_cleanup_still_removes_fifo_when_library_generation_changed(
    tmp_path,
):
    database, _ = _database_in_container(tmp_path)
    channel = macos_wechat_capture.create_capture_channel(database)
    assert channel is not None
    library = channel.path.with_suffix(".dylib")
    library.write_bytes(b"first")
    library.chmod(0o700)
    original = library.lstat()
    channel.library_path = library
    channel.library_device = original.st_dev
    channel.library_inode = original.st_ino
    library.unlink()
    library.write_bytes(b"replacement")
    library.chmod(0o700)

    fifo = channel.path
    assert channel.close() is False
    assert not fifo.exists()
    assert library.read_bytes() == b"replacement"
    assert macos_wechat_capture.last_error() == "capture_library_identity_changed"
    library.unlink()


def test_validate_capture_fifo_checks_exact_generation(tmp_path):
    database, _ = _database_in_container(tmp_path)
    channel = macos_wechat_capture.create_capture_channel(database)
    assert channel is not None

    assert macos_wechat_capture.validate_capture_fifo(
        channel.path,
        expected_identity=channel.identity,
    )
    assert not macos_wechat_capture.validate_capture_fifo(
        channel.path,
        expected_identity=(channel.device, channel.inode + 1),
    )
    assert channel.close() is True


def test_validate_capture_library_rejects_symlink_at_expected_path(
    monkeypatch, tmp_path
):
    expected = tmp_path / "capture.dylib"
    target = tmp_path / "target.dylib"
    target.write_bytes(b"binary")
    target.chmod(0o700)
    expected.symlink_to(target)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_capture_library_path",
        lambda: expected,
    )

    assert not macos_wechat_capture.validate_capture_library(expected)


def test_ensure_capture_library_targets_macos_11_arm64_and_stable_install_name(
    monkeypatch, tmp_path
):
    source = tmp_path / "capture.c"
    source.write_text("int capture_test;", encoding="utf-8")
    prebuilt = tmp_path / "missing.dylib"
    output_root = tmp_path / "data"
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["xcrun", "clang"]:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"mach-o")
        stderr = "TeamIdentifier=not set\n" if "--verbose=4" in argv else ""
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "", "stderr": stderr},
        )()

    monkeypatch.setattr(macos_wechat_capture.sys, "platform", "darwin")
    monkeypatch.setattr(macos_wechat_capture, "_source_path", lambda: source)
    monkeypatch.setattr(macos_wechat_capture, "_prebuilt_path", lambda: prebuilt)
    monkeypatch.setattr(macos_wechat_capture, "data_dir", lambda: output_root)
    monkeypatch.setattr(macos_wechat_capture.subprocess, "run", fake_run)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_TRUSTED_CAPTURE_LIBRARY",
        None,
    )

    helper = macos_wechat_capture.ensure_capture_library()

    assert helper is not None and helper.is_file()
    compile_argv = next(argv for argv in calls if argv[:2] == ["xcrun", "clang"])
    assert compile_argv[compile_argv.index("-arch") + 1] == "arm64"
    assert "-mmacosx-version-min=11.0" in compile_argv
    assert "-Wl,-install_name,@rpath/macos_wechat_key_capture.dylib" in compile_argv
    assert macos_wechat_capture.validate_capture_library(helper)

    database, data = _database_in_container(tmp_path)
    channel = macos_wechat_capture.create_capture_channel(
        database,
        capture_library=helper,
    )
    assert channel is not None
    assert channel.library_path is not None
    assert channel.library_path.parent == data / "tmp"
    assert channel.library_identity is not None
    assert channel.library_path.read_bytes() == helper.read_bytes()
    assert macos_wechat_capture.validate_launch_capture_library(
        channel.library_path,
        expected_identity=channel.library_identity,
    )
    fifo = channel.path
    staged = channel.library_path
    assert channel.close() is True
    assert not fifo.exists()
    assert not staged.exists()


def test_ad_hoc_resigned_capture_cache_is_rebuilt_from_source(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "capture.c"
    source.write_text("int capture_test;", encoding="utf-8")
    output_root = tmp_path / "data"
    signing_calls = []

    def fake_run(argv, **kwargs):
        if argv[:2] == ["xcrun", "clang"]:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"trusted-mach-o")
        if argv[0] == "codesign" and "--force" in argv:
            signing_calls.append(argv)
        stderr = "TeamIdentifier=not set\n" if "--verbose=4" in argv else ""
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "", "stderr": stderr},
        )()

    monkeypatch.setattr(macos_wechat_capture.sys, "platform", "darwin")
    monkeypatch.setattr(macos_wechat_capture, "_source_path", lambda: source)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_prebuilt_path",
        lambda: tmp_path / "missing.dylib",
    )
    monkeypatch.setattr(macos_wechat_capture, "data_dir", lambda: output_root)
    monkeypatch.setattr(macos_wechat_capture.subprocess, "run", fake_run)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_TRUSTED_CAPTURE_LIBRARY",
        None,
    )

    helper = macos_wechat_capture.ensure_capture_library()
    assert helper is not None
    helper.unlink()
    helper.write_bytes(b"attacker-dylib-with-valid-ad-hoc-signature")
    helper.chmod(0o700)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_TRUSTED_CAPTURE_LIBRARY",
        None,
    )

    rebuilt = macos_wechat_capture.ensure_capture_library()
    assert rebuilt == helper
    assert rebuilt.read_bytes() == b"trusted-mach-o"
    assert len(signing_calls) == 2


def test_capture_build_rejects_non_ad_hoc_team_id(monkeypatch, tmp_path):
    source = tmp_path / "capture.c"
    source.write_text("int capture_test;", encoding="utf-8")
    output_root = tmp_path / "data"

    def fake_run(argv, **kwargs):
        if argv[:2] == ["xcrun", "clang"]:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"mach-o")
        stderr = "TeamIdentifier=ATTACKER1\n" if "--verbose=4" in argv else ""
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "", "stderr": stderr},
        )()

    monkeypatch.setattr(macos_wechat_capture.sys, "platform", "darwin")
    monkeypatch.setattr(macos_wechat_capture, "_source_path", lambda: source)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_prebuilt_path",
        lambda: tmp_path / "missing.dylib",
    )
    monkeypatch.setattr(macos_wechat_capture, "data_dir", lambda: output_root)
    monkeypatch.setattr(macos_wechat_capture.subprocess, "run", fake_run)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_TRUSTED_CAPTURE_LIBRARY",
        None,
    )

    assert macos_wechat_capture.ensure_capture_library() is None
    assert (
        macos_wechat_capture.last_error()
        == "capture_signature_validation_failed"
    )


def test_capture_permission_tamper_is_rebuilt(monkeypatch, tmp_path):
    source = tmp_path / "capture.c"
    source.write_text("int capture_test;", encoding="utf-8")
    output_root = tmp_path / "data"
    signing_calls = []

    def fake_run(argv, **kwargs):
        if argv[:2] == ["xcrun", "clang"]:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"mach-o")
        if argv[0] == "codesign" and "--force" in argv:
            signing_calls.append(argv)
        stderr = "TeamIdentifier=not set\n" if "--verbose=4" in argv else ""
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "", "stderr": stderr},
        )()

    monkeypatch.setattr(macos_wechat_capture.sys, "platform", "darwin")
    monkeypatch.setattr(macos_wechat_capture, "_source_path", lambda: source)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_prebuilt_path",
        lambda: tmp_path / "missing.dylib",
    )
    monkeypatch.setattr(macos_wechat_capture, "data_dir", lambda: output_root)
    monkeypatch.setattr(macos_wechat_capture.subprocess, "run", fake_run)
    monkeypatch.setattr(
        macos_wechat_capture,
        "_TRUSTED_CAPTURE_LIBRARY",
        None,
    )

    helper = macos_wechat_capture.ensure_capture_library()
    assert helper is not None
    first_identity = helper.lstat().st_ino
    helper.chmod(0o755)

    rebuilt = macos_wechat_capture.ensure_capture_library()
    assert rebuilt == helper
    assert (rebuilt.stat().st_mode & 0o777) == 0o700
    assert rebuilt.lstat().st_ino != first_identity
    assert len(signing_calls) == 2
