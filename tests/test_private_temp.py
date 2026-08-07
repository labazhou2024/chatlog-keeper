"""Private plaintext temporary-directory lifecycle tests."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from chatlog_keeper import qq_db
from chatlog_keeper.core import _private_temp
from chatlog_keeper.core._secrets import write_secret_text


def test_private_temp_is_restricted_and_owner_marked_before_use() -> None:
    path = _private_temp.create_private_temp_dir("qq_db_")
    try:
        assert _private_temp.private_temp_dir_is_safe(path)
        owner = path / _private_temp.OWNER_FILE
        assert owner.read_text(encoding="utf-8") == f"pid={os.getpid()}\n"
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o700
            assert stat.S_IMODE(owner.stat().st_mode) == 0o600
    finally:
        _private_temp.cleanup_private_temp_dir(path)
    assert not path.exists()


def test_private_temp_cleanup_retries_a_transient_delete_failure(monkeypatch) -> None:
    path = _private_temp.create_private_temp_dir("qq_page_")
    assert write_secret_text(path / "decrypted.db", "plaintext")
    original_rmtree = _private_temp.shutil.rmtree
    calls = []

    def fail_once(target):
        calls.append(Path(target))
        if len(calls) == 1:
            raise OSError("transient-private-path")
        return original_rmtree(target)

    monkeypatch.setattr(_private_temp.shutil, "rmtree", fail_once)
    monkeypatch.setattr(_private_temp.time, "sleep", lambda _delay: None)

    _private_temp.cleanup_private_temp_dir(path)

    assert calls == [path, path]
    assert not path.exists()


def test_private_temp_cleanup_failure_is_loud_and_path_free(monkeypatch) -> None:
    path = _private_temp.create_private_temp_dir("qq_directory_")
    assert write_secret_text(path / "decrypted.db", "plaintext")
    original_rmtree = _private_temp.shutil.rmtree

    def always_fail(_target):
        raise RuntimeError(f"busy:{path}")

    monkeypatch.setattr(_private_temp.shutil, "rmtree", always_fail)
    monkeypatch.setattr(_private_temp.time, "sleep", lambda _delay: None)
    try:
        with pytest.raises(_private_temp.PrivateTempLifecycleError) as exc_info:
            _private_temp.cleanup_private_temp_dir(path)
        assert str(exc_info.value) == "private temporary plaintext cleanup failed"
        assert str(path) not in str(exc_info.value)
        assert path.exists()
    finally:
        monkeypatch.setattr(_private_temp.shutil, "rmtree", original_rmtree)
        _private_temp.cleanup_private_temp_dir(path)


def test_startup_scavenger_removes_dead_owners_and_preserves_live_owner(
    monkeypatch,
    tmp_path,
) -> None:
    original_mkdtemp = tempfile.mkdtemp
    monkeypatch.setattr(
        _private_temp.tempfile,
        "mkdtemp",
        lambda prefix: original_mkdtemp(prefix=prefix, dir=tmp_path),
    )
    created = {
        prefix: _private_temp.create_private_temp_dir(prefix)
        for prefix in qq_db._QQ_PLAINTEXT_TEMP_PREFIXES
    }
    live_prefix = "qq_participants_"
    dead_pid = 424242
    for prefix, path in created.items():
        assert write_secret_text(path / "decrypted.db", "plaintext")
        if prefix != live_prefix:
            assert write_secret_text(
                path / _private_temp.OWNER_FILE,
                f"pid={dead_pid}\n",
            )
    monkeypatch.setattr(
        _private_temp,
        "process_is_alive",
        lambda pid: pid == os.getpid(),
    )

    assert _private_temp.scavenge_private_temp_dirs(
        qq_db._QQ_PLAINTEXT_TEMP_PREFIXES,
        temp_root=tmp_path,
        force=True,
    ) == 3
    for prefix, path in created.items():
        assert path.exists() is (prefix == live_prefix)

    _private_temp.cleanup_private_temp_dir(created[live_prefix])


def test_qq_finalizer_cleans_after_close_failure_and_reports_stable_error(
    monkeypatch,
    tmp_path,
) -> None:
    events = []

    class FailingConnection:
        @staticmethod
        def close():
            events.append("close")
            raise OSError("private-database-path")

    def cleanup(path):
        events.append("cleanup")
        assert path == tmp_path

    monkeypatch.setattr(qq_db, "cleanup_private_temp_dir", cleanup)
    with pytest.raises(RuntimeError) as exc_info:
        qq_db._finalize_qq_plaintext_temp(FailingConnection(), tmp_path)

    assert events == ["close", "cleanup"]
    assert str(exc_info.value) == "QQ SQLite helper close failed"
    assert "private-database-path" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_qq_finalizer_prioritizes_cleanup_failure_after_safe_close(
    monkeypatch,
    tmp_path,
) -> None:
    events = []

    class Connection:
        @staticmethod
        def close():
            events.append("close")

    def cleanup(_path):
        events.append("cleanup")
        raise _private_temp.PrivateTempLifecycleError(
            f"private temporary plaintext cleanup failed: {tmp_path}"
        )

    monkeypatch.setattr(qq_db, "cleanup_private_temp_dir", cleanup)
    with pytest.raises(RuntimeError) as exc_info:
        qq_db._finalize_qq_plaintext_temp(Connection(), tmp_path)

    assert events == ["close", "cleanup"]
    assert str(exc_info.value) == "QQ temporary plaintext cleanup failed"
    assert str(tmp_path) not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
