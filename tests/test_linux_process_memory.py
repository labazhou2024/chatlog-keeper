from __future__ import annotations

import errno
from pathlib import Path

import pytest

from chatlog_keeper import qq_db, wechat_db
from chatlog_keeper.core import _linux_process_memory as linux_mem
from chatlog_keeper.core._windows_process_memory import ProcessMemoryAccessDenied


def test_linux_maps_keep_anonymous_and_skip_file_backed(monkeypatch):
    sample = "\n".join(
        [
            "00400000-0040b000 r-xp 00000000 08:01 123 /opt/wechat/wechat",
            "7fff0000-7fff8000 rw-p 00000000 00:00 0   [heap]",
            "7ffff000-7ffff100 r--p 00000000 00:00 0   [vdso]",
            "7ff00000-7ff10000 rw-p 00000000 00:00 0",
        ]
    )
    monkeypatch.setattr(linux_mem, "_read_maps", lambda _pid: sample)
    regions = list(linux_mem.iter_candidate_regions(42))
    paths = [region.pathname for region in regions]
    assert "[heap]" in paths
    assert "" in paths
    assert "/opt/wechat/wechat" not in paths
    assert "[vdso]" not in paths


def test_linux_access_denied_is_the_shared_contract():
    with pytest.raises(ProcessMemoryAccessDenied):
        linux_mem.raise_if_access_denied(errno.EPERM)
    with pytest.raises(ProcessMemoryAccessDenied):
        linux_mem.raise_if_access_denied(errno.EACCES)
    linux_mem.raise_if_access_denied(errno.ESRCH)


def test_wechat_linux_scan_verifies_hex_blob(monkeypatch, tmp_path):
    expected = bytes(range(32))
    payload = b"padx'" + expected.hex().encode("ascii") + b"'tail"
    db = tmp_path / "message_0.db"
    db.write_bytes(b"w" * 4096)
    monkeypatch.setattr(wechat_db.sys, "platform", "linux")
    monkeypatch.setattr(
        linux_mem,
        "iter_process_memory_chunks",
        lambda *_args, **_kwargs: iter([payload]),
    )
    monkeypatch.setattr(wechat_db, "_read_stable_page1", lambda _path: b"p" * 4096)
    monkeypatch.setattr(
        wechat_db,
        "_verify_key_v4",
        lambda candidate, _page: candidate == expected,
    )
    assert wechat_db._scan_linux_memory_for_key(9, db_path=db) == expected


def test_qq_linux_scan_verifies_ascii_passphrase(monkeypatch, tmp_path):
    expected = b"abcdefghijklmnop"
    payload = b"\x00" + expected + b"\x00"
    db = tmp_path / "nt_msg.db"
    db.write_bytes(b"q" * 5120)
    monkeypatch.setattr(qq_db.sys, "platform", "linux")
    monkeypatch.setattr(
        linux_mem,
        "iter_process_memory_chunks",
        lambda *_args, **_kwargs: iter([payload]),
    )
    monkeypatch.setattr(qq_db, "_read_qq_verification_bytes", lambda _path: b"v" * 5120)
    monkeypatch.setattr(
        qq_db,
        "_verify_key_qq",
        lambda candidate, _raw: candidate == expected,
    )
    assert qq_db._scan_linux_memory_for_key(8, db_path=db) == expected


def test_linux_scan_maps_yama_denial(monkeypatch, tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"w" * 4096)

    def _denied(*_args, **_kwargs):
        raise ProcessMemoryAccessDenied()
        yield  # pragma: no cover

    monkeypatch.setattr(linux_mem, "iter_process_memory_chunks", _denied)
    monkeypatch.setattr(wechat_db, "_read_stable_page1", lambda _path: b"p" * 4096)
    with pytest.raises(ProcessMemoryAccessDenied):
        wechat_db._scan_linux_memory_for_key(7, db_path=db)
