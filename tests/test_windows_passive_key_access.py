from __future__ import annotations

import ctypes
import json
import sys
from pathlib import Path

import pytest

from chatlog_keeper import cli, qq_db, wechat_db
from chatlog_keeper.core import _windows_process_memory as windows_process_memory


class _FakeMemoryKernel:
    """Minimal Kernel32 surface that fails at one exact reader operation."""

    def __init__(
        self,
        stage: str,
        winerror: int,
        *,
        partial_payload: bytes | None = None,
    ) -> None:
        self.stage = stage
        self.winerror = winerror
        self.partial_payload = partial_payload
        self.calls: list[str] = []
        self._query_count = 0

    def OpenProcess(self, *_args):
        self.calls.append("OpenProcess")
        return 0 if self.stage == "OpenProcess" else 1

    def VirtualQueryEx(self, _handle, _address, mbi_pointer, _size):
        self.calls.append("VirtualQueryEx")
        self._query_count += 1
        if self.stage == "VirtualQueryEx" or self._query_count > 1:
            if self._query_count > 1:
                self.winerror = 87
            return 0
        mbi = mbi_pointer._obj
        mbi.BaseAddress = 0
        mbi.RegionSize = 4096
        mbi.State = 0x1000
        mbi.Protect = 0x04
        return 1

    def ReadProcessMemory(self, _handle, _address, buffer, _size, read_pointer):
        self.calls.append("ReadProcessMemory")
        if self.partial_payload is not None:
            ctypes.memmove(buffer, self.partial_payload, len(self.partial_payload))
            read_pointer._obj.value = len(self.partial_payload)
            return False
        return self.stage != "ReadProcessMemory"

    def CloseHandle(self, _handle):
        self.calls.append("CloseHandle")
        return 1

    def GetLastError(self):
        self.calls.append("GetLastError")
        return self.winerror


def test_windows_provider_reads_ctypes_captured_last_error(monkeypatch):
    """A use_last_error WinDLL must use ctypes' captured thread-local value."""

    class _CapturedLastErrorDll:
        _chatlog_keeper_uses_ctypes_last_error = True

        @staticmethod
        def GetLastError():
            pytest.fail("use_last_error provider fell back to raw GetLastError")

    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1314, raising=False)

    observed = windows_process_memory.last_error(_CapturedLastErrorDll())

    assert observed == 1314
    with pytest.raises(windows_process_memory.ProcessMemoryAccessDenied):
        windows_process_memory.raise_if_access_denied(observed)


def _qq_root(tmp_path: Path) -> Path:
    root = tmp_path / "Tencent Files"
    database = root / "123456" / "nt_qq" / "nt_db" / "nt_msg.db"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"q" * 8192)
    return root


def _wechat_root(tmp_path: Path) -> Path:
    root = tmp_path / "xwechat_files"
    database = root / "wxid_access_test" / "db_storage" / "message" / "message_0.db"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"w" * 4096)
    return root


def _configure_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
    kernel: _FakeMemoryKernel,
) -> Path:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("CHATLOG_FORCE_EXTRACT", raising=False)
    monkeypatch.setattr(cli, "scavenge_private_temp_dirs", lambda *_args: None)
    if source == "qq":
        root = _qq_root(tmp_path)
        monkeypatch.setenv("CHATLOG_QQ_DATA_ROOT", str(root))
        monkeypatch.delenv("CHATLOG_QQ_FORCE_LIVE_KEY", raising=False)
        monkeypatch.delenv("CHATLOG_QQ_REQUIRE_LIVE_KEY", raising=False)
        monkeypatch.setattr(qq_db, "_get_qq_pids", lambda: [101])
        monkeypatch.setattr(qq_db, "_windows_kernel32", lambda: kernel)
        monkeypatch.setattr(qq_db, "load_cached_key", lambda: None)
        monkeypatch.setattr(qq_db, "load_cached_key_for_account", lambda _account: None)
        return root

    root = _wechat_root(tmp_path)
    monkeypatch.setenv("CHATLOG_WECHAT_DATA_ROOT", str(root))
    monkeypatch.setattr(wechat_db, "_get_weixin_pids", lambda: [202])
    monkeypatch.setattr(wechat_db, "_windows_kernel32", lambda: kernel)
    monkeypatch.setattr(
        wechat_db,
        "load_cached_wechat_key_for_account",
        lambda _account: None,
    )
    return root


@pytest.mark.parametrize("source", ["qq", "wechat"])
@pytest.mark.parametrize(
    "stage",
    ["OpenProcess", "VirtualQueryEx", "ReadProcessMemory"],
)
@pytest.mark.parametrize("winerror", [5, 1314])
def test_cli_passive_key_reports_exact_windows_access_denial(
    monkeypatch,
    tmp_path,
    capsys,
    source,
    stage,
    winerror,
):
    kernel = _FakeMemoryKernel(stage, winerror)
    root = _configure_source(monkeypatch, tmp_path, source, kernel)

    exit_code = cli.main(
        [
            "extract-key",
            "--source",
            source,
            "--method",
            "passive",
            "--data-root",
            str(root),
        ]
    )

    assert exit_code == 1
    assert json.loads(capsys.readouterr().out) == {
        "source": source,
        "method": "passive",
        "ok": False,
        "error": "process_access_denied",
    }
    assert stage in kernel.calls
    assert "GetLastError" in kernel.calls


@pytest.mark.parametrize("source", ["qq", "wechat"])
@pytest.mark.parametrize(
    ("stage", "winerror"),
    [("OpenProcess", 87), ("VirtualQueryEx", 87), ("ReadProcessMemory", 299)],
)
def test_cli_passive_key_keeps_no_key_semantics_for_non_permission_failures(
    monkeypatch,
    tmp_path,
    capsys,
    source,
    stage,
    winerror,
):
    kernel = _FakeMemoryKernel(stage, winerror)
    root = _configure_source(monkeypatch, tmp_path, source, kernel)

    exit_code = cli.main(
        [
            "extract-key",
            "--source",
            source,
            "--method",
            "passive",
            "--data-root",
            str(root),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["source"] == source
    assert payload["method"] == "passive"
    assert payload["ok"] is False
    assert payload["error"] != "process_access_denied"
    assert payload["error"].startswith("passive scan found no key")
    assert stage in kernel.calls


@pytest.mark.parametrize("source", ["qq", "wechat"])
def test_partial_copy_bytes_still_reach_source_key_verification(
    monkeypatch,
    tmp_path,
    source,
):
    """ERROR_PARTIAL_COPY must not discard bytes reported by ReadProcessMemory."""

    if source == "qq":
        expected = b"partial-copy-key"
        payload = b"\x00" + expected + b"\x00"
    else:
        expected = bytes(range(32))
        payload = b"x'" + expected.hex().encode("ascii") + b"'"
    kernel = _FakeMemoryKernel(
        "ReadProcessMemory",
        299,
        partial_payload=payload,
    )
    root = _configure_source(monkeypatch, tmp_path, source, kernel)

    if source == "qq":
        database = root / "123456" / "nt_qq" / "nt_db" / "nt_msg.db"
        monkeypatch.setattr(
            qq_db,
            "_verify_key_qq",
            lambda candidate, _page: candidate == expected,
        )
        observed = qq_db.extract_key_from_qq(101, db_path=database)
    else:
        database = (
            root
            / "wxid_access_test"
            / "db_storage"
            / "message"
            / "message_0.db"
        )
        monkeypatch.setattr(
            wechat_db,
            "_verify_key_v4",
            lambda candidate, _page: candidate == expected,
        )
        monkeypatch.setattr(
            wechat_db,
            "save_cached_wechat_key_for_account",
            lambda *_args, **_kwargs: True,
        )
        observed = wechat_db.extract_key_from_weixin(
            202,
            db_path=database,
            account_id="wxid_access_test",
        )

    assert observed == expected
    assert "ReadProcessMemory" in kernel.calls
    assert "GetLastError" in kernel.calls
    assert "CloseHandle" in kernel.calls
