"""Private Win32 process-memory primitives for passive key readers.

The public ``extract_key_from_*`` functions intentionally keep returning only
key bytes or ``None``. This module provides a path-free exception for the one
failure callers must distinguish from an ordinary no-key scan: an exact Win32
access denial.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes as wt
from functools import lru_cache
from typing import Any


PROCESS_ACCESS_DENIED = "process_access_denied"
_ACCESS_DENIED_WINERRORS = frozenset({5, 1314})


class ProcessMemoryAccessDenied(RuntimeError):
    """An exact Win32 permission denial with no PID, path, or raw message."""

    code = PROCESS_ACCESS_DENIED

    def __init__(self) -> None:
        super().__init__(self.code)


@lru_cache(maxsize=1)
def kernel32() -> Any:
    """Load the memory-reader APIs with last-error and 64-bit-safe signatures."""

    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    dll.OpenProcess.restype = wt.HANDLE
    dll.VirtualQueryEx.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    dll.VirtualQueryEx.restype = ctypes.c_size_t
    dll.ReadProcessMemory.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    dll.ReadProcessMemory.restype = wt.BOOL
    dll.CloseHandle.argtypes = [wt.HANDLE]
    dll.CloseHandle.restype = wt.BOOL
    dll._chatlog_keeper_uses_ctypes_last_error = True
    return dll


def last_error(dll: Any) -> int:
    """Read the error captured by ``use_last_error`` (fake-friendly in tests)."""

    getter = getattr(ctypes, "get_last_error", None)
    if getter is not None and getattr(dll, "_chatlog_keeper_uses_ctypes_last_error", False) is True:
        return int(getter())
    # ``ctypes.get_last_error`` exists on Windows. The fallback lets the exact
    # same provider path be exercised by deterministic tests on other hosts.
    return int(dll.GetLastError())


def raise_if_access_denied(winerror: int) -> None:
    """Raise only for frozen, explicit Win32 permission failures."""

    if int(winerror) in _ACCESS_DENIED_WINERRORS:
        raise ProcessMemoryAccessDenied()


__all__ = [
    "PROCESS_ACCESS_DENIED",
    "ProcessMemoryAccessDenied",
    "kernel32",
    "last_error",
    "raise_if_access_denied",
]
