"""Private Linux process-memory primitives for passive key readers.

The public ``extract_key_from_*`` functions keep returning only key bytes or
``None``. This module maps an exact Yama/ptrace denial onto the existing
:class:`ProcessMemoryAccessDenied` so CLI and host-app callers see the same
``process_access_denied`` code they already handle on Windows and macOS.
"""
from __future__ import annotations

import ctypes
import errno
import re
from dataclasses import dataclass
from typing import Iterator, Optional

from chatlog_keeper.core._windows_process_memory import (
    PROCESS_ACCESS_DENIED,
    ProcessMemoryAccessDenied,
)


_MAPS_RE = re.compile(
    r"^(?P<start>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)\s+(?P<perms>\S+)"
    r"\s+[0-9a-fA-F]+\s+\S+\s+\d+\s*(?P<path>.*)$"
)
_SKIP_PATHS = ("[vvar]", "[vdso]", "[vsyscall]", "[vvar_vclock]")
_MAX_REGION_BYTES = 200 * 1024 * 1024
_CHUNK_BYTES = 8 * 1024 * 1024
_ACCESS_DENIED_ERRNOS = frozenset({errno.EPERM, errno.EACCES})


class iovec(ctypes.Structure):
    _fields_ = (
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    )


@dataclass(frozen=True)
class MemoryRegion:
    start: int
    end: int
    perms: str
    pathname: str

    @property
    def size(self) -> int:
        return self.end - self.start


def raise_if_access_denied(err: int) -> None:
    """Raise only for frozen, explicit Linux permission failures."""
    if int(err) in _ACCESS_DENIED_ERRNOS:
        raise ProcessMemoryAccessDenied()


def parse_maps(pid: int) -> list[MemoryRegion]:
    """Parse ``/proc/<pid>/maps``. Permission denials fail closed."""
    try:
        raw = _read_maps(pid)
    except OSError as exc:
        raise_if_access_denied(exc.errno or 0)
        return []
    regions: list[MemoryRegion] = []
    for line in raw.splitlines():
        match = _MAPS_RE.match(line)
        if match is None:
            continue
        pathname = (match.group("path") or "").strip()
        regions.append(
            MemoryRegion(
                start=int(match.group("start"), 16),
                end=int(match.group("end"), 16),
                perms=match.group("perms"),
                pathname=pathname,
            )
        )
    return regions


def _read_maps(pid: int) -> str:
    with open(f"/proc/{int(pid)}/maps", "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def iter_candidate_regions(pid: int) -> Iterator[MemoryRegion]:
    """Yield readable anonymous/heap/stack regions suitable for a key scan."""
    for region in parse_maps(pid):
        if not region.perms.startswith("r"):
            continue
        if not (0 < region.size < _MAX_REGION_BYTES):
            continue
        if region.pathname in _SKIP_PATHS:
            continue
        if region.pathname and not region.pathname.startswith("["):
            continue
        yield region


def read_process_memory(pid: int, address: int, size: int) -> bytes:
    """Read ``size`` bytes from ``pid`` via ``process_vm_readv``.

    ``EPERM`` / ``EACCES`` become :class:`ProcessMemoryAccessDenied`. Short
    reads are returned as-is so a partial heap page can still be scanned.
    """
    if size <= 0:
        return b""
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(size)
    local = iovec(ctypes.cast(buf, ctypes.c_void_p), size)
    remote = iovec(ctypes.c_void_p(address), size)
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    libc.process_vm_readv.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(iovec),
        ctypes.c_ulong,
        ctypes.POINTER(iovec),
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    got = libc.process_vm_readv(
        int(pid),
        ctypes.byref(local),
        1,
        ctypes.byref(remote),
        1,
        0,
    )
    if got < 0:
        err = ctypes.get_errno()
        raise_if_access_denied(err)
        return b""
    return buf.raw[: int(got)]


def iter_process_memory_chunks(
    pid: int,
    *,
    timeout_s: Optional[float] = None,
) -> Iterator[bytes]:
    """Yield readable memory chunks until timeout or the address space ends."""
    import time as _time

    deadline = (_time.monotonic() + timeout_s) if timeout_s else None
    for region in iter_candidate_regions(pid):
        offset = 0
        while offset < region.size:
            if deadline is not None and _time.monotonic() > deadline:
                return
            chunk_size = min(_CHUNK_BYTES, region.size - offset)
            data = read_process_memory(pid, region.start + offset, chunk_size)
            if data:
                yield data
            if len(data) < chunk_size:
                break
            offset += chunk_size


__all__ = [
    "PROCESS_ACCESS_DENIED",
    "ProcessMemoryAccessDenied",
    "MemoryRegion",
    "iter_candidate_regions",
    "iter_process_memory_chunks",
    "parse_maps",
    "raise_if_access_denied",
    "read_process_memory",
]
