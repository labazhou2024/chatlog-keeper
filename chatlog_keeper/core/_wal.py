"""Validated SQLite WAL recovery for decrypted SQLCipher snapshots.

SQLite authenticates the structural WAL stream with cumulative checksums and
salt values.  SQLCipher independently authenticates each encrypted page image.
Callers provide the page decrypt/HMAC oracle; this module validates SQLite's
own WAL and WAL-index contracts before any plaintext database is mutated.
"""
from __future__ import annotations

import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

_WAL_MAGIC_LITTLE_CHECKSUM = 0x377F0682
_WAL_MAGIC_BIG_CHECKSUM = 0x377F0683
_WAL_VERSION = 3007000


class WalValidationError(OSError):
    """The WAL family cannot be proven structurally consistent."""


@dataclass(frozen=True)
class WalPlan:
    present: bool
    page_size: int
    frames_to_apply: int
    commit_size: int
    valid_frames: int
    physical_frames: int
    used_shm: bool
    file_signature: tuple[int, int, int, int]


@dataclass(frozen=True)
class _ShmState:
    mx_frame: int
    n_page: int
    frame_checksum: tuple[int, int]


def _checksum_bytes(
    data: bytes,
    checksum: tuple[int, int] = (0, 0),
    *,
    big_endian: bool,
) -> tuple[int, int]:
    if len(data) % 8:
        raise WalValidationError("WAL checksum input is not 8-byte aligned")
    endian = ">" if big_endian else "<"
    values = struct.unpack(f"{endian}{len(data) // 4}I", data)
    s0, s1 = checksum
    for index in range(0, len(values), 2):
        s0 = (s0 + values[index] + s1) & 0xFFFFFFFF
        s1 = (s1 + values[index + 1] + s0) & 0xFFFFFFFF
    return s0, s1


def _read_shm_state(
    shm_path: Path,
    *,
    wal_header: bytes,
    magic: int,
    page_size: int,
) -> Optional[_ShmState]:
    if not shm_path.is_file():
        return None
    try:
        with shm_path.open("rb") as handle:
            raw = handle.read(96)
    except OSError as exc:
        raise WalValidationError(f"cannot read WAL index: {type(exc).__name__}") from exc
    if len(raw) < 96:
        raise WalValidationError("WAL index header is truncated")
    first, second = raw[:48], raw[48:96]
    if first != second:
        raise WalValidationError("WAL index header copies disagree")

    native = "<" if sys.byteorder == "little" else ">"
    version = struct.unpack_from(f"{native}I", first, 0)[0]
    is_init = first[12]
    big_end_checksum = first[13]
    encoded_page_size = struct.unpack_from(f"{native}H", first, 14)[0]
    index_page_size = 65536 if encoded_page_size == 1 else encoded_page_size
    mx_frame, n_page = struct.unpack_from(f"{native}II", first, 16)
    frame_checksum = struct.unpack_from(f"{native}II", first, 24)
    stored_checksum = struct.unpack_from(f"{native}II", first, 40)
    computed_checksum = _checksum_bytes(
        first[:40],
        big_endian=(sys.byteorder == "big"),
    )

    if version != _WAL_VERSION or first[4:8] != b"\0\0\0\0":
        raise WalValidationError("unsupported WAL index version")
    if is_init not in (0, 1):
        raise WalValidationError("invalid WAL index initialization flag")
    if index_page_size != page_size:
        raise WalValidationError("WAL index page size mismatch")
    expected_big = int(magic == _WAL_MAGIC_BIG_CHECKSUM)
    if big_end_checksum != expected_big:
        raise WalValidationError("WAL index checksum byte order mismatch")
    if first[32:40] != wal_header[16:24]:
        raise WalValidationError("WAL index salt mismatch")
    if computed_checksum != stored_checksum:
        raise WalValidationError("WAL index header checksum mismatch")
    if not is_init:
        if mx_frame != 0:
            raise WalValidationError("uninitialized WAL index has committed frames")
        return _ShmState(0, 0, (0, 0))
    return _ShmState(mx_frame, n_page, frame_checksum)


def inspect_wal(
    wal_path: Path,
    *,
    shm_path: Optional[Path] = None,
    expected_page_size: Optional[int] = None,
) -> WalPlan:
    """Validate a WAL snapshot and return the committed recovery boundary.

    When a copied ``-shm`` file is available, its two checksummed headers and
    ``mxFrame`` are authoritative.  Without ``-shm`` we mirror SQLite recovery:
    scan checksum-valid frames until the first stale/invalid tail and use the
    last complete commit marker.
    """
    wal_path = Path(wal_path)
    try:
        stat = wal_path.stat()
    except FileNotFoundError:
        return WalPlan(False, expected_page_size or 0, 0, 0, 0, 0, False, (0, 0, 0, 0))
    signature = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    if stat.st_size == 0:
        return WalPlan(True, expected_page_size or 0, 0, 0, 0, 0, False, signature)
    if stat.st_size < 32:
        raise WalValidationError("WAL header is truncated")

    with wal_path.open("rb") as wal:
        header = wal.read(32)
        try:
            magic, version, encoded_page_size = struct.unpack(">III", header[:12])
        except struct.error as exc:
            raise WalValidationError("WAL header is malformed") from exc
        if magic not in (_WAL_MAGIC_LITTLE_CHECKSUM, _WAL_MAGIC_BIG_CHECKSUM):
            raise WalValidationError("WAL magic is invalid")
        if version != _WAL_VERSION:
            raise WalValidationError("unsupported WAL version")
        page_size = 65536 if encoded_page_size in (0, 1) else encoded_page_size
        if expected_page_size is not None and page_size != expected_page_size:
            raise WalValidationError("WAL page size is unsupported")
        big_endian = magic == _WAL_MAGIC_BIG_CHECKSUM
        stored_header_checksum = struct.unpack(">II", header[24:32])
        checksum = _checksum_bytes(header[:24], big_endian=big_endian)
        if checksum != stored_header_checksum:
            raise WalValidationError("WAL header checksum mismatch")

        frame_size = 24 + page_size
        physical_frames = max(0, (stat.st_size - 32) // frame_size)
        resolved_shm = shm_path or wal_path.with_name(
            wal_path.name[:-4] + "-shm"
            if wal_path.name.endswith("-wal")
            else wal_path.name + "-shm"
        )
        shm = _read_shm_state(
            Path(resolved_shm),
            wal_header=header,
            magic=magic,
            page_size=page_size,
        )
        scan_limit = shm.mx_frame if shm is not None else physical_frames
        if scan_limit > physical_frames:
            raise WalValidationError("WAL index references missing frames")

        salt = header[16:24]
        valid_frames = 0
        last_commit = 0
        commit_size = 0
        last_frame_checksum = stored_header_checksum
        for index in range(scan_limit):
            frame_header = wal.read(24)
            page = wal.read(page_size)
            if len(frame_header) != 24 or len(page) != page_size:
                if shm is not None:
                    raise WalValidationError("committed WAL frame is truncated")
                break
            page_no, db_size = struct.unpack(">II", frame_header[:8])
            if page_no <= 0 or frame_header[8:16] != salt:
                if shm is not None:
                    raise WalValidationError("committed WAL frame salt/page is invalid")
                break
            checksum = _checksum_bytes(
                frame_header[:8] + page,
                checksum,
                big_endian=big_endian,
            )
            stored_frame_checksum = struct.unpack(">II", frame_header[16:24])
            if checksum != stored_frame_checksum:
                if shm is not None:
                    raise WalValidationError("committed WAL frame checksum mismatch")
                break
            valid_frames += 1
            last_frame_checksum = stored_frame_checksum
            if db_size:
                last_commit = index + 1
                commit_size = db_size

        if shm is not None:
            if valid_frames != shm.mx_frame:
                raise WalValidationError("WAL index committed-frame count mismatch")
            if shm.mx_frame:
                if last_commit != shm.mx_frame or commit_size != shm.n_page:
                    raise WalValidationError("WAL index does not end at a commit frame")
                if last_frame_checksum != shm.frame_checksum:
                    raise WalValidationError("WAL index frame checksum mismatch")
            else:
                last_commit = 0
                commit_size = 0

    return WalPlan(
        True,
        page_size,
        last_commit,
        commit_size,
        valid_frames,
        physical_frames,
        shm is not None,
        signature,
    )


def apply_wal(
    wal_path: Path,
    output_path: Path,
    decrypt_page: Callable[[bytes, int], Optional[bytes]],
    *,
    shm_path: Optional[Path] = None,
    expected_page_size: Optional[int] = None,
) -> int:
    """Validate/decrypt committed frames, then atomically mutate the temp DB.

    Every SQLCipher page is authenticated in a full first pass.  Only after all
    committed pages pass does a second pass write them to the already-private
    plaintext output.  The WAL snapshot identity must remain unchanged across
    both passes.
    """
    wal_path = Path(wal_path)
    plan = inspect_wal(
        wal_path,
        shm_path=shm_path,
        expected_page_size=expected_page_size,
    )
    if not plan.present or plan.frames_to_apply == 0:
        return 0

    def iter_committed():
        with wal_path.open("rb") as wal:
            wal.seek(32)
            for _index in range(plan.frames_to_apply):
                frame_header = wal.read(24)
                page = wal.read(plan.page_size)
                if len(frame_header) != 24 or len(page) != plan.page_size:
                    raise WalValidationError("WAL changed during page recovery")
                page_no = struct.unpack(">I", frame_header[:4])[0]
                yield page_no, page

    # Pass 1: SQLCipher HMAC/decrypt validation, without output mutation.
    for page_no, page in iter_committed():
        plain = decrypt_page(page, page_no)
        if plain is None or len(plain) != plan.page_size:
            raise WalValidationError("SQLCipher WAL page authentication failed")

    # Pass 2: deterministic application through the exact commit boundary.
    applied = 0
    with Path(output_path).open("r+b") as output:
        for page_no, page in iter_committed():
            plain = decrypt_page(page, page_no)
            if plain is None or len(plain) != plan.page_size:
                raise WalValidationError("SQLCipher WAL changed after validation")
            output.seek((page_no - 1) * plan.page_size)
            output.write(plain)
            applied += 1
        output.truncate(plan.commit_size * plan.page_size)

    stat = wal_path.stat()
    final_signature = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    if final_signature != plan.file_signature:
        raise WalValidationError("WAL snapshot changed during recovery")
    return applied
