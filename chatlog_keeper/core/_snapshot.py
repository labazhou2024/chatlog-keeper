"""Consistent private snapshots of a SQLite/SQLCipher DB family."""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

_SIDECAR_SUFFIXES = ("-wal", "-shm")
_MAX_SNAPSHOT_ATTEMPTS = 3


def _copy_file(source: Path, destination: Path) -> None:
    # APFS clone-copy is effectively immediate and avoids reading a changing
    # multi-GB DB through Python. Fall back for non-APFS filesystems/platforms.
    if sys.platform == "darwin":
        proc = subprocess.run(
            ["/bin/cp", "-c", "-p", str(source), str(destination)],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if proc.returncode == 0:
            return
    shutil.copy2(source, destination)


def _file_fingerprint(path: Path, size: int) -> str:
    """Hash bounded edge content so mmap/in-place sidecar writes are visible."""
    digest = hashlib.blake2b(digest_size=16)
    with path.open("rb") as handle:
        digest.update(handle.read(4096))
        if size > 4096:
            handle.seek(max(4096, size - 4096))
            digest.update(handle.read(4096))
    return digest.hexdigest()


def _family_signature(
    db_path: Path,
) -> tuple[tuple[str, bool, int, int, str], ...]:
    """Detect both metadata changes and in-place WAL-index generation changes."""
    signature = []
    for suffix in ("", *_SIDECAR_SUFFIXES):
        path = db_path if not suffix else db_path.with_name(db_path.name + suffix)
        try:
            stat = path.stat()
        except FileNotFoundError:
            signature.append((suffix, False, 0, 0, ""))
        else:
            try:
                fingerprint = _file_fingerprint(path, stat.st_size)
            except FileNotFoundError:
                signature.append((suffix, False, 0, 0, ""))
            else:
                signature.append(
                    (suffix, True, stat.st_size, stat.st_mtime_ns, fingerprint)
                )
    return tuple(signature)


def read_stable_prefix(db_path: Path, size: int) -> bytes:
    """Read a DB prefix only when the live DB family stays unchanged.

    Key HMAC verification only needs page 1. Cloning a multi-GB database merely
    to read 4 KiB is wasteful on non-APFS storage, but a plain read can race a
    WAL checkpoint or DB replacement. Comparing the main/WAL/SHM signature
    around the bounded read gives the verifier the same fail-closed stability
    guarantee without copying the family.
    """
    db_path = Path(db_path)
    if size <= 0:
        raise ValueError("size must be positive")
    for _attempt in range(_MAX_SNAPSHOT_ATTEMPTS):
        before = _family_signature(db_path)
        if not before[0][1]:
            raise FileNotFoundError(db_path)
        try:
            with db_path.open("rb") as handle:
                value = handle.read(size)
        except FileNotFoundError:
            continue
        if len(value) == size and before == _family_signature(db_path):
            return value
    raise OSError(
        f"database remained active during {_MAX_SNAPSHOT_ATTEMPTS} prefix reads: "
        f"{db_path.name}"
    )


@contextmanager
def snapshot_db_family(db_path: Path) -> Iterator[Path]:
    """Yield a stable private DB copy with any ``-wal``/``-shm`` siblings.

    SQLCipher cannot be opened through Python's SQLite backup API before it is
    decrypted. We therefore clone the file family and require its size/mtime
    signature to be unchanged across the copy. A busy writer gets three fast
    retries instead of silently producing a main-DB/WAL mixture from different
    moments.
    """
    db_path = Path(db_path)
    with tempfile.TemporaryDirectory(prefix="chatlog_db_snapshot_") as tmp:
        root = Path(tmp)
        snap = root / db_path.name
        for _attempt in range(_MAX_SNAPSHOT_ATTEMPTS):
            before = _family_signature(db_path)
            if not before[0][1]:
                raise FileNotFoundError(db_path)
            for suffix in ("", *_SIDECAR_SUFFIXES):
                destination = (
                    snap if not suffix else snap.with_name(snap.name + suffix)
                )
                destination.unlink(missing_ok=True)
            try:
                _copy_file(db_path, snap)
                for suffix in _SIDECAR_SUFFIXES:
                    sidecar = db_path.with_name(db_path.name + suffix)
                    if sidecar.is_file():
                        _copy_file(sidecar, snap.with_name(snap.name + suffix))
            except FileNotFoundError:
                continue
            if before == _family_signature(db_path):
                yield snap
                return
        raise OSError(
            f"database remained active during {_MAX_SNAPSHOT_ATTEMPTS} snapshot attempts: "
            f"{db_path.name}"
        )


@contextmanager
def snapshot_db_families(db_paths: Iterable[Path]) -> Iterator[dict[Path, Path]]:
    """Yield one stable copy-set for every requested live DB family.

    The aggregate before/after fence covers each main file plus its WAL/SHM
    sidecars.  SQLite connections are opened only after the copies are yielded,
    so any SHM files created by the reader beside a private copy cannot create
    a false change in the live-family fence.
    """

    paths = tuple(dict.fromkeys(Path(path) for path in db_paths))
    if not paths:
        raise ValueError("at least one database family is required")
    with tempfile.TemporaryDirectory(prefix="chatlog_db_families_snapshot_") as tmp:
        root = Path(tmp)
        snapshots = {
            path: root / f"{index:04d}_{path.name}"
            for index, path in enumerate(paths)
        }
        for _attempt in range(_MAX_SNAPSHOT_ATTEMPTS):
            before = {path: _family_signature(path) for path in paths}
            if any(not signature[0][1] for signature in before.values()):
                raise FileNotFoundError("database family is unavailable")
            for snapshot in snapshots.values():
                for suffix in ("", *_SIDECAR_SUFFIXES):
                    target = (
                        snapshot
                        if not suffix
                        else snapshot.with_name(snapshot.name + suffix)
                    )
                    target.unlink(missing_ok=True)
            try:
                for path in paths:
                    snapshot = snapshots[path]
                    _copy_file(path, snapshot)
                    for suffix in _SIDECAR_SUFFIXES:
                        sidecar = path.with_name(path.name + suffix)
                        if sidecar.is_file():
                            _copy_file(
                                sidecar,
                                snapshot.with_name(snapshot.name + suffix),
                            )
            except FileNotFoundError:
                continue
            after = {path: _family_signature(path) for path in paths}
            if before == after:
                yield dict(snapshots)
                return
        raise OSError(
            "database families remained active during "
            f"{_MAX_SNAPSHOT_ATTEMPTS} snapshot attempts"
        )
