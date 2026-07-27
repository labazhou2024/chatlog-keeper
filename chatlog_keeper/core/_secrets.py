"""Local secret-file writes with atomic replacement and restrictive modes."""
from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, IO, Iterator, TextIO, cast


@contextmanager
def _private_writer(
    path: Path, *, binary: bool, secure_parent: bool
) -> Iterator[IO]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if secure_parent and os.name != "nt":
        path.parent.chmod(0o700)

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        if binary:
            handle = os.fdopen(fd, "wb")
        else:
            handle = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        fd = -1
        with handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            path.chmod(0o600)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            tmp.unlink()
        except OSError:
            pass


@contextmanager
def private_text_writer(
    path: Path, *, secure_parent: bool = False
) -> Iterator[TextIO]:
    """Yield an atomic UTF-8 writer whose published file is owner-only.

    ``mkstemp`` prevents a symlink race and starts private on POSIX.  The
    explicit chmods make the guarantee independent of the caller's umask.
    Existing output directories are left alone unless ``secure_parent`` is
    requested for a secret cache directory.
    """
    with _private_writer(
        path, binary=False, secure_parent=secure_parent
    ) as handle:
        yield cast(TextIO, handle)


@contextmanager
def private_binary_writer(
    path: Path, *, secure_parent: bool = False
) -> Iterator[BinaryIO]:
    """Binary counterpart to :func:`private_text_writer`."""
    with _private_writer(
        path, binary=True, secure_parent=secure_parent
    ) as handle:
        yield cast(BinaryIO, handle)


def write_secret_text(path: Path, text: str) -> bool:
    try:
        with private_text_writer(path, secure_parent=True) as handle:
            handle.write(text)
        return True
    except OSError:
        return False
