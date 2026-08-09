"""Pre-login WeChat master-key candidate capture for macOS.

The original signed client is never modified.  A tiny, locally-built interpose
library is loaded into the already-isolated debug copy at process creation, so
automatic login cannot outrun the key observer.  A byte-identical helper copy
and the same-user ``0600`` FIFO are staged inside WeChat's own sandbox; both are
removed after the exact private process exits. Candidate bytes are never
persisted by this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from typing import Callable, Optional

from chatlog_keeper.core._path_resolver import data_dir

_LAST_ERROR = ""
_CAPTURE_FORMAT = b"wechat-pbkdf2-startup-interpose-v1"
_RECORD_MAGIC = b"WXK1"
_RECORD_SIZE = len(_RECORD_MAGIC) + 32
_MAX_BUFFER_BYTES = _RECORD_SIZE * 1024
_TEAM_IDENTIFIER_RE = re.compile(
    r"^TeamIdentifier=(?P<team>[^\r\n]+)$",
    re.MULTILINE,
)
_TRUSTED_CAPTURE_LIBRARY: Optional[
    tuple[bytes, Path, bytes, int, int]
] = None


def last_error() -> str:
    return _LAST_ERROR


def clear_last_error() -> None:
    global _LAST_ERROR
    _LAST_ERROR = ""


def _source_path() -> Path:
    return Path(__file__).resolve().parent / "scripts" / "macos_wechat_key_capture.c"


def _prebuilt_path() -> Path:
    return Path(__file__).resolve().parent / "scripts" / "macos_wechat_key_capture.dylib"


def _helper_input_path() -> Path:
    prebuilt = _prebuilt_path()
    return prebuilt if prebuilt.is_file() else _source_path()


def _capture_library_path() -> Path:
    digest = hashlib.sha256()
    digest.update(_helper_input_path().read_bytes())
    digest.update(b"\0chatlog-keeper-wechat-capture\0")
    digest.update(_CAPTURE_FORMAT)
    return data_dir() / "bin" / f"macos-wechat-key-capture-{digest.hexdigest()[:12]}.dylib"


def _capture_build_digest() -> bytes:
    digest = hashlib.sha256()
    digest.update(_helper_input_path().read_bytes())
    digest.update(b"\0chatlog-keeper-wechat-capture\0")
    digest.update(_CAPTURE_FORMAT)
    return digest.digest()


def _ensure_private_directory(path: Path) -> bool:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
        ):
            return False
        if (info.st_mode & 0o777) != 0o700:
            path.chmod(0o700)
            current = path.lstat()
            if (
                (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                or (current.st_mode & 0o777) != 0o700
            ):
                return False
        return True
    except OSError:
        return False


def _is_private_regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == os.geteuid()
        and (info.st_mode & 0o077) == 0
    )


def _codesign_valid(path: Path) -> bool:
    try:
        verified = subprocess.run(
            ["codesign", "--verify", "--strict", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return verified.returncode == 0


def _code_team_identifier(path: Path) -> Optional[str]:
    try:
        described = subprocess.run(
            ["codesign", "-d", "--verbose=4", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if described.returncode != 0:
        return None
    raw = (described.stdout or "") + "\n" + (described.stderr or "")
    match = _TEAM_IDENTIFIER_RE.search(raw)
    if match is None:
        return None
    team = match.group("team").strip()
    return "" if team.lower() == "not set" else team


def _file_digest_and_identity(
    path: Path,
    *,
    expected_mode: int,
) -> Optional[tuple[bytes, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or (before.st_mode & 0o777) != expected_mode
        ):
            return None
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        entry = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (entry.st_dev, entry.st_ino) != (before.st_dev, before.st_ino)
            or path.is_symlink()
        ):
            return None
        return digest.digest(), before.st_dev, before.st_ino
    except OSError:
        return None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _file_digest(path: Path) -> Optional[bytes]:
    value = _file_digest_and_identity(path, expected_mode=0o700)
    return value[0] if value is not None else None


def _validate_capture_artifact(
    path: Path,
    *,
    expected_digest: bytes,
    expected_identity: Optional[tuple[int, int]] = None,
    require_canonical_path: bool,
) -> Optional[tuple[int, int]]:
    try:
        actual = Path(os.path.abspath(os.fspath(path)))
        expected = Path(os.path.abspath(os.fspath(_capture_library_path())))
    except OSError:
        return None
    if require_canonical_path and actual != expected:
        return None
    if require_canonical_path and not _ensure_private_directory(expected.parent):
        return None
    first = _file_digest_and_identity(actual, expected_mode=0o700)
    if first is None or first[0] != expected_digest:
        return None
    identity = (first[1], first[2])
    if expected_identity is not None and identity != expected_identity:
        return None
    if not _codesign_valid(actual) or _code_team_identifier(actual) != "":
        return None
    second = _file_digest_and_identity(actual, expected_mode=0o700)
    if second is None or second[0] != expected_digest:
        return None
    if (second[1], second[2]) != identity:
        return None
    return identity


def validate_capture_library(path: Path) -> bool:
    """Prove that ``path`` is our private, signed deterministic helper."""
    trusted = _TRUSTED_CAPTURE_LIBRARY
    if trusted is None:
        return False
    try:
        expected = Path(os.path.abspath(os.fspath(_capture_library_path())))
        actual = Path(os.path.abspath(os.fspath(Path(path))))
        build_digest = _capture_build_digest()
    except OSError:
        return False
    trusted_build, trusted_path, artifact_digest, device, inode = trusted
    if (
        actual != expected
        or trusted_build != build_digest
        or trusted_path != expected
    ):
        return False
    return _validate_capture_artifact(
        actual,
        expected_digest=artifact_digest,
        expected_identity=(device, inode),
        require_canonical_path=True,
    ) is not None


def validate_launch_capture_library(
    path: Path,
    *,
    expected_identity: tuple[int, int],
) -> bool:
    """Validate the exact helper copy staged inside WeChat's sandbox."""
    staged = Path(path)
    source = _capture_library_path()
    if not staged.is_absolute() or not validate_capture_library(source):
        return False
    try:
        info = staged.lstat()
        resolved_parent = staged.parent.resolve(strict=True)
    except OSError:
        return False
    if (
        not _is_private_regular_file(staged)
        or (info.st_mode & 0o777) != 0o700
        or expected_identity != (info.st_dev, info.st_ino)
        or resolved_parent.name != "tmp"
        or resolved_parent.parent.name != "Data"
        or not staged.name.startswith(".chatlog-key-")
        or not staged.name.endswith(".dylib")
    ):
        return False
    source_digest = _file_digest(source)
    if source_digest is None:
        return False
    return _validate_capture_artifact(
        staged,
        expected_digest=source_digest,
        expected_identity=expected_identity,
        require_canonical_path=False,
    ) is not None


def ensure_capture_library() -> Optional[Path]:
    """Build/sign the local interpose library before the private app starts."""
    global _LAST_ERROR, _TRUSTED_CAPTURE_LIBRARY
    _LAST_ERROR = ""
    if sys.platform != "darwin":
        _LAST_ERROR = "capture_platform_unsupported"
        return None
    source = _source_path()
    prebuilt = _prebuilt_path()
    if not source.is_file() and not prebuilt.is_file():
        _LAST_ERROR = "capture_source_missing"
        return None
    try:
        build_digest = _capture_build_digest()
        helper = _capture_library_path()
    except OSError:
        _LAST_ERROR = "capture_source_unreadable"
        return None
    trusted = _TRUSTED_CAPTURE_LIBRARY
    if trusted is not None and trusted[:2] == (build_digest, helper):
        if validate_capture_library(helper):
            return helper
    _TRUSTED_CAPTURE_LIBRARY = None
    if not _ensure_private_directory(helper.parent):
        _LAST_ERROR = "capture_cache_directory_invalid"
        return None
    temporary: Optional[Path] = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{helper.name}.",
            suffix=".tmp",
            dir=str(helper.parent),
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        if prebuilt.is_file():
            temporary.write_bytes(prebuilt.read_bytes())
        else:
            compiled = subprocess.run(
                [
                    "xcrun",
                    "clang",
                    "-dynamiclib",
                    "-arch",
                    "arm64",
                    "-mmacosx-version-min=11.0",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    str(source),
                    "-Wl,-install_name,@rpath/macos_wechat_key_capture.dylib",
                    "-o",
                    str(temporary),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if compiled.returncode != 0:
                _LAST_ERROR = "capture_compile_failed"
                return None
        temporary.chmod(0o700)
        signed = subprocess.run(
            [
                "codesign",
                "--force",
                "--sign",
                "-",
                "--identifier",
                "com.memexa.chatlog-keeper.macos-wechat-key-capture",
                str(temporary),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if signed.returncode != 0:
            _LAST_ERROR = "capture_codesign_failed"
            return None
        artifact = _file_digest_and_identity(temporary, expected_mode=0o700)
        if (
            artifact is None
            or not _codesign_valid(temporary)
            or _code_team_identifier(temporary) != ""
        ):
            _LAST_ERROR = "capture_signature_validation_failed"
            return None
        if _capture_build_digest() != build_digest:
            _LAST_ERROR = "capture_source_changed_during_build"
            return None
        os.replace(temporary, helper)
        temporary = None
        helper.chmod(0o700)
        identity = _validate_capture_artifact(
            helper,
            expected_digest=artifact[0],
            require_canonical_path=True,
        )
        if identity is None:
            _LAST_ERROR = "capture_validation_failed"
            return None
        _TRUSTED_CAPTURE_LIBRARY = (
            build_digest,
            helper,
            artifact[0],
            identity[0],
            identity[1],
        )
        return helper
    except subprocess.TimeoutExpired:
        _LAST_ERROR = "capture_build_timeout"
        return None
    except OSError as exc:
        _LAST_ERROR = f"capture_build_failed:{type(exc).__name__}"
        return None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _container_tmp_for_database(db_path: Path) -> Optional[Path]:
    """Resolve the owning WeChat sandbox ``Data/tmp`` without guessing paths."""
    try:
        database = Path(db_path).resolve(strict=True)
    except OSError:
        return None
    xwechat_root = next(
        (parent for parent in database.parents if parent.name == "xwechat_files"),
        None,
    )
    if xwechat_root is None or xwechat_root.parent.name != "Documents":
        return None
    container_data = xwechat_root.parent.parent
    if container_data.name != "Data":
        return None
    try:
        resolved_data = container_data.resolve(strict=True)
    except OSError:
        return None
    tmp_dir = resolved_data / "tmp"
    try:
        tmp_dir.mkdir(mode=0o700, exist_ok=True)
        resolved_tmp = tmp_dir.resolve(strict=True)
        resolved_tmp.relative_to(resolved_data)
    except (OSError, ValueError):
        return None
    return resolved_tmp


@dataclass
class CaptureChannel:
    path: Path
    read_fd: int
    device: int
    inode: int
    _buffer: bytearray = field(default_factory=bytearray)
    invalid: bool = False
    closed: bool = False
    library_path: Optional[Path] = None
    library_device: Optional[int] = None
    library_inode: Optional[int] = None

    @property
    def identity(self) -> tuple[int, int]:
        return self.device, self.inode

    @property
    def library_identity(self) -> Optional[tuple[int, int]]:
        if self.library_device is None or self.library_inode is None:
            return None
        return self.library_device, self.library_inode

    def read_candidates(self) -> list[bytes]:
        """Drain complete fixed-size records without blocking or logging bytes."""
        global _LAST_ERROR
        if self.closed or self.invalid:
            return []
        while True:
            try:
                chunk = os.read(self.read_fd, 4096)
            except BlockingIOError:
                break
            except OSError:
                self.invalid = True
                _LAST_ERROR = "capture_channel_read_failed"
                return []
            if not chunk:
                break
            self._buffer.extend(chunk)
            if len(self._buffer) > _MAX_BUFFER_BYTES:
                self.invalid = True
                _LAST_ERROR = "capture_channel_limit_exceeded"
                return []

        candidates: list[bytes] = []
        while len(self._buffer) >= _RECORD_SIZE:
            record = bytes(self._buffer[:_RECORD_SIZE])
            del self._buffer[:_RECORD_SIZE]
            if not record.startswith(_RECORD_MAGIC):
                self.invalid = True
                _LAST_ERROR = "capture_channel_invalid_record"
                return []
            candidates.append(record[len(_RECORD_MAGIC):])
        return candidates

    def close(self) -> bool:
        """Close and unlink only the exact FIFO/helper generations we created."""
        global _LAST_ERROR
        if self.closed:
            return True
        self.closed = True
        cleaned = True
        cleanup_error = ""
        try:
            os.close(self.read_fd)
        except OSError:
            cleaned = False
            cleanup_error = "capture_channel_cleanup_failed"

        entries = [
            (
                self.path,
                stat.S_ISFIFO,
                0o600,
                self.device,
                self.inode,
                "capture_channel_identity_changed",
            )
        ]
        if (
            self.library_path is not None
            and self.library_device is not None
            and self.library_inode is not None
        ):
            entries.append(
                (
                    self.library_path,
                    stat.S_ISREG,
                    0o700,
                    self.library_device,
                    self.library_inode,
                    "capture_library_identity_changed",
                )
            )
        for path, kind_check, mode, device, inode, identity_error in entries:
            try:
                info = path.lstat()
                exact = (
                    kind_check(info.st_mode)
                    and not path.is_symlink()
                    and info.st_uid == os.geteuid()
                    and (info.st_mode & 0o777) == mode
                    and info.st_dev == device
                    and info.st_ino == inode
                )
                if not exact:
                    cleaned = False
                    cleanup_error = cleanup_error or identity_error
                    continue
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                cleaned = False
                cleanup_error = cleanup_error or "capture_channel_cleanup_failed"
        if not cleaned:
            _LAST_ERROR = cleanup_error or "capture_channel_cleanup_failed"
        return cleaned


def stage_capture_library(
    channel: CaptureChannel,
    source_library: Path,
) -> bool:
    """Copy the verified helper into the app-sandbox-visible channel directory."""
    global _LAST_ERROR
    source = Path(source_library)
    if not validate_capture_library(source):
        _LAST_ERROR = "capture_validation_failed"
        return False
    destination = channel.path.with_suffix(".dylib")
    source_fd = None
    destination_fd = None
    destination_identity: Optional[tuple[int, int]] = None
    stage_error = ""
    try:
        read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        read_flags |= getattr(os, "O_NOFOLLOW", 0)
        write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        write_flags |= getattr(os, "O_CLOEXEC", 0)
        write_flags |= getattr(os, "O_NOFOLLOW", 0)
        source_fd = os.open(source, read_flags)
        destination_fd = os.open(destination, write_flags, 0o700)
        os.fchmod(destination_fd, 0o700)
        destination_info = os.fstat(destination_fd)
        destination_identity = (
            destination_info.st_dev,
            destination_info.st_ino,
        )
        while True:
            chunk = os.read(source_fd, 1 << 20)
            if not chunk:
                break
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_fd, chunk[offset:])
                if written <= 0:
                    raise OSError("short capture-library write")
                offset += written
        os.fsync(destination_fd)
    except OSError as exc:
        stage_error = f"capture_library_stage_failed:{type(exc).__name__}"
    finally:
        for fd in (source_fd, destination_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass

    if stage_error:
        _LAST_ERROR = stage_error
        try:
            info = destination.lstat()
            if destination_identity is None or destination_identity == (
                info.st_dev,
                info.st_ino,
            ):
                destination.unlink()
        except OSError:
            pass
        return False
    if destination_identity is None:
        _LAST_ERROR = "capture_library_stage_failed:unknown"
        try:
            destination.unlink()
        except OSError:
            pass
        return False

    if not validate_launch_capture_library(
        destination,
        expected_identity=destination_identity,
    ):
        _LAST_ERROR = "capture_library_stage_validation_failed"
        try:
            info = destination.lstat()
            if destination_identity == (info.st_dev, info.st_ino):
                destination.unlink()
        except OSError:
            pass
        return False
    channel.library_path = destination
    channel.library_device, channel.library_inode = destination_identity
    return True


def create_capture_channel(
    db_path: Path,
    *,
    capture_library: Optional[Path] = None,
    _durable_record: Optional[Callable[[CaptureChannel], None]] = None,
) -> Optional[CaptureChannel]:
    """Create the FIFO and optional verified helper inside WeChat's sandbox."""
    global _LAST_ERROR
    _LAST_ERROR = ""
    tmp_dir = _container_tmp_for_database(Path(db_path))
    if tmp_dir is None:
        _LAST_ERROR = "capture_sandbox_path_unavailable"
        return None
    flags = os.O_RDONLY | os.O_NONBLOCK
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for _ in range(16):
        path = tmp_dir / f".chatlog-key-{secrets.token_hex(16)}.fifo"
        try:
            os.mkfifo(path, 0o600)
            os.chmod(path, 0o600)
            info = path.lstat()
            if (
                not stat.S_ISFIFO(info.st_mode)
                or info.st_uid != os.geteuid()
                or (info.st_mode & 0o777) != 0o600
            ):
                path.unlink(missing_ok=True)
                continue
            read_fd = os.open(path, flags)
            channel = CaptureChannel(path, read_fd, info.st_dev, info.st_ino)
            if capture_library is not None and not stage_capture_library(
                channel,
                capture_library,
            ):
                channel.close()
                return None
            if _durable_record is not None:
                try:
                    _durable_record(channel)
                except BaseException:
                    channel.close()
                    raise
            return channel
        except FileExistsError:
            continue
        except OSError as exc:
            try:
                path.unlink()
            except OSError:
                pass
            _LAST_ERROR = f"capture_channel_create_failed:{type(exc).__name__}"
            return None
    _LAST_ERROR = "capture_channel_name_exhausted"
    return None


def validate_capture_fifo(
    path: Path,
    *,
    expected_identity: Optional[tuple[int, int]] = None,
) -> bool:
    """Validate the FIFO immediately before handing it to LaunchServices."""
    try:
        info = Path(path).lstat()
    except OSError:
        return False
    valid = (
        stat.S_ISFIFO(info.st_mode)
        and not Path(path).is_symlink()
        and info.st_uid == os.geteuid()
        and (info.st_mode & 0o777) == 0o600
    )
    if not valid:
        return False
    return expected_identity is None or expected_identity == (
        info.st_dev,
        info.st_ino,
    )
