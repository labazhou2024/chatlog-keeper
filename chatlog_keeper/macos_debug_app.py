"""Create an isolated, reversible debug-enabled copy of a macOS chat client.

The signed app in ``/Applications`` is never modified.  Explicit ``active``
extraction may launch this private copy so Apple's task-port policy can be met
without disabling SIP or weakening the user's daily client.  The WeChat flow
can additionally load chatlog-keeper's fixed startup capture library into only
that non-hardened private copy, before automatic login begins.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
import plistlib
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import BinaryIO, Optional

from chatlog_keeper.core._path_resolver import data_dir

_APPS = {
    "wechat": (Path("/Applications/WeChat.app"), "WeChat"),
    "qq": (Path("/Applications/QQ.app"), "QQ"),
}
_DEBUG_COPY_FORMAT = (
    b"preserve-nested-signatures-v7-wechat-compat-exact-entitlements-kernel-pid"
)
_LAST_ERROR = ""
_RUNTIME_FLAGS_RE = re.compile(
    r"^CodeDirectory\b[^\n]*\bflags=0x[0-9a-f]+\([^\n)]*\bruntime\b[^\n)]*\)",
    re.IGNORECASE | re.MULTILINE,
)
_TEAM_IDENTIFIER_RE = re.compile(
    r"^TeamIdentifier=(?P<team>[^\r\n]+)$",
    re.MULTILINE,
)
_DEBUG_COPY_MARKER = ".chatlog-keeper-debug-copy"
_TRUSTED_DEBUG_COPIES: dict[
    str,
    tuple[str, Path, bytes, int, int],
] = {}


@dataclass(frozen=True)
class _DebugProcessToken:
    source: str
    pid: int
    executable: Path
    path_bytes: bytes
    start_sec: int
    start_usec: int
    lock_file: Optional[BinaryIO] = None


_ACTIVE_DEBUG_PROCESSES: dict[tuple[str, int], _DebugProcessToken] = {}


def last_error() -> str:
    """Return the most recent internal debug-copy launch failure code."""
    return _LAST_ERROR


def clear_last_error() -> None:
    """Clear diagnostics before one independent active-key attempt."""
    global _LAST_ERROR
    _LAST_ERROR = ""


def _run(argv: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _app_identity(app: Path) -> str:
    info = (app / "Contents" / "Info.plist").read_bytes()
    try:
        metadata = plistlib.loads(info)
    except Exception as exc:
        raise OSError("app bundle has an invalid Info.plist") from exc
    executable_name = metadata.get("CFBundleExecutable")
    if not isinstance(executable_name, str) or not executable_name:
        raise OSError("app bundle has no CFBundleExecutable")
    executable = app / "Contents" / "MacOS" / executable_name
    digest = hashlib.sha256()
    digest.update(info)
    with executable.open("rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    digest.update(b"\0chatlog-keeper-debug-copy\0")
    digest.update(_DEBUG_COPY_FORMAT)
    return digest.hexdigest()[:12]


def _private_directory(path: Path) -> bool:
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


def _stable_regular_file_digest(path: Path) -> Optional[bytes]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
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
        return digest.digest()
    except OSError:
        return None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _unsigned_executable_digest(executable: Path) -> Optional[bytes]:
    """Hash Mach-O content after stripping only its mutable code signature."""
    try:
        with tempfile.TemporaryDirectory(prefix="chatlog_unsigned_macho_") as raw:
            candidate = Path(raw) / "executable"
            shutil.copyfile(executable, candidate, follow_symlinks=False)
            removed = _run(
                ["codesign", "--remove-signature", str(candidate)],
                timeout=60,
            )
            if removed.returncode != 0:
                return None
            return _stable_regular_file_digest(candidate)
    except OSError:
        return None


def _bundle_source_digest(app: Path) -> Optional[bytes]:
    """Canonical bundle digest excluding only our top signature and marker.

    The copied main executable is normalized by removing its signature, because
    adding ``get-task-allow`` necessarily changes that signature. Every other
    file and symlink, including nested code signatures, must remain identical
    to the installed source application.
    """
    try:
        root_info = app.lstat()
        if app.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
            return None
        info_path = app / "Contents" / "Info.plist"
        metadata = plistlib.loads(info_path.read_bytes())
        if not isinstance(metadata, dict):
            return None
        executable_name = metadata.get("CFBundleExecutable")
        if not isinstance(executable_name, str) or not executable_name:
            return None
        executable_relative = Path("Contents") / "MacOS" / executable_name
        entries = sorted(
            app.rglob("*"),
            key=lambda item: os.fsencode(item.relative_to(app)),
        )
    except (OSError, ValueError, TypeError):
        return None

    digest = hashlib.sha256()
    digest.update(b"chatlog-debug-copy-source-v1\0")
    marker_relative = Path("Contents") / "Resources" / _DEBUG_COPY_MARKER
    for entry in entries:
        try:
            relative = entry.relative_to(app)
            parts = relative.parts
            if relative == marker_relative:
                continue
            if len(parts) >= 2 and parts[:2] == ("Contents", "_CodeSignature"):
                continue
            info = entry.lstat()
        except (OSError, ValueError):
            return None
        if (
            stat.S_ISDIR(info.st_mode)
            and relative == Path("Contents") / "Resources"
        ):
            # The marker may introduce this conventional directory in a
            # minimal bundle; its descendants remain provenance-relevant.
            continue
        relative_bytes = os.fsencode(relative)
        digest.update(len(relative_bytes).to_bytes(4, "big"))
        digest.update(relative_bytes)
        if stat.S_ISDIR(info.st_mode):
            digest.update(b"D")
            continue
        if stat.S_ISLNK(info.st_mode):
            try:
                target = os.fsencode(os.readlink(entry))
            except OSError:
                return None
            digest.update(b"L")
            digest.update(len(target).to_bytes(4, "big"))
            digest.update(target)
            continue
        if not stat.S_ISREG(info.st_mode):
            return None
        value = (
            _unsigned_executable_digest(entry)
            if relative == executable_relative
            else _stable_regular_file_digest(entry)
        )
        if value is None:
            return None
        digest.update(b"F")
        digest.update((info.st_mode & 0o777).to_bytes(2, "big"))
        digest.update(value)
    return digest.digest()


def _canonical_debug_copy_identity(
    target: Path,
    *,
    expected_root: Path,
    expected_identity: Optional[tuple[int, int]] = None,
) -> Optional[tuple[int, int]]:
    try:
        actual = Path(os.path.abspath(os.fspath(target)))
        root = Path(os.path.abspath(os.fspath(expected_root)))
        info = actual.lstat()
    except OSError:
        return None
    if actual.parent != root or not _private_directory(root):
        return None
    identity = (info.st_dev, info.st_ino)
    if (
        actual.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or (info.st_mode & 0o777) != 0o700
        or (expected_identity is not None and identity != expected_identity)
    ):
        return None
    return identity


def _entitlements(app: Path) -> Optional[dict]:
    proc = _run(["codesign", "-d", "--entitlements", ":-", str(app)], timeout=30)
    raw = (
        (getattr(proc, "stdout", "") or getattr(proc, "stderr", "") or "")
        .encode("utf-8", errors="replace")
    )
    start = raw.find(b"<?xml")
    if start < 0:
        return None
    try:
        value = plistlib.loads(raw[start:])
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _has_hardened_runtime(app: Path) -> bool:
    proc = _run(["codesign", "-d", "--verbose=4", str(app)], timeout=30)
    raw = (
        (getattr(proc, "stdout", "") or "")
        + "\n"
        + (getattr(proc, "stderr", "") or "")
    )
    return proc.returncode == 0 and bool(_RUNTIME_FLAGS_RE.search(raw))


def _copy_uses_hardened_runtime(source: str) -> bool:
    """Return whether the private copy must retain Hardened Runtime.

    WeChat 4.1.12 loads Tencent-signed embedded frameworks. Re-signing only the
    private main executable ad-hoc while retaining Hardened Runtime makes
    Apple's library validation terminate that copy before its UI appears. The
    upstream v0.2 macOS extractor intentionally signs its isolated WeChat copy
    without the runtime flag; keep that compatibility exception scoped to the
    explicit WeChat active-key flow. The original application is never changed.
    """
    return source != "wechat"


def _code_team_identifier(path: Path) -> Optional[str]:
    """Return a signed code object's Team ID, ``""`` for ad-hoc, or ``None``.

    ``codesign --verify`` proves that each signature is internally consistent,
    but Hardened Runtime library validation also compares the main executable's
    Team ID with every embedded library it maps.  Keep that runtime relation as
    a separate, fail-closed check.
    """
    try:
        proc = _run(["codesign", "-d", "--verbose=4", str(path)], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    raw = (
        (getattr(proc, "stdout", "") or "")
        + "\n"
        + (getattr(proc, "stderr", "") or "")
    )
    match = _TEAM_IDENTIFIER_RE.search(raw)
    if match is None:
        return None
    team = match.group("team").strip()
    return "" if team.lower() == "not set" else team


def _direct_embedded_dependencies(
    app: Path,
    executable: Path,
) -> Optional[tuple[Path, ...]]:
    """Resolve direct non-system Mach-O dependencies contained in ``app``.

    Only the main executable's direct load closure is needed to catch the
    launch-blocking mismatch before LaunchServices is invoked. Dependency names
    are treated as untrusted metadata and accepted only after resolving inside
    the copied bundle.
    """
    try:
        proc = _run(["otool", "-L", str(executable)], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        app_root = app.resolve()
        executable_dir = executable.parent.resolve()
    except OSError:
        return None

    resolved: list[Path] = []
    seen: set[Path] = set()
    for line in (getattr(proc, "stdout", "") or "").splitlines():
        stripped = line.strip()
        marker = " (compatibility version "
        if marker not in stripped:
            continue
        install_name = stripped.split(marker, 1)[0]
        if install_name.startswith("@rpath/"):
            candidate = app / "Contents" / "Frameworks" / install_name[7:]
        elif install_name.startswith("@executable_path/"):
            candidate = executable_dir / install_name[len("@executable_path/"):]
        elif install_name.startswith("@loader_path/"):
            candidate = executable_dir / install_name[len("@loader_path/"):]
        elif install_name.startswith("/"):
            # Normalize traversal before trusting Apple's immutable system
            # roots. Do this lexically: some system frameworks resolve through
            # the OS cryptex, while their Mach install name remains rooted at
            # /System/Library.
            candidate = Path(os.path.normpath(install_name))
            system_roots = (Path("/System/Library"), Path("/usr/lib"))
            if any(
                candidate == root or root in candidate.parents
                for root in system_roots
            ):
                continue
        else:
            return None
        try:
            candidate = candidate.resolve()
            candidate.relative_to(app_root)
        except (OSError, ValueError):
            return None
        if not candidate.is_file():
            return None
        if candidate not in seen:
            seen.add(candidate)
            resolved.append(candidate)
    return tuple(resolved)


def _runtime_library_validation_compatible(
    app: Path,
    executable: Path,
) -> Optional[bool]:
    """Return true/false when compatibility is proved, else ``None``."""
    try:
        hardened_runtime = _has_hardened_runtime(executable)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if not hardened_runtime:
        # Library validation is a Hardened Runtime policy. The explicit
        # WeChat compatibility copy follows upstream v0.2 and does not enable
        # that flag, so its preserved Tencent-signed libraries remain loadable.
        # Re-verify here as well as during preparation so a replaced or damaged
        # bundle cannot turn an unreadable signature into a fail-open result.
        try:
            verified = _run(
                ["codesign", "--verify", "--deep", "--strict", str(app)],
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if verified.returncode != 0:
            return None
        return True
    dependencies = _direct_embedded_dependencies(app, executable)
    if dependencies is None:
        return None
    if not dependencies:
        return True

    try:
        entitlements = _entitlements(executable)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if entitlements is None:
        return None
    if entitlements.get("com.apple.security.cs.disable-library-validation") is True:
        return True

    main_team = _code_team_identifier(executable)
    if main_team is None:
        return None
    # Ad-hoc code has no Team ID, so it cannot satisfy Hardened Runtime's
    # same-Team-ID rule for embedded third-party libraries.
    if main_team == "":
        return False
    unverifiable = False
    for dependency in dependencies:
        dependency_team = _code_team_identifier(dependency)
        if dependency_team is None:
            unverifiable = True
        elif dependency_team != main_team:
            return False
    return None if unverifiable else True


def _verified_debug_copy(
    target: Path,
    marker: Path,
    expected_identity: str,
    expected_entitlements: dict,
    *,
    hardened_runtime: bool = True,
) -> bool:
    if not marker.is_file():
        return False
    try:
        if marker.read_text(encoding="ascii").strip() != expected_identity:
            return False
    except (OSError, UnicodeError):
        return False
    current = _entitlements(target) or {}
    verified = _run(
        ["codesign", "--verify", "--deep", "--strict", str(target)], timeout=60
    )
    return (
        verified.returncode == 0
        and current == expected_entitlements
        and current.get("com.apple.security.get-task-allow") is True
        and _has_hardened_runtime(target) is hardened_runtime
        and _code_team_identifier(target) == ""
    )


def _verified_cached_debug_copy(
    target: Path,
    marker: Path,
    expected_identity: str,
    expected_entitlements: dict,
    expected_source_digest: bytes,
    *,
    hardened_runtime: bool,
    expected_generation: Optional[tuple[int, int]] = None,
) -> Optional[tuple[int, int]]:
    """Bind the canonical cache entry back to the installed source bundle."""
    root = data_dir() / "debug-apps"
    identity = _canonical_debug_copy_identity(
        target,
        expected_root=root,
        expected_identity=expected_generation,
    )
    if identity is None or not _verified_debug_copy(
        target,
        marker,
        expected_identity,
        expected_entitlements,
        hardened_runtime=hardened_runtime,
    ):
        return None
    if _bundle_source_digest(target) != expected_source_digest:
        return None
    final = _canonical_debug_copy_identity(
        target,
        expected_root=root,
        expected_identity=identity,
    )
    return final


def _remove_generated_debug_copy(target: Path, *, root: Path) -> bool:
    """Remove only one exact, user-owned generated cache entry."""
    try:
        actual = Path(os.path.abspath(os.fspath(target)))
        expected_root = Path(os.path.abspath(os.fspath(root)))
        info = actual.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if actual.parent != expected_root or info.st_uid != os.geteuid():
        return False
    try:
        if actual.is_symlink() or not stat.S_ISDIR(info.st_mode):
            actual.unlink()
        else:
            shutil.rmtree(actual)
    except OSError:
        return False
    return True


def _validate_prepared_debug_copy(source: str, target: Path) -> bool:
    """Revalidate the canonical bundle generation immediately before launch."""
    configured = _APPS.get(source)
    if configured is None:
        return False
    original, _executable_name = configured
    expected_root = data_dir() / "debug-apps"
    try:
        actual_parent = Path(os.path.abspath(os.fspath(target.parent)))
        canonical_root = Path(os.path.abspath(os.fspath(expected_root)))
    except OSError:
        return False
    # Keep the existing embedding/test hook for explicitly supplied non-cache
    # bundles. Product preparation always returns a child of ``debug-apps``.
    if actual_parent != canonical_root:
        return True
    try:
        identity = _app_identity(original)
    except OSError:
        return False
    original_entitlements = _entitlements(original)
    source_digest = _bundle_source_digest(original)
    if original_entitlements is None or source_digest is None:
        return False
    expected_entitlements = dict(original_entitlements)
    expected_entitlements["com.apple.security.get-task-allow"] = True
    record = _TRUSTED_DEBUG_COPIES.get(source)
    expected_generation = None
    if (
        record is not None
        and record[0] == identity
        and record[1] == target
        and record[2] == source_digest
    ):
        expected_generation = (record[3], record[4])
    marker = target / "Contents" / "Resources" / _DEBUG_COPY_MARKER
    valid = _verified_cached_debug_copy(
        target,
        marker,
        identity,
        expected_entitlements,
        source_digest,
        hardened_runtime=_copy_uses_hardened_runtime(source),
        expected_generation=expected_generation,
    )
    if valid is None:
        return False
    _TRUSTED_DEBUG_COPIES[source] = (
        identity,
        target,
        source_digest,
        valid[0],
        valid[1],
    )
    return True


def prepare_debug_copy(source: str) -> Optional[Path]:
    """Return a verified debug-enabled app copy, or ``None`` on failure."""
    if sys.platform != "darwin" or source not in _APPS:
        return None
    original, _ = _APPS[source]
    if not original.is_dir():
        return None
    try:
        identity = _app_identity(original)
    except OSError:
        return None
    root = data_dir() / "debug-apps"
    if not _private_directory(root):
        return None
    original_entitlements = _entitlements(original)
    source_digest = _bundle_source_digest(original)
    if original_entitlements is None or source_digest is None:
        return None
    expected_entitlements = dict(original_entitlements)
    expected_entitlements["com.apple.security.get-task-allow"] = True
    hardened_runtime = _copy_uses_hardened_runtime(source)

    target = root / f"{original.stem}-{identity}.app"
    marker = (
        target
        / "Contents"
        / "Resources"
        / _DEBUG_COPY_MARKER
    )
    record = _TRUSTED_DEBUG_COPIES.get(source)
    expected_generation = None
    if (
        record is not None
        and record[0] == identity
        and record[1] == target
        and record[2] == source_digest
    ):
        expected_generation = (record[3], record[4])
    try:
        target.lstat()
    except FileNotFoundError:
        target_present = False
    except OSError:
        return None
    else:
        target_present = True
    if target_present:
        valid = _verified_cached_debug_copy(
            target,
            marker,
            identity,
            expected_entitlements,
            source_digest,
            hardened_runtime=hardened_runtime,
            expected_generation=expected_generation,
        )
        if valid is not None:
            _TRUSTED_DEBUG_COPIES[source] = (
                identity,
                target,
                source_digest,
                valid[0],
                valid[1],
            )
            return target
        if not _remove_generated_debug_copy(target, root=root):
            return None
        _TRUSTED_DEBUG_COPIES.pop(source, None)
    if not _private_directory(root):
        return None
    # Build and sign in a private staging directory. A failed ditto/codesign is
    # removed automatically and can be retried; the canonical target appears
    # only after every verification gate passes.
    with tempfile.TemporaryDirectory(
        prefix=f".{original.stem}-{identity}-", dir=str(root)
    ) as temporary:
        stage_root = Path(temporary)
        stage = stage_root / target.name
        copied = _run(["/usr/bin/ditto", str(original), str(stage)], timeout=600)
        if copied.returncode != 0:
            return None

        ent_path = stage_root / "entitlements.plist"
        ent_path.write_bytes(
            plistlib.dumps(expected_entitlements, fmt=plistlib.FMT_XML)
        )
        stage_marker = (
            stage
            / "Contents"
            / "Resources"
            / _DEBUG_COPY_MARKER
        )
        # The provenance marker is covered by the final bundle resource seal.
        stage_marker.parent.mkdir(parents=True, exist_ok=True)
        stage_marker.write_text(identity, encoding="ascii")

        signing_argv = ["codesign", "--force", "--sign", "-"]
        if hardened_runtime:
            signing_argv.extend(["--options", "runtime"])
        signing_argv.extend(["--entitlements", str(ent_path), str(stage)])
        signed = _run(signing_argv, timeout=600)
        if signed.returncode != 0 or not _verified_debug_copy(
            stage,
            stage_marker,
            identity,
            expected_entitlements,
            hardened_runtime=hardened_runtime,
        ):
            return None
        if _bundle_source_digest(stage) != source_digest:
            return None
        try:
            stage.chmod(0o700)
        except OSError:
            return None
        try:
            stage.replace(target)
        except OSError:
            # Another process may have won the same deterministic directory
            # rename race.  macOS can report this as ENOTEMPTY/EEXIST rather
            # than Python's FileExistsError.  Only accept the winner after the
            # complete signature + entitlement + marker verification gate;
            # every other rename error still fails closed.
            valid = _verified_cached_debug_copy(
                target,
                marker,
                identity,
                expected_entitlements,
                source_digest,
                hardened_runtime=hardened_runtime,
            )
            if valid is None:
                return None
            _TRUSTED_DEBUG_COPIES[source] = (
                identity,
                target,
                source_digest,
                valid[0],
                valid[1],
            )
            return target
    valid = _verified_cached_debug_copy(
        target,
        marker,
        identity,
        expected_entitlements,
        source_digest,
        hardened_runtime=hardened_runtime,
    )
    if valid is None:
        return None
    _TRUSTED_DEBUG_COPIES[source] = (
        identity,
        target,
        source_digest,
        valid[0],
        valid[1],
    )
    return target


def _kernel_process_identity(pid: int) -> Optional[tuple[bytes, int, int]]:
    from chatlog_keeper.macos_key import process_identity

    return process_identity(pid)


def _exact_process_pids(executable: Path) -> Optional[tuple[int, ...]]:
    """Return exact-path PIDs, or ``None`` when enumeration was not reliable."""
    from chatlog_keeper.core._macos import _process_pids_for_executable_checked

    complete, pids = _process_pids_for_executable_checked(executable)
    return tuple(pids) if complete else None


def _same_user_process(pid: int) -> bool:
    """Prove that ``pid`` belongs to this effective user, else fail closed."""
    get_euid = getattr(os, "geteuid", None)
    if get_euid is None:
        return False
    try:
        expected_uid = int(get_euid())
    except (OSError, TypeError, ValueError):
        return False
    try:
        proc = _run(
            ["/bin/ps", "-o", "uid=", "-p", str(int(pid))],
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    if proc.returncode != 0 or not isinstance(proc.stdout, str):
        return False
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return False
    try:
        process_uid = int(lines[0], 10)
    except ValueError:
        return False
    return process_uid == expected_uid


def _generation_for_pid(
    source: str,
    executable: Path,
    pid: int,
    *,
    lock_file: Optional[BinaryIO] = None,
) -> Optional[_DebugProcessToken]:
    pids = _exact_process_pids(executable)
    if pids is None or pid not in pids or not _same_user_process(pid):
        return None
    identity = _kernel_process_identity(pid)
    if identity is None:
        return None
    path_bytes, start_sec, start_usec = identity
    token = _DebugProcessToken(
        source,
        pid,
        executable,
        path_bytes,
        start_sec,
        start_usec,
        lock_file,
    )
    if path_bytes != os.fsencode(executable) or not _process_matches(token):
        return None
    return token


def _generation_state(token: _DebugProcessToken) -> str:
    """Return ``same``, ``gone``, ``replaced``, or ``unknown``."""
    pids = _exact_process_pids(token.executable)
    if pids is None:
        return "unknown"
    if token.pid not in pids:
        return "gone"
    identity = _kernel_process_identity(token.pid)
    if identity is None:
        return "unknown"
    if identity != (token.path_bytes, token.start_sec, token.start_usec):
        return "replaced"
    pids = _exact_process_pids(token.executable)
    if pids is None:
        return "unknown"
    if token.pid not in pids:
        return "gone"
    return "same"


def _process_matches(token: _DebugProcessToken) -> bool:
    """Check exact path and kernel process generation."""
    return _generation_state(token) == "same"


def _wait_for_stable_pid(
    source: str,
    executable: Path,
    *,
    wait_s: float,
    settle_s: float,
) -> tuple[Optional[_DebugProcessToken], bool, tuple[_DebugProcessToken, ...]]:
    """Return one stable generation plus every generation observed this launch."""
    wait_s = max(0.0, wait_s)
    settle_s = min(max(0.0, settle_s), wait_s)
    deadline = time.monotonic() + wait_s
    first_seen: dict[tuple[int, int, int], tuple[float, _DebugProcessToken]] = {}
    observed: dict[tuple[int, int, int], _DebugProcessToken] = {}
    saw_pid = False
    while True:
        now = time.monotonic()
        current_keys: set[tuple[int, int, int]] = set()
        pids = _exact_process_pids(executable)
        if pids is None:
            return None, saw_pid, tuple(observed.values())
        saw_pid = saw_pid or bool(pids)
        for pid in pids:
            token = _generation_for_pid(source, executable, pid)
            if token is None:
                continue
            key = (token.pid, token.start_sec, token.start_usec)
            current_keys.add(key)
            observed.setdefault(key, token)
            first_seen.setdefault(key, (now, token))
            started_at, first_token = first_seen[key]
            if now - started_at >= settle_s and _process_matches(first_token):
                return first_token, True, tuple(observed.values())
        for key in tuple(first_seen):
            if key not in current_keys:
                del first_seen[key]
        if now >= deadline:
            return None, saw_pid, tuple(observed.values())
        time.sleep(min(0.25, max(0.0, deadline - now)))


def _acquire_launch_lock(root: Path, source: str) -> Optional[BinaryIO]:
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    lock_path = root / f".{source}-active.lock"
    try:
        handle = lock_path.open("a+b")
        os.chmod(lock_path, 0o600)
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        try:
            handle.close()
        except (OSError, UnboundLocalError):
            pass
        return None
    return handle


def _release_launch_lock(handle: Optional[BinaryIO]) -> None:
    if handle is None:
        return
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        handle.close()
    except OSError:
        pass


def _terminate_generation(
    token: _DebugProcessToken,
    *,
    wait_s: float,
) -> bool:
    """Terminate only ``token`` and prove that exact generation disappeared."""
    initial_state = _generation_state(token)
    if initial_state in {"gone", "replaced"}:
        return True
    if initial_state != "same":
        return False
    try:
        os.kill(token.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    deadline = time.monotonic() + max(0.0, wait_s)
    while time.monotonic() < deadline:
        state = _generation_state(token)
        if state in {"gone", "replaced"}:
            return True
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    state = _generation_state(token)
    if state in {"gone", "replaced"}:
        return True
    if state != "same":
        return False
    try:
        os.kill(token.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    kill_deadline = time.monotonic() + 2.0
    while time.monotonic() < kill_deadline:
        state = _generation_state(token)
        if state in {"gone", "replaced"}:
            return True
        time.sleep(min(0.1, max(0.0, kill_deadline - time.monotonic())))
    return _generation_state(token) in {"gone", "replaced"}


def _cleanup_observed_processes(
    observed: tuple[_DebugProcessToken, ...],
    executable: Path,
) -> bool:
    cleaned = True
    for token in observed:
        cleaned = _terminate_generation(token, wait_s=1.0) and cleaned
    remaining = _exact_process_pids(executable)
    return cleaned and remaining is not None and not remaining


def validate_debug_copy_process(source: str, pid: int) -> bool:
    """Validate that ``pid`` is the exact generation launched for ``source``."""
    token = _ACTIVE_DEBUG_PROCESSES.get((source, pid))
    return bool(token and _process_matches(token))


def debug_copy_process_identity(
    source: str,
    pid: int,
) -> Optional[tuple[bytes, int, int]]:
    """Return the immutable identity expected by the Mach helper."""
    token = _ACTIVE_DEBUG_PROCESSES.get((source, pid))
    if token is None or not _process_matches(token):
        return None
    return token.path_bytes, token.start_sec, token.start_usec


def terminate_debug_copy(
    source: str,
    pid: int,
    *,
    wait_s: float = 5.0,
) -> bool:
    """Terminate and reap only the exact debug-copy generation we launched."""
    global _LAST_ERROR
    key = (source, pid)
    token = _ACTIVE_DEBUG_PROCESSES.pop(key, None)
    if token is None:
        _LAST_ERROR = "debug_copy_cleanup_failed"
        return False
    try:
        generation_cleaned = _terminate_generation(token, wait_s=wait_s)
        remaining = _exact_process_pids(token.executable)
        cleaned = generation_cleaned and remaining is not None and not remaining
        if not cleaned:
            _LAST_ERROR = "debug_copy_cleanup_failed"
        return cleaned
    finally:
        _release_launch_lock(token.lock_file)


def launch_debug_copy(
    source: str,
    wait_s: float = 15.0,
    settle_s: float = 5.0,
    *,
    capture_library: Optional[Path] = None,
    capture_library_identity: Optional[tuple[int, int]] = None,
    capture_fifo: Optional[Path] = None,
    capture_fifo_identity: Optional[tuple[int, int]] = None,
) -> Optional[int]:
    """Launch the isolated copy and return its verified, exact main PID.

    Current WeChat/QQ builds can briefly create a process and then exit when a
    signed daily client already owns the single-instance lock.  A transient
    PID must never be handed to ``task_for_pid``: it produces a misleading SIP
    denial. A private non-blocking lock serializes this lifecycle so one caller
    can clean up only the exact process generation it launched. WeChat returns
    as soon as exact path, same-user ownership, kernel start generation, and
    liveness have all been re-verified so the short login key window is not
    spent on the QQ-oriented settle delay; QQ retains that stability window.
    """
    global _LAST_ERROR
    _LAST_ERROR = ""

    capture_requested = any(
        value is not None
        for value in (
            capture_library,
            capture_library_identity,
            capture_fifo,
            capture_fifo_identity,
        )
    )
    if capture_requested:
        if (
            source != "wechat"
            or capture_library is None
            or capture_library_identity is None
            or capture_fifo is None
            or capture_fifo_identity is None
        ):
            _LAST_ERROR = "capture_launch_configuration_invalid"
            return None
        from chatlog_keeper.macos_wechat_capture import (
            validate_capture_fifo,
            validate_launch_capture_library,
        )

        try:
            same_channel_directory = (
                capture_library.parent.resolve(strict=True)
                == capture_fifo.parent.resolve(strict=True)
            )
        except OSError:
            same_channel_directory = False
        if (
            not same_channel_directory
            or not validate_launch_capture_library(
                capture_library,
                expected_identity=capture_library_identity,
            )
            or not validate_capture_fifo(
                capture_fifo,
                expected_identity=capture_fifo_identity,
            )
        ):
            _LAST_ERROR = "capture_launch_configuration_invalid"
            return None

    original, executable_name = _APPS.get(source, (None, None))
    if source == "wechat" and original is not None and executable_name:
        daily_executable = original / "Contents" / "MacOS" / executable_name
        daily_pids = _exact_process_pids(daily_executable)
        if daily_pids is None:
            _LAST_ERROR = "process_enumeration_failed"
            return None
        if daily_pids:
            _LAST_ERROR = "daily_client_single_instance_conflict"
            return None

    target = prepare_debug_copy(source)
    if not target:
        _LAST_ERROR = "debug_copy_prepare_failed"
        return None
    if not _validate_prepared_debug_copy(source, target):
        _LAST_ERROR = "debug_copy_validation_failed"
        return None
    executable = target / "Contents" / "MacOS" / _APPS[source][1]
    library_validation = _runtime_library_validation_compatible(target, executable)
    if library_validation is not True:
        _LAST_ERROR = (
            "debug_copy_library_validation_incompatible"
            if library_validation is False
            else "debug_copy_library_validation_unverifiable"
        )
        return None
    launch_lock = _acquire_launch_lock(target.parent, source)
    if launch_lock is None:
        _LAST_ERROR = "debug_copy_busy"
        return None

    try:
        existing_pids = _exact_process_pids(executable)
        if existing_pids is None:
            _LAST_ERROR = "process_enumeration_failed"
            return None
        if existing_pids:
            _LAST_ERROR = "debug_copy_already_running"
            return None

        if not _validate_prepared_debug_copy(source, target):
            _LAST_ERROR = "debug_copy_validation_failed"
            return None
        launch_argv = ["/usr/bin/open", "-n"]
        if capture_requested:
            # Revalidate at the last possible moment.  Values are passed as argv
            # entries to LaunchServices, never through a shell or global process
            # environment, and are scoped to this private WeChat launch.
            if not validate_launch_capture_library(
                capture_library,
                expected_identity=capture_library_identity,
            ) or not validate_capture_fifo(
                capture_fifo,
                expected_identity=capture_fifo_identity,
            ):
                _LAST_ERROR = "capture_launch_configuration_invalid"
                return None
            launch_argv.extend(
                [
                    "--env",
                    f"DYLD_INSERT_LIBRARIES={capture_library}",
                    "--env",
                    f"CHATLOG_KEEPER_WECHAT_KEY_FIFO={capture_fifo}",
                ]
            )
        launch_argv.append(str(target))
        launched = _run(launch_argv, timeout=30)
        if launched.returncode != 0:
            _LAST_ERROR = "debug_copy_launch_failed"
            return None
        stable, saw_pid, observed = _wait_for_stable_pid(
            source,
            executable,
            wait_s=wait_s,
            settle_s=0.0 if source == "wechat" else settle_s,
        )
        if stable is not None:
            owned = _DebugProcessToken(
                stable.source,
                stable.pid,
                stable.executable,
                stable.path_bytes,
                stable.start_sec,
                stable.start_usec,
                launch_lock,
            )
            if _process_matches(owned):
                _ACTIVE_DEBUG_PROCESSES[(source, owned.pid)] = owned
                launch_lock = None
                return owned.pid
            cleaned = _cleanup_observed_processes(observed, executable)
            _LAST_ERROR = (
                "debug_copy_identity_changed"
                if cleaned
                else "debug_copy_cleanup_failed"
            )
            return None
        cleaned = _cleanup_observed_processes(observed, executable)
        if not cleaned:
            _LAST_ERROR = "debug_copy_cleanup_failed"
        else:
            _LAST_ERROR = (
                "debug_copy_ephemeral_exit"
                if saw_pid
                else "debug_copy_launch_failed"
            )
        return None
    finally:
        _release_launch_lock(launch_lock)
