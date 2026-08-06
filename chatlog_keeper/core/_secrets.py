"""Private local secret files with bounded, race-aware reads and writes."""
from __future__ import annotations

import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, IO, Iterator, Optional, TextIO, cast


_DEFAULT_MAX_SECRET_BYTES = 4096
_WINDOWS_REPARSE_POINT = 0x0400
_WINDOWS_FULL_CONTROL = 0x001F01FF
_WINDOWS_SYSTEM_SID = "S-1-5-18"


def _is_windows() -> bool:
    return os.name == "nt"


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _is_reparse_point(value: os.stat_result) -> bool:
    return bool(
        getattr(value, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    )


def _posix_parent_is_private(value: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == os.geteuid()
        and stat.S_IMODE(value.st_mode) == 0o700
    )


def _posix_file_is_private(value: os.stat_result) -> bool:
    return (
        stat.S_ISREG(value.st_mode)
        and value.st_uid == os.geteuid()
        and stat.S_IMODE(value.st_mode) == 0o600
    )


def _windows_current_user_sid() -> Optional[str]:
    """Return the process token's user SID without invoking a shell."""
    if not _is_windows():
        return None
    try:
        import ctypes
        from ctypes import wintypes

        token_query = 0x0008
        token_user_class = 1
        token = wintypes.HANDLE()
        kernel32 = ctypes.windll.kernel32
        advapi32 = ctypes.windll.advapi32
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), token_query, ctypes.byref(token)
        ):
            return None
        try:
            needed = wintypes.DWORD()
            advapi32.GetTokenInformation(
                token, token_user_class, None, 0, ctypes.byref(needed)
            )
            if needed.value == 0:
                return None
            buffer = ctypes.create_string_buffer(needed.value)
            if not advapi32.GetTokenInformation(
                token,
                token_user_class,
                buffer,
                needed,
                ctypes.byref(needed),
            ):
                return None
            sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
            if not sid_pointer:
                return None
            string_sid = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(
                ctypes.c_void_p(sid_pointer), ctypes.byref(string_sid)
            ):
                return None
            try:
                return str(string_sid.value or "") or None
            finally:
                kernel32.LocalFree(ctypes.cast(string_sid, ctypes.c_void_p))
        finally:
            kernel32.CloseHandle(token)
    except Exception:  # noqa: BLE001 - Win32 binding failures must fail closed
        return None


def _windows_apply_private_acl(path: Path, *, directory: bool) -> bool:
    """Replace a Windows DACL with current-user and LocalSystem full control.

    SDDL is converted and installed through the standard Windows security API;
    inheritance is disabled.  Callers always verify the resulting ACL before a
    secret is read or published.
    """
    if not _is_windows():
        return False
    sid = _windows_current_user_sid()
    if not sid:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        owner_security_information = 0x00000001
        dacl_security_information = 0x00000004
        protected_dacl_security_information = 0x80000000
        se_file_object = 1
        inheritance = "OICI" if directory else ""
        aces = [f"(A;{inheritance};FA;;;{sid})"]
        if sid != _WINDOWS_SYSTEM_SID:
            aces.append(f"(A;{inheritance};FA;;;SY)")
        sddl = f"O:{sid}D:P{''.join(aces)}"
        security_descriptor = ctypes.c_void_p()
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
            wintypes.BOOL
        )
        advapi32.GetSecurityDescriptorOwner.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
        advapi32.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        advapi32.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(security_descriptor), None
        ):
            return False
        try:
            owner = ctypes.c_void_p()
            owner_defaulted = wintypes.BOOL()
            if not advapi32.GetSecurityDescriptorOwner(
                security_descriptor,
                ctypes.byref(owner),
                ctypes.byref(owner_defaulted),
            ):
                return False
            dacl_present = wintypes.BOOL()
            dacl = ctypes.c_void_p()
            dacl_defaulted = wintypes.BOOL()
            if not advapi32.GetSecurityDescriptorDacl(
                security_descriptor,
                ctypes.byref(dacl_present),
                ctypes.byref(dacl),
                ctypes.byref(dacl_defaulted),
            ):
                return False
            if not dacl_present.value or not dacl.value:
                return False
            result = advapi32.SetNamedSecurityInfoW(
                str(path),
                se_file_object,
                owner_security_information
                | dacl_security_information
                | protected_dacl_security_information,
                owner,
                None,
                dacl,
                None,
            )
            return result == 0
        finally:
            kernel32.LocalFree(security_descriptor)
    except Exception:  # noqa: BLE001 - Win32 binding failures must fail closed
        return False


def _windows_sid_to_string(pointer) -> Optional[str]:
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        string_sid = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(pointer, ctypes.byref(string_sid)):
            return None
        try:
            return str(string_sid.value or "") or None
        finally:
            kernel32.LocalFree(ctypes.cast(string_sid, ctypes.c_void_p))
    except Exception:  # noqa: BLE001 - Win32 binding failures must fail closed
        return None


def _windows_acl_is_private(path: Path) -> bool:
    """Verify an exact protected DACL for current user plus LocalSystem."""
    if not _is_windows():
        return False
    current_sid = _windows_current_user_sid()
    if not current_sid:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class _Acl(ctypes.Structure):
            _fields_ = [
                ("revision", ctypes.c_ubyte),
                ("reserved", ctypes.c_ubyte),
                ("size", wintypes.WORD),
                ("ace_count", wintypes.WORD),
                ("reserved2", wintypes.WORD),
            ]

        class _AceHeader(ctypes.Structure):
            _fields_ = [
                ("ace_type", ctypes.c_ubyte),
                ("ace_flags", ctypes.c_ubyte),
                ("ace_size", wintypes.WORD),
            ]

        se_file_object = 1
        owner_security_information = 0x00000001
        dacl_security_information = 0x00000004
        inherited_ace = 0x10
        access_allowed_ace = 0x00
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        security_descriptor = ctypes.c_void_p()
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        advapi32.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
        advapi32.GetAce.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        advapi32.GetAce.restype = wintypes.BOOL
        advapi32.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
        result = advapi32.GetNamedSecurityInfoW(
            str(path),
            se_file_object,
            owner_security_information | dacl_security_information,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(security_descriptor),
        )
        if result != 0 or not security_descriptor.value:
            return False
        try:
            if _windows_sid_to_string(owner) != current_sid or not dacl.value:
                return False
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not advapi32.GetSecurityDescriptorControl(
                security_descriptor,
                ctypes.byref(control),
                ctypes.byref(revision),
            ):
                return False
            if not control.value & 0x1000:  # SE_DACL_PROTECTED
                return False
            acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
            expected = {current_sid, _WINDOWS_SYSTEM_SID}
            if acl.ace_count != len(expected):
                return False
            observed = set()
            for index in range(acl.ace_count):
                ace = ctypes.c_void_p()
                if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                    return False
                header = ctypes.cast(ace, ctypes.POINTER(_AceHeader)).contents
                if (
                    header.ace_type != access_allowed_ace
                    or header.ace_flags & inherited_ace
                    or header.ace_size < 20
                ):
                    return False
                mask = ctypes.c_uint32.from_address(ace.value + 4).value
                sid = _windows_sid_to_string(ctypes.c_void_p(ace.value + 8))
                if sid not in expected or mask != _WINDOWS_FULL_CONTROL:
                    return False
                observed.add(sid)
            return observed == expected
        finally:
            kernel32.LocalFree(security_descriptor)
    except Exception:  # noqa: BLE001 - Win32 binding failures must fail closed
        return False


def _secret_parent_is_safe(value: os.stat_result) -> bool:
    if _is_reparse_point(value) or not stat.S_ISDIR(value.st_mode):
        return False
    if _is_windows():
        return True
    return _posix_parent_is_private(value)


def _secret_file_is_safe(value: os.stat_result) -> bool:
    if _is_reparse_point(value) or not stat.S_ISREG(value.st_mode):
        return False
    if _is_windows():
        return True
    return _posix_file_is_private(value)


def _prepare_secret_parent(path: Path) -> os.stat_result:
    """Create/tighten one secret directory and return its stable identity."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    before = os.lstat(path)
    if _is_reparse_point(before) or not stat.S_ISDIR(before.st_mode):
        raise PermissionError("secret parent must be a real directory")
    if _is_windows():
        if not _windows_apply_private_acl(path, directory=True):
            raise PermissionError("could not restrict secret parent ACL")
        if not _windows_acl_is_private(path):
            raise PermissionError("secret parent ACL verification failed")
    else:
        if before.st_uid != os.geteuid():
            raise PermissionError("secret parent has another owner")
        os.chmod(path, 0o700, follow_symlinks=False)
    after = os.lstat(path)
    if not _same_identity(before, after) or not _secret_parent_is_safe(after):
        raise PermissionError("secret parent identity changed")
    return after


@contextmanager
def _private_writer(
    path: Path, *, binary: bool, secure_parent: bool
) -> Iterator[IO]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_before = (
        _prepare_secret_parent(path.parent) if secure_parent else None
    )

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(tmp_name)
    temp_identity = None
    replaced = False
    published = False
    try:
        temp_identity = os.fstat(fd)
        if not _is_windows():
            os.fchmod(fd, 0o600)
        elif secure_parent:
            if not _windows_apply_private_acl(tmp, directory=False):
                raise PermissionError("could not restrict temporary secret ACL")
            if not _windows_acl_is_private(tmp):
                raise PermissionError("temporary secret ACL verification failed")
        if secure_parent:
            parent_during = os.lstat(path.parent)
            if not _same_identity(parent_before, parent_during):
                raise PermissionError("secret parent identity changed")
        if binary:
            handle = os.fdopen(fd, "wb")
        else:
            handle = os.fdopen(fd, "w", encoding="utf-8", newline="\n")
        fd = -1
        with handle:
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
        temp_after = os.lstat(tmp)
        if not _same_identity(temp_identity, temp_after):
            raise PermissionError("temporary secret identity changed")
        if secure_parent and not _same_identity(
            parent_before, os.lstat(path.parent)
        ):
            raise PermissionError("secret parent identity changed")
        os.replace(tmp, path)
        replaced = True
        if not _is_windows():
            os.chmod(path, 0o600, follow_symlinks=False)
        elif secure_parent:
            if not _windows_apply_private_acl(path, directory=False):
                raise PermissionError("could not restrict published secret ACL")
            if not _windows_acl_is_private(path):
                raise PermissionError("published secret ACL verification failed")
        published_value = os.lstat(path)
        if not _same_identity(temp_identity, published_value):
            raise PermissionError("published secret identity changed")
        if secure_parent:
            if not _secret_file_is_safe(published_value):
                raise PermissionError("published secret is not private")
            parent_after = os.lstat(path.parent)
            if (
                not _same_identity(parent_before, parent_after)
                or not _secret_parent_is_safe(parent_after)
            ):
                raise PermissionError("secret parent identity changed")
        published = True
    finally:
        if fd >= 0:
            os.close(fd)
        if not published:
            cleanup_path = path if replaced else tmp
            try:
                cleanup_value = os.lstat(cleanup_path)
                if temp_identity is None and not replaced:
                    cleanup_path.unlink()
                elif temp_identity is not None and _same_identity(
                    temp_identity, cleanup_value
                ):
                    cleanup_path.unlink()
            except OSError:
                pass


@contextmanager
def private_text_writer(
    path: Path, *, secure_parent: bool = False
) -> Iterator[TextIO]:
    """Yield an atomic UTF-8 writer whose published file is owner-only."""
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


def read_secret_text(
    path: Path, *, max_bytes: int = _DEFAULT_MAX_SECRET_BYTES
) -> Optional[str]:
    """Read one private UTF-8 secret without following a final symlink.

    The read is bounded and accepted only when the parent and file identities
    match before/open/after observations.  POSIX requires current-UID ``0700``
    parent and ``0600`` regular file.  Windows first installs, then verifies,
    an exact protected ACL; inability to do either fails closed.
    """
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
        return None
    if max_bytes <= 0 or max_bytes > _DEFAULT_MAX_SECRET_BYTES:
        return None
    path = Path(path)
    fd = -1
    try:
        parent_initial = os.lstat(path.parent)
        file_initial = os.lstat(path)
        if (
            _is_reparse_point(parent_initial)
            or not stat.S_ISDIR(parent_initial.st_mode)
            or _is_reparse_point(file_initial)
            or not stat.S_ISREG(file_initial.st_mode)
        ):
            return None
        if _is_windows():
            if not _windows_apply_private_acl(path.parent, directory=True):
                return None
            if not _windows_apply_private_acl(path, directory=False):
                return None
            if not _windows_acl_is_private(path.parent):
                return None
            if not _windows_acl_is_private(path):
                return None

        parent_before = os.lstat(path.parent)
        file_before = os.lstat(path)
        if (
            not _same_identity(parent_initial, parent_before)
            or not _same_identity(file_initial, file_before)
            or not _secret_parent_is_safe(parent_before)
            or not _secret_file_is_safe(file_before)
        ):
            return None

        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        opened_before = os.fstat(fd)
        if (
            not _same_identity(file_before, opened_before)
            or not _secret_file_is_safe(opened_before)
        ):
            return None

        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            return None

        opened_after = os.fstat(fd)
        file_after = os.lstat(path)
        parent_after = os.lstat(path.parent)
        if (
            not _same_identity(opened_before, opened_after)
            or opened_before.st_size != opened_after.st_size
            or opened_before.st_mtime_ns != opened_after.st_mtime_ns
            or not _same_identity(file_before, file_after)
            or not _same_identity(parent_before, parent_after)
            or not _secret_file_is_safe(file_after)
            or not _secret_parent_is_safe(parent_after)
        ):
            return None
        return raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError, ValueError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def write_secret_text(path: Path, text: str) -> bool:
    if not isinstance(text, str):
        return False
    try:
        encoded = text.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    if len(encoded) > _DEFAULT_MAX_SECRET_BYTES:
        return False
    try:
        with private_text_writer(path, secure_parent=True) as handle:
            handle.write(text)
        return True
    except (OSError, ValueError):
        return False
