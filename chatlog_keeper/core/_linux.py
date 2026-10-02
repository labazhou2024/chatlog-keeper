"""Small, read-only Linux platform helpers.

Keep client discovery separate from the database/crypto code: the latter is
portable, while official Debian/Ubuntu install paths and XDG layouts are not.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional


_PROC_PID_RE = re.compile(r"^[0-9]+$")
_HELPER_MARKERS = (
    "--type=",
    "crashpad",
    "renderer",
    "gpu-process",
    "zygote",
)
_USER_DIRS_RE = re.compile(
    r'^XDG_DOCUMENTS_DIR=(?P<value>"[^"]+"|\S+)\s*$',
    re.MULTILINE,
)
_FLATPAK_WECHAT_APPS = ("com.tencent.WeChat",)
_FLATPAK_QQ_APPS = ("com.qq.QQ", "com.qq.QQlinux")


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def xdg_documents(home: Path | None = None) -> Path:
    """Return the current user's Documents directory on Linux.

    Order: ``xdg-user-dir DOCUMENTS``, then ``~/.config/user-dirs.dirs``, then
    ``~/Documents``. The Chinese ``~/文档`` fallback is added by
    :func:`wechat_data_roots` / :func:`qq_data_roots` as a sibling candidate.
    """
    home = home or Path.home()
    try:
        proc = subprocess.run(
            ["xdg-user-dir", "DOCUMENTS"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        proc = None
    if proc is not None and getattr(proc, "returncode", 1) == 0:
        raw = (proc.stdout or "").strip()
        if raw:
            return Path(raw)

    configured = _documents_from_user_dirs(home)
    if configured is not None:
        return configured
    return home / "Documents"


def _documents_from_user_dirs(home: Path) -> Optional[Path]:
    path = home / ".config" / "user-dirs.dirs"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = _USER_DIRS_RE.search(text)
    if match is None:
        return None
    raw = match.group("value").strip().strip('"')
    raw = raw.replace("$HOME", str(home))
    if not raw:
        return None
    return Path(raw)


def wechat_data_roots(home: Path | None = None) -> List[Path]:
    """Known message-database roots for official Linux WeChat 4.x."""
    home = home or Path.home()
    documents = xdg_documents(home)
    roots = [
        documents / "xwechat_files",
        home / "Documents" / "xwechat_files",
        home / "文档" / "xwechat_files",
    ]
    for app in _FLATPAK_WECHAT_APPS:
        base = home / ".var" / "app" / app
        roots.extend(
            (
                base / "xwechat_files",
                base / "data" / "xwechat_files",
                base / "home" / "Documents" / "xwechat_files",
                base / "home" / "文档" / "xwechat_files",
            )
        )
    return _unique_paths(roots)


def qq_data_roots(home: Path | None = None) -> List[Path]:
    """Known NTQQ roots for official Linux QQ (``nt_qq_<hash>/nt_db``)."""
    home = home or Path.home()
    roots = [home / ".config" / "QQ"]
    for app in _FLATPAK_QQ_APPS:
        base = home / ".var" / "app" / app
        roots.extend(
            (
                base / "config" / "QQ",
                base / ".config" / "QQ",
            )
        )
    return _unique_paths(roots)


def official_wechat_executables() -> List[Path]:
    """Bounded official WeChat binaries; environment overrides are ignored."""
    return _existing_executables(
        (
            Path("/opt/wechat/wechat"),
            Path("/usr/bin/wechat"),
        )
    )


def official_qq_executables() -> List[Path]:
    """Bounded official QQ NT binaries; environment overrides are ignored."""
    return _existing_executables(
        (
            Path("/opt/QQ/qq"),
            Path("/usr/bin/qq"),
        )
    )


def process_pids(app_executables: Iterable[str]) -> List[int]:
    """Return oldest-first PIDs whose official client exe matches ``names``.

    Matching uses ``/proc/<pid>/exe`` plus comm/cmdline so Chromium helpers
    (``--type=renderer`` and similar) never make ``probe`` report a live
    client. Enumeration is fail-closed off Linux.
    """
    if not is_linux():
        return []
    wanted = {name.casefold() for name in app_executables}
    found: List[int] = []
    for pid, exe, comm, cmdline in _iter_proc_clients():
        if _is_helper(comm, cmdline, exe):
            continue
        if Path(exe).name.casefold() not in wanted:
            continue
        found.append(pid)
    return sorted(set(found))


def _process_pids_for_executable_checked(
    executable: Path,
) -> tuple[bool, List[int]]:
    """Return whether exact-path enumeration succeeded and its PIDs."""
    if not is_linux():
        return False, []
    try:
        expected = os.path.realpath(os.fspath(executable))
    except (OSError, TypeError, ValueError):
        return False, []
    found: List[int] = []
    try:
        listed = os.listdir("/proc")
    except OSError:
        return False, []
    if not any(_PROC_PID_RE.fullmatch(name) for name in listed):
        return False, []
    try:
        for pid, exe, comm, cmdline in _iter_proc_clients():
            if exe != expected:
                continue
            if _is_helper(comm, cmdline, exe):
                continue
            found.append(pid)
    except OSError:
        return False, []
    return True, sorted(set(found))


def process_pids_for_executable(executable: Path) -> List[int]:
    """Return PIDs whose exe is one exact official client path."""
    _complete, pids = _process_pids_for_executable_checked(executable)
    return pids


def _existing_executables(candidates: Iterable[Path]) -> List[Path]:
    found: List[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            if not candidate.exists():
                continue
            resolved = Path(os.path.realpath(os.fspath(candidate)))
            if not resolved.is_file():
                continue
        except OSError:
            continue
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        found.append(resolved)
    return found


def _unique_paths(paths: Iterable[Path]) -> List[Path]:
    out: List[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def _is_helper(comm: str, cmdline: str, exe: str) -> bool:
    haystack = f"{comm}\0{cmdline}\0{exe}".casefold()
    return any(marker in haystack for marker in _HELPER_MARKERS)


def _iter_proc_clients() -> Iterable[tuple[int, str, str, str]]:
    proc_root = Path("/proc")
    try:
        names = os.listdir(proc_root)
    except OSError:
        return
    for name in names:
        if not _PROC_PID_RE.fullmatch(name):
            continue
        pid = int(name)
        exe = _read_proc_exe(pid)
        if not exe:
            continue
        comm = _read_proc_text(proc_root / name / "comm")
        cmdline = _read_proc_cmdline(proc_root / name / "cmdline")
        yield pid, exe, comm, cmdline


def _read_proc_exe(pid: int) -> str:
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _read_proc_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _read_proc_cmdline(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
