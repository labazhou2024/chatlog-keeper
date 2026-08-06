"""Small, read-only macOS platform helpers.

Keep client discovery separate from the database/crypto code: the latter is
portable, while process names and sandbox container layouts are not.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Iterable, List


def is_macos() -> bool:
    return sys.platform == "darwin"


def process_pids(app_executables: Iterable[str]) -> List[int]:
    """Return oldest-first PIDs whose executable path matches an app binary.

    ``ps`` is available on every supported macOS release.  Matching is limited
    to ``.app/Contents/MacOS/<name>`` so similarly named helper commands do not
    make ``probe`` report a false positive.
    """
    if not is_macos():
        return []
    wanted = tuple(f".app/Contents/MacOS/{name}" for name in app_executables)
    try:
        proc = subprocess.run(
            ["ps", "-axo", "pid=,comm="],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    found: List[int] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not any(
            parts[1].endswith(marker) for marker in wanted
        ):
            continue
        try:
            found.append(int(parts[0]))
        except ValueError:
            continue
    return sorted(set(found))


def _process_pids_for_executable_checked(
    executable: Path,
) -> tuple[bool, List[int]]:
    """Return whether exact-path process enumeration succeeded and its PIDs."""
    if not is_macos():
        return False, []
    try:
        proc = subprocess.run(
            ["ps", "-axo", "pid=,comm="],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False, []
    if getattr(proc, "returncode", 0) != 0 or not isinstance(proc.stdout, str):
        return False, []
    expected = str(executable)
    found: List[int] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        command = parts[1]
        if command != expected:
            continue
        try:
            found.append(int(parts[0]))
        except ValueError:
            return False, []
    return True, sorted(set(found))


def process_pids_for_executable(executable: Path) -> List[int]:
    """Return PIDs whose command is one exact app executable path.

    This compatibility wrapper preserves the historical best-effort ``[]`` on
    unsupported platforms or ``ps`` failure. Security-sensitive lifecycle code
    uses :func:`_process_pids_for_executable_checked` so failure cannot be
    confused with a proven-empty process set.
    """
    _complete, pids = _process_pids_for_executable_checked(executable)
    return pids


def wechat_data_roots(home: Path | None = None) -> List[Path]:
    """Known sandbox roots for Tencent's direct-download macOS WeChat."""
    home = home or Path.home()
    return [
        home
        / "Library"
        / "Containers"
        / "com.tencent.xinWeChat"
        / "Data"
        / "Documents"
        / "xwechat_files",
        home
        / "Library"
        / "Group Containers"
        / "5A4RE8SF68.com.tencent.xinWeChat"
        / "xwechat_files",
    ]


def qq_container_roots(home: Path | None = None) -> List[Path]:
    """Bounded macOS QQ sandbox roots; DB layout is fingerprinted separately."""
    home = home or Path.home()
    return [
        home / "Library" / "Containers" / "com.tencent.qq" / "Data",
        home / "Library" / "Group Containers" / "FN2V63AD2J.com.tencent",
    ]
