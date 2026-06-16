"""Machine-neutral path discovery helpers.

No hardcoded drive letters or usernames — everything is derived at runtime so a
release build works on any machine: English or Chinese Windows, OneDrive-backed
or local Documents, data on any drive, or a fully custom location supplied via an
environment override. All functions are read-only and touch nothing on disk.
"""
from __future__ import annotations

import os
import string
from pathlib import Path
from typing import List, Optional


def all_drive_roots() -> List[Path]:
    """Every existing logical drive root (``C:/``, ``D:/`` …) on Windows.

    Returns ``[]`` on non-Windows. Used so we never assume a chat client lives on
    C: or D: — the user may have relocated its data dir to any drive.
    """
    roots: List[Path] = []
    if os.name != "nt":
        return roots
    for letter in string.ascii_uppercase:
        d = Path(f"{letter}:/")
        try:
            if d.exists():
                roots.append(d)
        except OSError:
            pass
    return roots


def real_documents() -> Optional[Path]:
    """The user's real "Documents" folder, honoring Windows folder redirection.

    A user can move Documents to another drive or back it with OneDrive; this asks
    the Win32 known-folder API for the actual location rather than assuming
    ``~/Documents``. Read-only (does not create or modify anything). Returns
    ``None`` off-Windows or on any failure.
    """
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        CSIDL_PERSONAL = 5  # "My Documents"
        SHGFP_TYPE_CURRENT = 0
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        ctypes.windll.shell32.SHGetFolderPathW(  # type: ignore[attr-defined]
            None, CSIDL_PERSONAL, None, SHGFP_TYPE_CURRENT, buf
        )
        if buf.value:
            p = Path(buf.value)
            return p if p.exists() else None
    except Exception:
        return None
    return None


def candidate_documents_roots() -> List[Path]:
    """Likely "Documents" locations across machine configurations, de-duplicated.

    Order: the real (possibly redirected) Documents first, then common home and
    OneDrive variants — English ``Documents`` and Chinese ``文档``.
    """
    out: List[Path] = []
    seen: set = set()

    def _add(p: Optional[Path]) -> None:
        if p is None:
            return
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            out.append(p)

    _add(real_documents())
    home = Path.home()
    _add(home / "Documents")
    _add(home / "OneDrive" / "Documents")
    _add(home / "OneDrive" / "文档")
    return out
