"""Resolve the per-user writable data directory for chatlog-keeper.

Key caches, the WeChat link cache, and any other writable state live under this
single root so they are easy to find — and easy to delete. Everything stays on
your own machine; nothing here ever touches the network.

Override the location with the ``CHATLOG_KEEPER_DATA_DIR`` environment variable.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    """Return (and create) the writable data root for the current platform.

    * ``CHATLOG_KEEPER_DATA_DIR`` env var, if set, wins.
    * Windows  → ``%LOCALAPPDATA%\\chatlog-keeper\\data``
    * macOS    → ``~/Library/Application Support/chatlog-keeper``
    * Linux/*  → ``$XDG_DATA_HOME/chatlog-keeper`` (or ``~/.local/share/...``)
    """
    override = os.environ.get("CHATLOG_KEEPER_DATA_DIR")
    if override:
        d = Path(override)
    elif sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        d = Path(base) / "chatlog-keeper" / "data"
    elif sys.platform == "darwin":
        d = Path.home() / "Library" / "Application Support" / "chatlog-keeper"
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg) if xdg else (Path.home() / ".local" / "share")
        d = Path(base) / "chatlog-keeper"
    d.mkdir(parents=True, exist_ok=True)
    return d
