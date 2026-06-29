"""Frozen entry point for chatlog-keeper.exe (PyInstaller).

A standalone build of the chatlog-keeper CLI so a host application (e.g. 镜我
Memexa) or a scheduled task can download one self-contained executable — no
Python install required — and run key extraction + decrypt + export.

The bundled PowerShell debugger scripts are located at runtime via
``active_key._scripts_dir()`` (PyInstaller ``sys._MEIPASS`` aware), so
``extract-key --method active`` and the ``qq`` / ``wechat`` exports work frozen.
"""
import sys

from chatlog_keeper.cli import main

if __name__ == "__main__":
    sys.exit(main())
