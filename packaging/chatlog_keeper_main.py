"""Frozen entry point for chatlog-keeper.exe (PyInstaller).

A standalone build of the chatlog-keeper CLI so a host application (e.g. 镜我
Memexa) or a scheduled task can download one self-contained executable — no
Python install required — and run key extraction + decrypt + export.

The bundled PowerShell debugger scripts are located at runtime via
``active_key._scripts_dir()`` (PyInstaller ``sys._MEIPASS`` aware), so
``extract-key --method active`` and the ``qq`` / ``wechat`` exports work frozen.
"""
import sys

if __name__ == "__main__":
    if sys.argv[1:2] == ["--_qq-sqlite-helper"]:
        # Private frozen-child entry point.  The parent starts the same signed
        # executable as a separate process because a PyInstaller executable
        # cannot be used as ``python -I helper.py``.
        from chatlog_keeper._qq_sqlite_helper import main as helper_main

        sys.exit(helper_main(sys.argv[2:]))

    from chatlog_keeper.cli import main

    sys.exit(main())
