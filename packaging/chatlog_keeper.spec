# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — standalone one-file ``chatlog-keeper.exe``.

Build from the repo root:
    pyinstaller packaging/chatlog_keeper.spec --noconfirm --clean --distpath dist_exe

Produces a single self-contained ``chatlog-keeper.exe`` (key extraction +
decrypt + export) for host apps / scheduled tasks to download and invoke. The
two PowerShell debugger scripts are bundled under ``chatlog_keeper/scripts`` so
``active_key._scripts_dir()`` finds them via ``sys._MEIPASS`` when frozen.
"""
import os
import sys as _sys
import glob as _glob

from PyInstaller.utils.hooks import collect_all

# SPECPATH is injected by PyInstaller = absolute dir of this .spec (packaging/).
# Resolve everything off it so paths never double up regardless of invoke cwd.
SPEC_DIR = SPECPATH
ROOT = os.path.dirname(SPEC_DIR)  # repo root (parent of packaging/)
SCRIPTS_SRC = os.path.join(ROOT, "chatlog_keeper", "scripts")
SCRIPTS_DST = os.path.join("chatlog_keeper", "scripts")

binaries = []
datas = [
    (os.path.join(SCRIPTS_SRC, "windows_ntqq_get_key.ps1"), SCRIPTS_DST),
    (os.path.join(SCRIPTS_SRC, "windows_wechat_get_key.ps1"), SCRIPTS_DST),
]
hiddenimports = []

# ── conda-env C-extension runtime DLLs (Library/bin) ────────────────────────
# A conda build's _ctypes.pyd / _ssl / _hashlib / lzma / bz2 / sqlite3 load their
# backing DLLs (ffi-8, libcrypto-3, libssl-3, liblzma, sqlite3, zlib...) from
# <env>/Library/bin — which conda puts on PATH at activation but PyInstaller does
# NOT search. Without bundling, the frozen exe dies with "DLL load failed while
# importing _ctypes" (active_key imports ctypes). Skip api-ms-win-* stubs + tcl/tk.
# Same lesson as packaging/memexa_light.spec. No-op on a python.org build host.
_lib_bin = os.path.join(os.path.dirname(os.path.abspath(_sys.executable)), "Library", "bin")
if os.path.isdir(_lib_bin):
    for _dll in _glob.glob(os.path.join(_lib_bin, "*.dll")):
        _n = os.path.basename(_dll).lower()
        if _n.startswith("api-ms-win") or _n.startswith(("tcl", "tk")):
            continue
        binaries.append((_dll, "."))

# ── pycryptodome (Crypto.*) + zstandard — HMAC/cipher + NTQQ zstd codec ──────
# C-extension .pyd modules (Crypto.Cipher._raw_aes, zstandard._cffi/_zstd) are
# load-bearing binaries PyInstaller's static scan can miss; collect_all pins
# submodules + .pyd binaries + data so the frozen exe can verify keys + decode.
for _pkg in ("Crypto", "zstandard"):
    try:
        _cd, _cb, _ch = collect_all(_pkg)
        datas += _cd
        binaries += _cb
        hiddenimports += _ch
    except Exception:
        pass

a = Analysis(
    [os.path.join(SPEC_DIR, "chatlog_keeper_main.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Keep the exe lean + guarantee no host-app code leaks in if env paths mix.
    excludes=["memexa", "torch", "transformers", "tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="chatlog-keeper",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
