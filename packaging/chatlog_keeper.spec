# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — standalone one-file ``chatlog-keeper`` executable.

Build from the repo root:
    pyinstaller packaging/chatlog_keeper.spec --noconfirm --clean --distpath dist_exe

Produces one self-contained executable (``.exe`` on Windows) for host apps /
scheduled tasks to invoke. The Windows PowerShell debugger scripts plus the
macOS scanner/capture sources are bundled under ``chatlog_keeper/scripts`` so
the platform key helpers can find them through ``sys._MEIPASS`` when frozen.
"""
import os
import sys as _sys
import glob as _glob
import subprocess as _subprocess

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
    (os.path.join(SCRIPTS_SRC, "macos_memory_scan.c"), SCRIPTS_DST),
    (os.path.join(SCRIPTS_SRC, "macos_wechat_key_capture.c"), SCRIPTS_DST),
]
hiddenimports = []

# A standalone macOS release must not require Xcode Command Line Tools on the
# user's machine. Compile the read-only Mach helper on the arm64 build runner
# and embed it next to the source fallback. Source installs still compile the C
# file on first use, which keeps the implementation auditable.
if _sys.platform == "darwin":
    _mac_helper_dir = os.path.join(ROOT, "build_pyi", "macos-helper")
    os.makedirs(_mac_helper_dir, exist_ok=True)
    _mac_helper = os.path.join(_mac_helper_dir, "macos_memory_scan")
    _compiled = _subprocess.run(
        [
            "xcrun",
            "clang",
            "-O2",
            "-Wall",
            "-Wextra",
            os.path.join(SCRIPTS_SRC, "macos_memory_scan.c"),
            "-o",
            _mac_helper,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if _compiled.returncode != 0:
        raise RuntimeError(
            "failed to compile macOS key helper: " + (_compiled.stderr or "").strip()
        )
    datas.append((_mac_helper, SCRIPTS_DST))

    # Startup capture must be loadable on every supported Apple Silicon macOS,
    # not just the SDK version installed on the build runner.  A stable install
    # name also prevents an ephemeral build path from entering LC_ID_DYLIB.
    _mac_capture = os.path.join(
        _mac_helper_dir,
        "macos_wechat_key_capture.dylib",
    )
    _capture_compiled = _subprocess.run(
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
            os.path.join(SCRIPTS_SRC, "macos_wechat_key_capture.c"),
            "-Wl,-install_name,@rpath/macos_wechat_key_capture.dylib",
            "-o",
            _mac_capture,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if _capture_compiled.returncode != 0:
        raise RuntimeError(
            "failed to compile macOS WeChat startup capture helper: "
            + (_capture_compiled.stderr or "").strip()
        )
    datas.append((_mac_capture, SCRIPTS_DST))

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
