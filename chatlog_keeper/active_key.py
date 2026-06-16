"""Active (debugger-based) key extraction for newer WeChat / QQ builds.

Why this exists
---------------
The passive memory scan in :mod:`qq_db` / :mod:`wechat_db` finds the SQLCipher
key as a plaintext blob in the client's process heap. That works on older
builds, but:

* **WeChat 4.1.10.31+** moved the key out of the heap — a passive scan finds
  nothing.
* **QQ NT** keeps a 16-char passphrase in the heap, but the process can hold
  1+ GB, so a full scan can take many minutes.

For those cases this module drives two bundled PowerShell debugger scripts
(``scripts/windows_ntqq_get_key.ps1`` / ``scripts/windows_wechat_get_key.ps1``).
Each one is a pure .NET/Win32 debugger — ``CreateProcessW(DEBUG_ONLY_THIS_PROCESS)``
launches a *fresh* client, sets an INT3 software breakpoint on the SQLCipher
key-set function, and reads the key from registers when it fires. The key is
verified by an HMAC oracle against your own DB's page 1, so a wrong guess can
never be returned. No DLL injection, no third-party binary, nothing uploaded.

This needs Administrator rights (a debugger has to attach) and you have to log
into the freshly-launched client once. After that the key is cached and every
later export reads the cache — no scan, no debugger, no login.

Everything here is Windows-only and operates on **your own** logged-in client.
"""
from __future__ import annotations

import ctypes
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Markers the bundled scripts print the key after (kept in sync with the script
# sources).
_QQ_MARKERS = ("找到密钥:", "加密密钥:")
_WX_MARKERS = ("master key:", "找到密钥:")


# ─── script discovery ─────────────────────────────────────────────────────────

def _scripts_dir() -> Path:
    """Locate the bundled debugger scripts.

    Order: ``CHATLOG_KEEPER_SCRIPTS_DIR`` env override → PyInstaller bundle
    (``sys._MEIPASS``) → this package's ``scripts/`` directory.
    """
    env = os.environ.get("CHATLOG_KEEPER_SCRIPTS_DIR", "").strip()
    if env:
        return Path(env)
    base = getattr(sys, "_MEIPASS", None)
    if base:
        for cand in (Path(base) / "chatlog_keeper" / "scripts", Path(base) / "scripts"):
            if cand.exists():
                return cand
    return Path(__file__).resolve().parent / "scripts"


def qq_key_script() -> Optional[Path]:
    """Path to the bundled QQ debugger script, or None if not present."""
    p = _scripts_dir() / "windows_ntqq_get_key.ps1"
    return p if p.exists() else None


def wechat_key_script() -> Optional[Path]:
    """Path to the bundled WeChat debugger script, or None if not present."""
    p = _scripts_dir() / "windows_wechat_get_key.ps1"
    return p if p.exists() else None


def is_admin() -> bool:
    """True if the current process is elevated (Administrator on Windows)."""
    if os.name != "nt":
        return bool(getattr(os, "geteuid", lambda: 1)() == 0)
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _version_key(name: str):
    """Sort key from a version-ish dir name: '9.9.31-49738' -> (9, 9, 31, 49738)."""
    nums = re.findall(r"\d+", name)
    return tuple(int(n) for n in nums) if nums else (0,)


def _find_qq_wrapper_node() -> Optional[str]:
    """Find the newest QQ NT ``wrapper.node`` across machine-neutral install roots.

    QQ NT installs each version under
    ``.../QQNT/versions/<version>/resources/app/wrapper.node``; several versions
    can coexist (the bundled PS1 refuses to guess when it finds more than one).
    We enumerate every drive's common install paths — plus a
    ``CHATLOG_QQ_INSTALL_ROOT`` override — and pick the highest version. Returns
    a path string, or None if QQ NT is not installed.
    """
    roots: List[Path] = []
    env = os.environ.get("CHATLOG_QQ_INSTALL_ROOT", "").strip()
    if env:
        roots.append(Path(env))
    try:
        from chatlog_keeper.core._paths import all_drive_roots
        drives = list(all_drive_roots())
    except Exception:  # noqa: BLE001
        drives = [Path("C:\\"), Path("D:\\")]
    for d in drives:
        roots.append(d / "Program Files" / "Tencent" / "QQNT")
        roots.append(d / "Program Files (x86)" / "Tencent" / "QQNT")
    la = os.environ.get("LOCALAPPDATA", "")
    if la:
        roots.append(Path(la) / "Programs" / "QQNT")

    candidates = []  # (version_tuple, path_str)
    for root in roots:
        versions = root / "versions"
        if versions.is_dir():
            try:
                for vdir in versions.iterdir():
                    wn = vdir / "resources" / "app" / "wrapper.node"
                    if wn.exists():
                        candidates.append((_version_key(vdir.name), str(wn)))
            except OSError:
                continue
        wn = root / "resources" / "app" / "wrapper.node"
        if wn.exists():
            candidates.append(((0,), str(wn)))
    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0])
    return candidates[-1][1]


# ─── key-line parsing ─────────────────────────────────────────────────────────

def _validate_qq(cand: str) -> Optional[str]:
    """Return the 16-char ASCII passphrase from a candidate, else None."""
    tok = ""
    for c in cand:
        if " " <= c <= "~":
            tok += c
        else:
            break
    tok = tok.strip()
    # NTQQ passphrase is 16 chars; allow 32 too (qq_db._scan_memory accepts both).
    if len(tok) in (16, 32) and all(0x20 <= ord(b) <= 0x7E for b in tok):
        return tok
    return None


def _validate_wechat(cand: str) -> Optional[str]:
    """Return the 64-hex master key (lowercased) from a candidate, else None."""
    tok = ""
    for c in cand:
        if c in "0123456789abcdefABCDEF":
            tok += c
        else:
            break
    tok = tok.lower()
    return tok if len(tok) == 64 else None


def _parse_key(text: str, markers, validate) -> Optional[str]:
    """Scan transcript text for the last validated key after any marker."""
    found = None
    for line in text.splitlines():
        for marker in markers:
            i = line.find(marker)
            if i < 0:
                continue
            tok = validate(line[i + len(marker):].strip())
            if tok:
                found = tok  # last valid wins (mirrors main.rs)
    return found


# ─── script runner (handles UAC elevation + transcript capture) ───────────────

def _quote(a: str) -> str:
    """Quote a PowerShell argument unless it is a ``-Flag`` token."""
    if a.startswith("-"):
        return a
    return "'" + a.replace("'", "''") + "'"


def _run_active(script: Path, args: List[str], timeout: int,
                elevate: bool = True) -> str:
    """Run a debugger script and return its full console transcript text.

    Output always routes through ``Start-Transcript`` to a temp file:
    ``Write-Host`` output is reliably captured there, and — crucially — a
    ``Start-Process -Verb RunAs`` child cannot inherit our stdout pipe across
    UAC integrity levels.

    ``elevate`` requests Administrator via UAC when we are not already admin
    (needed to attach a debugger). Static analysis (``-NoDebugForKey``) attaches
    nothing, so callers pass ``elevate=False`` to avoid a needless UAC prompt.
    """
    stamp = time.time_ns()
    tmp = Path(tempfile.gettempdir())
    out_path = tmp / f"chatlog_key_{stamp}.txt"
    launcher = tmp / f"chatlog_launch_{stamp}.ps1"

    inner = "& '{s}'".format(s=str(script).replace("'", "''"))
    if args:
        inner += " " + " ".join(_quote(a) for a in args)
    launcher_text = (
        "Start-Transcript -Path '{out}' -Force *> $null\r\n"
        "try {{ {inner} }} catch {{ Write-Host $_ }}\r\n"
        "Stop-Transcript *> $null\r\n"
    ).format(out=str(out_path).replace("'", "''"), inner=inner)
    # UTF-8 BOM: PS 5.1 otherwise reads as GBK and mangles a Chinese install
    # path → `& '<script>'` can't find the script.
    launcher.write_bytes(b"\xef\xbb\xbf" + launcher_text.encode("utf-8"))

    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    try:
        if is_admin() or not elevate:
            cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                   "-File", str(launcher)]
        else:
            outer = (
                "Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait "
                "-WindowStyle Normal -ArgumentList "
                "@('-NoProfile','-ExecutionPolicy','Bypass','-File','{l}')"
            ).format(l=str(launcher).replace("'", "''"))
            cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                   "-Command", outer]
        try:
            subprocess.run(cmd, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            logger.warning("active key script timed out after %ss", timeout)
        except FileNotFoundError:
            logger.warning("powershell.exe not found; active extraction needs Windows")
            return ""
        return out_path.read_text(encoding="utf-8", errors="replace") if out_path.exists() else ""
    finally:
        for p in (launcher, out_path):
            try:
                p.unlink()
            except OSError:
                pass


# ─── public API ───────────────────────────────────────────────────────────────

def extract_qq_key_active(*, wrapper_node: Optional[str] = None,
                          analyze_only: bool = False,
                          timeout: int = 600) -> Optional[bytes]:
    """Extract the QQ NT 16-char passphrase via the debugger script.

    Returns the passphrase as 16 ASCII bytes, or None. ``analyze_only`` runs
    static analysis only (``-NoDebugForKey``: locate the key-set function, do
    not launch/debug QQ) — useful to verify the script runs on this machine
    without closing or restarting the user's QQ.
    """
    if os.name != "nt":
        logger.warning("active QQ extraction is Windows-only")
        return None
    script = qq_key_script()
    if not script:
        logger.warning("QQ debugger script not bundled (scripts/windows_ntqq_get_key.ps1)")
        return None
    args: List[str] = []
    wn = wrapper_node or _find_qq_wrapper_node()
    if wn:
        args.append(wn)  # positional WrapperNodePath (newest version auto-picked)
    if analyze_only:
        args.append("-NoDebugForKey")
    text = _run_active(script, args, timeout, elevate=not analyze_only)
    if analyze_only:
        if "函数 RVA" in text or "FunctionRVA" in text:
            logger.info("QQ static analysis located the key-set function")
        return None
    tok = _parse_key(text, _QQ_MARKERS, _validate_qq)
    return tok.encode("ascii") if tok else None


def extract_wechat_key_active(*, weixin_dll: Optional[str] = None,
                              db_path: Optional[str] = None,
                              analyze_only: bool = False,
                              timeout: int = 600) -> Optional[bytes]:
    """Extract the WeChat 4.x 32-byte master key via the debugger script.

    Returns the 32-byte master key, or None. ``analyze_only`` runs static
    analysis only (``-NoDebugForKey``) and never launches/restarts WeChat.
    """
    if os.name != "nt":
        logger.warning("active WeChat extraction is Windows-only")
        return None
    script = wechat_key_script()
    if not script:
        logger.warning("WeChat debugger script not bundled (scripts/windows_wechat_get_key.ps1)")
        return None
    args: List[str] = []
    if weixin_dll:
        args += ["-WeixinDllPath", weixin_dll]
    if db_path:
        args += ["-DbPath", db_path]
    if analyze_only:
        args.append("-NoDebugForKey")
    text = _run_active(script, args, timeout, elevate=not analyze_only)
    if analyze_only:
        if "函数 RVA" in text or "funcRva" in text or "key-set" in text:
            logger.info("WeChat static analysis located the cipher-config function")
        return None
    tok = _parse_key(text, _WX_MARKERS, _validate_wechat)
    if not tok:
        return None
    try:
        return bytes.fromhex(tok)
    except ValueError:
        return None
