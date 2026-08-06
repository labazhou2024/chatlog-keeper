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

On Windows this module drives two bundled PowerShell debugger scripts
(``scripts/windows_ntqq_get_key.ps1`` / ``scripts/windows_wechat_get_key.ps1``).
Each one is a pure .NET/Win32 debugger — ``CreateProcessW(DEBUG_ONLY_THIS_PROCESS)``
launches a *fresh* client, sets an INT3 software breakpoint on the SQLCipher
key-set function, and reads the key from registers when it fires.

On macOS the original signed app is left untouched. An isolated copy under the
tool's Application Support directory is ad-hoc signed with
``com.apple.security.get-task-allow``. QQ retains Hardened Runtime and is
checked against its embedded-library Team-ID relation. WeChat follows the
upstream v0.2 compatibility mode and does not enable Hardened Runtime on that
private copy, because current Tencent-signed embedded frameworks otherwise make
the ad-hoc main process exit before its UI appears.  For WeChat only, a locally
built fixed-purpose interpose library is loaded into that private copy before
automatic login starts, so the key setup boundary cannot outrun the observer.
No administrator process is used, SIP is never disabled, and the signed daily
client is neither modified nor injected.

Every candidate on either platform is verified by an HMAC oracle against your
own DB page 1 before it can be returned or cached. The isolated client reuses
the existing login session; only an expired session requires normal WeChat QR
authentication. Later exports use the private local cache.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
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
_MACOS_WECHAT_SCAN_SLICE_SECONDS = 60
_MACOS_WECHAT_LOGIN_POLL_SECONDS = 2.0
_MACOS_WECHAT_MAX_ORACLES = 64
_MAX_ACTIVE_TRANSCRIPT_BYTES = 1024 * 1024
_BUNDLED_SCRIPT_SHA256 = {
    "windows_ntqq_get_key.ps1": "78502d5357a73633df9d6d784986c3297460ac87a9a15d4a5f726480a1cd3161",
    "windows_wechat_get_key.ps1": "26757546e0c6da0cb156c41f8ee7582e69db2cd38a5576399c1e7b9ebb4e74da",
}


# ─── script discovery ─────────────────────────────────────────────────────────

def _scripts_dir() -> Path:
    """Locate the bundled debugger scripts.

    A privileged active-key action must never select executable PowerShell from
    an environment override.  Resolve only the immutable PyInstaller payload or
    this installed package's own ``scripts/`` directory.
    """
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
    and pick the highest version. Returns a path string, or None if QQ NT is not
    installed. Environment overrides are intentionally excluded from this
    privileged discovery path.
    """
    roots: List[Path] = []
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


def _wechat_active_oracle_paths(db_path: Path, wechat_db) -> List[Path]:
    """Return a bounded, deterministic HMAC-oracle set for macOS WeChat.

    ``extract_wechat_key_active`` keeps its historical single-``db_path``
    contract.  For a normal 4.x path we can still recover the containing data
    root, then reuse :func:`wechat_db.find_wxid_dirs` and
    :func:`wechat_db.find_msg_databases` to include one message DB per account.
    The original path remains the compatibility fallback for callers passing a
    standalone/archive database.

    This helper only returns paths.  Stable page bytes and the eventual match
    stay local to one scan iteration so login-created databases and checkpoints
    are observed on the next poll without retaining account metadata.
    """
    seed = Path(db_path)
    seed_account = None
    if (
        seed.parent.name.lower() == "message"
        and seed.parent.parent.name.lower() == "db_storage"
    ):
        seed_account = seed.parents[2]
    elif (
        seed.parent.name.lower() == "multi"
        and seed.parent.parent.name.lower() == "msg"
    ):
        seed_account = seed.parents[2]

    if seed_account is None:
        return [seed] if seed.is_file() else []

    account_roots = [seed_account]
    try:
        discovered = wechat_db.find_wxid_dirs(seed_account.parent)
    except (OSError, RuntimeError):
        discovered = []
    account_roots.extend(
        sorted(
            (Path(account) for account in discovered),
            key=lambda account: (account.name.lower(), str(account)),
        )
    )

    unique_accounts = []
    seen_accounts = set()
    for account in account_roots:
        account_key = os.path.normcase(os.fspath(account))
        if account_key in seen_accounts:
            continue
        seen_accounts.add(account_key)
        unique_accounts.append(account)
        if len(unique_accounts) >= _MACOS_WECHAT_MAX_ORACLES:
            break

    oracles: List[Path] = []
    for account in unique_accounts:
        try:
            candidates = [
                Path(candidate)
                for candidate in wechat_db.find_msg_databases(account)
                if Path(candidate).is_file()
            ]
        except (OSError, RuntimeError):
            continue
        if not candidates:
            continue
        candidates.sort(
            key=lambda candidate: (
                candidate != seed if account == seed_account else True,
                candidate.name.lower() != "message_0.db",
                candidate.name.lower(),
                str(candidate),
            )
        )
        oracles.append(candidates[0])

    # A direct caller may supply a valid standalone DB that the account-layout
    # discoverer does not recognize.  Preserve that pre-existing behavior while
    # ensuring every additional multi-account path came from the discoverers.
    if not oracles and seed.is_file():
        return [seed]
    return oracles


# ─── script runner (non-elevated child debugger + transcript capture) ─────────

def _powershell_literal(value: str) -> str:
    """Return one single-quoted PowerShell literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _verified_script_digest(script: Path) -> Optional[str]:
    """Return the pinned digest for an exact bundled script, else ``None``."""
    expected = _BUNDLED_SCRIPT_SHA256.get(Path(script).name)
    if expected is None:
        return None
    try:
        path = Path(script)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            return None
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None
    return expected if secrets.compare_digest(actual, expected) else None


def _windows_active_environment() -> dict[str, str]:
    """Build the minimum environment needed by a trusted Windows client.

    In particular this drops Python/PowerShell module injection variables and
    all ``CHATLOG_*`` development overrides before starting PowerShell.
    """
    allowed = {
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "COMMONPROGRAMW6432",
        "COMPUTERNAME",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "LOGONSERVER",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "PUBLIC",
        "SESSIONNAME",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERDOMAIN_ROAMINGPROFILE",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed
    }
    env["PYTHONUTF8"] = "1"
    return env


def _active_bootstrap(
    *,
    script: Path,
    script_digest: str,
    args: List[str],
    out_path: Path,
) -> str:
    """Build a small bootstrap that verifies then executes in memory.

    The script is read exactly once, SHA-256 checked inside the child process,
    converted to a ``ScriptBlock`` and invoked from those verified bytes.  This
    removes the former check/use race through a writable launcher file.
    """
    encoded_args = base64.b64encode(
        json.dumps(list(args), ensure_ascii=True).encode("utf-8")
    ).decode("ascii")
    return "\r\n".join(
        (
            "$ErrorActionPreference = 'Stop'",
            f"$scriptPath = {_powershell_literal(str(script))}",
            f"$expectedHash = {_powershell_literal(script_digest)}",
            f"$outPath = {_powershell_literal(str(out_path))}",
            f"$argsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_args}'))",
            "$scriptArgs = @((ConvertFrom-Json -InputObject $argsJson))",
            "$scriptBytes = [IO.File]::ReadAllBytes($scriptPath)",
            "$sha = [Security.Cryptography.SHA256]::Create()",
            "try { $actualHash = ([BitConverter]::ToString($sha.ComputeHash($scriptBytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }",
            "if ($actualHash -cne $expectedHash) { throw 'bundled active-key script integrity check failed' }",
            "$scriptText = [Text.Encoding]::UTF8.GetString($scriptBytes)",
            "if ($scriptText.Length -gt 0 -and [int]$scriptText[0] -eq 0xFEFF) { $scriptText = $scriptText.Substring(1) }",
            "$scriptBlock = [ScriptBlock]::Create($scriptText)",
            "Start-Transcript -LiteralPath $outPath -Force *> $null",
            "try { & $scriptBlock @scriptArgs } catch { Write-Host ('active extraction failed: ' + $_.Exception.Message) } finally { Stop-Transcript *> $null }",
        )
    )


def _read_active_transcript(path: Path) -> str:
    """Read one bounded regular transcript without following a POSIX symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return ""
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_ACTIVE_TRANSCRIPT_BYTES:
            return ""
        data = os.read(fd, _MAX_ACTIVE_TRANSCRIPT_BYTES + 1)
        after = os.fstat(fd)
        if (
            len(data) > _MAX_ACTIVE_TRANSCRIPT_BYTES
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            return ""
        return data.decode("utf-8", errors="replace")
    finally:
        os.close(fd)


def _run_active(script: Path, args: List[str], timeout: int) -> str:
    """Run a debugger script and return its full console transcript text.

    Output always routes through ``Start-Transcript`` to a private random file:
    ``Write-Host`` output is reliably captured there.  The debugger creates its
    own child with ``DEBUG_PROCESS``/``DEBUG_ONLY_THIS_PROCESS`` and therefore
    runs with the current user's token; it never attaches to an unrelated
    process and does not cross a UAC boundary.
    """
    pinned_digest = _verified_script_digest(Path(script))
    if pinned_digest is None:
        logger.warning("active key script failed bundled integrity validation")
        return ""
    private_dir = Path(tempfile.mkdtemp(prefix="chatlog_active_"))
    out_path = private_dir / f"result-{secrets.token_hex(16)}.txt"
    bootstrap = _active_bootstrap(
        script=Path(script),
        script_digest=pinned_digest,
        args=args,
        out_path=out_path,
    )
    encoded_bootstrap = base64.b64encode(
        bootstrap.encode("utf-16le")
    ).decode("ascii")
    env = _windows_active_environment()
    try:
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded_bootstrap,
        ]
        try:
            subprocess.run(
                cmd,
                timeout=timeout,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning("active key script timed out after %ss", timeout)
        except FileNotFoundError:
            logger.warning("powershell.exe not found; active extraction needs Windows")
            return ""
        return _read_active_transcript(out_path)
    finally:
        shutil.rmtree(private_dir, ignore_errors=True)


# ─── public API ───────────────────────────────────────────────────────────────

def _is_windows_host() -> bool:
    """Return whether this process is running on Windows.

    This test seam avoids mutating process-global ``os.name`` in pytest,
    which would also corrupt ``pathlib`` platform selection.
    """
    return os.name == "nt"


def _is_macos_host() -> bool:
    """Return whether this process is running on macOS."""
    return sys.platform == "darwin"


def extract_qq_key_active(*, wrapper_node: Optional[str] = None,
                          db_path: Optional[str] = None,
                          analyze_only: bool = False,
                          timeout: int = 600) -> Optional[bytes]:
    """Extract the QQ NT 16-char passphrase via the debugger script.

    Returns the passphrase as 16 ASCII bytes, or None. ``analyze_only`` runs
    static analysis only (``-NoDebugForKey``: locate the key-set function, do
    not launch/debug QQ) — useful to verify the script runs on this machine
    without closing or restarting the user's QQ.
    """
    if _is_macos_host():
        from chatlog_keeper.macos_debug_app import clear_last_error as clear_launch_error
        from chatlog_keeper.macos_key import clear_last_error as clear_helper_error
        clear_launch_error()
        clear_helper_error()
        if analyze_only:
            from chatlog_keeper.macos_key import ensure_helper
            ensure_helper()
            return None
        from chatlog_keeper import qq_db
        from chatlog_keeper.macos_debug_app import (
            debug_copy_process_identity,
            launch_debug_copy,
            terminate_debug_copy,
            validate_debug_copy_process,
        )
        from chatlog_keeper.macos_key import extract_verified
        resolved = Path(db_path) if db_path else None
        if not resolved:
            root = qq_db.find_qq_data_root()
            resolved = qq_db.find_msg_database(root) if root else None
        if not resolved or not resolved.is_file():
            return None
        debug_pid = launch_debug_copy("qq")
        if not debug_pid:
            # The daily signed client does not carry get-task-allow. Falling
            # back to it would fail SIP/taskgated policy and must never trigger
            # a privileged helper path.
            return None
        result = None
        try:
            # A first login/checkpoint can replace page 1 while the helper scans.
            # Verify against a stable pre-scan oracle, then re-read and confirm on
            # the current DB family before returning a cacheable key. Retry once
            # on a real checkpoint race; never accept a stale-page-only match.
            for _attempt in range(2):
                db_raw = qq_db._read_qq_verification_bytes(resolved)
                identity = debug_copy_process_identity("qq", debug_pid)
                if not db_raw or identity is None:
                    break
                key = extract_verified(
                    "qq", debug_pid,
                    lambda candidate: qq_db._verify_key_qq(candidate, db_raw),
                    primary_verify=lambda candidate: qq_db._verify_key_qq_with_algo(
                        candidate, db_raw, "sha512", "sha1", 48
                    ),
                    elevate=False,
                    timeout=timeout,
                    expected_identity=identity,
                )
                if not key or not validate_debug_copy_process("qq", debug_pid):
                    break
                latest = qq_db._read_qq_verification_bytes(resolved)
                if latest and qq_db._verify_key_qq(key, latest):
                    result = key
                    break
        except BaseException:
            terminate_debug_copy("qq", debug_pid)
            raise
        if not terminate_debug_copy("qq", debug_pid):
            return None
        return result
    if not _is_windows_host():
        logger.warning("active QQ extraction is Windows-only")
        return None
    script = qq_key_script()
    if not script:
        logger.warning("QQ debugger script not bundled (scripts/windows_ntqq_get_key.ps1)")
        return None
    args: List[str] = []
    if wrapper_node:
        args.append(wrapper_node)
    script_timeout = max(1, int(timeout) - 15) if int(timeout) > 15 else max(1, int(timeout))
    args += ["-TimeoutSeconds", str(script_timeout)]
    if analyze_only:
        args.append("-NoDebugForKey")
    text = _run_active(script, args, timeout)
    if analyze_only:
        if "函数 RVA" in text or "FunctionRVA" in text:
            logger.info("QQ static analysis located the key-set function")
        return None
    tok = _parse_key(text, _QQ_MARKERS, _validate_qq)
    if not tok:
        return None
    candidate = tok.encode("ascii")
    if db_path:
        from chatlog_keeper import qq_db

        verification = qq_db._read_qq_verification_bytes(Path(db_path))
        if not verification or not qq_db._verify_key_qq(candidate, verification):
            return None
    return candidate


def extract_wechat_key_active(*, weixin_dll: Optional[str] = None,
                              db_path: Optional[str] = None,
                              analyze_only: bool = False,
                              timeout: int = 600) -> Optional[bytes]:
    """Extract the WeChat 4.x 32-byte master key via the debugger script.

    Returns the 32-byte master key, or None. ``analyze_only`` runs static
    analysis only (``-NoDebugForKey``) and never launches/restarts WeChat.
    """
    if _is_macos_host():
        from chatlog_keeper.macos_debug_app import clear_last_error as clear_launch_error
        from chatlog_keeper.macos_key import clear_last_error as clear_helper_error
        from chatlog_keeper.macos_wechat_capture import (
            clear_last_error as clear_capture_error,
        )
        clear_launch_error()
        clear_helper_error()
        clear_capture_error()
        if analyze_only:
            from chatlog_keeper.macos_key import ensure_helper
            from chatlog_keeper.macos_wechat_capture import ensure_capture_library
            ensure_helper()
            ensure_capture_library()
            return None
        from chatlog_keeper import wechat_db
        from chatlog_keeper.macos_debug_app import (
            debug_copy_process_identity,
            launch_debug_copy,
            terminate_debug_copy,
            validate_debug_copy_process,
        )
        from chatlog_keeper.macos_key import ensure_helper, extract_verified
        from chatlog_keeper.macos_wechat_capture import (
            create_capture_channel,
            ensure_capture_library,
        )
        resolved = Path(db_path) if db_path else None
        if not resolved or not resolved.is_file():
            return None
        # Build and verify both observers before the private client starts.  The
        # startup interposer is the primary path; the read-only memory scan is a
        # compatibility fallback for older client builds.
        if ensure_helper() is None:
            return None
        capture_library = ensure_capture_library()
        if capture_library is None:
            return None
        capture_channel = create_capture_channel(
            resolved,
            capture_library=capture_library,
        )
        if (
            capture_channel is None
            or capture_channel.library_path is None
            or capture_channel.library_identity is None
        ):
            if capture_channel is not None:
                capture_channel.close()
            return None

        debug_pid = None
        result = None
        process_clean = True
        channel_clean = False
        try:
            debug_pid = launch_debug_copy(
                "wechat",
                capture_library=capture_channel.library_path,
                capture_library_identity=capture_channel.library_identity,
                capture_fifo=capture_channel.path,
                capture_fifo_identity=capture_channel.identity,
            )
            if debug_pid:
                # A candidate can reach the FIFO before LaunchServices returns
                # the stable PID.  Keep candidates in bounded process memory
                # until the matching DB page exists; login may create/replace
                # that page just after the KDF call.
                pending_candidates: List[bytes] = []
                deadline = time.monotonic() + max(1, int(timeout))
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    if not validate_debug_copy_process("wechat", debug_pid):
                        break

                    for candidate in capture_channel.read_candidates():
                        if candidate not in pending_candidates:
                            pending_candidates.append(candidate)
                    if capture_channel.invalid:
                        break

                    oracle_pages = []
                    for oracle_path in _wechat_active_oracle_paths(
                        resolved, wechat_db
                    ):
                        page1 = wechat_db._read_stable_page1(oracle_path)
                        if page1:
                            oracle_pages.append((oracle_path, page1))

                    def verified_captured_candidate() -> Optional[bytes]:
                        for candidate in pending_candidates:
                            for oracle_path, page1 in oracle_pages:
                                if not wechat_db._verify_key_v4(candidate, page1):
                                    continue
                                if not validate_debug_copy_process(
                                    "wechat", debug_pid
                                ):
                                    return None
                                latest_page1 = wechat_db._read_stable_page1(
                                    oracle_path
                                )
                                if latest_page1 and wechat_db._verify_key_v4(
                                    candidate, latest_page1
                                ):
                                    return candidate
                        return None

                    result = verified_captured_candidate()
                    if result:
                        break

                    identity = debug_copy_process_identity("wechat", debug_pid)
                    if identity is None:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    key = None
                    matched_oracle: List[Optional[Path]] = [None]
                    if oracle_pages:
                        def verify_candidate(candidate: bytes) -> bool:
                            for oracle_path, page1 in oracle_pages:
                                if wechat_db._verify_key_v4(candidate, page1):
                                    matched_oracle[0] = oracle_path
                                    return True
                            return False

                        key = extract_verified(
                            "wechat", debug_pid,
                            verify_candidate,
                            elevate=False,
                            timeout=max(
                                1,
                                min(
                                    _MACOS_WECHAT_SCAN_SLICE_SECONDS,
                                    int(remaining),
                                ),
                            ),
                            expected_identity=identity,
                        )
                    if key:
                        if not validate_debug_copy_process("wechat", debug_pid):
                            break
                        matched_path = matched_oracle[0]
                        if matched_path is None:
                            continue
                        latest_page1 = wechat_db._read_stable_page1(matched_path)
                        if latest_page1 and wechat_db._verify_key_v4(
                            key, latest_page1
                        ):
                            result = key
                            break
                        # Login/checkpoint changed the DB family. Re-scan the
                        # same process immediately against the new stable page.
                        continue

                    # The startup channel remains authoritative even when the
                    # legacy Mach scanner is unavailable or times out.  Keep the
                    # QR/authentication window alive until the outer deadline.
                    clear_helper_error()
                    for candidate in capture_channel.read_candidates():
                        if candidate not in pending_candidates:
                            pending_candidates.append(candidate)
                    if capture_channel.invalid:
                        break
                    result = verified_captured_candidate()
                    if result:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(_MACOS_WECHAT_LOGIN_POLL_SECONDS, remaining))
        finally:
            try:
                if debug_pid is not None:
                    process_clean = terminate_debug_copy("wechat", debug_pid)
            finally:
                channel_clean = capture_channel.close()

        if not debug_pid or not process_clean or not channel_clean:
            return None
        return result
    if not _is_windows_host():
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
    script_timeout = max(1, int(timeout) - 15) if int(timeout) > 15 else max(1, int(timeout))
    args += ["-TimeoutSeconds", str(script_timeout)]
    if analyze_only:
        args.append("-NoDebugForKey")
    text = _run_active(script, args, timeout)
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
