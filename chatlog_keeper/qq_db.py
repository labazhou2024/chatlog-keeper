r"""
qq_db.py — QQ NT (QQNT) local message database reader.

Based on wechat_db.py architecture but adapted for QQ NT parameters:
- SQLCipher v4 with 32-byte key
- 1024-byte file header to skip
- KDF iterations: 4000 (vs default 256000)
- HMAC algorithm: SHA1 (vs SHA512)

Storage layout (QQ NT):
  Root:     C:\\Users\\<user>\Documents\Tencent Files\nt_qq\
  Global:   global\nt_db\nt_msg.db
  Key:      32-byte key extracted from QQ.exe process memory
  Cipher:   AES-256-CBC, SQLCipher v4
  Tables:   c2c_msg_table (private), group_msg_table (groups)
"""
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac as hmac_mod
import logging
import math
import os
import re
import struct
import subprocess
import sys
import unicodedata
from datetime import datetime, date, timedelta
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple, Iterator, Callable

from chatlog_keeper.core._private_temp import (
    PrivateTempLifecycleError,
    cleanup_private_temp_dir,
    create_private_temp_dir,
    scavenge_private_temp_dirs,
)

logger = logging.getLogger(__name__)


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class QQMessage:
    timestamp: datetime
    sender: str        # QQ number or nickname
    sender_name: str   # Display name
    content: str
    chat_name: str     # Chat/group name
    chat_uid: str      # Chat unique ID
    msg_type: int = 1  # 1=text, 2=image, 3=file, etc.
    # IM attachment metadata (file/voice cards in QQ NTQQ msg_body).
    # Populated by _extract_msg_text when protobuf field 45402 (image) or
    # equivalent file/voice fields are detected. Mirrors the wechat WxMessage
    # attachment_meta shape.
    attachment_meta: Optional[dict] = None
    conversation_type: str = "direct"
    is_group_chat: bool = False

    def is_text(self):
        return self.msg_type == 1

    def __str__(self):
        t = self.timestamp.strftime("%H:%M")
        return f"[{t}] {self.sender_name}: {self.content}"


_QQ_MESSAGE_PAGE_DEFAULT_SIZE = 200
_QQ_MESSAGE_PAGE_MAX_SIZE = 1000


@dataclass(frozen=True)
class _QQMessagePageCursor:
    """Opaque, scope-bound keyset position inside one decrypted QQ snapshot."""

    account_id: str
    conversation_id: str
    conversation_type: Optional[str]
    since_ts: float
    until_ts: float
    msg_time: float
    table_rank: int
    rowid: int


@dataclass(frozen=True)
class _QQMessageDictPage:
    """One bounded page plus the raw-row cursor needed to resume it exactly."""

    records: Tuple[Dict, ...]
    cursor_after: Optional[_QQMessagePageCursor]
    has_more: bool


class QQMessagePageCancelled(RuntimeError):
    """Raised when a bounded QQ page stream is cancelled between DB queries."""


def _raise_if_qq_message_page_cancelled(
    cancel_requested: Optional[Callable[[], bool]],
) -> None:
    """Convert the reader's cooperative cancellation signal to one stable error."""

    if cancel_requested is not None and cancel_requested():
        raise QQMessagePageCancelled("QQ message page read cancelled")


# ─── QQ Process helpers ───────────────────────────────────────────────────────

def _qq_process_creation_ticks(pid: int) -> Optional[int]:
    """Return a Windows process creation timestamp suitable for ordering.

    NTQQ starts one root ``QQ.exe`` before its GPU/network/renderer helpers.
    The database passphrase lives in the logged-in client process, while a
    helper-first scan can consume the whole timeout without ever reaching it.
    ``GetProcessTimes`` is local, fast, and does not require WMI/PowerShell.
    """
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.windll.kernel32
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        open_process.restype = wt.HANDLE
        get_process_times = kernel32.GetProcessTimes
        get_process_times.argtypes = [
            wt.HANDLE,
            ctypes.POINTER(wt.FILETIME),
            ctypes.POINTER(wt.FILETIME),
            ctypes.POINTER(wt.FILETIME),
            ctypes.POINTER(wt.FILETIME),
        ]
        get_process_times.restype = wt.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wt.HANDLE]
        close_handle.restype = wt.BOOL

        handle = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            created = wt.FILETIME()
            exited = wt.FILETIME()
            kernel = wt.FILETIME()
            user = wt.FILETIME()
            if not get_process_times(
                handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return None
            return (created.dwHighDateTime << 32) | created.dwLowDateTime
        finally:
            close_handle(handle)
    except Exception:
        return None


def _rank_qq_pids(pids: List[int]) -> List[int]:
    """Put the earliest (root) NTQQ process before later helper processes."""
    unique = list(dict.fromkeys(pids))
    observed_index = {pid: index for index, pid in enumerate(unique)}
    creation = {pid: _qq_process_creation_ticks(pid) for pid in unique}
    return sorted(
        unique,
        key=lambda pid: (
            creation[pid] is None,
            creation[pid] if creation[pid] is not None else observed_index[pid],
            observed_index[pid],
        ),
    )


def _get_qq_pids() -> list:
    """Return QQ.exe PIDs with the root client before Chromium helpers."""
    if sys.platform == "darwin":
        from chatlog_keeper.core._macos import process_pids
        return process_pids(("QQ",))
    try:
        r = subprocess.run(
            ["tasklist", "/FO", "CSV", "/FI", "IMAGENAME eq QQ.exe"],
            capture_output=True, timeout=5
        )
        text = r.stdout.decode("gbk", errors="replace")
        pids = []
        for line in text.strip().splitlines()[1:]:
            parts = line.split('","')
            if len(parts) >= 2:
                try:
                    pids.append(int(parts[1]))
                except ValueError:
                    pass
        return _rank_qq_pids(pids)
    except Exception as e:
        logger.warning(f"PID lookup failed: {e}")
        return []


# ─── Data directory discovery ─────────────────────────────────────────────────

def find_qq_data_root() -> Optional[Path]:
    """Locate the ``Tencent Files`` directory (one subdir per QQ number), neutrally.

    Real NT QQ layout: ``<Documents>/Tencent Files/<qq-id>/nt_qq/nt_db/nt_msg.db``,
    where ``<Documents>`` may be the local Documents, a OneDrive-backed Documents
    (English ``Documents`` or Chinese ``文档``), or a folder the user has moved to
    any drive. NT QQ also lets the user relocate its data dir to any drive root.

    Discovery order (machine-neutral — nothing hardcoded):
      1. ``CHATLOG_QQ_DATA_ROOT`` env var (explicit override — most reliable)
      2. real Documents (honoring Windows folder redirection) + OneDrive variants
      3. every logical drive root (data dir may be relocated to any drive)

    Returns the first candidate holding a live ``nt_msg.db``; else any that exists.
    """
    from chatlog_keeper.core._paths import all_drive_roots, candidate_documents_roots

    candidates: List[Path] = []
    env = os.environ.get("CHATLOG_QQ_DATA_ROOT", "").strip()
    if env:
        candidates.append(Path(env))
    if sys.platform == "darwin":
        from chatlog_keeper.core._macos import qq_container_roots
        for container in qq_container_roots():
            candidates.append(container / "Library" / "Application Support" / "QQ")
    for doc in candidate_documents_roots():
        candidates.append(doc / "Tencent Files")
    for drive in all_drive_roots():
        candidates.append(drive / "Tencent Files")
        candidates.append(drive / "Documents" / "Tencent Files")

    # de-duplicate, preserving order
    seen: set = set()
    uniq: List[Path] = []
    for c in candidates:
        k = str(c).lower()
        if k not in seen:
            seen.add(k)
            uniq.append(c)

    # First pass: prefer a candidate whose subdir has a live nt_msg.db.
    for c in uniq:
        try:
            if not c.exists():
                continue
            for sub in c.iterdir():
                if not sub.is_dir():
                    continue
                if not sub.name.isdigit() and sys.platform != "darwin":
                    continue
                db = sub / "nt_qq" / "nt_db" / "nt_msg.db"
                if not db.exists():
                    db = sub / "nt_db" / "nt_msg.db"
                if db.exists() and db.stat().st_size > 0:
                    logger.info(f"Found QQ data root (live): {c} (account={sub.name})")
                    return c
        except OSError:
            continue
    # Second pass: any directory that exists.
    for c in uniq:
        try:
            if c.exists():
                logger.info(f"Found QQ data root (fallback): {c}")
                return c
        except OSError:
            continue
    logger.warning("Could not locate QQ data root; set CHATLOG_QQ_DATA_ROOT to override")
    return None


def find_qq_number_dirs(data_root: Path) -> List[Path]:
    """Return account directories inside data_root.

    Windows names these folders with the numeric QQ account.  Current macOS QQ
    uses an opaque account directory, so accept a non-numeric directory only
    when it contains the expected ``nt_db/nt_msg.db`` layout.
    """
    dirs = []
    try:
        for item in data_root.iterdir():
            if not item.is_dir():
                continue
            if item.name.isdigit() or (
                sys.platform == "darwin"
                and (item / "nt_db" / "nt_msg.db").is_file()
            ):
                dirs.append(item)
    except OSError as e:
        logger.warning(f"Failed to scan data root: {e}")
    return dirs


def qq_account_database(account_dir: Path) -> Optional[Path]:
    """Return the live message database inside an already-discovered account.

    ``account_dir`` must come from :func:`find_qq_number_dirs`; callers must not
    construct it from an untrusted account identifier.  Keeping the path
    resolution here makes the CLI's account selection an exact name lookup
    rather than a path join.
    """
    primary = account_dir / "nt_qq" / "nt_db" / "nt_msg.db"
    if primary.is_file():
        return primary
    legacy = account_dir / "nt_db" / "nt_msg.db"
    if legacy.is_file():
        return legacy
    return None


def find_qq_account_databases(data_root: Path) -> Dict[str, Path]:
    """Return every locally discovered QQ account and its message database."""
    accounts: Dict[str, Path] = {}
    for account_dir in find_qq_number_dirs(data_root):
        db_path = qq_account_database(account_dir)
        if db_path is not None:
            accounts[account_dir.name] = db_path
    return dict(sorted(accounts.items(), key=lambda item: item[0]))


def find_msg_database(data_root: Path) -> Optional[Path]:
    """Locate the main NT QQ message database (nt_msg.db).

    Walks ``data_root/<qq-id>/nt_qq/nt_db/nt_msg.db``. Picks the dir with the
    largest db file (= the actively-used account). Falls back to a bundled
    snapshot under ``archive/nt_db_snapshot/`` if no live install present.

    Ranking by size+mtime so multi-account setups always prefer the live db
    over a stale snapshot stored alongside.
    """
    candidates: List[tuple] = []
    for db_path in find_qq_account_databases(data_root).values():
        try:
            st = db_path.stat()
            candidates.append((st.st_mtime, st.st_size, db_path))
        except OSError:
            pass
    if candidates:
        # Pick most-recently-modified (mtime desc); break tie by size desc.
        candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
        chosen = candidates[0][2]
        logger.info(f"Using live db: {chosen} (mtime={candidates[0][0]:.0f}, size={candidates[0][1]})")
        return chosen
    # Backup snapshot fallback (used when an account becomes unavailable)
    repo_root = Path(__file__).resolve().parents[1]
    snap = repo_root / "archive" / "nt_db_snapshot" / "nt_msg.db"
    if snap.exists():
        logger.info(f"Using archived snapshot: {snap}")
        return snap
    return None


# ─── Current-account auto-detection ───────────────────────────────────────────

def detect_current_qq_account():
    """Detect which QQ account is currently logged in / has live nt_msg.db.

    By design, callers must NOT depend on a hardcoded env/CLI value for the
    active QQ account — it is resolved by querying the filesystem directly.

    Algorithm:
      1. find_qq_data_root() → ~/OneDrive/文档/Tencent Files (or fallback)
      2. enumerate <qq-id>/nt_qq/nt_db/nt_msg.db with mtime
      3. pick the most-recently-modified (= currently active account)
      4. Returns None ONLY if no live install + no archived snapshot — callers
         treat that as a graceful skip.

    Returns:
      int QQ id (e.g. 10001) on success, None when not determinable.
    """
    root = find_qq_data_root()
    if not root:
        return None
    best: Optional[Tuple[float, object]] = None
    for qq_dir in find_qq_number_dirs(root):
        try:
            qid = int(qq_dir.name) if qq_dir.name.isdigit() else qq_dir.name
        except ValueError:
            continue
        db = qq_dir / "nt_qq" / "nt_db" / "nt_msg.db"
        if not db.exists():
            db = qq_dir / "nt_db" / "nt_msg.db"  # legacy
        if not db.exists():
            continue
        try:
            mtime = db.stat().st_mtime
        except OSError:
            continue
        if best is None or mtime > best[0]:
            best = (mtime, qid)
    if best:
        logger.info(f"detect_current_qq_account: {best[1]} (db mtime={best[0]:.0f})")
        return best[1]
    return None


# ─── Key cache (decouples key from a live QQ.exe) ────────────────────────────

def _persistent_key_cache_path() -> Optional[Path]:
    """Durable key cache under the per-install app-data dir
    (``%LOCALAPPDATA%\\chatlog-keeper\\data\\secrets`` on a frozen Windows build), the
    SAME persistent root every other writable state uses. Survives app
    upgrade/reinstall — NSIS overwrites ``_internal`` but never the app-data
    dir. Returns None only if the resolver is unavailable, in which case
    callers fall back to :func:`_legacy_key_cache_path`."""
    try:
        from chatlog_keeper.core._path_resolver import data_dir
        return data_dir() / "secrets" / "qq_db.key"
    except Exception:
        return None


def _legacy_key_cache_path() -> Path:
    """Legacy location: ``<decryptor>.parents[1]/data/secrets/qq_db.key``.
    In a frozen build this lands inside ``_internal/`` (wiped on every upgrade),
    so it is kept only as a READ fallback so an existing install's key migrates
    forward on first run after upgrading to a persistent-cache build."""
    repo_root = Path(__file__).resolve().parents[1]
    return repo_root / "data" / "secrets" / "qq_db.key"


def _key_cache_path() -> Path:
    """Resolve the key cache file to WRITE (persistent first).

    Prefers the app-data secrets dir so a cached key survives upgrades; falls
    back to the legacy package-relative path only if the resolver is missing."""
    p = _persistent_key_cache_path()
    return p if p is not None else _legacy_key_cache_path()


def _account_key_cache_path(account_id: str) -> Path:
    """Return a private cache path without exposing the native QQ account ID."""
    normalized = str(account_id or "").strip()
    if not normalized:
        return _key_cache_path()
    digest = hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()
    return _key_cache_path().parent / "qq_accounts" / f"{digest}.key"


def _parse_cached_key_text(text: str) -> Optional[bytes]:
    """Parse a cached key file's text → key bytes, or None if unrecognised.

    The format is the ASCII passphrase (16 or 32 chars printable). Legacy
    64-char hex (32-byte binary key) is still accepted for backward compat but
    won't actually decrypt NTQQ 9.9.x dbs."""
    text = (text or "").strip()
    # NTQQ 9.9.x: ASCII passphrase 16 or 32 chars
    if len(text) in (16, 32) and all(0x20 <= ord(c) <= 0x7E for c in text):
        return text.encode("ascii")
    # Legacy: 64-char hex = 32-byte raw key (NTQQ pre-9.9.x compat only)
    if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        return bytes.fromhex(text)
    return None


def load_cached_key() -> Optional[bytes]:
    """Read the cached NTQQ passphrase, persistent dir first.

    Read order: persistent app-data secrets dir → legacy ``_internal`` path
    (old-install migration fallback). First file that parses to a valid key
    wins; missing/garbage files are skipped silently."""
    from chatlog_keeper.core._secrets import read_secret_text

    seen: set = set()
    candidates = []
    persistent = _persistent_key_cache_path()
    if persistent is not None:
        candidates.append(persistent)
    candidates.append(_legacy_key_cache_path())
    for p in candidates:
        try:
            rp = str(p)
        except Exception:
            continue
        if rp in seen:
            continue
        seen.add(rp)
        text = read_secret_text(p)
        if text is None:
            continue
        key = _parse_cached_key_text(text)
        if key:
            return key
    return None


def load_cached_key_for_account(account_id: str) -> Optional[bytes]:
    """Load an account-scoped key, then fall back to the legacy global key."""
    from chatlog_keeper.core._secrets import read_secret_text

    normalized = str(account_id or "").strip()
    if normalized:
        path = _account_key_cache_path(normalized)
        text = read_secret_text(path)
        if text is not None:
            key = _parse_cached_key_text(text)
            if key:
                return key
    return load_cached_key()


def _cached_key_text(key) -> Optional[str]:
    """Serialize a supported QQ passphrase without logging or previewing it."""
    if not key:
        return None
    if isinstance(key, str):
        try:
            key = key.encode("ascii")
        except UnicodeEncodeError:
            return None
    if len(key) in (16, 32) and all(0x20 <= b <= 0x7E for b in key):
        return key.decode("ascii")
    if len(key) == 32:
        return key.hex()
    return None


def save_cached_key(key) -> bool:
    """Persist NTQQ passphrase (str or bytes) to data/secrets/qq_db.key.

    Stores as raw ASCII string (length 16 or 32) for 9.9.x passphrase format.
    Falls back to hex for 32-byte raw key (legacy <9.9.x).
    """
    text = _cached_key_text(key)
    if text is None:
        return False
    from chatlog_keeper.core._secrets import write_secret_text
    return write_secret_text(_key_cache_path(), text)


def save_cached_key_for_account(key, account_id: str) -> bool:
    """Persist a key under an irreversible account-scoped cache filename."""
    normalized = str(account_id or "").strip()
    text = _cached_key_text(key)
    if not normalized or text is None:
        return False
    from chatlog_keeper.core._secrets import write_secret_text
    return write_secret_text(_account_key_cache_path(normalized), text)


# ─── Key extraction from QQ process memory ────────────────────────────────────

def _verify_key_qq_with_algo(passphrase, db_raw: bytes, algo_kdf: str,
                              algo_hmac: str, reserve: int) -> bool:
    """Verify an ASCII passphrase against the FIRST page of a NTQQ nt_msg.db.

    ``passphrase``: str or bytes (NTQQ uses 16 or 32 ASCII chars).
    ``db_raw``: MUST include the 1024-byte NTQQ header (stripped here).
    ``algo_kdf``: "sha1" or "sha512" — for PBKDF2 (key derivation).
    ``algo_hmac``: "sha1" or "sha512" — for page-auth HMAC.
    ``reserve``: page-end reserve size in bytes (48 for SHA-1, 80 for SHA-512,
                 64 for some NTQQ builds).

    NTQQ 9.9.x (current, post-2024) uses MIXED:
      PBKDF2_HMAC_SHA512 (KDF) + HMAC_SHA1 (page auth)

    Correct SQLCipher v4 chain:
      aes_key  = PBKDF2_HMAC_<algo_kdf>(passphrase, salt, 4000, dklen=32)
      mac_key  = PBKDF2_HMAC_<algo_kdf>(aes_key, salt^0x3a, fast=2, dklen=32)
      tag      = HMAC_<algo_hmac>(mac_key, body + iv + page_no_le)
    """
    PAGE_SZ = 4096
    SALT_SZ = 16
    KEY_SZ = 32
    HEADER_SZ = 1024
    IV_SZ = 16

    if isinstance(passphrase, str):
        passphrase_bytes = passphrase.encode("ascii")
    else:
        passphrase_bytes = bytes(passphrase)

    try:
        if len(db_raw) < HEADER_SZ + PAGE_SZ:
            return False
        cipher_raw = db_raw[HEADER_SZ:HEADER_SZ + PAGE_SZ]
        salt = cipher_raw[:SALT_SZ]
        mac_salt = bytes(b ^ 0x3A for b in salt)

        kdf_func = algo_kdf  # "sha1" or "sha512"
        aes_key = hashlib.pbkdf2_hmac(kdf_func, passphrase_bytes, salt, 4000, dklen=KEY_SZ)
        mac_key = hashlib.pbkdf2_hmac(kdf_func, aes_key, mac_salt, 2, dklen=KEY_SZ)

        if algo_hmac == "sha1":
            hash_func = hashlib.sha1
            digest_len = 20
        elif algo_hmac == "sha512":
            hash_func = hashlib.sha512
            digest_len = 64
        else:
            return False

        body = cipher_raw[SALT_SZ:PAGE_SZ - reserve]
        iv = cipher_raw[PAGE_SZ - reserve:PAGE_SZ - reserve + IV_SZ]
        stored_tag = cipher_raw[PAGE_SZ - reserve + IV_SZ:PAGE_SZ - reserve + IV_SZ + digest_len]
        page_no_le = struct.pack("<I", 1)
        computed = hmac_mod.new(mac_key, body + iv + page_no_le, hash_func).digest()
        return hmac_mod.compare_digest(computed, stored_tag)
    except Exception:
        return False


# Try multiple (KDF, HMAC, reserve) combinations.
# Order = most likely first to optimize verify cost.
_VERIFY_COMBOS = [
    # (algo_kdf, algo_hmac, reserve) — NTQQ 9.9.x main mode
    ("sha512", "sha1", 48),
    ("sha512", "sha1", 64),
    ("sha512", "sha1", 80),
    # Legacy + same-algo fallbacks
    ("sha1", "sha1", 48),
    ("sha512", "sha512", 64),
    ("sha512", "sha512", 80),
    ("sha1", "sha1", 64),
    ("sha1", "sha1", 80),
]


def _verify_key_qq(passphrase, db_raw_or_page1) -> bool:
    """Verify NTQQ passphrase against db raw bytes by trying all known
    (KDF, HMAC, reserve) combinations until one matches.

    Accepts either full db_raw (with 1024 NTQQ header) OR a 4096-byte page1
    slice (legacy callers).
    """
    if len(db_raw_or_page1) == 4096:
        db_raw = b"\x00" * 1024 + db_raw_or_page1
    else:
        db_raw = db_raw_or_page1
    for kdf, hmac_algo, reserve in _VERIFY_COMBOS:
        if _verify_key_qq_with_algo(passphrase, db_raw, kdf, hmac_algo, reserve):
            return True
    return False


def _read_qq_verification_bytes(db_path: Path) -> Optional[bytes]:
    """Read only NTQQ's 1024-byte header plus encrypted 4096-byte page 1."""
    from chatlog_keeper.core._snapshot import read_stable_prefix

    try:
        return read_stable_prefix(Path(db_path), 1024 + 4096)
    except OSError:
        return None


def _is_printable_ascii(b: int) -> bool:
    """0x20..0x7E inclusive, the printable ASCII range."""
    return 0x20 <= b <= 0x7E


def _scan_memory_for_key(pid: int, db_path: Path = None,
                         timeout_s: Optional[float] = None) -> Optional[bytes]:
    """Scan QQ.exe process memory for the SQLCipher PASSPHRASE.

    NTQQ wrapper.node calls sqlite3_key_v2() with an ASCII string (16 or 32
    chars), so we scan for:
      - sequences of exactly 16 or 32 printable-ASCII bytes
      - followed by a 0x00 terminator (C string)
      - preceded by 0x00 (helps reject mid-string matches)
    Each candidate is verified against the live db's page-1 HMAC tag using
    both SHA-512 (NTQQ 2024-12+) and SHA-1 (legacy) algorithms.

    Returns the passphrase as bytes (preserving original ASCII string) or None.
    """
    if sys.platform == "darwin":
        if not db_path or not Path(db_path).is_file():
            return None
        db_raw = _read_qq_verification_bytes(Path(db_path))
        if not db_raw:
            return None
        from chatlog_keeper.macos_key import extract_verified
        return extract_verified(
            "qq",
            pid,
            lambda candidate: _verify_key_qq(candidate, db_raw),
            primary_verify=lambda candidate: _verify_key_qq_with_algo(
                candidate, db_raw, "sha512", "sha1", 48
            ),
            elevate=False,
            timeout=max(1, int(timeout_s or 120)),
        )

    kernel32 = ctypes.windll.kernel32
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400

    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        logger.warning(f"Cannot open PID {pid} — try running as Administrator")
        return None

    db_raw = None
    if db_path and db_path.exists():
        db_raw = _read_qq_verification_bytes(Path(db_path))

    class MBI64(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_uint64),
            ("AllocationBase", ctypes.c_uint64),
            ("AllocationProtect", wt.DWORD),
            ("__alignment1", wt.DWORD),
            ("RegionSize", ctypes.c_uint64),
            ("State", wt.DWORD),
            ("Protect", wt.DWORD),
            ("Type", wt.DWORD),
            ("__alignment2", wt.DWORD),
        ]

    MEM_COMMIT = 0x1000
    READABLE_PROTECTS = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

    found = None
    mbi = MBI64()
    address = 0
    seen = set()  # dedup candidates across regions

    # Wall-clock guard: scanning a multi-GB process (a large account's heap can
    # run to a few GB) shouldn't hang the caller for minutes. None = unbounded.
    import time as _time
    deadline = (_time.monotonic() + timeout_s) if timeout_s else None

    try:
        while address < 0x7FFFFFFFFFFF:
            if deadline and _time.monotonic() > deadline:
                logger.warning(f"PID {pid} memory scan hit {timeout_s:.0f}s timeout; "
                               "giving up (try `extract-key --method active` or `set-key`)")
                break
            ret = kernel32.VirtualQueryEx(
                handle, ctypes.c_uint64(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not ret:
                break

            if (mbi.State == MEM_COMMIT and
                    mbi.Protect in READABLE_PROTECTS and
                    0 < mbi.RegionSize < 200 * 1024 * 1024):
                buf = ctypes.create_string_buffer(mbi.RegionSize)
                read_n = ctypes.c_size_t(0)
                kernel32.ReadProcessMemory(
                    handle, ctypes.c_uint64(mbi.BaseAddress),
                    buf, mbi.RegionSize, ctypes.byref(read_n)
                )
                chunk = bytes(buf[:read_n.value])

                # Sliding window: find runs of printable ASCII terminated by 0x00.
                # Run length must be exactly 16 or 32 (NTQQ key formats).
                i = 0
                n = len(chunk)
                while i < n:
                    if _is_printable_ascii(chunk[i]):
                        j = i
                        while j < n and _is_printable_ascii(chunk[j]):
                            j += 1
                        run_len = j - i
                        # Must terminate with 0x00 to be a C string
                        if j < n and chunk[j] == 0x00 and run_len in (16, 32):
                            candidate = chunk[i:j]
                            if candidate not in seen:
                                seen.add(candidate)
                                if db_raw and _verify_key_qq(candidate, db_raw):
                                    logger.info(
                                        f"Passphrase verified at PID={pid} len={run_len}"
                                    )
                                    found = candidate
                                    break
                        i = j + 1
                    else:
                        i += 1

                if found:
                    break

            nxt = mbi.BaseAddress + mbi.RegionSize
            if nxt <= address:
                break
            address = nxt

        return found
    except Exception as e:
        logger.error(f"Memory scan error for PID {pid}: {e}")
        return None
    finally:
        kernel32.CloseHandle(handle)


def extract_key_from_qq(pid: int, db_path: Path = None,
                        timeout_s: Optional[float] = None) -> Optional[bytes]:
    """Extract NTQQ SQLCipher passphrase (16 or 32 char ASCII) from QQ.exe
    process memory. Returns passphrase as bytes, or None on failure.

    Note: passphrase semantics; not a raw binary key.
    ``timeout_s`` bounds the passive scan (see _scan_memory_for_key).
    """
    logger.info(f"Attempting passphrase extraction from QQ PID {pid}")
    key = _scan_memory_for_key(pid, db_path=db_path, timeout_s=timeout_s)
    if key:
        logger.info(f"Passphrase extracted: len={len(key)}")
    else:
        logger.warning("Passphrase extraction failed")
    return key


# ─── Database decryption ─────────────────────────────────────────────────────

_NTQQ_WRAPPER_SIZE = 1024
_NTQQ_PAGE_SIZE = 4096
_SQLITE_STANDARD_PENDING_BYTE = 0x40000000
_NTQQ_STRIPPED_PENDING_BYTE = _SQLITE_STANDARD_PENDING_BYTE - _NTQQ_WRAPPER_SIZE
_NTQQ_WRAPPED_LOCK_PAGE_NO = (_NTQQ_STRIPPED_PENDING_BYTE // _NTQQ_PAGE_SIZE) + 1
_QQ_PLAINTEXT_TEMP_PREFIXES = (
    "qq_page_",
    "qq_db_",
    "qq_directory_",
    "qq_participants_",
)

# The 1024-byte NTQQ wrapper shifts Windows' absolute lock-byte range into the
# fourth quarter of one SQLCipher page.  After stripping the wrapper, that page
# is 262144 (1-indexed), not stock SQLite's 262145 lock-byte page.
assert _NTQQ_STRIPPED_PENDING_BYTE == 0x3FFFFC00
assert _NTQQ_WRAPPED_LOCK_PAGE_NO == 262144


def _create_qq_plaintext_temp_dir(prefix: str) -> Path:
    if prefix not in _QQ_PLAINTEXT_TEMP_PREFIXES:
        raise RuntimeError("QQ private temporary directory setup failed")
    try:
        return create_private_temp_dir(prefix)
    except PrivateTempLifecycleError:
        raise RuntimeError("QQ private temporary directory setup failed") from None


def _finalize_qq_plaintext_temp(connection, temporary_root: Path) -> None:
    """Close SQLite first, then unconditionally delete all plaintext files."""

    close_failed = False
    if connection is not None:
        try:
            connection.close()
        except BaseException:  # noqa: BLE001 - cleanup must still run
            close_failed = True
    try:
        cleanup_private_temp_dir(Path(temporary_root))
    except BaseException:  # noqa: BLE001 - never expose cleanup internals
        raise RuntimeError("QQ temporary plaintext cleanup failed") from None
    if close_failed:
        raise RuntimeError("QQ SQLite helper close failed") from None


try:
    scavenge_private_temp_dirs(_QQ_PLAINTEXT_TEMP_PREFIXES)
except PrivateTempLifecycleError:
    raise RuntimeError("QQ stale temporary plaintext cleanup failed") from None


@dataclass(frozen=True)
class _QQDecryptResult:
    ok: bool
    shifted_pending_byte: bool = False


@dataclass(frozen=True)
class _QQDecryptedDatabase:
    path: Path
    shifted_pending_byte: bool = False


def _is_wrapped_windows_lock_placeholder(
    page: bytes,
    *,
    page_no: int,
    source_wrapper_size: int,
    platform_name: str,
) -> bool:
    """Recognize only NTQQ's exact Windows lock-page/HMAC exception."""

    return (
        platform_name == "nt"
        and source_wrapper_size == _NTQQ_WRAPPER_SIZE
        and page_no == _NTQQ_WRAPPED_LOCK_PAGE_NO
        and len(page) == _NTQQ_PAGE_SIZE
        and not any(page)
    )


def _skip_header(db_path: Path, output_path: Path) -> bool:
    """
    Skip the first 1024 bytes of QQ NT database header.
    QQ NT adds a 1024-byte header before the actual SQLCipher data.
    """
    try:
        import shutil
        from chatlog_keeper.core._snapshot import snapshot_db_family
        with snapshot_db_family(db_path) as snapshot:
            # Stream the copy in chunks (skipping the 1024-byte header) to bound memory.
            with open(snapshot, "rb") as f:
                f.seek(0, 2)
                if f.tell() < _NTQQ_WRAPPER_SIZE + _NTQQ_PAGE_SIZE:
                    logger.warning("QQ database snapshot is too small")
                    return False
                f.seek(_NTQQ_WRAPPER_SIZE)
                with open(output_path, "wb") as out:
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk:
                            break
                        out.write(chunk)
            # Preserve the same stable WAL/SHM generation beside the stripped
            # main DB.  SQLCipher WAL pages do not carry QQ's 1024-byte wrapper
            # header and are copied verbatim for authenticated recovery after
            # the main pages are decrypted.
            for suffix in ("-wal", "-shm"):
                source = snapshot.with_name(snapshot.name + suffix)
                destination = output_path.with_name(output_path.name + suffix)
                destination.unlink(missing_ok=True)
                if source.is_file():
                    shutil.copy2(source, destination)
        logger.info("QQ database wrapper removed (streaming)")
        return True
    except Exception as e:
        logger.warning("QQ header removal failed: %s", type(e).__name__)
        return False


def _resolve_qq_cipher(key_bytes: bytes, first_page: bytes):
    """Return the HMAC-verified SQLCipher parameter tuple for page 1."""
    raw = b"\0" * 1024 + first_page
    for kdf, hmac_algo, reserve in _VERIFY_COMBOS:
        if _verify_key_qq_with_algo(
            key_bytes, raw, kdf, hmac_algo, reserve
        ):
            return kdf, hmac_algo, reserve
    return None


def _decrypt_qq_page(
    page: bytes,
    *,
    page_no: int,
    salt: bytes,
    aes_key: bytes,
    mac_key: bytes,
    hmac_algo: str,
    reserve: int,
) -> Optional[bytes]:
    """Authenticate and decrypt one current/legacy NTQQ SQLCipher page."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            return None
    if len(page) != 4096 or page_no <= 0:
        return None
    if hmac_algo == "sha1":
        hash_func = hashlib.sha1
        digest_len = 20
    elif hmac_algo == "sha512":
        hash_func = hashlib.sha512
        digest_len = 64
    else:
        return None
    prefix = 16 if page_no == 1 else 0
    if prefix and page[:16] != salt:
        return None
    body = page[prefix:4096 - reserve]
    iv_start = 4096 - reserve
    iv = page[iv_start:iv_start + 16]
    stored_tag = page[
        iv_start + 16:iv_start + 16 + digest_len
    ]
    computed = hmac_mod.new(
        mac_key,
        body + iv + struct.pack("<I", page_no),
        hash_func,
    ).digest()
    if not hmac_mod.compare_digest(computed, stored_tag):
        return None
    plain = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(body)
    if page_no == 1:
        return b"SQLite format 3\x00" + plain + page[4096 - reserve:]
    return plain + page[4096 - reserve:]


def _decrypt_db_qq_result(
    db_path: Path,
    key,
    output_path: Path,
    *,
    source_wrapper_size: int,
    platform_name: Optional[str] = None,
) -> _QQDecryptResult:
    """Decrypt NTQQ nt_msg.db (post-1024-header-strip) to plain SQLite.

    Resolves the DB's HMAC-verified current/legacy cipher tuple from page 1,
    authenticates every main page, then validates and applies committed WAL
    frames through the copied WAL-index ``mxFrame``.

    NTQQ 9.9.x parameters (confirmed by passphrase verify):
      - Key:       16-char ASCII passphrase ({XXXXX...) — wrapper.node sqlite3_key_v2
      - KDF:       PBKDF2_HMAC_SHA512, 4000 iter, dklen=32 → aes_key
      - Cipher:    AES-256-CBC
      - Page size: 4096
      - Reserve:   48 (16 IV + 20 HMAC + 12 padding) — HMAC-SHA1 default
      - HMAC:      SHA-1 (only for verify, not decrypt)
    """
    if isinstance(key, str):
        key_bytes = key.encode("ascii")
    else:
        key_bytes = bytes(key)

    PAGE_SZ = _NTQQ_PAGE_SIZE
    SALT_SZ = 16
    KEY_SZ = 32

    shifted_pending_byte = False
    effective_platform = os.name if platform_name is None else platform_name
    try:
        # Decrypt page-by-page so peak memory stays at a single 4 KB page.
        # Reading a whole (potentially multi-GB) DB into memory at once can
        # exhaust RAM; streaming keeps the footprint constant.
        pages = 0
        with open(db_path, "rb") as f, open(output_path, "wb") as out:
            first = f.read(PAGE_SZ)
            if len(first) < PAGE_SZ:
                raise OSError("encrypted DB is too small to decrypt")
            salt = first[:SALT_SZ]
            resolved = _resolve_qq_cipher(key_bytes, first)
            if resolved is None:
                raise OSError("page-1 HMAC does not match the supplied key")
            kdf, hmac_algo, reserve = resolved
            aes_key = hashlib.pbkdf2_hmac(
                kdf, key_bytes, salt, 4000, dklen=KEY_SZ
            )
            mac_salt = bytes(value ^ 0x3A for value in salt)
            mac_key = hashlib.pbkdf2_hmac(
                kdf, aes_key, mac_salt, 2, dklen=KEY_SZ
            )
            plain = _decrypt_qq_page(
                first,
                page_no=1,
                salt=salt,
                aes_key=aes_key,
                mac_key=mac_key,
                hmac_algo=hmac_algo,
                reserve=reserve,
            )
            if plain is None:
                raise OSError("page 1 authentication failed")
            out.write(plain)
            pages = 1
            while True:
                page = f.read(PAGE_SZ)
                if not page:
                    break
                if len(page) != PAGE_SZ:
                    raise OSError("encrypted DB has a truncated trailing page")
                page_no = pages + 1
                plain = _decrypt_qq_page(
                    page,
                    page_no=page_no,
                    salt=salt,
                    aes_key=aes_key,
                    mac_key=mac_key,
                    hmac_algo=hmac_algo,
                    reserve=reserve,
                )
                if plain is None:
                    if _is_wrapped_windows_lock_placeholder(
                        page,
                        page_no=page_no,
                        source_wrapper_size=source_wrapper_size,
                        platform_name=effective_platform,
                    ):
                        # The original Windows VFS reserved this whole page
                        # because its 512 lock bytes overlap the page after the
                        # NTQQ wrapper shift.  It is the only unauthenticated
                        # main-page exception we accept.
                        plain = b"\0" * PAGE_SZ
                        shifted_pending_byte = True
                    else:
                        raise OSError(f"page {page_no} authentication failed")
                out.write(plain)
                pages += 1

        from chatlog_keeper.core._wal import apply_wal
        wal_path = db_path.with_name(db_path.name + "-wal")
        shm_path = db_path.with_name(db_path.name + "-shm")
        wal_frames = apply_wal(
            wal_path,
            output_path,
            lambda page, page_no: _decrypt_qq_page(
                page,
                page_no=page_no,
                salt=salt,
                aes_key=aes_key,
                mac_key=mac_key,
                hmac_algo=hmac_algo,
                reserve=reserve,
            ),
            shm_path=shm_path,
            expected_page_size=PAGE_SZ,
        )
        logger.info(
            "Decrypted %d main pages + %d committed WAL frames "
            "kdf=%s hmac=%s reserve=%d (streaming)",
            pages,
            wal_frames,
            kdf,
            hmac_algo,
            reserve,
        )
        return _QQDecryptResult(
            ok=True,
            shifted_pending_byte=shifted_pending_byte,
        )
    except Exception as e:
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        logger.warning("QQ database decryption failed: %s", type(e).__name__)
        return _QQDecryptResult(
            ok=False,
            shifted_pending_byte=shifted_pending_byte,
        )


def _decrypt_db_qq(db_path: Path, key, output_path: Path) -> bool:
    """Compatibility wrapper for ordinary stripped NTQQ databases.

    The shifted Windows lock-page exception is intentionally unavailable here:
    callers must have just removed and explicitly attested the 1024-byte NTQQ
    wrapper via :func:`_decrypt_db_qq_result`.
    """

    return _decrypt_db_qq_result(
        db_path,
        key,
        output_path,
        source_wrapper_size=0,
    ).ok


def _open_qq_sqlite_connection(database):
    """Open a decrypted QQ DB, isolating the shifted Windows format."""

    if isinstance(database, _QQDecryptedDatabase):
        path = database.path
        shifted_pending_byte = database.shifted_pending_byte
    else:
        path = Path(database)
        shifted_pending_byte = False
    if shifted_pending_byte:
        if os.name != "nt":
            raise OSError("shifted NTQQ lock-page databases are Windows-only")
        from chatlog_keeper._qq_sqlite_proxy import open_shifted_pending_connection

        return open_shifted_pending_connection(path)
    import sqlite3

    return sqlite3.connect(str(path))


def _qq_decrypted_database_path(database) -> Path:
    if isinstance(database, _QQDecryptedDatabase):
        return database.path
    return Path(database)


# ─── Message reading ─────────────────────────────────────────────────────────

def _decompress_message(data) -> str:
    """Decompress message content if needed."""
    if not data:
        return ""
    if isinstance(data, bytes):
        # Check for zstd compression
        if data[:4] == b"\x28\xb5\x2f\xfd":
            try:
                import zstandard as zstd
                cctx = zstd.ZstdDecompressor()
                return cctx.decompress(data).decode("utf-8", errors="replace")
            except Exception:
                return data.decode("utf-8", errors="replace")
        return data.decode("utf-8", errors="replace")
    return str(data)


def _proto_varint(data: bytes, off: int) -> Tuple[Optional[int], int]:
    """Decode a protobuf varint at offset. Returns (value, new_offset)."""
    val = 0
    shift = 0
    while off < len(data):
        b = data[off]
        off += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, off
        shift += 7
        if shift > 70:
            return None, off
    return None, off


def _proto_parse(data: bytes) -> Dict[int, list]:
    """Parse protobuf wire format. Returns {field_num: [(wire_type_tag, value)]}.

    Tolerant: stops on first parse error, keeps already-extracted fields.
    Wire types: 0=varint, 1=fixed64, 2=length-delimited, 5=fixed32.
    """
    fields: Dict[int, list] = {}
    off = 0
    while off < len(data):
        tag, off = _proto_varint(data, off)
        if tag is None:
            break
        wt = tag & 7
        fnum = tag >> 3
        try:
            if wt == 0:
                v, off = _proto_varint(data, off)
                if v is None:
                    break
                fields.setdefault(fnum, []).append(("varint", v))
            elif wt == 2:
                ln, off = _proto_varint(data, off)
                if ln is None or ln < 0 or off + ln > len(data):
                    break
                fields.setdefault(fnum, []).append(("bytes", data[off:off + ln]))
                off += ln
            elif wt == 5:
                fields.setdefault(fnum, []).append(("fixed32", data[off:off + 4]))
                off += 4
            elif wt == 1:
                fields.setdefault(fnum, []).append(("fixed64", data[off:off + 8]))
                off += 8
            else:
                break
        except Exception:
            break
    return fields


# NTQQ msgBody (col 40800) protobuf field IDs.
#
# Reverse-engineered from live-decoded samples + an empirical field inventory:
# the 4-field set already covers 100% of observed msgs (0 empty narratives,
# 0 URL leaks). Below we keep the high-confidence 4 fields + add image
# dimension extraction (45411/45412) for richer narrative, and add an explicit
# skip-list for media-metadata fields that must NEVER leak to text.
#
# Outer wrapper field that ALL msg_body BLOBs begin with:
_NTQQ_MSG_OUTER_WRAPPER = 40800

# Inner fields (after unwrapping 40800):
_NTQQ_MSG_TEXT_PRIMARY = 45101       # 主文本 content (text+reply inner)
_NTQQ_MSG_REPLY_CONTAINER = 47423    # reply wrapper; nested 45101 = quoted text
_NTQQ_MSG_IMAGE_FILENAME = 45402     # image filename .jpg/.png/.gif (also file/voice names)
_NTQQ_MSG_IMAGE_WIDTH = 45411        # image width px (varint)
_NTQQ_MSG_IMAGE_HEIGHT = 45412       # image height px (varint)
_NTQQ_MSG_SENDER_UID_NESTED = 40020  # sender uid string (u_xxx) inside body

# Large-account inventory expansion — ALL msg types from a stratified sample
# of a multi-GB nt_msg.db (per-combo deep dive):
_NTQQ_MSG_FILE_SIZE = 45405          # file/image size (varint, bytes)
_NTQQ_MSG_FILE_LOCAL_PATH = 45403    # file local path (NTQQ ::NTOSFull:: prefix)
_NTQQ_MSG_FILE_MD5_BIN = 45406       # 16-byte md5 (image+voice+file)
_NTQQ_MSG_FILE_MD5_ALT = 45407       # 16-byte md5 (file-only variant)
_NTQQ_MSG_FILE_SDK_VERSION = 45550   # 1=file, 4=voice (sub-type discriminator)
_NTQQ_MSG_VOICE_DURATION_MS = 45906  # voice duration in ms (when 45550=4)
_NTQQ_MSG_VOICE_FORMAT = 45907       # voice format (1=amr)

# Sticker / face (msg_class=17, msg_subtype=8) — "super face"
_NTQQ_MSG_FACE_ID = 80810            # face_id (varint, e.g. 209590)
_NTQQ_MSG_FACE_HASH = 80824          # face hash (utf8 hex)
_NTQQ_MSG_FACE_NAME = 80900          # display text '[骰子]' '[掀桌]' etc
_NTQQ_MSG_FACE_MD5 = 80903           # 16-byte md5

# Ark/markdown application messages (msg_class=11, msg_subtype=0)
_NTQQ_MSG_ARK_JSON = 47901           # JSON payload {"app": "com.tencent.video.lua", ...}

# Merged forward (msg_class=8, msg_subtype=0)
_NTQQ_MSG_MERGED_PREVIEW = 48601     # base64 preview blob
_NTQQ_MSG_MERGED_XML = 48602         # XML msg list (full content)
_NTQQ_MSG_MERGED_GUID = 48603        # UUID

# Reply / react with emoji (msg_class=5, msg_subtype=4)
_NTQQ_MSG_REACT_REPLY_GROUP = 47702  # react group base
# 47703/47704 = sender uids; 47705/47714 = display labels '回应'/emoji
_NTQQ_MSG_REACT_LABEL_FROM = 47705
_NTQQ_MSG_REACT_LABEL_TO = 47714
_NTQQ_MSG_REACT_EMOJI = 47706

# Pai-yi-pai 戳一戳 (msg_class=9, msg_subtype=33)
_NTQQ_MSG_PAI_GROUP = 47401          # base — 47419=action(47=戳), 47413='我戳了你的游戏'

# System gtip (msg_class=5, msg_subtype=12)
_NTQQ_MSG_GTIP_XML = 48214           # <gtip><nor>记为验证消息</nor>
_NTQQ_MSG_GTIP_JSON = 48271          # JSON {align,items} alt

# Quoted nested ref (49154/49155 — appears in msg_subtype=17 reply chain)
_NTQQ_MSG_QUOTE_NESTED_TAG = 49154   # utf8 'nt_1'
_NTQQ_MSG_QUOTE_NESTED_TS = 49155    # quoted msg timestamp

# Fields that contain media-pipeline metadata (CDN URLs, aeskey, md5, etc.)
# and MUST NEVER be emitted as narrative — the brute UTF-8 fallback would
# happily decode them otherwise. Explicit skip-list prevents URL leak.
_NTQQ_MSG_MEDIA_META_SKIP = frozenset({
    45406,  # image/file/voice md5 (16 bytes binary)
    45407,  # file md5 alt
    45408,  # image SHA1 (20 bytes)
    45416,  # image flag varint
    45418,  # image flag varint
    45424,  # alt filename (sometimes duplicate of 45402)
    45503,  # image url metadata wrapper (base64 token)
    45504,  # file/image alt token D6EA...
    45505,  # image timestamp
    45511,  # image flag varint
    45513,  # image flag varint
    45517,  # ts varint
    45518,  # ttl varint
    45802,  # CDN download URL primary
    45803,  # CDN download URL alt1
    45804,  # CDN download URL alt2
    45815,  # (empty in obs samples)
    45816,  # multimedia.nt.qq.com.cn hostname
    45817,  # CDN config flag
    45818,  # CDN config empty
    45821,  # CDN config flag
    45822,  # CDN config flag
    45906,  # voice 'flag' varint (24 in samples — NOT duration, kept for analysis only)
    45907,  # voice format flag
    45909,  # voice CDN flag
    45911,  # voice CDN flag
    45922,  # voice flag
    47702,  # react flag
    47703,  # react sender uid
    47704,  # react receiver uid
    47705,  # react sender nickname (NOT emoji)
    47706,  # react extra label
    47710,  # react md5
    47711,  # react flag
    47713,  # react bytes
    47714,  # react receiver nickname (NOT emoji)
    48212,  # gtip seq
    48213,  # gtip flag
    48215,  # gtip msg seq
    48216,  # gtip ts
    48217,  # client metadata wrapper
    48218,  # gtip extra
    48272,  # gtip JSON 1
    48273,  # gtip JSON 2
    47402,  # pai 戳一戳 ts/seq
    47403,  # pai sender uin
    47404,  # pai ts
    47411,  # pai flag
    47416,  # pai flag
    47422,  # pai ref ts
    49155,  # quote nested ts
    80810,  # face_id raw (covered via _NTQQ_MSG_FACE_ID handler)
    80824,  # face hash hex
    80901, 80902, 80905, 80908, 80909, 80910,  # face dims/flags
})


def _extract_msg_text(blob: bytes) -> str:
    """Extract human-readable text from NTQQ msgBody (col 40800) protobuf BLOB.

    Real protobuf decode replaces brute UTF-8. Coverage:
      - text  (45101) — chat 内容主要载体
      - reply (47423.45101) — [引用: …] 引用消息
      - image (45402) — [图片: filename.jpg WxH]
      - sender_uid (40020) — skip (not user-facing)
      - media-meta (45406/45503/45802/45816/etc) — explicit skip (no URL leak)
      - unknown nested → recurse depth-3 → fallback brute UTF-8

    A field-inventory analysis showed this 4-field decode covers 100% of real
    msgs. Image dimension capture (45411 width, 45412 height) enriches the
    image narrative; the explicit media-meta skip list
    (_NTQQ_MSG_MEDIA_META_SKIP) prevents CDN URL leak via the brute fallback.

    Returns "" when BLOB has zero recoverable text.
    """
    if not blob:
        return ""
    parts: List[str] = []
    fields = _proto_parse(blob)

    def _collect(fdict: Dict[int, list], depth: int = 0,
                 image_w: List[Optional[int]] = None,
                 image_h: List[Optional[int]] = None) -> None:
        if depth > 3:
            return
        for fnum in sorted(fdict.keys()):
            for (typ, val) in fdict[fnum]:
                # Capture image dims even when wire_type=varint
                if typ == "varint" and fnum == _NTQQ_MSG_IMAGE_WIDTH and image_w is not None:
                    if image_w and image_w[0] is None:
                        image_w[0] = int(val)
                    continue
                if typ == "varint" and fnum == _NTQQ_MSG_IMAGE_HEIGHT and image_h is not None:
                    if image_h and image_h[0] is None:
                        image_h[0] = int(val)
                    continue
                if typ != "bytes":
                    continue
                if fnum == _NTQQ_MSG_TEXT_PRIMARY:
                    try:
                        parts.append(val.decode("utf-8"))
                        continue
                    except UnicodeDecodeError:
                        pass
                if fnum == _NTQQ_MSG_REPLY_CONTAINER:
                    # Mirror wechat `_format_refermsg` — recurse into nested
                    # filename (45402) to detect a quoted image/file/voice, not
                    # just text (45101). Emit `[引用 <kind>: <filename>]` for
                    # nested attachments instead of a bare `[引用: <text>]`.
                    sub = _proto_parse(val)
                    quoted_atts: List[str] = []
                    quoted_texts: List[str] = []
                    for sfn, svals in sub.items():
                        # nested filename (image/file/voice)
                        if sfn == _NTQQ_MSG_IMAGE_FILENAME:
                            for (st, sv) in svals:
                                if st == "bytes":
                                    try:
                                        fname = sv.decode("utf-8", errors="replace")
                                        ext = (fname.lower().rsplit(".", 1)[-1]
                                               if "." in fname else "")
                                        if ext in ("amr", "silk"):
                                            quoted_atts.append(f"[语音 {fname}]")
                                        elif ext in ("mp4", "mov", "avi", "mkv"):
                                            quoted_atts.append(f"[视频 {fname}]")
                                        elif ext in ("pdf", "docx", "doc", "xlsx",
                                                     "xls", "pptx", "ppt", "zip",
                                                     "rar", "7z", "txt", "csv"):
                                            quoted_atts.append(f"[文件 {fname}]")
                                        else:
                                            quoted_atts.append(f"[图片 {fname}]")
                                    except UnicodeDecodeError:
                                        pass
                        # quoted text
                        elif sfn == _NTQQ_MSG_TEXT_PRIMARY:
                            for (_, sv) in svals:
                                if not isinstance(sv, (bytes, bytearray)):
                                    continue
                                try:
                                    quoted_texts.append(sv.decode("utf-8"))
                                except UnicodeDecodeError:
                                    pass
                    body_parts = quoted_atts + quoted_texts
                    if body_parts:
                        body = " ".join(body_parts)[:120]
                        parts.append(f"[引用: {body}]")
                    continue
                if fnum == _NTQQ_MSG_IMAGE_FILENAME:
                    # 45402 carries image OR file OR voice filename —
                    # discriminate by sibling fields:
                    #   - sibling 45550=4 → voice (.amr)
                    #   - sibling 45403 present OR 45411/12 both 0 → file
                    #   - otherwise → image (with w/h)
                    try:
                        name = val.decode("utf-8", errors="replace")
                        # Probe sibling fields for type discrimination
                        sibling_w = [None]
                        sibling_h = [None]
                        sibling_size = [None]
                        sibling_local_path = [None]
                        sibling_sdk_ver = [None]
                        sibling_voice_ms = [None]
                        for sf, svs in fdict.items():
                            if sf == _NTQQ_MSG_IMAGE_WIDTH:
                                for (st, sv) in svs:
                                    if st == "varint":
                                        sibling_w[0] = int(sv); break
                            elif sf == _NTQQ_MSG_IMAGE_HEIGHT:
                                for (st, sv) in svs:
                                    if st == "varint":
                                        sibling_h[0] = int(sv); break
                            elif sf == _NTQQ_MSG_FILE_SIZE:
                                for (st, sv) in svs:
                                    if st == "varint":
                                        sibling_size[0] = int(sv); break
                            elif sf == _NTQQ_MSG_FILE_LOCAL_PATH:
                                for (st, sv) in svs:
                                    if st == "bytes":
                                        try:
                                            sibling_local_path[0] = sv.decode("utf-8", errors="replace")
                                        except Exception:
                                            pass
                                        break
                            elif sf == _NTQQ_MSG_FILE_SDK_VERSION:
                                for (st, sv) in svs:
                                    if st == "varint":
                                        sibling_sdk_ver[0] = int(sv); break
                            elif sf == _NTQQ_MSG_VOICE_DURATION_MS:
                                for (st, sv) in svs:
                                    if st == "varint":
                                        sibling_voice_ms[0] = int(sv); break

                        def _fmt_size(n: Optional[int]) -> str:
                            if not n:
                                return ""
                            if n < 1024:
                                return f"{n}B"
                            if n < 1024 * 1024:
                                return f"{n / 1024:.1f}KB"
                            return f"{n / 1024 / 1024:.1f}MB"

                        # Voice: STRICT — only if (a) filename ends with .amr/.silk
                        # OR (b) sdk_ver=4 AND has voice metadata (45906/45907 present).
                        # 2026-05-23: too-loose check caused image false-positives
                        # because 45550=4 sometimes appears outside voice context.
                        is_voice = name.lower().endswith((".amr", ".silk"))
                        if not is_voice and sibling_sdk_ver[0] == 4 and sibling_voice_ms[0] is not None:
                            is_voice = True
                        if is_voice:
                            sz = _fmt_size(sibling_size[0])
                            # 45906 varies — small ints likely flag, large = ms duration
                            if sibling_voice_ms[0] and sibling_voice_ms[0] > 100:
                                sec = sibling_voice_ms[0] / 1000.0
                                label = f"[语音 {sec:.1f}s {sz}]"
                            else:
                                label = f"[语音 {sz}]"
                            parts.append(label.strip())
                            continue
                        # File: has local_path OR w/h both 0 OR known file ext
                        is_likely_file = (
                            sibling_local_path[0]
                            or (sibling_w[0] == 0 and sibling_h[0] == 0)
                            or name.lower().endswith((".pdf", ".docx", ".doc", ".xlsx", ".xls",
                                                       ".pptx", ".ppt", ".zip", ".rar", ".7z",
                                                       ".exe", ".mp4", ".mov", ".avi", ".mkv",
                                                       ".txt", ".csv", ".rtf"))
                        )
                        if is_likely_file:
                            sz = _fmt_size(sibling_size[0])
                            # Video files get [视频] label, others [文件]
                            if name.lower().endswith((".mp4", ".mov", ".avi", ".mkv", ".webm")):
                                label = f"[视频: {name} {sz}]"
                            else:
                                label = f"[文件: {name} {sz}]"
                            parts.append(label.strip())
                            continue
                        # Image: has w/h
                        if sibling_w[0] and sibling_h[0]:
                            parts.append(f"[图片: {name} {sibling_w[0]}x{sibling_h[0]}]")
                        else:
                            parts.append(f"[图片: {name}]")
                        continue
                    except Exception:
                        pass
                # super face / sticker (msg_class=17, subtype=8)
                if fnum == _NTQQ_MSG_FACE_NAME:
                    try:
                        face_label = val.decode("utf-8", errors="replace").strip()
                        if face_label:
                            # Often comes pre-bracketed like '[骰子]'; if not, add brackets
                            if not (face_label.startswith("[") and face_label.endswith("]")):
                                face_label = f"[表情: {face_label}]"
                            parts.append(face_label)
                            continue
                    except Exception:
                        pass
                # Ark/markdown application messages
                if fnum == _NTQQ_MSG_ARK_JSON:
                    try:
                        ark = val.decode("utf-8", errors="replace")
                        # Parse JSON to extract app + desc + prompt
                        import json as _json
                        try:
                            d = _json.loads(ark)
                            app = d.get("app", "")
                            prompt = d.get("prompt") or d.get("desc") or ""
                            meta = d.get("meta") or {}
                            # Common: video.lua / news / structmsg etc
                            label_parts = []
                            if prompt:
                                label_parts.append(prompt[:80])
                            if app and app not in (prompt or ""):
                                short_app = app.split(".")[-1] if "." in app else app
                                label_parts.append(f"({short_app})")
                            if label_parts:
                                parts.append(f"[小程序: {' '.join(label_parts)}]")
                            else:
                                parts.append("[小程序]")
                        except Exception:
                            parts.append("[小程序]")
                        continue
                    except Exception:
                        pass
                # Merged forward: extract gist from XML
                # Mirror wechat `_format_merged_forward` — parse XML, find
                # dataitems, then inline each (sourcename + datadesc) up to a
                # 500-char budget instead of `[聊天记录: title] (Nitems)`.
                if fnum == _NTQQ_MSG_MERGED_XML:
                    try:
                        xml_str = val.decode("utf-8", errors="replace")
                        # Try strict XML parse first to get dataitems
                        try:
                            import xml.etree.ElementTree as _ET
                            root_xml = _ET.fromstring(xml_str)
                            title_node = root_xml.find(".//title")
                            head_title = (
                                title_node.text.strip()
                                if title_node is not None and title_node.text
                                else "聊天记录"
                            )
                            dataitems = root_xml.findall(".//dataitem")
                            if dataitems:
                                head = f"[聊天记录: {head_title[:50]} | {len(dataitems)}条]"
                                inline_parts = [head]
                                used = len(head)
                                MAX_CHARS = 500
                                for di in dataitems:
                                    sender_node = di.find("sourcename")
                                    desc_node = di.find("datadesc")
                                    sender_txt = (
                                        sender_node.text.strip()[:20]
                                        if sender_node is not None and sender_node.text
                                        else "?"
                                    )
                                    desc_txt = (
                                        desc_node.text.strip()[:80]
                                        if desc_node is not None and desc_node.text
                                        else ""
                                    )
                                    if not desc_txt:
                                        continue
                                    item_str = f" | {sender_txt}: {desc_txt}"
                                    if used + len(item_str) > MAX_CHARS:
                                        inline_parts.append(" | …")
                                        break
                                    inline_parts.append(item_str)
                                    used += len(item_str)
                                parts.append("".join(inline_parts))
                                continue
                        except _ET.ParseError:
                            pass
                        # Fallback to old regex behavior on parse failure
                        import re as _re
                        titles = _re.findall(r"<title[^>]*>([^<]+)</title>", xml_str)
                        msg_cnt = len(_re.findall(r"<msg[^>]", xml_str))
                        if titles:
                            parts.append(f"[聊天记录: {titles[0][:50]}] ({msg_cnt}条消息)")
                        else:
                            parts.append(f"[聊天记录 {msg_cnt}条消息]")
                        continue
                    except Exception:
                        pass
                # Pai 戳一戳: extract action label from 47413
                if fnum == _NTQQ_MSG_PAI_GROUP:
                    try:
                        sub = _proto_parse(val)
                        action_text = None
                        for sfn, svals in sub.items():
                            if sfn == 47413:  # pai action text
                                for (_, sv) in svals:
                                    if isinstance(sv, (bytes, bytearray)):
                                        try:
                                            action_text = sv.decode("utf-8", errors="replace").strip()
                                            break
                                        except Exception:
                                            pass
                                if action_text:
                                    break
                        if action_text:
                            parts.append(f"[戳一戳: {action_text[:40]}]")
                        else:
                            parts.append("[戳一戳]")
                        continue
                    except Exception:
                        pass
                # Sysmsg gtip (system event)
                if fnum == _NTQQ_MSG_GTIP_XML:
                    try:
                        gtip = val.decode("utf-8", errors="replace")
                        # Strip XML tags
                        import re as _re
                        txt = _re.sub(r"<[^>]+>", " ", gtip).strip()
                        if txt:
                            parts.append(f"[系统: {txt[:80]}]")
                            continue
                    except Exception:
                        pass
                # react/回应 (msg_subtype=4) — 47705/47714 turned out to be
                # sender/receiver NICKNAMES (not emoji labels). Without a clear
                # field mapping for the actual emoji, emit a generic
                # placeholder. All 47702-47714 fields are skipped below via the
                # media-meta skip set.
                if fnum == _NTQQ_MSG_SENDER_UID_NESTED:
                    continue
                if fnum in _NTQQ_MSG_MEDIA_META_SKIP:
                    # Explicit skip: media pipeline metadata (URLs, md5, aeskey,
                    # CDN endpoints) — never leak to narrative text.
                    continue
                # Unknown nested — recurse with the same image-dim trackers
                if len(val) >= 4 and depth < 3:
                    sub = _proto_parse(val)
                    if sub:
                        _collect(sub, depth + 1, image_w, image_h)

    _collect(fields, image_w=[None], image_h=[None])

    if not parts:
        # 47702 is a precise reaction/reply marker.  Its nested payload carries
        # native participant metadata that must not be promoted to narrative,
        # but silently dropping the row would make bounded coverage dishonest.
        # Emit one fixed marker only when no structured narrative was decoded.
        reaction_fields = fields
        for wire_type, value in fields.get(_NTQQ_MSG_OUTER_WRAPPER, []):
            if wire_type == "bytes":
                reaction_fields = _proto_parse(value)
                break
        if _NTQQ_MSG_REACT_REPLY_GROUP in reaction_fields:
            return "[回应]"
        fallback = _brute_extract_utf8_fallback(blob)
        return "" if _qq_fallback_text_is_machine_only(fallback) else fallback

    out: List[str] = []
    for p in parts:
        p = p.strip()
        if p and (not out or out[-1] != p):
            out.append(p)
    return " ".join(out)[:1000]


def _extract_qq_attachment_meta(blob: bytes) -> Optional[Dict]:
    """Extract IM attachment metadata from NTQQ msg_body protobuf.

    A full multi-msg-type inventory on a large-account db revealed that 45402
    carries image, file, AND voice filenames, discriminated by sibling fields:
    sdk_ver (45550) ∈ {1=file, 4=voice}, voice_ms (45906), local_path (45403),
    file_size (45405), w/h (45411/12). Voice + file handlers feed downstream
    voice transcription and chat↔doc linkage respectively.

    Returns dict with `kind` ∈ {image, voice, file} + type-specific fields,
    or None when no recognizable attachment.
    """
    if not blob:
        return None
    top = _proto_parse(blob)
    # Unwrap outer 40800 if present (always 1 occurrence)
    inner_fields: Dict[int, list] = {}
    for (wt, val) in top.get(_NTQQ_MSG_OUTER_WRAPPER, []):
        if wt == "bytes":
            inner_fields = _proto_parse(val)
            break
    if not inner_fields:
        # Fallback: blob might be already unwrapped
        inner_fields = top

    # 45402 carries image / file / voice filename — extract first.
    filename = None
    for (wt, val) in inner_fields.get(_NTQQ_MSG_IMAGE_FILENAME, []):
        if wt == "bytes":
            try:
                filename = val.decode("utf-8", errors="replace")
                break
            except Exception:
                pass
    if not filename:
        return None

    # Gather discriminator siblings.
    sibling_w: Optional[int] = None
    sibling_h: Optional[int] = None
    sibling_size: Optional[int] = None
    sibling_local_path: Optional[str] = None
    sibling_sdk_ver: Optional[int] = None
    sibling_voice_ms: Optional[int] = None
    for (wt, val) in inner_fields.get(_NTQQ_MSG_IMAGE_WIDTH, []):
        if wt == "varint":
            sibling_w = int(val); break
    for (wt, val) in inner_fields.get(_NTQQ_MSG_IMAGE_HEIGHT, []):
        if wt == "varint":
            sibling_h = int(val); break
    for (wt, val) in inner_fields.get(_NTQQ_MSG_FILE_SIZE, []):
        if wt == "varint":
            sibling_size = int(val); break
    for (wt, val) in inner_fields.get(_NTQQ_MSG_FILE_LOCAL_PATH, []):
        if wt == "bytes":
            try:
                sibling_local_path = val.decode("utf-8", errors="replace")
            except Exception:
                pass
            break
    for (wt, val) in inner_fields.get(_NTQQ_MSG_FILE_SDK_VERSION, []):
        if wt == "varint":
            sibling_sdk_ver = int(val); break
    for (wt, val) in inner_fields.get(_NTQQ_MSG_VOICE_DURATION_MS, []):
        if wt == "varint":
            sibling_voice_ms = int(val); break

    # Voice: strict — filename ends with .amr/.silk OR (sdk_ver=4 AND voice_ms present).
    is_voice = filename.lower().endswith((".amr", ".silk"))
    if not is_voice and sibling_sdk_ver == 4 and sibling_voice_ms is not None:
        is_voice = True
    if is_voice:
        meta = {"kind": "voice", "filename": filename}
        if sibling_size is not None:
            meta["total_bytes"] = sibling_size
        # 45906 varies — small (e.g. 24) is flag, large (>100ms) is duration.
        if sibling_voice_ms and sibling_voice_ms > 100:
            meta["duration_ms"] = sibling_voice_ms
            meta["duration_s"] = round(sibling_voice_ms / 1000.0, 1)
        if filename.lower().endswith(".amr"):
            meta["codec"] = "amr"
        elif filename.lower().endswith(".silk"):
            meta["codec"] = "silk"
        return meta

    # File: has local_path OR (w=0 AND h=0) OR known non-image ext.
    is_likely_file = (
        bool(sibling_local_path)
        or (sibling_w == 0 and sibling_h == 0)
        or filename.lower().endswith((
            ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
            ".zip", ".rar", ".7z", ".exe", ".mp4", ".mov", ".avi", ".mkv",
            ".webm", ".txt", ".csv", ".rtf",
        ))
    )
    if is_likely_file:
        meta = {"kind": "file", "filename": filename}
        if sibling_size is not None:
            meta["total_bytes"] = sibling_size
        if sibling_local_path:
            meta["local_path"] = sibling_local_path
        # Sub-discriminator: video by extension
        if filename.lower().endswith((".mp4", ".mov", ".avi", ".mkv", ".webm")):
            meta["sub_kind"] = "video"
        return meta

    # Image (default fallthrough — has filename but no voice/file signal)
    meta = {"kind": "image", "filename": filename}
    if sibling_size is not None:
        meta["total_bytes"] = sibling_size
    if sibling_w is not None:
        meta["width"] = sibling_w
    if sibling_h is not None:
        meta["height"] = sibling_h
    return meta


def _brute_extract_utf8_fallback(blob: bytes, min_run: int = 4) -> str:
    """Last-resort scan when structured protobuf decode misses everything.

    Same algorithm as the old `_brute_extract_utf8_text`; kept as named
    fallback so primary path stays structured.
    """
    if not blob:
        return ""
    runs = []
    i = 0
    n = len(blob)
    while i < n:
        if blob[i] < 0x20 or blob[i] in (0x7F,):
            i += 1
            continue
        for length in range(min(500, n - i), 0, -1):
            chunk = blob[i:i + length]
            try:
                s = chunk.decode("utf-8")
                txt_n = sum(1 for c in s if (
                    "一" <= c <= "鿿" or "　" <= c <= "〿" or "＀" <= c <= "￯"
                    or " " <= c <= "~"
                ))
                if txt_n >= min_run and txt_n >= len(s) * 0.7:
                    runs.append(s)
                    i += length
                    break
            except UnicodeDecodeError:
                continue
        else:
            i += 1
    out: List[str] = []
    for r in runs:
        if not out or out[-1] != r:
            out.append(r)
    return " ".join(out)[:1000]


_QQ_FALLBACK_MACHINE_TOKEN_RE = re.compile(
    r"(?:ntid|ntuid|uin)[:_-][A-Za-z0-9_-]{8,}|"
    r"[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)*",
    re.IGNORECASE,
)
_QQ_FALLBACK_KNOWN_ID_RE = re.compile(
    r"(?i)^(?:ntid|ntuid|uin)[:_-][A-Za-z0-9_-]{8,}$"
)
_QQ_FALLBACK_OPAQUE_PREFIX_RE = re.compile(
    r"(?i)^(?:u_|nt_)[A-Za-z0-9_-]{18,}$"
)
_QQ_FALLBACK_UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_QQ_FALLBACK_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z]:[\\/]|\\\\|/|\.{1,2}[\\/])\S+"
)


def _qq_fallback_text_is_machine_only(value: str) -> bool:
    """Reject protobuf fallback output made only of QQ internal identifiers.

    The structured decoder already skips sender/reaction UID fields.  This guard
    applies only when decoding fell all the way back to an untyped UTF-8 scan,
    where the same ``u_...`` value can otherwise be mistaken for message text.
    Natural language, URLs, paths, email addresses and error-bearing sentences
    remain available to the caller.
    """

    text = str(value or "").strip()
    if not text:
        return False
    if re.search(r"[\u3400-\u4dbf\u4e00-\u9fff]", text):
        return False
    if (
        re.search(r"(?i)\b(?:https?|ftp)://\S+", text)
        or re.search(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b", text)
        or _QQ_FALLBACK_PATH_RE.search(text)
    ):
        return False
    if len(re.findall(r"(?<![A-Za-z])[A-Za-z]{2,}(?![A-Za-z])", text)) >= 3 and re.search(
        r"\s", text
    ):
        return False

    tokens = [match.group(0) for match in _QQ_FALLBACK_MACHINE_TOKEN_RE.finditer(text)]
    if not tokens:
        return False
    unmatched = _QQ_FALLBACK_MACHINE_TOKEN_RE.sub("", text)
    if any(
        not char.isspace()
        and unicodedata.category(char)[:1] not in {"P", "S", "Z", "C"}
        for char in unmatched
    ):
        return False
    return all(_qq_fallback_token_is_machine_identifier(token) for token in tokens)


def _qq_fallback_token_is_machine_identifier(value: str) -> bool:
    """Return whether one fallback token has strong internal-ID characteristics."""

    token = str(value or "").strip().rstrip("=")
    if _QQ_FALLBACK_KNOWN_ID_RE.fullmatch(token) or _QQ_FALLBACK_UUID_RE.fullmatch(token):
        return True
    if re.fullmatch(r"(?i)[0-9a-f]{16,}", token):
        return True
    if _QQ_FALLBACK_OPAQUE_PREFIX_RE.fullmatch(token):
        return _qq_fallback_token_has_opaque_shape(token)
    if re.fullmatch(r"[A-Za-z0-9_-]{24,}={0,2}", token) is None:
        return False
    return _qq_fallback_token_has_opaque_shape(token)


def _qq_fallback_token_has_opaque_shape(token: str) -> bool:
    """Require random-looking shape before treating an unlabelled token as an ID."""

    compact = "".join(char for char in token if char.isalnum())
    if len(compact) < 20:
        return False
    classes = sum(
        (
            any(char.islower() for char in token),
            any(char.isupper() for char in token),
            any(char.isdigit() for char in token),
            "_" in token or "-" in token,
        )
    )
    if classes < 3:
        return False
    frequencies = {char: compact.count(char) for char in set(compact)}
    entropy = -sum(
        (count / len(compact)) * math.log2(count / len(compact))
        for count in frequencies.values()
    )
    unique_ratio = len(frequencies) / len(compact)
    return entropy >= 3.5 and unique_ratio >= 0.62


# Back-compat alias: callers using the legacy name still work.
_brute_extract_utf8_text = _extract_msg_text


# NTQQ 9.9.x column-id schema (numeric col names — they're hex-ish ids)
_NTQQ_COL_MSG_UID = "40001"     # msg_uid (BIGINT)
_NTQQ_COL_PEER_UIN = "40030"    # peer QQ number (for c2c)
_NTQQ_COL_MSG_SEQ = "40003"     # msg seq number
_NTQQ_COL_SENDER_UID = "40020"  # sender uid (string u_xxx)
_NTQQ_COL_GROUP_CODE = "40021"  # group code (group_msg_table)
_NTQQ_COL_SENDER_NAME = "40090" # sender display name
_NTQQ_COL_MSG_BODY = "40800"    # msg body BLOB (protobuf)
_NTQQ_COL_MSG_TIME = "40050"    # msg unix epoch seconds
_NTQQ_COL_SENDER_UIN = "40033"  # sender QQ number (BIGINT)


@dataclass(frozen=True)
class _QQMessageTableSpec:
    """Allowlisted NTQQ message-table identifiers and their global sort rank."""

    table: str
    conversation_column: str
    conversation_type: str
    table_rank: int


_QQ_MESSAGE_TABLE_SPECS = (
    _QQMessageTableSpec(
        table="c2c_msg_table",
        conversation_column=_NTQQ_COL_PEER_UIN,
        conversation_type="direct",
        table_rank=0,
    ),
    _QQMessageTableSpec(
        table="group_msg_table",
        conversation_column=_NTQQ_COL_GROUP_CODE,
        conversation_type="group",
        table_rank=1,
    ),
)


def _qq_table_columns(cursor, table: str) -> Optional[set[str]]:
    """Return an NTQQ table's declared columns, or ``None`` on schema errors.

    SQLite may evaluate a double-quoted missing column as a string literal.
    Every numeric-column query must therefore validate the live table schema
    before constructing its ``SELECT`` statement.
    """
    import sqlite3

    try:
        cursor.execute(f'PRAGMA table_info("{table}")')
        return {
            str(row[1])
            for row in cursor.fetchall()
            if len(row) > 1 and row[1] is not None
        }
    except sqlite3.Error as exc:
        logger.debug(
            "QQ table schema query failed for %s: %s",
            table,
            type(exc).__name__,
        )
        return None


# ─── Buddy / group nickname lookup ────────────────────────────────────────────
# profile_info.db tables:
#   profile_info_v6: col 1002=qq_uin, 20002=nickname, 20009=remark, 1000=uid
#   buddy_list: friends only — col 1000=uid, 1002=qq_uin
# group_info.db tables:
#   group_member3: col 60001=group_id, 1002=qq_uin, 20002=group nickname, 1000=uid
#
# NTQQ c2c_msg_table col 40090 (sender_name) is consistently empty for c2c
# messages — only group_msg_table carries it. We close the gap by joining
# profile_info.db.profile_info_v6 and group_info.db.group_member3.

_NTQQ_PROFILE_COL_UID = "1000"        # TEXT — NT internal UID
_NTQQ_PROFILE_COL_QQ_UIN = "1002"     # BIGINT — QQ number
_NTQQ_PROFILE_COL_NICKNAME = "20002"  # TEXT — display nickname
_NTQQ_PROFILE_COL_REMARK = "20009"    # TEXT — local friend remark
_NTQQ_GROUP_MEMBER_COL_GROUP = "60001"  # BIGINT — group_id
_NTQQ_GROUP_MEMBER_COL_UIN = "1002"     # BIGINT — member QQ number
_NTQQ_GROUP_COL_NAME = "60007"           # TEXT — group display name


def _decrypt_aux_db(
    src_db: Path,
    key,
    tmp_dir: Path,
) -> Optional[_QQDecryptedDatabase]:
    """Decrypt an auxiliary NTQQ database (profile_info.db, group_info.db)
    using the same cipher chain as nt_msg.db. Returns the decrypted database
    descriptor or None on failure. Used by buddy/group nickname lookups.

    Aux dbs share the same key as nt_msg.db, so we bypass the QQDBReader path
    and just use the same header-strip/decrypt result path directly.
    """
    try:
        no_hdr = tmp_dir / f"{src_db.stem}_no_hdr.db"
        if not _skip_header(src_db, no_hdr):
            return None
        dec = tmp_dir / f"{src_db.stem}_dec.db"
        result = _decrypt_db_qq_result(
            no_hdr,
            key,
            dec,
            source_wrapper_size=_NTQQ_WRAPPER_SIZE,
        )
        if not result.ok:
            return None
        return _QQDecryptedDatabase(
            path=dec,
            shifted_pending_byte=result.shifted_pending_byte,
        )
    except Exception as e:
        logger.warning(
            "QQ auxiliary database decryption failed: %s",
            type(e).__name__,
        )
        return None


@dataclass(frozen=True)
class QQBuddyIdentity:
    """QQ 联系人的本机备注与公开昵称。"""

    nickname: str = ""
    remark: str = ""

    @property
    def preferred_name(self) -> str:
        """聊天正文优先使用用户自己的备注，缺失时回退公开昵称。"""

        return self.remark or self.nickname

    @property
    def directory_label(self) -> str:
        """生成让用户能区分备注与昵称的目录标签。"""

        if self.remark and self.nickname and self.remark != self.nickname:
            return f"备注：{self.remark} · 昵称：{self.nickname}"
        if self.remark and self.nickname:
            return f"备注/昵称：{self.remark}"
        if self.remark:
            return f"备注：{self.remark}"
        if self.nickname:
            return f"昵称：{self.nickname}"
        return ""


def _clean_qq_display_name(value) -> str:
    """把 QQ 资料字段收敛为适合本机 UI 的单行短文本。"""

    if not isinstance(value, str):
        return ""
    return " ".join(value.split()).strip()[:120]


def _build_buddy_identity_map(profile_db) -> Dict[int, QQBuddyIdentity]:
    """读取 profile_info_v6，建立 QQ 号到备注和昵称的映射。

    Returns {} on any failure (db missing, table missing, etc.) so callers
    can fall back gracefully.
    """
    import sqlite3
    out: Dict[int, QQBuddyIdentity] = {}
    if not _qq_decrypted_database_path(profile_db).exists():
        return out
    try:
        conn = _open_qq_sqlite_connection(profile_db)
        try:
            cursor = conn.cursor()
            columns = _qq_table_columns(cursor, "profile_info_v6")
            if columns is None or _NTQQ_PROFILE_COL_QQ_UIN not in columns:
                return out
            nickname_expression = (
                f'"{_NTQQ_PROFILE_COL_NICKNAME}"'
                if _NTQQ_PROFILE_COL_NICKNAME in columns
                else "NULL"
            )
            remark_expression = (
                f'"{_NTQQ_PROFILE_COL_REMARK}"'
                if _NTQQ_PROFILE_COL_REMARK in columns
                else "NULL"
            )
            cursor.execute(
                f'SELECT "{_NTQQ_PROFILE_COL_QQ_UIN}", '
                f'{nickname_expression}, {remark_expression} '
                f'FROM profile_info_v6 '
                f'WHERE "{_NTQQ_PROFILE_COL_QQ_UIN}" IS NOT NULL'
            )
            for uin, nickname, remark in cursor.fetchall():
                identity = QQBuddyIdentity(
                    nickname=_clean_qq_display_name(nickname),
                    remark=_clean_qq_display_name(remark),
                )
                if not uin or not identity.preferred_name:
                    continue
                try:
                    out[int(uin)] = identity
                except (ValueError, TypeError):
                    pass
        finally:
            conn.close()
    except Exception as e:
        logger.debug(f"buddy_identity_map build failed: {e}")
    return out


def _build_buddy_name_map(profile_db) -> Dict[int, str]:
    """建立聊天正文使用的 QQ 展示名映射，备注优先于昵称。"""

    return {
        uin: identity.preferred_name
        for uin, identity in _build_buddy_identity_map(profile_db).items()
    }


def _build_buddy_directory_label_map(profile_db) -> Dict[int, str]:
    """建立 GUI 目录标签映射，同时明确显示本机备注和公开昵称。"""

    return {
        uin: identity.directory_label
        for uin, identity in _build_buddy_identity_map(profile_db).items()
        if identity.directory_label
    }


def _build_buddy_directory_map(profile_db) -> Dict[int, str]:
    """读取 ``buddy_list``，建立只包含好友的 QQ 会话目录。

    ``profile_info_v6`` 还缓存群成员和其他见过的账号，不能直接当作好友
    清单。这里用 ``buddy_list`` 限定成员，再复用 profile 的备注/昵称作为
    展示标签；没有资料缓存的好友仍以稳定的 QQ 号占位，不会从目录消失。
    """

    import sqlite3

    identities = _build_buddy_identity_map(profile_db)
    out: Dict[int, str] = {}
    if not _qq_decrypted_database_path(profile_db).exists():
        return out
    try:
        conn = _open_qq_sqlite_connection(profile_db)
        try:
            cursor = conn.cursor()
            columns = _qq_table_columns(cursor, "buddy_list")
            if columns is None or _NTQQ_PROFILE_COL_QQ_UIN not in columns:
                return out
            cursor.execute(
                f'SELECT DISTINCT "{_NTQQ_PROFILE_COL_QQ_UIN}" '
                f'FROM buddy_list '
                f'WHERE "{_NTQQ_PROFILE_COL_QQ_UIN}" IS NOT NULL'
            )
            rows = cursor.fetchall()
        finally:
            conn.close()
        for (raw_uin,) in rows:
            try:
                uin = int(raw_uin)
            except (TypeError, ValueError):
                continue
            if uin <= 0:
                continue
            identity = identities.get(uin)
            out[uin] = (
                identity.directory_label
                if identity is not None and identity.directory_label
                else f"qq_friend_{uin}"
            )
    except sqlite3.Error as exc:
        logger.debug("buddy directory build failed: %s", type(exc).__name__)
    return out


def _normalize_qq_number(value: object) -> str:
    """返回可展示的 ASCII QQ 号；其他数字或内部 UID 返回空字符串。"""

    candidate = str(value or "").strip()
    return candidate if re.fullmatch(r"[1-9][0-9]{4,19}", candidate) else ""


def _exclude_self_from_buddy_directory(
    buddy_directory_map: Dict[int, str],
    account_qq_number: object,
) -> None:
    """从好友元数据目录移除自身 QQ 号，不影响消息表中的真实自聊。"""

    normalized = _normalize_qq_number(account_qq_number)
    if not normalized:
        return
    buddy_directory_map.pop(int(normalized), None)


def _build_account_qq_number_map(profile_db) -> Dict[str, str]:
    """按 QQ UIN 和 NT UID 建立本机账号到 QQ 号的映射。"""

    import sqlite3

    out: Dict[str, str] = {}
    if not _qq_decrypted_database_path(profile_db).exists():
        return out
    try:
        conn = _open_qq_sqlite_connection(profile_db)
        try:
            cursor = conn.cursor()
            columns = _qq_table_columns(cursor, "profile_info_v6")
            required_columns = {
                _NTQQ_PROFILE_COL_UID,
                _NTQQ_PROFILE_COL_QQ_UIN,
            }
            if columns is None or not required_columns.issubset(columns):
                return out
            cursor.execute(
                f'SELECT "{_NTQQ_PROFILE_COL_UID}", '
                f'"{_NTQQ_PROFILE_COL_QQ_UIN}" '
                f'FROM profile_info_v6 '
                f'WHERE "{_NTQQ_PROFILE_COL_QQ_UIN}" IS NOT NULL'
            )
            for uid, uin in cursor.fetchall():
                qq_number = _normalize_qq_number(uin)
                if not qq_number:
                    continue
                for value in (uid, uin):
                    key = str(value or "").strip()
                    if key:
                        out[key] = qq_number
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - metadata lookup is optional
        logger.debug("account_qq_number_map build failed: %s", exc)
    return out


def _query_account_qq_number(conn) -> str:
    """从直聊 sender/peer 元数据确认当前数据库唯一的自身 QQ 号。"""

    import sqlite3

    try:
        cursor = conn.cursor()
        columns = _qq_table_columns(cursor, "c2c_msg_table")
        required_columns = {_NTQQ_COL_SENDER_UIN, _NTQQ_COL_PEER_UIN}
        if columns is None or not required_columns.issubset(columns):
            return ""
        cursor.execute(
            f'SELECT "{_NTQQ_COL_SENDER_UIN}" FROM c2c_msg_table '
            f'WHERE "{_NTQQ_COL_SENDER_UIN}" IS NOT NULL '
            f'AND "{_NTQQ_COL_PEER_UIN}" IS NOT NULL '
            f'AND CAST("{_NTQQ_COL_SENDER_UIN}" AS TEXT) '
            f'<> CAST("{_NTQQ_COL_PEER_UIN}" AS TEXT) '
            f'GROUP BY "{_NTQQ_COL_SENDER_UIN}"'
        )
        rows = cursor.fetchall()
    except sqlite3.Error as exc:
        logger.debug("account QQ number query failed: %s", type(exc).__name__)
        return ""
    candidates = {
        candidate
        for row in rows
        if row and (candidate := _normalize_qq_number(row[0]))
    }
    return next(iter(candidates)) if len(candidates) == 1 else ""


def _build_group_member_map(group_db) -> Dict[Tuple[int, int], str]:
    """Read group_member3 and build {(group_id, qq_uin): nickname}.

    Group nickname > buddy nickname (a friend may have a custom name inside
    a group). Falls back to buddy_name_map at lookup time.
    """
    import sqlite3
    out: Dict[Tuple[int, int], str] = {}
    if not _qq_decrypted_database_path(group_db).exists():
        return out
    try:
        conn = _open_qq_sqlite_connection(group_db)
        try:
            cursor = conn.cursor()
            columns = _qq_table_columns(cursor, "group_member3")
            required_columns = {
                _NTQQ_GROUP_MEMBER_COL_GROUP,
                _NTQQ_GROUP_MEMBER_COL_UIN,
            }
            if columns is None or not required_columns.issubset(columns):
                return out
            nickname_expression = (
                f'"{_NTQQ_PROFILE_COL_NICKNAME}"'
                if _NTQQ_PROFILE_COL_NICKNAME in columns
                else "NULL"
            )
            cursor.execute(
                f'SELECT "{_NTQQ_GROUP_MEMBER_COL_GROUP}", '
                f'"{_NTQQ_GROUP_MEMBER_COL_UIN}", '
                f'{nickname_expression} '
                f'FROM group_member3 '
                f'WHERE "{_NTQQ_GROUP_MEMBER_COL_GROUP}" IS NOT NULL '
                f'AND "{_NTQQ_GROUP_MEMBER_COL_UIN}" IS NOT NULL'
            )
            for gid, uin, nick in cursor.fetchall():
                if not (gid and uin and nick and isinstance(nick, str) and nick.strip()):
                    continue
                try:
                    out[(int(gid), int(uin))] = nick.strip()
                except (ValueError, TypeError):
                    pass
        finally:
            conn.close()
    except Exception as e:
        logger.debug(f"group_member_map build failed: {e}")
    return out


def _build_group_name_map(group_db) -> Dict[int, str]:
    """Read QQ group metadata and build ``{group_id: display_name}``.

    Both ``group_list`` and ``group_detail_info_ver1`` occur in current NTQQ
    releases. The detail table is read last so its newer non-empty label wins.
    A valid group ID with no name is retained with an empty internal label;
    callers apply a machine-ID placeholder that Core later masks. Each table's
    schema is checked first because SQLite may treat a quoted missing column as
    a string literal instead of raising an error.
    """
    import sqlite3

    out: Dict[int, str] = {}
    if not _qq_decrypted_database_path(group_db).exists():
        return out
    try:
        conn = _open_qq_sqlite_connection(group_db)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {str(row[0]) for row in cursor.fetchall()}
            for table in ("group_list", "group_detail_info_ver1"):
                if table not in tables:
                    continue
                try:
                    columns = _qq_table_columns(cursor, table)
                    if (
                        columns is None
                        or _NTQQ_GROUP_MEMBER_COL_GROUP not in columns
                    ):
                        continue
                    name_expression = (
                        f'"{_NTQQ_GROUP_COL_NAME}"'
                        if _NTQQ_GROUP_COL_NAME in columns
                        else "NULL"
                    )
                    cursor.execute(
                        f'SELECT "{_NTQQ_GROUP_MEMBER_COL_GROUP}", '
                        f'{name_expression} FROM "{table}" '
                        f'WHERE "{_NTQQ_GROUP_MEMBER_COL_GROUP}" IS NOT NULL'
                    )
                    rows = cursor.fetchall()
                except sqlite3.Error as exc:
                    logger.debug(
                        "QQ group metadata table is incompatible: %s",
                        type(exc).__name__,
                    )
                    continue
                for group_id, name in rows:
                    try:
                        normalized_id = int(group_id)
                    except (TypeError, ValueError):
                        continue
                    if normalized_id <= 0:
                        continue
                    clean_name = name.strip() if isinstance(name, str) else ""
                    if clean_name:
                        out[normalized_id] = clean_name
                    else:
                        out.setdefault(normalized_id, "")
        finally:
            conn.close()
    except Exception as exc:
        logger.debug("group_name_map build failed: %s", type(exc).__name__)
    return out


def _resolve_sender_name(
    raw_name: str,
    sender_uin: int,
    chat_uid: str,
    is_group: bool,
    buddy_map: Dict[int, str],
    group_map: Dict[Tuple[int, int], str],
) -> str:
    """Return a human-readable sender name.

    Priority:
      1. raw_name (from col 40090) if non-empty and not a numeric uin
      2. group_map[(group_id, uin)] (group-specific nickname)
      3. buddy_map[uin] (profile nickname)
      4. str(uin) (last resort — numeric QQ number)
    """
    if raw_name and isinstance(raw_name, str) and raw_name.strip():
        s = raw_name.strip()
        # Reject names that are just the numeric uin or already prefixed "用户N"
        if not s.isdigit() and not (s.startswith("用户") and s[2:].isdigit()):
            return s
    if not sender_uin:
        return raw_name or "?"
    if is_group and chat_uid and chat_uid.isdigit():
        try:
            gid = int(chat_uid)
            if (gid, sender_uin) in group_map:
                return group_map[(gid, sender_uin)]
        except ValueError:
            pass
    if sender_uin in buddy_map:
        return buddy_map[sender_uin]
    return str(sender_uin)


def _query_conversation_directory(
    conn,
    buddy_map: Optional[Dict[int, str]] = None,
    buddy_directory_map: Optional[Dict[int, str]] = None,
    group_name_map: Optional[Dict[int, str]] = None,
) -> List[Dict]:
    """Read the QQ conversation directory without selecting message bodies.

    Only the peer/group identifier and ``COUNT(*)`` are queried from the two
    message tables.  This function is intentionally separate from
    :func:`_query_messages` so directory discovery cannot accidentally decode
    message content.
    """
    import sqlite3

    buddy_map = buddy_map or {}
    buddy_directory_map = buddy_directory_map or {}
    group_name_map = group_name_map or {}
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {str(row[0]) for row in cursor.fetchall()}
    directory: List[Dict] = []

    queries = (
        ("c2c_msg_table", _NTQQ_COL_PEER_UIN, "direct"),
        ("group_msg_table", _NTQQ_COL_GROUP_CODE, "group"),
    )
    for table, id_column, conversation_type in queries:
        if table not in tables:
            continue
        columns = _qq_table_columns(cursor, table)
        if columns is None or id_column not in columns:
            logger.debug(
                "QQ conversation table lacks required column: %s.%s",
                table,
                id_column,
            )
            continue
        try:
            cursor.execute(
                f'SELECT "{id_column}", COUNT(*) FROM "{table}" '
                f'WHERE "{id_column}" IS NOT NULL GROUP BY "{id_column}"'
            )
            rows = cursor.fetchall()
        except sqlite3.Error as exc:
            logger.debug("QQ conversation directory query failed: %s", type(exc).__name__)
            continue
        for raw_id, raw_count in rows:
            conversation_id = str(raw_id or "").strip()
            if not conversation_id:
                continue
            label = ""
            if conversation_type == "direct":
                try:
                    label = buddy_map.get(int(conversation_id), "")
                except (TypeError, ValueError):
                    label = ""
            else:
                try:
                    label = group_name_map.get(int(conversation_id), "")
                except (TypeError, ValueError):
                    label = ""
            if not label:
                prefix = "qq_group" if conversation_type == "group" else "qq_friend"
                label = f"{prefix}_{conversation_id}"
            directory.append({
                "conversation_id": conversation_id,
                "label": label,
                "conversation_type": conversation_type,
                "message_count": int(raw_count or 0),
            })

    represented = {
        (item["conversation_type"], item["conversation_id"])
        for item in directory
    }
    for raw_id, label in buddy_directory_map.items():
        conversation_id = str(raw_id or "").strip()
        key = ("direct", conversation_id)
        if not conversation_id or key in represented:
            continue
        directory.append({
            "conversation_id": conversation_id,
            "label": str(label or f"qq_friend_{conversation_id}"),
            "conversation_type": "direct",
            "message_count": 0,
        })
        represented.add(key)
    for raw_id, label in group_name_map.items():
        conversation_id = str(raw_id or "").strip()
        key = ("group", conversation_id)
        if not conversation_id or key in represented:
            continue
        directory.append({
            "conversation_id": conversation_id,
            "label": str(label or f"qq_group_{conversation_id}"),
            "conversation_type": "group",
            "message_count": 0,
        })
        represented.add(key)

    directory.sort(key=lambda item: (item["conversation_type"], item["conversation_id"]))
    return directory


def _normalize_qq_message_page_scope(
    account_id: str,
    conversation_id: str,
    conversation_type: Optional[str],
) -> Tuple[str, str, Optional[str]]:
    """Validate one source-account/conversation scope without broadening it."""

    if not isinstance(account_id, str) or not account_id.strip():
        raise ValueError("account_id must identify one QQ source account")
    if not isinstance(conversation_id, str) or not conversation_id.strip():
        raise ValueError("conversation_id must identify one exact QQ conversation")
    normalized_type: Optional[str]
    if conversation_type is None:
        normalized_type = None
    elif isinstance(conversation_type, str):
        normalized_type = conversation_type.strip().lower()
        if normalized_type not in {"direct", "group"}:
            raise ValueError("conversation_type must be direct, group, or None")
    else:
        raise ValueError("conversation_type must be direct, group, or None")
    return account_id.strip(), conversation_id.strip(), normalized_type


def _validate_qq_message_page_request(
    *,
    account_id: str,
    conversation_id: str,
    conversation_type: Optional[str],
    since_ts: float,
    until_ts: float,
    page_size: int,
    cursor: Optional[_QQMessagePageCursor],
) -> Tuple[str, str, Optional[str], float, float]:
    """Return normalized page inputs, rejecting unsafe bounds and cursor reuse."""

    account_id, conversation_id, conversation_type = (
        _normalize_qq_message_page_scope(
            account_id,
            conversation_id,
            conversation_type,
        )
    )
    if isinstance(page_size, bool) or not isinstance(page_size, int):
        raise ValueError("page_size must be an integer")
    if page_size < 1 or page_size > _QQ_MESSAGE_PAGE_MAX_SIZE:
        raise ValueError(
            f"page_size must be between 1 and {_QQ_MESSAGE_PAGE_MAX_SIZE}"
        )
    if isinstance(since_ts, bool) or isinstance(until_ts, bool):
        raise ValueError("since_ts and until_ts must be finite numbers")
    try:
        since_value = float(since_ts)
        until_value = float(until_ts)
    except (TypeError, ValueError) as exc:
        raise ValueError("since_ts and until_ts must be finite numbers") from exc
    if not math.isfinite(since_value) or not math.isfinite(until_value):
        raise ValueError("since_ts and until_ts must be finite numbers")
    if since_value > until_value:
        raise ValueError("since_ts must not be after until_ts")

    if cursor is not None:
        if not isinstance(cursor, _QQMessagePageCursor):
            raise ValueError("cursor must be a QQ message page cursor")
        if cursor.account_id != account_id:
            raise ValueError("cursor account_id does not match the requested scope")
        if cursor.conversation_id != conversation_id:
            raise ValueError("cursor conversation_id does not match the requested scope")
        if cursor.conversation_type != conversation_type:
            raise ValueError("cursor conversation_type does not match the requested scope")
        if cursor.since_ts != since_value:
            raise ValueError("cursor since_ts does not match the requested window")
        if cursor.until_ts != until_value:
            raise ValueError("cursor until_ts does not match the requested window")
        allowed_ranks = {
            spec.table_rank
            for spec in _QQ_MESSAGE_TABLE_SPECS
            if conversation_type is None or spec.conversation_type == conversation_type
        }
        if (
            isinstance(cursor.table_rank, bool)
            or not isinstance(cursor.table_rank, int)
            or cursor.table_rank not in allowed_ranks
        ):
            raise ValueError("cursor table_rank does not match the requested scope")
        try:
            cursor_time = float(cursor.msg_time)
        except (TypeError, ValueError) as exc:
            raise ValueError("cursor keyset position is invalid") from exc
        if (
            not math.isfinite(cursor_time)
            or isinstance(cursor.rowid, bool)
            or not isinstance(cursor.rowid, int)
            or cursor.rowid < 1
        ):
            raise ValueError("cursor keyset position is invalid")
    return account_id, conversation_id, conversation_type, since_value, until_value


def _qq_message_keyset_sql(
    spec: _QQMessageTableSpec,
    cursor: Optional[_QQMessagePageCursor],
) -> Tuple[str, Tuple[object, ...]]:
    """Build the per-table half of the global (time, table, rowid) keyset."""

    if cursor is None:
        return "", ()
    time_column = f'"{_NTQQ_COL_MSG_TIME}"'
    if spec.table_rank < cursor.table_rank:
        return f" AND {time_column} > ?", (cursor.msg_time,)
    if spec.table_rank > cursor.table_rank:
        return f" AND {time_column} >= ?", (cursor.msg_time,)
    return (
        f" AND ({time_column} > ? OR "
        f"({time_column} = ? AND rowid > ?))",
        (cursor.msg_time, cursor.msg_time, cursor.rowid),
    )


def _qq_message_page_select(
    spec: _QQMessageTableSpec,
    columns: set[str],
    *,
    conversation_id: str,
    since_ts: float,
    until_ts: float,
    cursor: Optional[_QQMessagePageCursor],
) -> Tuple[str, Tuple[object, ...]]:
    """Build one allowlisted message-table SELECT with all row filters pushed down."""

    def optional_column(column: str) -> str:
        return f'"{column}"' if column in columns else "NULL"

    keyset_sql, keyset_params = _qq_message_keyset_sql(spec, cursor)
    sql = (
        f"SELECT {optional_column(_NTQQ_COL_MSG_UID)} AS _msg_uid, "
        f'"{_NTQQ_COL_MSG_TIME}" AS _msg_time, '
        f"{optional_column(_NTQQ_COL_SENDER_NAME)} AS _sender_name, "
        f'"{_NTQQ_COL_SENDER_UIN}" AS _sender_uin, '
        f'"{_NTQQ_COL_MSG_BODY}" AS _msg_body, '
        f'"{spec.conversation_column}" AS _conversation_id, '
        f"{spec.table_rank} AS _table_rank, rowid AS _rowid, "
        f"'{spec.conversation_type}' AS _conversation_type, "
        f"{optional_column(_NTQQ_COL_SENDER_UID)} AS _sender_uid "
        f'FROM "{spec.table}" '
        f'WHERE "{_NTQQ_COL_MSG_TIME}" >= ? '
        f'AND "{_NTQQ_COL_MSG_TIME}" <= ? '
        f'AND "{_NTQQ_COL_MSG_TIME}" > 0 '
        f'AND "{spec.conversation_column}" = ?'
        f"{keyset_sql}"
    )
    return sql, (since_ts, until_ts, conversation_id, *keyset_params)


def _qq_message_page_record(
    row: Tuple,
    *,
    account_id: str,
    conversation_id: str,
    buddy_map: Dict[int, str],
    group_map: Dict[Tuple[int, int], str],
    group_name_map: Dict[int, str],
) -> Optional[Dict]:
    """Decode one already-bounded raw row into the legacy dictionary shape."""

    from datetime import timezone

    (
        msg_uid,
        msg_time,
        sender_name,
        sender_uin,
        msg_body,
        _raw_conversation_id,
        _table_rank,
        source_rowid,
        conversation_type,
        sender_uid,
    ) = row
    try:
        ts = float(msg_time)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(ts):
        return None
    if not msg_body:
        raise RuntimeError("QQ message body is unavailable")
    content = _extract_msg_text(msg_body)
    content = str(content or "")
    if not content.strip():
        raise RuntimeError("QQ message body has no safe narrative")
    is_group = conversation_type == "group"
    raw_sender_uin = str(sender_uin).strip() if sender_uin is not None else ""
    if not raw_sender_uin:
        raise RuntimeError("QQ message sender identity is unavailable")
    try:
        sender_uin_int = int(raw_sender_uin)
    except (TypeError, ValueError):
        raise RuntimeError("QQ message sender identity is invalid") from None
    if sender_uin_int < 0:
        raise RuntimeError("QQ message sender identity is invalid")
    normalized_sender_uid = str(sender_uid or "").strip()
    if normalized_sender_uid and (
        len(normalized_sender_uid) > 512
        or any(ord(character) < 32 for character in normalized_sender_uid)
    ):
        raise RuntimeError("QQ message sender identity is invalid")
    if sender_uin_int == 0 and not normalized_sender_uid:
        raise RuntimeError("QQ message sender identity is unavailable")
    raw_sender_name = sender_name.strip() if isinstance(sender_name, str) else ""
    resolved_name = _resolve_sender_name(
        raw_name=raw_sender_name,
        sender_uin=sender_uin_int,
        chat_uid=conversation_id,
        is_group=is_group,
        buddy_map=buddy_map,
        group_map=group_map,
    )
    sender_identity = (
        str(sender_uin_int) if sender_uin_int != 0 else normalized_sender_uid
    )
    if is_group:
        try:
            chat_name = group_name_map.get(int(conversation_id), "")
        except (TypeError, ValueError):
            chat_name = ""
        chat_name = chat_name or f"qq_group_{conversation_id}"
    else:
        try:
            chat_name = buddy_map.get(int(conversation_id), "")
        except (TypeError, ValueError):
            chat_name = ""
        chat_name = chat_name or f"qq_friend_{conversation_id}"
    try:
        normalized_msg_uid = int(msg_uid) if msg_uid is not None else None
    except (TypeError, ValueError):
        normalized_msg_uid = None
    wxid_hash = hashlib.sha256(sender_identity.encode("utf-8")).hexdigest()[:16]
    return {
        "ts": ts,
        "ts_iso": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
        "wxid_hash": wxid_hash,
        "sender_qq": sender_uin_int,
        "sender_uid": normalized_sender_uid,
        "sender_name": resolved_name or sender_identity,
        # Bounded page reads bound row count, not message-body length.  The
        # stream transport applies its own per-frame byte ceiling and must see
        # the complete local message so downstream SourceRecord construction is
        # lossless.
        "content": content,
        "msg_id": normalized_msg_uid,
        "chat_uid": conversation_id,
        "chat_kind": "group" if is_group else "friend",
        "chat_name": chat_name,
        "account_id": account_id,
        "conversation_id": conversation_id,
        "thread_id": f"{account_id}::{conversation_id}",
        "conversation_type": conversation_type,
        "is_group_chat": is_group,
        "source_offset": (
            f"qq_db:{conversation_id}:{conversation_type}:{int(source_rowid)}"
        ),
        "attachment_meta": (
            _extract_qq_attachment_meta(msg_body) if msg_body else None
        ),
    }


def _query_message_dict_page(
    conn,
    *,
    account_id: str,
    conversation_id: str,
    conversation_type: Optional[str],
    since_ts: float,
    until_ts: float,
    page_size: int = _QQ_MESSAGE_PAGE_DEFAULT_SIZE,
    cursor: Optional[_QQMessagePageCursor] = None,
    buddy_map: Optional[Dict[int, str]] = None,
    group_map: Optional[Dict[Tuple[int, int], str]] = None,
    group_name_map: Optional[Dict[int, str]] = None,
) -> _QQMessageDictPage:
    """Read one bounded, deterministic keyset page from a decrypted QQ DB.

    The source account is bound by the caller's already-selected database and
    repeated in the cursor. Conversation, direct/group type, inclusive time
    window, keyset position, ordering, and LIMIT are all enforced by SQLite.
    ``conversation_type=None`` intentionally merges the two fixed allowlisted
    message tables; an exact type only touches its corresponding table.
    """

    import sqlite3

    (
        account_id,
        conversation_id,
        conversation_type,
        since_ts,
        until_ts,
    ) = _validate_qq_message_page_request(
        account_id=account_id,
        conversation_id=conversation_id,
        conversation_type=conversation_type,
        since_ts=since_ts,
        until_ts=until_ts,
        page_size=page_size,
        cursor=cursor,
    )
    buddy_map = buddy_map or {}
    group_map = group_map or {}
    group_name_map = group_name_map or {}
    db_cursor = conn.cursor()
    db_cursor.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name IN (?, ?) ORDER BY name",
        tuple(spec.table for spec in _QQ_MESSAGE_TABLE_SPECS),
    )
    available_tables = {
        str(row[0])
        for row in db_cursor.fetchmany(len(_QQ_MESSAGE_TABLE_SPECS) + 1)
    }
    requested_specs = [
        spec
        for spec in _QQ_MESSAGE_TABLE_SPECS
        if conversation_type is None or spec.conversation_type == conversation_type
    ]
    specs = []
    for spec in requested_specs:
        if spec.table not in available_tables:
            if conversation_type is not None:
                raise RuntimeError("requested QQ message table is unavailable")
            continue
        specs.append(spec)

    selects: List[str] = []
    parameters: List[object] = []
    for spec in specs:
        columns = _qq_table_columns(db_cursor, spec.table)
        required_columns = {
            spec.conversation_column,
            _NTQQ_COL_SENDER_UIN,
            _NTQQ_COL_MSG_TIME,
            _NTQQ_COL_MSG_BODY,
        }
        if columns is None or not required_columns.issubset(columns):
            logger.warning("%s: incompatible message page schema", spec.table)
            raise RuntimeError("requested QQ message table schema is incompatible")
        select_sql, select_parameters = _qq_message_page_select(
            spec,
            columns,
            conversation_id=conversation_id,
            since_ts=since_ts,
            until_ts=until_ts,
            cursor=cursor,
        )
        selects.append(select_sql)
        parameters.extend(select_parameters)

    if not selects:
        return _QQMessageDictPage(records=(), cursor_after=cursor, has_more=False)

    # One-row lookahead makes ``has_more`` exact while peak result materialization
    # remains bounded by ``page_size + 1``. The returned page never exceeds the
    # caller's requested page size.
    sql = (
        "SELECT * FROM ("
        + " UNION ALL ".join(selects)
        + ") AS _qq_message_page "
        "ORDER BY _msg_time ASC, _table_rank ASC, _rowid ASC LIMIT ?"
    )
    parameters.append(page_size + 1)
    try:
        db_cursor.execute(sql, tuple(parameters))
        raw_rows = db_cursor.fetchmany(page_size + 1)
    except sqlite3.Error as exc:
        logger.warning("QQ bounded message page query failed: %s", type(exc).__name__)
        raise

    has_more = len(raw_rows) > page_size
    consumed_rows = raw_rows[:page_size]
    if not consumed_rows:
        return _QQMessageDictPage(records=(), cursor_after=cursor, has_more=False)
    last_row = consumed_rows[-1]
    cursor_after = _QQMessagePageCursor(
        account_id=account_id,
        conversation_id=conversation_id,
        conversation_type=conversation_type,
        since_ts=since_ts,
        until_ts=until_ts,
        msg_time=float(last_row[1]),
        table_rank=int(last_row[6]),
        rowid=int(last_row[7]),
    )
    records = tuple(
        record
        for record in (
            _qq_message_page_record(
                row,
                account_id=account_id,
                conversation_id=conversation_id,
                buddy_map=buddy_map,
                group_map=group_map,
                group_name_map=group_name_map,
            )
            for row in consumed_rows
        )
        if record is not None
    )
    return _QQMessageDictPage(
        records=records,
        cursor_after=cursor_after,
        has_more=has_more,
    )


def _query_messages(
    conn,
    days_back: int = 1,
    buddy_map: Optional[Dict[int, str]] = None,
    group_map: Optional[Dict[Tuple[int, int], str]] = None,
    group_name_map: Optional[Dict[int, str]] = None,
) -> List[QQMessage]:
    """Query messages from NTQQ 9.9.x message tables using hardcoded numeric
    column IDs (NTQQ stores cols as numeric "40001"/"40050" etc., not semantic
    names).

    Reads c2c_msg_table (private) + group_msg_table (groups).

    The optional buddy_map / group_map fall back to profile_info.db /
    group_info.db nickname when col 40090 (sender_name) is empty — which is the
    c2c case 100% of the time, and the group case for members with no
    group-nickname set.
    """
    import sqlite3
    cursor = conn.cursor()

    if buddy_map is None:
        buddy_map = {}
    if group_map is None:
        group_map = {}
    if group_name_map is None:
        group_name_map = {}

    messages: List[QQMessage] = []
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cursor.fetchall()]

    target_tables = [t for t in ("c2c_msg_table", "group_msg_table") if t in tables]
    since_ts = int((datetime.now() - timedelta(days=days_back)).timestamp())

    for table in target_tables:
        is_group = table == "group_msg_table"
        conversation_column = (
            _NTQQ_COL_GROUP_CODE if is_group else _NTQQ_COL_PEER_UIN
        )
        columns = _qq_table_columns(cursor, table)
        required_columns = {
            conversation_column,
            _NTQQ_COL_SENDER_UIN,
            _NTQQ_COL_MSG_TIME,
            _NTQQ_COL_MSG_BODY,
        }
        if columns is None or not required_columns.issubset(columns):
            logger.warning("%s: incompatible message schema", table)
            continue

        def select_expression(column: str) -> str:
            return f'"{column}"' if column in columns else "NULL"

        try:
            cursor.execute(
                f'SELECT {select_expression(_NTQQ_COL_MSG_UID)}, '
                f'"{_NTQQ_COL_MSG_TIME}", '
                f'{select_expression(_NTQQ_COL_SENDER_NAME)}, '
                f'"{_NTQQ_COL_SENDER_UIN}", "{_NTQQ_COL_MSG_BODY}", '
                f'{select_expression(_NTQQ_COL_PEER_UIN)}, '
                f'{select_expression(_NTQQ_COL_GROUP_CODE)} '
                f'FROM "{table}" WHERE "{_NTQQ_COL_MSG_TIME}" > ? '
                f'ORDER BY "{_NTQQ_COL_MSG_TIME}"',
                (since_ts,),
            )
            rows = cursor.fetchall()
            logger.info(f"{table}: {len(rows)} rows since {since_ts}")
        except sqlite3.Error as e:
            logger.warning(f"{table}: query fail {e}")
            continue

        for row in rows:
            msg_uid, msg_time, sender_name, sender_uin, msg_body, peer_uin, group_code = row
            ts_epoch = msg_time if isinstance(msg_time, (int, float)) and msg_time > 10**8 else None
            if not ts_epoch:
                continue
            ts = datetime.fromtimestamp(ts_epoch)
            text = _extract_msg_text(msg_body) if msg_body else ""
            if not text:
                continue
            att_meta = _extract_qq_attachment_meta(msg_body) if msg_body else None
            chat_uid = str(group_code) if is_group else str(peer_uin)
            if is_group:
                try:
                    chat_name = group_name_map.get(int(chat_uid), "")
                except (TypeError, ValueError):
                    chat_name = ""
                chat_name = chat_name or f"qq_group_{chat_uid}"
            else:
                try:
                    chat_name = buddy_map.get(int(chat_uid), "")
                except (TypeError, ValueError):
                    chat_name = ""
                chat_name = chat_name or f"qq_friend_{chat_uid}"
            try:
                sender_uin_int = int(sender_uin) if sender_uin else 0
            except (ValueError, TypeError):
                sender_uin_int = 0
            resolved_name = _resolve_sender_name(
                raw_name=sender_name or "",
                sender_uin=sender_uin_int,
                chat_uid=chat_uid,
                is_group=is_group,
                buddy_map=buddy_map,
                group_map=group_map,
            )
            sender_str = str(sender_uin_int) if sender_uin_int else (sender_name or "")
            messages.append(QQMessage(
                timestamp=ts,
                sender=sender_str,
                sender_name=resolved_name or sender_str,
                content=text,
                chat_name=chat_name,
                chat_uid=chat_uid,
                msg_type=1,
                conversation_type="group" if is_group else "direct",
                is_group_chat=is_group,
                attachment_meta=att_meta,
            ))
    messages.sort(key=lambda m: m.timestamp)
    return messages


# ─── High-level reader ───────────────────────────────────────────────────────

class QQDBReader:
    """
    High-level interface for reading QQ NT messages.
    
    Usage:
        reader = QQDBReader()
        ok = reader.initialize()
        if ok:
            messages = reader.read_recent(days=1)
            text = reader.format_for_ai(messages)
        else:
            print("Use clipboard fallback")
    """
    
    def __init__(
        self,
        data_root: Optional[Path] = None,
        account_id: Optional[str] = None,
        *,
        allow_live_key_extract: bool = True,
        live_key_timeout_s: Optional[float] = None,
    ):
        """Create a reader, optionally scoped to one discovered account.

        ``account_id`` is matched against :func:`find_qq_account_databases` and
        is never joined onto a filesystem path.  Calling without arguments
        preserves the v0.2.0 active-account behavior. Directory-only callers
        disable live extraction so listing accounts never scans process memory.
        """
        self._configured_data_root = Path(data_root) if data_root is not None else None
        self._configured_account_id = str(account_id) if account_id is not None else None
        self._allow_live_key_extract = bool(allow_live_key_extract)
        self._live_key_timeout_s = (
            max(float(live_key_timeout_s), 0.1)
            if live_key_timeout_s is not None
            else None
        )
        self.data_root = None
        self.db_path = None
        self.account_id = None
        self.account_label = ""
        self.key = None
        self.key_source = None  # "live" | "cache"; never contains key material
        self._initialized = False
    
    def initialize(self) -> bool:
        """Find data directory and extract (or load cached) encryption key.

        Priority for key acquisition:
          1. Live QQ.exe memory (if running) — also persists key to cache.
          2. Cached key file ``data/secrets/qq_db.key`` (extracted previously).
          3. None — caller sees ``key=None`` and downstream skips gracefully.
        """
        self.data_root = self._configured_data_root or find_qq_data_root()
        if not self.data_root:
            logger.warning("QQ data root not found")
            self._initialized = True
            return False

        account_databases = find_qq_account_databases(self.data_root)
        if self._configured_account_id is not None:
            self.db_path = account_databases.get(self._configured_account_id)
            self.account_id = self._configured_account_id if self.db_path is not None else None
        else:
            self.db_path = find_msg_database(self.data_root)
            for discovered_id, discovered_db in account_databases.items():
                if discovered_db == self.db_path:
                    self.account_id = discovered_id
                    break
        if not self.db_path:
            logger.warning("QQ message database is unavailable for the requested scope")
            self._initialized = True
            return False

        logger.info(f"Using database: {self.db_path}")

        # Prefer the cached key first (live extract scans GBs of QQ.exe memory
        # per-PID and can hang many minutes × N_pids). Override with env
        # CHATLOG_QQ_FORCE_LIVE_KEY=1 to bypass the cache (e.g. after a QQ login
        # change invalidates the cached key).
        force_live = os.environ.get("CHATLOG_QQ_FORCE_LIVE_KEY", "").strip() in ("1", "true", "yes")

        # 0. Try cached key first (fast path)
        if not force_live:
            cached = (
                load_cached_key_for_account(self.account_id)
                if self.account_id
                else load_cached_key()
            )
            verification = _read_qq_verification_bytes(self.db_path) if cached else None
            if cached and verification and _verify_key_qq(cached, verification):
                logger.info("Using cached key from data/secrets/qq_db.key (fast path)")
                self.key = cached
                self.key_source = "cache"
            elif cached:
                logger.warning("Cached QQ key does not unlock the requested account database")

        # 1. Try live extraction if no cached key OR force_live
        if not self.key and self._allow_live_key_extract:
            pids = _get_qq_pids()
            if pids:
                # Bound the complete passive scan, not every QQ helper. The
                # earliest/root process is attempted first; later helpers only
                # receive the remaining wall-clock budget.
                import time as _time
                per_process_budget = max(
                    0.1, float(os.environ.get("CHATLOG_QQ_SCAN_TIMEOUT_S", "120"))
                )
                total_budget = max(
                    0.1, float(os.environ.get("CHATLOG_QQ_SCAN_TOTAL_S", "120"))
                )
                if self._live_key_timeout_s is not None:
                    total_budget = min(total_budget, self._live_key_timeout_s)
                    per_process_budget = min(per_process_budget, total_budget)
                deadline = _time.monotonic() + total_budget
                for pid in pids:
                    remaining = deadline - _time.monotonic()
                    if remaining <= 0:
                        logger.warning(
                            f"QQ passive scan exhausted total {total_budget:.0f}s budget"
                        )
                        break
                    self.key = extract_key_from_qq(pid, db_path=self.db_path,
                                                   timeout_s=min(per_process_budget, remaining))
                    if self.key:
                        self.key_source = "live"
                        saved = (
                            save_cached_key_for_account(self.key, self.account_id)
                            if self.account_id
                            else save_cached_key(self.key)
                        )
                        if saved:
                            logger.info("Key extracted from QQ.exe and cached for the selected account")
                        break
                if not self.key:
                    logger.warning("QQ running but key extraction failed (try Admin or different PID).")

        # 2. Final fallback (already tried above unless force_live)
        require_live = os.environ.get("CHATLOG_QQ_REQUIRE_LIVE_KEY", "").strip().lower() in (
            "1", "true", "yes", "on",
        )
        if not self.key and not require_live:
            cached = (
                load_cached_key_for_account(self.account_id)
                if self.account_id
                else load_cached_key()
            )
            verification = _read_qq_verification_bytes(self.db_path) if cached else None
            if cached and verification and _verify_key_qq(cached, verification):
                logger.info("Using cached key from data/secrets/qq_db.key (fallback)")
                self.key = cached
                self.key_source = "cache"
            elif not self._allow_live_key_extract:
                logger.warning("No verified cached key is available for the requested account")
            else:
                logger.warning("No key available (QQ.exe not running and no cached key).")
        elif not self.key:
            logger.warning("A fresh live QQ key was required; cached-key fallback is disabled.")

        self._initialized = True
        return self.db_path is not None

    # ── Compat shim for the reader interface. Returns True when we have BOTH
    #    db_path AND key — i.e. extraction will actually produce rows.
    def is_available(self) -> bool:
        if not self._initialized:
            self.initialize()
        return bool(self.db_path) and bool(self.key)

    def iter_message_dict_pages(
        self,
        since_ts: float,
        until_ts: float,
        *,
        account_id: str,
        conversation_id: str,
        conversation_type: Optional[str],
        page_size: int = _QQ_MESSAGE_PAGE_DEFAULT_SIZE,
        cursor: Optional[_QQMessagePageCursor] = None,
        cancel_requested: Optional[Callable[[], bool]] = None,
    ) -> Iterator[_QQMessageDictPage]:
        """Yield bounded keyset pages for one explicitly selected QQ scope.

        A single decrypted snapshot and SQLite connection live for the whole
        iterator. The method never calls ``read_recent``/``read_recent_dicts``
        and therefore never materializes the account's complete history first.
        ``account_id`` must exactly match this reader's discovered database;
        stream-v1 callers should also provide an exact direct/group type.
        """

        if cancel_requested is not None and not callable(cancel_requested):
            raise ValueError("cancel_requested must be callable")
        (
            account_id,
            conversation_id,
            conversation_type,
            since_ts,
            until_ts,
        ) = _validate_qq_message_page_request(
            account_id=account_id,
            conversation_id=conversation_id,
            conversation_type=conversation_type,
            since_ts=since_ts,
            until_ts=until_ts,
            page_size=page_size,
            cursor=cursor,
        )
        _raise_if_qq_message_page_cancelled(cancel_requested)
        if not self._initialized:
            self.initialize()
        _raise_if_qq_message_page_cancelled(cancel_requested)
        reader_account_id = str(self.account_id or "").strip()
        if reader_account_id != account_id:
            raise ValueError("account_id does not match the reader's selected database")
        if not self.db_path or not self.key:
            return

        tmp_dir = _create_qq_plaintext_temp_dir("qq_page_")
        conn = None
        try:
            no_header_path = Path(tmp_dir) / "no_header.db"
            if not _skip_header(self.db_path, no_header_path):
                raise OSError("failed to prepare the selected QQ database snapshot")
            decrypted_path = Path(tmp_dir) / "decrypted.db"
            decrypt_result = _decrypt_db_qq_result(
                no_header_path,
                self.key,
                decrypted_path,
                source_wrapper_size=_NTQQ_WRAPPER_SIZE,
            )
            if decrypt_result.ok:
                database = _QQDecryptedDatabase(
                    path=decrypted_path,
                    shifted_pending_byte=decrypt_result.shifted_pending_byte,
                )
            elif decrypt_result.shifted_pending_byte:
                raise OSError("shifted NTQQ database failed authenticated decryption")
            else:
                logger.warning("QQ page snapshot decryption failed, trying as plaintext")
                database = no_header_path
            _raise_if_qq_message_page_cancelled(cancel_requested)

            buddy_map: Dict[int, str] = {}
            group_map: Dict[Tuple[int, int], str] = {}
            group_name_map: Dict[int, str] = {}
            nt_db_dir = self.db_path.parent
            profile_src = nt_db_dir / "profile_info.db"
            if profile_src.exists():
                profile_dec = _decrypt_aux_db(profile_src, self.key, Path(tmp_dir))
                if profile_dec:
                    buddy_map = _build_buddy_name_map(profile_dec)
                    account_numbers = _build_account_qq_number_map(profile_dec)
                    profile_account_label = account_numbers.get(account_id, "")
                    if profile_account_label:
                        self.account_label = profile_account_label
            group_src = nt_db_dir / "group_info.db"
            if group_src.exists():
                _raise_if_qq_message_page_cancelled(cancel_requested)
                group_dec = _decrypt_aux_db(group_src, self.key, Path(tmp_dir))
                if group_dec:
                    group_map = _build_group_member_map(group_dec)
                    group_name_map = _build_group_name_map(group_dec)

            conn = _open_qq_sqlite_connection(database)
            account_number = _query_account_qq_number(conn)
            if account_number:
                self.account_label = account_number
            current_cursor = cursor
            while True:
                _raise_if_qq_message_page_cancelled(cancel_requested)
                page = _query_message_dict_page(
                    conn,
                    account_id=account_id,
                    conversation_id=conversation_id,
                    conversation_type=conversation_type,
                    since_ts=since_ts,
                    until_ts=until_ts,
                    page_size=page_size,
                    cursor=current_cursor,
                    buddy_map=buddy_map,
                    group_map=group_map,
                    group_name_map=group_name_map,
                )
                _raise_if_qq_message_page_cancelled(cancel_requested)
                progressed = page.cursor_after != current_cursor
                if page.records or progressed:
                    yield page
                    _raise_if_qq_message_page_cancelled(cancel_requested)
                if not page.has_more:
                    break
                if not progressed or page.cursor_after is None:
                    raise RuntimeError("QQ message keyset page did not advance")
                current_cursor = page.cursor_after
        finally:
            _finalize_qq_plaintext_temp(conn, tmp_dir)
    
    def read_recent(self, days: int = 1, hours: Optional[float] = None) -> List[QQMessage]:
        """Read messages from the last N days (or hours).

        Caller can pass either ``days=`` (legacy) or ``hours=``.
        ``hours`` wins when provided.

        Also decrypts the profile_info.db / group_info.db sibling dbs to
        populate buddy_name_map / group_member_map, which resolves a numeric
        sender QQ uin → human-readable nickname in the narrative.
        """
        if not self._initialized:
            self.initialize()

        if not self.db_path:
            logger.warning("No database available")
            return []
        if not self.key:
            logger.warning("No key available — cannot decrypt; returning [] (graceful skip)")
            return []

        if hours is not None:
            days = max(1, int(hours / 24) or 1)

        tmp_dir = _create_qq_plaintext_temp_dir("qq_db_")
        conn = None

        try:
            no_header_path = Path(tmp_dir) / "no_header.db"
            if not _skip_header(self.db_path, no_header_path):
                logger.error("Failed to remove header")
                return []

            decrypted_path = Path(tmp_dir) / "decrypted.db"
            decrypt_result = _decrypt_db_qq_result(
                no_header_path,
                self.key,
                decrypted_path,
                source_wrapper_size=_NTQQ_WRAPPER_SIZE,
            )
            if decrypt_result.ok:
                database = _QQDecryptedDatabase(
                    path=decrypted_path,
                    shifted_pending_byte=decrypt_result.shifted_pending_byte,
                )
            elif decrypt_result.shifted_pending_byte:
                logger.warning("Shifted NTQQ database failed authenticated decryption")
                return []
            else:
                logger.warning("Decryption failed, trying as plaintext")
                database = no_header_path

            # Decrypt profile_info.db + group_info.db side-by-side and build
            # name lookup maps. Failure is non-fatal (= numeric uin fallback).
            buddy_map: Dict[int, str] = {}
            group_map: Dict[Tuple[int, int], str] = {}
            group_name_map: Dict[int, str] = {}
            try:
                nt_db_dir = self.db_path.parent  # nt_db/
                profile_src = nt_db_dir / "profile_info.db"
                group_src = nt_db_dir / "group_info.db"
                tmp_path = Path(tmp_dir)
                if profile_src.exists():
                    profile_dec = _decrypt_aux_db(
                        profile_src, self.key, tmp_path
                    )
                    if profile_dec:
                        buddy_map = _build_buddy_name_map(profile_dec)
                        account_numbers = _build_account_qq_number_map(profile_dec)
                        profile_account_label = account_numbers.get(
                            str(self.account_id or "").strip(),
                            "",
                        )
                        if profile_account_label:
                            self.account_label = profile_account_label
                        logger.info(f"buddy_map loaded: {len(buddy_map)} entries")
                if group_src.exists():
                    group_dec = _decrypt_aux_db(
                        group_src, self.key, tmp_path
                    )
                    if group_dec:
                        group_map = _build_group_member_map(group_dec)
                        group_name_map = _build_group_name_map(group_dec)
                        logger.info(f"group_member_map loaded: {len(group_map)} entries")
                        logger.info(f"group_name_map loaded: {len(group_name_map)} entries")
            except Exception as e:
                logger.warning(
                    "QQ auxiliary name lookup failed: %s",
                    type(e).__name__,
                )

            try:
                conn = _open_qq_sqlite_connection(database)
                account_number = _query_account_qq_number(conn)
                if account_number:
                    self.account_label = account_number
                messages = _query_messages(
                    conn, days_back=days,
                    buddy_map=buddy_map,
                    group_map=group_map,
                    group_name_map=group_name_map,
                )
                return messages
            except Exception as e:
                logger.warning("QQ SQLite query failed: %s", type(e).__name__)
                return []

        finally:
            _finalize_qq_plaintext_temp(conn, tmp_dir)

    def read_conversation_directory(self) -> Optional[List[Dict]]:
        """Return native QQ conversations and counts without reading bodies.

        ``None`` means the database could not be opened/decrypted; an empty
        list means it was read successfully and contains no conversation rows.
        """
        if not self._initialized:
            self.initialize()
        if not self.db_path or not self.key:
            return None

        self.account_label = ""
        tmp_dir = _create_qq_plaintext_temp_dir("qq_directory_")
        conn = None
        try:
            no_header_path = Path(tmp_dir) / "no_header.db"
            if not _skip_header(self.db_path, no_header_path):
                return None
            decrypted_path = Path(tmp_dir) / "decrypted.db"
            decrypt_result = _decrypt_db_qq_result(
                no_header_path,
                self.key,
                decrypted_path,
                source_wrapper_size=_NTQQ_WRAPPER_SIZE,
            )
            if decrypt_result.ok:
                database = _QQDecryptedDatabase(
                    path=decrypted_path,
                    shifted_pending_byte=decrypt_result.shifted_pending_byte,
                )
            elif decrypt_result.shifted_pending_byte:
                return None
            else:
                database = no_header_path

            buddy_map: Dict[int, str] = {}
            buddy_directory_map: Dict[int, str] = {}
            group_name_map: Dict[int, str] = {}
            profile_src = self.db_path.parent / "profile_info.db"
            if profile_src.exists():
                profile_dec = _decrypt_aux_db(profile_src, self.key, Path(tmp_dir))
                if profile_dec:
                    buddy_map = _build_buddy_directory_label_map(profile_dec)
                    buddy_directory_map = _build_buddy_directory_map(profile_dec)
                    account_numbers = _build_account_qq_number_map(profile_dec)
                    self.account_label = account_numbers.get(
                        str(self.account_id or "").strip(),
                        "",
                    )

            group_src = self.db_path.parent / "group_info.db"
            if group_src.exists():
                group_dec = _decrypt_aux_db(group_src, self.key, Path(tmp_dir))
                if group_dec:
                    group_name_map = _build_group_name_map(group_dec)

            conn = _open_qq_sqlite_connection(database)
            account_number = _query_account_qq_number(conn)
            if account_number:
                self.account_label = account_number
            _exclude_self_from_buddy_directory(
                buddy_directory_map,
                self.account_label,
            )
            return _query_conversation_directory(
                conn,
                buddy_map=buddy_map,
                buddy_directory_map=buddy_directory_map,
                group_name_map=group_name_map,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("QQ conversation directory is unavailable: %s", type(exc).__name__)
            return None
        finally:
            _finalize_qq_plaintext_temp(conn, tmp_dir)
    
    def format_for_ai(self, messages: List[QQMessage]) -> str:
        """Format messages as plain text for AI."""
        if not messages:
            return ""
        lines = []
        for m in messages:
            t = m.timestamp.strftime("%H:%M")
            chat = f"[{m.chat_name}] " if m.chat_name else ""
            sender = m.sender_name if m.sender_name else m.sender
            if m.content:
                lines.append(f"{t} {chat}{sender}: {m.content}")
        return "\n".join(lines)

    def format_unified(self, messages: List[QQMessage]) -> str:
        """Chronological flat list.

        One line per msg: ``[YYYY-MM-DD HH:MM] <chat> | <sender>: <text>``.
        """
        if not messages:
            return "(无QQ消息)"
        lines: list[str] = []
        for m in messages:
            dt = m.timestamp.strftime("%Y-%m-%d %H:%M")
            chat = m.chat_name or "?"
            sender = m.sender_name or m.sender or "?"
            lines.append(f"[{dt}] {chat} | {sender}: {m.content}")
        return "\n".join(lines)

    def read_recent_dicts(self, since_ts: float, until_ts: float) -> List[Dict]:
        """Return raw dict-shaped messages for a downstream batch builder.

        Output schema:

            {
              "ts": float (epoch seconds),
              "ts_iso": str (UTC ISO-8601),
              "wxid_hash": str (sha16 of sender_id, for parity with WeChat),
              "sender_qq": int,
              "sender_name": str,
              "content": str (max 1500),
              "msg_id": int|None,
              "chat_uid": str,   # group_id or buddy_uid as string
              "chat_kind": "group"|"friend",
              "source_offset": "qq_db:<msg_id>",
            }
        """
        import hashlib
        from datetime import timezone
        msgs = self.read_recent(days=max(1, int((until_ts - since_ts) / 86400) + 1))
        out: List[Dict] = []
        account_id = str(self.account_id or "unknown")
        for m in msgs:
            ts = m.timestamp.timestamp()
            if ts < since_ts or ts > until_ts:
                continue
            sid = str(m.sender or m.sender_name or "?")
            wxid_hash = hashlib.sha256(sid.encode("utf-8")).hexdigest()[:16]
            content = (m.content or "").strip()
            if not content:
                continue
            try:
                sender_qq = int(m.sender) if m.sender and m.sender.isdigit() else 0
            except (ValueError, AttributeError):
                sender_qq = 0
            conversation_id = str(m.chat_uid or m.chat_name or "")
            conversation_type = str(
                getattr(m, "conversation_type", "") or ""
            ).strip().lower()
            is_group_chat = bool(
                getattr(m, "is_group_chat", False)
                or conversation_type == "group"
            )
            if conversation_type not in {"direct", "group"}:
                conversation_type = "group" if is_group_chat else "direct"
            out.append({
                "ts": ts,
                "ts_iso": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                "wxid_hash": wxid_hash,
                "sender_qq": sender_qq,
                "sender_name": m.sender_name or sid,
                "content": content[:1500],
                "msg_id": None,
                "chat_uid": m.chat_uid or m.chat_name,
                "chat_kind": "group" if is_group_chat else "friend",
                "account_id": account_id,
                "conversation_id": conversation_id,
                "thread_id": f"{account_id}::{conversation_id}",
                "conversation_type": conversation_type,
                "is_group_chat": is_group_chat,
                "source_offset": f"qq_db:{m.chat_uid}:{int(ts)}",
                # attachment metadata for doc cross-linkage
                "attachment_meta": m.attachment_meta,
            })
        out.sort(key=lambda x: x["ts"])
        return out
    
    def diagnose(self) -> dict:
        """Return diagnostic info."""
        self.initialize()
        pids = _get_qq_pids()
        return {
            "data_root": str(self.data_root),
            "db_path": str(self.db_path) if self.db_path else None,
            "qq_pids": list(pids),
            "key_extracted": self.key is not None,
            "key_length": len(self.key) if self.key else 0,
        }


# ─── Utility functions ───────────────────────────────────────────────────────

def diagnose_qq_db():
    """Diagnostic function to check QQ database setup."""
    reader = QQDBReader()
    info = reader.diagnose()
    
    print("\n=== QQ Database Diagnostic ===")
    for k, v in info.items():
        print(f"  {k}: {v}")
    
    if info["db_path"] and info["key_extracted"]:
        print("\n[OK] Ready to read messages")
    elif info["db_path"] and not info["key_extracted"]:
        print("\n[WARN] Database found but key extraction failed")
        print("       Make sure QQ is running and try as Administrator")
    else:
        print("\n[WARN] Database not found")
        print("       Make sure you have logged into QQ at least once")


if __name__ == "__main__":
    # Run diagnostics when executed directly
    diagnose_qq_db()
