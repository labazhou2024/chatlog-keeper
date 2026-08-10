"""
wechat_db.py — Weixin 4.x (Weixin.exe) local message database reader.

Storage layout (Weixin 4.x):
  Root:     C:\\wechat files\\xwechat_files\\
  wxid dir: wxid_<id>_<hash>\\db_storage\\message\\message_0.db
  Key:      32-byte enc_key stored as ASCII x'<64hex><32hex_salt>' in process memory
  Cipher:   AES-256-CBC. Page key = enc_key raw (raw-key mode, WeChat <=4.0.x) OR
            PBKDF2-HMAC-SHA512(enc_key, salt, 256000, 32) (password mode, 4.1.10.31+).
            HMAC-SHA512 mac_key = PBKDF2(page_key, salt^0x3A, 2). See _effective_page_key().
  Tables:   Msg_<md5(wxid)>  — one per conversation/group
  Sender:   Name2Id table, rowid == real_sender_id
"""
import ctypes
import ctypes.wintypes as wt
from contextvars import ContextVar
import hashlib
import hmac as hmac_mod
import json
import logging
import math
import os
import re
import secrets
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time as _time
from datetime import datetime, date, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Tuple

from chatlog_keeper.core._windows_process_memory import (
    PROCESS_ACCESS_DENIED,
    ProcessMemoryAccessDenied,
    kernel32 as _windows_kernel32,
    last_error as _windows_last_error,
    raise_if_access_denied as _raise_if_windows_access_denied,
)

logger = logging.getLogger(__name__)


_PASSIVE_KEY_ERROR_CODE: ContextVar[Optional[str]] = ContextVar(
    "chatlog_keeper_wechat_passive_key_error_code",
    default=None,
)


def _clear_passive_key_error() -> None:
    _PASSIVE_KEY_ERROR_CODE.set(None)


def _passive_key_error() -> Optional[str]:
    return _PASSIVE_KEY_ERROR_CODE.get()


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class WxMessage:
    timestamp: datetime
    sender: str        # raw wxid (for backward compat); see sender_display_name for human-readable
    content: str
    chat_name: str     # raw wxid/@chatroom of the conversation
    msg_type: int = 1  # 1=text, 3=image, 43=video, 47=emoji, etc.
    # Human-readable display fields populated by WeChatContactResolver.
    # Default to empty string so callers ignoring these still work.
    sender_display_name: str = ""
    chat_display_name: str = ""
    is_group_chat: bool = False
    # Attachment metadata (file/voice/image cards): populated when
    # msg_type=49 sub=6 (file) or sub=2 (image), or msg_type=34 (voice).
    # Keys: filename, md5, total_bytes, fileext, voice_length_ms.
    # Lets a downstream doc builder cross-reference (by filename + size + md5)
    # and stamp linked_from_chat on doc cards.
    attachment_meta: Optional[dict] = None
    # WeChat server-side msg ID. Globally unique across all chats, used as the
    # svrid anchor in the narrative for refermsg / cross-batch jumps.
    # Empty string when unknown (e.g. local-only msgs not yet acked by server).
    server_id: str = ""

    def is_text(self):
        return self.msg_type == 1

    def display_sender(self) -> str:
        """Return sender_display_name if set, else fall back to sender (wxid)."""
        return self.sender_display_name or self.sender

    def display_chat(self) -> str:
        """Return chat_display_name if set, else fall back to chat_name (wxid)."""
        return self.chat_display_name or self.chat_name

    def __str__(self):
        t = self.timestamp.strftime("%H:%M")
        return f"[{t}] {self.display_sender()}: {self.content}"


_WECHAT_MESSAGE_PAGE_CURSOR_VERSION = 1
_WECHAT_MESSAGE_PAGE_MAX_ROWS = 1000
_WECHAT_MESSAGE_SHARD_ID_RE = re.compile(r"[0-9a-f]{24}")


class WeChatMessagePageCancelled(RuntimeError):
    """Raised before a page cursor is advanced when its caller cancels."""


@dataclass(frozen=True)
class WeChatMessagePageCursor:
    """Serializable per-shard keyset positions for one bounded message read."""

    scope: str
    topology: str
    positions: Tuple[Tuple[str, int, int], ...] = ()
    version: int = _WECHAT_MESSAGE_PAGE_CURSOR_VERSION

    def __post_init__(self) -> None:
        if self.version != _WECHAT_MESSAGE_PAGE_CURSOR_VERSION:
            raise ValueError("WeChat message page cursor version is invalid")
        if not isinstance(self.scope, str) or not _WECHAT_MESSAGE_SHARD_ID_RE.fullmatch(
            self.scope
        ):
            raise ValueError("WeChat message page cursor scope is invalid")
        if not isinstance(self.topology, str) or not _WECHAT_MESSAGE_SHARD_ID_RE.fullmatch(
            self.topology
        ):
            raise ValueError("WeChat message page cursor topology is invalid")
        if not isinstance(self.positions, tuple):
            raise ValueError("WeChat message page cursor positions are invalid")
        previous_shard = ""
        for position in self.positions:
            if not isinstance(position, tuple) or len(position) != 3:
                raise ValueError("WeChat message page cursor position is invalid")
            shard_id, create_time, row_id = position
            if not isinstance(shard_id, str) or not _WECHAT_MESSAGE_SHARD_ID_RE.fullmatch(
                shard_id
            ):
                raise ValueError("WeChat message page cursor shard is invalid")
            if shard_id <= previous_shard:
                raise ValueError("WeChat message page cursor shards are not unique")
            if (
                isinstance(create_time, bool)
                or not isinstance(create_time, int)
                or isinstance(row_id, bool)
                or not isinstance(row_id, int)
                or row_id < 0
            ):
                raise ValueError("WeChat message page cursor position is invalid")
            previous_shard = shard_id

    def position_for(self, shard_id: str) -> Optional[Tuple[int, int]]:
        """Return ``(create_time, rowid)`` for one shard, if it advanced."""

        for current_shard, create_time, row_id in self.positions:
            if current_shard == shard_id:
                return create_time, row_id
        return None

    def to_dict(self) -> dict:
        """Return a JSON-safe cursor without database paths or conversation IDs."""

        return {
            "version": self.version,
            "scope": self.scope,
            "topology": self.topology,
            "positions": [
                {
                    "shard": shard_id,
                    "create_time": create_time,
                    "row_id": row_id,
                }
                for shard_id, create_time, row_id in self.positions
            ],
        }

    @classmethod
    def from_value(cls, value: Any) -> "WeChatMessagePageCursor":
        """Validate an existing cursor instance or its JSON-decoded mapping."""

        if isinstance(value, cls):
            return cls(
                scope=value.scope,
                topology=value.topology,
                positions=value.positions,
                version=value.version,
            )
        if not isinstance(value, Mapping):
            raise ValueError("WeChat message page cursor is invalid")
        raw_positions = value.get("positions")
        if not isinstance(raw_positions, list):
            raise ValueError("WeChat message page cursor positions are invalid")
        positions = []
        for item in raw_positions:
            if not isinstance(item, Mapping):
                raise ValueError("WeChat message page cursor position is invalid")
            shard_id = item.get("shard")
            create_time = item.get("create_time")
            row_id = item.get("row_id")
            if (
                not isinstance(shard_id, str)
                or not _WECHAT_MESSAGE_SHARD_ID_RE.fullmatch(shard_id)
                or isinstance(create_time, bool)
                or not isinstance(create_time, int)
                or isinstance(row_id, bool)
                or not isinstance(row_id, int)
            ):
                raise ValueError("WeChat message page cursor position is invalid")
            positions.append((shard_id, create_time, row_id))
        version = value.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError("WeChat message page cursor version is invalid")
        scope = value.get("scope")
        topology = value.get("topology")
        if not isinstance(scope, str):
            raise ValueError("WeChat message page cursor scope is invalid")
        if not isinstance(topology, str):
            raise ValueError("WeChat message page cursor topology is invalid")
        return cls(
            scope=scope,
            topology=topology,
            positions=tuple(sorted(positions, key=lambda item: item[0])),
            version=version,
        )


@dataclass(frozen=True)
class WeChatMessagePage:
    """One bounded raw-row page converted to the existing ``WxMessage`` type."""

    messages: Tuple[WxMessage, ...]
    next_cursor: Optional[WeChatMessagePageCursor]
    has_more: bool
    scanned_rows: int


@dataclass(frozen=True)
class _WeChatConversationPageRow:
    """One keyset-addressable database row before content normalization."""

    shard_id: str
    row_id: int
    create_time: int
    msg_type: int
    sender: str
    message_content: Any
    server_id: str
    packed_info_data: Any

    @property
    def order_key(self) -> Tuple[int, str, int]:
        return self.create_time, self.shard_id, self.row_id


# ─── WeChat process helpers ────────────────────────────────────────────────────

def _get_weixin_pids() -> list:
    """Return list of Weixin.exe PIDs.

    Sorted ASCENDING — smallest PID = oldest = likely parent process that holds
    the SQLCipher enc_keys in heap. This avoids the repeated "Key extraction
    failed" log spam that happens when descending order tries worker pids first.
    """
    if sys.platform == "darwin":
        from chatlog_keeper.core._macos import process_pids
        return process_pids(("WeChat", "Weixin"))

    # A 5s tasklist timeout was too tight on loaded systems (caused a false
    # "Weixin.exe not running" when many Weixin instances + concurrent Python
    # processes saturated the tasklist response). Use 30s + retry once on
    # TimeoutExpired (cheap; tasklist reads from kernel).
    last_err = None
    for attempt in (1, 2):
        try:
            r = subprocess.run(
                ["tasklist", "/FO", "CSV", "/FI", "IMAGENAME eq Weixin.exe"],
                capture_output=True, timeout=30
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
            return sorted(pids)  # ASCENDING — parent (smallest PID) first
        except subprocess.TimeoutExpired as e:
            last_err = e
            logger.warning(f"PID lookup timeout (attempt {attempt}/2, 30s)")
            continue
        except Exception as e:
            logger.warning(f"PID lookup failed: {e}")
            return []
    logger.warning(f"PID lookup failed after 2 attempts: {last_err}")
    return []


# ─── Data directory discovery ──────────────────────────────────────────────────

def find_weixin_data_root() -> Optional[Path]:
    """Locate the Weixin/WeChat user-data root, machine-neutrally.

    The 4.x default is ``<drive>/wechat files/xwechat_files`` and users can also
    relocate it directly to ``<drive>/xwechat_files``; 3.x used
    ``<Documents>/WeChat Files``. No drive letter is assumed.

    Discovery order (nothing hardcoded):
      1. ``CHATLOG_WECHAT_DATA_ROOT`` env var (explicit override)
      2. every logical drive root: ``<drive>/wechat files/xwechat_files`` +
         ``<drive>/xwechat_files`` + ``<drive>/WeChat Files``
      3. real Documents + OneDrive variants
    """
    from chatlog_keeper.core._paths import all_drive_roots, candidate_documents_roots

    candidates: list = []
    env = os.environ.get("CHATLOG_WECHAT_DATA_ROOT", "").strip()
    if env:
        candidates.append(Path(env))
    if sys.platform == "darwin":
        from chatlog_keeper.core._macos import wechat_data_roots
        candidates.extend(wechat_data_roots())
    else:
        for drive in all_drive_roots():
            candidates.append(drive / "wechat files" / "xwechat_files")
            candidates.append(drive / "xwechat_files")
            candidates.append(drive / "WeChat Files")
        for doc in candidate_documents_roots():
            candidates.append(doc / "xwechat_files")
            candidates.append(doc / "WeChat Files")

    seen: set = set()
    for c in candidates:
        k = str(c).lower()
        if k in seen:
            continue
        seen.add(k)
        try:
            if c.exists():
                logger.info(f"Found Weixin data root: {c}")
                return c
        except OSError:
            continue
    logger.warning("Could not locate Weixin data root; set CHATLOG_WECHAT_DATA_ROOT to override")
    return None


def find_wxid_dirs(data_root: Path) -> list:
    """Return list of wxid subdirectory paths inside data_root."""
    dirs = []
    try:
        for item in data_root.iterdir():
            if item.is_dir() and (item.name.startswith("wxid_") or len(item.name) > 10):
                dirs.append(item)
    except OSError as exc:
        logger.warning("Failed to scan WeChat account directories: %s", type(exc).__name__)
    return dirs


def find_msg_databases(wxid_dir: Path) -> list:
    """
    Find message databases under a wxid directory.
    Weixin 4.x: db_storage/message/message_*.db
    WeChat 3.x: Msg/Multi/MSG*.db (fallback)
    """
    dbs = []
    seen = set()

    # Weixin 4.x primary path — only actual message DBs (not FTS/resource)
    msg_dir = wxid_dir / "db_storage" / "message"
    if msg_dir.exists():
        for db_file in sorted(msg_dir.glob("message_*.db")):
            # Skip full-text-search and resource indexes
            if any(skip in db_file.name for skip in ("fts", "resource", "media")):
                continue
            if db_file not in seen:
                seen.add(db_file)
                dbs.append(db_file)

    # WeChat 3.x fallback
    for pattern in ["Msg/Multi", "."]:
        sub = wxid_dir / pattern.replace("/", os.sep)
        if sub.exists():
            for db_file in sub.glob("MSG*.db"):
                if db_file not in seen:
                    seen.add(db_file)
                    dbs.append(db_file)

    return dbs


# ─── Key extraction from Weixin process memory ────────────────────────────────

# WeChat 4.1.10.31 changed the in-memory key scheme: the value WCDB keeps in
# process memory is now the PASSWORD (master key), not the already-derived page
# key. The actual SQLCipher page key = PBKDF2-HMAC-SHA512(password, page1-salt,
# 256000, 32) — the SQLCipher-4 default kdf_iter the older builds pre-applied so
# the memory blob was usable raw. We support BOTH (raw-key for 4.0.x/older,
# derived for 4.1.10.31+). Verified against a captured master key: AES-CBC
# decrypt with the derived page key opens cleanly in sqlite3 (Msg_* tables) and
# HMAC-SHA512(salt^0x3a, fast_kdf_iter=2) matches.
_WECHAT_KDF_ITER = 256000


def _hmac_check_pagekey(page_key: bytes, db_page1: bytes) -> bool:
    """Standard SQLCipher-4 page-1 HMAC check given the actual 32-byte AES page key.
    HMAC-SHA512 over page1[16:4032] + LE-u32 page number, key = PBKDF2-HMAC-SHA512(
    page_key, salt^0x3A, fast_kdf_iter=2, 32)."""
    PAGE_SZ = 4096
    SALT_SZ = 16
    try:
        salt = db_page1[:SALT_SZ]
        mac_salt = bytes(b ^ 0x3A for b in salt)
        mac_key = hashlib.pbkdf2_hmac("sha512", page_key, mac_salt, 2, dklen=32)
        hm = hmac_mod.new(mac_key, db_page1[SALT_SZ: PAGE_SZ - 64], hashlib.sha512)
        hm.update(struct.pack("<I", 1))
        return hm.digest() == db_page1[PAGE_SZ - 64: PAGE_SZ]
    except Exception:
        return False


def _effective_page_key(enc_key: bytes, db_page1: bytes) -> Optional[bytes]:
    """Return the actual AES page key for THIS db (or None if enc_key does not fit),
    validated by the page-1 HMAC. Handles both WeChat key schemes:
      - raw-key mode (WeChat 4.0.x / older): enc_key IS the page key.
      - password mode (WeChat 4.1.10.31+): page key = PBKDF2-HMAC-SHA512(
        enc_key, page1-salt, 256000, 32).
    Per-db: the derived key depends on that db's salt, so a single cached master key
    decrypts every db (each derives its own page key)."""
    if not enc_key or len(enc_key) != 32 or not db_page1 or len(db_page1) < 4096:
        return None
    if _hmac_check_pagekey(enc_key, db_page1):
        return enc_key
    try:
        derived = hashlib.pbkdf2_hmac("sha512", enc_key, db_page1[:16], _WECHAT_KDF_ITER, dklen=32)
        if _hmac_check_pagekey(derived, db_page1):
            return derived
    except Exception:
        pass
    return None


def _verify_key_v4(enc_key: bytes, db_page1: bytes) -> bool:
    """True iff enc_key can decrypt db_page1 — raw-key (≤4.0.x) OR 4.1.10.31+ password
    mode (256000-iter PBKDF2 derivation). Backward-compatible superset of the old check."""
    return _effective_page_key(enc_key, db_page1) is not None


# ─── Persistent master-key cache (data/secrets, gitignored) ───────────────────
# The WeChat 4.x master key (32 bytes) is stable for one account but can change
# after an account switch or reinstall. New writes therefore use
# ``wechat_accounts/SHA256(account_id).key``; the historical ``wechat_db.key``
# remains a read fallback for existing installations and non-canonical archives.
# On WeChat 4.1.10.31+ the cache is also the only restart-independent read path.

def _persistent_wechat_key_cache_path() -> Optional[Path]:
    """Persistent app-data secrets path (survives app upgrade/reinstall — NSIS
    overwrites _internal but never the app-data dir)."""
    try:
        from chatlog_keeper.core._path_resolver import data_dir
        return data_dir() / "secrets" / "wechat_db.key"
    except Exception:
        return None


def _legacy_wechat_key_cache_path() -> Path:
    """Legacy package-relative path (READ fallback for old-install migration;
    in a frozen build this lands in _internal/ which is wiped on every upgrade)."""
    return Path(__file__).resolve().parents[1] / "data" / "secrets" / "wechat_db.key"


def _wechat_key_cache_path() -> Path:
    """Resolve the key cache file to WRITE (persistent app-data first)."""
    p = _persistent_wechat_key_cache_path()
    return p if p is not None else _legacy_wechat_key_cache_path()


def _wechat_account_key_cache_path(account_id: str) -> Path:
    """Return an account-scoped path without exposing the native WeChat ID."""
    normalized = str(account_id or "").strip()
    if not normalized:
        return _wechat_key_cache_path()
    digest = hashlib.sha256(
        normalized.encode("utf-8", errors="replace")
    ).hexdigest()
    return _wechat_key_cache_path().parent / "wechat_accounts" / f"{digest}.key"


def _parse_cached_wechat_key_text(text: str) -> Optional[bytes]:
    """Parse the on-disk 64-hex master-key representation."""
    normalized = (text or "").strip()
    if len(normalized) != 64 or any(
        char not in "0123456789abcdefABCDEF" for char in normalized
    ):
        return None
    try:
        return bytes.fromhex(normalized)
    except ValueError:
        return None


def load_cached_wechat_key() -> Optional[bytes]:
    """Read the cached 32-byte master key (64 hex on disk), persistent dir first.
    Never validates here — the caller HMAC-checks against the live DB so a stale
    key self-heals (it just fails _verify_key_v4 and a re-extract is attempted)."""
    from chatlog_keeper.core._secrets import read_secret_text

    seen: set = set()
    candidates = []
    persistent = _persistent_wechat_key_cache_path()
    if persistent is not None:
        candidates.append(persistent)
    candidates.append(_legacy_wechat_key_cache_path())
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
        key = _parse_cached_wechat_key_text(text)
        if key:
            return key
    return None


def load_cached_wechat_key_for_account(account_id: str) -> Optional[bytes]:
    """Load one account's key before the legacy global compatibility cache."""
    from chatlog_keeper.core._secrets import read_secret_text

    normalized = str(account_id or "").strip()
    if normalized:
        path = _wechat_account_key_cache_path(normalized)
        text = read_secret_text(path)
        if text is not None:
            key = _parse_cached_wechat_key_text(text)
            if key:
                return key
    return load_cached_wechat_key()


def save_cached_wechat_key(key: bytes) -> bool:
    """Persist a 32-byte master key (hex). Caller MUST have HMAC-verified it first."""
    if not key or len(key) != 32:
        return False
    p = _wechat_key_cache_path()
    from chatlog_keeper.core._secrets import write_secret_text
    return write_secret_text(p, bytes(key).hex())


def wechat_account_id_for_database(db_path: Path) -> Optional[str]:
    """Return the discovered wxid owner of a canonical message database path."""
    try:
        path = Path(db_path)
        if (
            path.parent.name.casefold() != "message"
            or path.parent.parent.name.casefold() != "db_storage"
        ):
            return None
        account_id = path.parent.parent.parent.name.strip()
    except (IndexError, OSError, TypeError):
        return None
    return account_id or None


def save_cached_wechat_key_for_account(
    key: bytes,
    account_id: str,
    verification_db: Path,
) -> bool:
    """HMAC-verify and persist a key only for ``verification_db``'s account."""
    normalized = str(account_id or "").strip()
    if not key or len(key) != 32 or not normalized:
        return False
    if wechat_account_id_for_database(verification_db) != normalized:
        return False
    page1 = _read_stable_page1(Path(verification_db))
    if not page1 or not _verify_key_v4(bytes(key), page1):
        return False
    from chatlog_keeper.core._secrets import write_secret_text
    return write_secret_text(
        _wechat_account_key_cache_path(normalized),
        bytes(key).hex(),
    )


def _read_stable_page1(db_path: Path) -> Optional[bytes]:
    """Return a checkpoint-safe SQLCipher page 1, or ``None`` if still busy."""
    from chatlog_keeper.core._snapshot import read_stable_prefix

    try:
        return read_stable_prefix(Path(db_path), 4096)
    except OSError:
        return None


def _scan_memory_for_key(pid: int, db_path: Path = None,
                         timeout_s: Optional[float] = None) -> Optional[bytes]:
    """
    Scan Weixin.exe process memory for the SQLCipher enc_key.

    Weixin 4.x stores:  x'<64 hex enc_key><32 hex salt>'
    in process heap as plain ASCII.  We scan all readable regions for this
    pattern and validate each candidate with HMAC-SHA512 against db_path page 1.
    """
    if sys.platform == "darwin":
        if not db_path or not Path(db_path).is_file():
            return None
        db_page1 = _read_stable_page1(Path(db_path))
        if not db_page1:
            return None
        from chatlog_keeper.macos_key import extract_verified
        return extract_verified(
            "wechat",
            pid,
            lambda candidate: _verify_key_v4(candidate, db_page1),
            elevate=False,
            timeout=max(1, int(timeout_s or 120)),
        )

    kernel32 = _windows_kernel32()
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        _raise_if_windows_access_denied(_windows_last_error(kernel32))
        logger.warning(f"Cannot open PID {pid} — try running as Administrator")
        return None

    # Load first page of DB for key verification
    db_page1 = None
    if db_path and db_path.exists():
        try:
            with open(db_path, "rb") as f:
                db_page1 = f.read(4096)
        except Exception:
            pass

    class MBI64(ctypes.Structure):
        _fields_ = [
            ("BaseAddress",       ctypes.c_uint64),
            ("AllocationBase",    ctypes.c_uint64),
            ("AllocationProtect", wt.DWORD),
            ("__alignment1",      wt.DWORD),
            ("RegionSize",        ctypes.c_uint64),
            ("State",             wt.DWORD),
            ("Protect",           wt.DWORD),
            ("Type",              wt.DWORD),
            ("__alignment2",      wt.DWORD),
        ]

    MEM_COMMIT = 0x1000
    READABLE_PROTECTS = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
    # Pattern: x'<64..192 hex chars>'  (key alone, or key+salt concatenated)
    hex_key_re = re.compile(rb"x'([0-9a-fA-F]{64,192})'")

    found_key = None
    mbi = MBI64()
    address = 0

    # 2026-06-16: wall-clock guard (mirrors qq_db) so the scan can't hang the
    # caller. None = unbounded (legacy behavior).
    import time as _time
    deadline = (_time.monotonic() + timeout_s) if timeout_s else None

    try:
        while address < 0x7FFFFFFFFFFF:
            if deadline and _time.monotonic() > deadline:
                logger.warning(f"PID {pid} memory scan hit {timeout_s:.0f}s timeout; "
                               "giving up (try `extract-key --method active` or `set-key`)")
                break
            ret = kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if not ret:
                _raise_if_windows_access_denied(_windows_last_error(kernel32))
                break

            if (mbi.State == MEM_COMMIT and
                    mbi.Protect in READABLE_PROTECTS and
                    0 < mbi.RegionSize < 200 * 1024 * 1024):
                buf = ctypes.create_string_buffer(mbi.RegionSize)
                read_n = ctypes.c_size_t(0)
                read_ok = kernel32.ReadProcessMemory(
                    handle, ctypes.c_void_p(mbi.BaseAddress),
                    buf, mbi.RegionSize, ctypes.byref(read_n)
                )
                if not read_ok:
                    _raise_if_windows_access_denied(_windows_last_error(kernel32))
                chunk = bytes(buf[:read_n.value])

                for m in hex_key_re.finditer(chunk):
                    hex_str = m.group(1).decode("ascii")
                    candidate = bytes.fromhex(hex_str[:64])

                    if db_page1:
                        if _verify_key_v4(candidate, db_page1):
                            logger.info(
                                f"Key verified at PID={pid} addr=0x{mbi.BaseAddress:x}"
                            )
                            found_key = candidate
                            break
                    else:
                        # No DB available — return first plausible match (unverified)
                        found_key = candidate
                        logger.info(f"Key candidate (unverified) at 0x{mbi.BaseAddress:x}")
                        break

                if found_key:
                    break

            nxt = mbi.BaseAddress + mbi.RegionSize
            if nxt <= address:
                break
            address = nxt

        return found_key
    except ProcessMemoryAccessDenied:
        raise
    except Exception as e:
        logger.error(f"Memory scan error for PID {pid}: {e}")
        return None
    finally:
        kernel32.CloseHandle(handle)


def extract_key_from_weixin(pid: int, db_path: Path = None,
                            timeout_s: Optional[float] = None,
                            account_id: Optional[str] = None) -> Optional[bytes]:
    """
    Obtain the Weixin 4.x master key for db_path. Returns 32-byte key or None.

    Acquisition order (cheapest first):
      1. Account cache, then legacy global cache, HMAC-validated against the live
         DB's page 1 — no scan, works without WeChat running. On 4.1.10.31 this is
         the only path that yields a key (seed it via `chatlog-keeper wechat set-key`).
      2. Live process-memory scan (works on 4.0.x/older where the plaintext key is
         in the heap; returns nothing on 4.1.10.31). A scanned key that verifies is
         persisted to the cache so future runs skip the scan.
    No key bytes are ever logged (privacy).
    """
    _clear_passive_key_error()
    db_page1 = None
    if db_path and Path(db_path).exists():
        db_page1 = _read_stable_page1(Path(db_path))

    # 1. Cache fast-path (self-healing: only used if it HMAC-verifies the live DB).
    if db_page1:
        cached = (
            load_cached_wechat_key_for_account(account_id)
            if account_id
            else load_cached_wechat_key()
        )
        if cached and len(cached) == 32 and _verify_key_v4(cached, db_page1):
            logger.info("Using a cached Weixin master key")
            return cached

    # 2. Live process-memory scan (fails on 4.1.10.31 — plaintext key not in heap).
    logger.info(f"Attempting key extraction from Weixin PID {pid}")
    try:
        key = _scan_memory_for_key(pid, db_path=db_path, timeout_s=timeout_s)
    except ProcessMemoryAccessDenied:
        _PASSIVE_KEY_ERROR_CODE.set(PROCESS_ACCESS_DENIED)
        logger.warning("WeChat process-memory access was denied")
        return None
    if key and len(key) == 32:
        # _scan_memory_for_key already HMAC-validates; persist for future runs.
        if db_page1 and _verify_key_v4(key, db_page1):
            saved = (
                save_cached_wechat_key_for_account(key, account_id, Path(db_path))
                if account_id and db_path
                else save_cached_wechat_key(key)
            )
            if saved:
                logger.info("Weixin master key extracted from memory and cached")
        return key
    # DEBUG not WARN — initialize batch-tries pids; per-pid failure is normal.
    logger.debug("Key extraction failed for this pid/db combination")
    return None


# ─── Database decryption ──────────────────────────────────────────────────────

def _decrypt_db_v4(db_path: Path, enc_key: bytes, output_path: Path) -> bool:
    """Snapshot the live DB family, then decrypt main DB and committed WAL."""
    from chatlog_keeper.core._snapshot import snapshot_db_family

    try:
        with snapshot_db_family(db_path) as snapshot:
            return _decrypt_db_v4_snapshot(snapshot, enc_key, output_path)
    except OSError as exc:
        logger.warning("Could not snapshot %s: %s", Path(db_path).name, exc)
        return False


def _decrypt_db_v4_snapshot(db_path: Path, enc_key: bytes, output_path: Path) -> bool:
    """
    Decrypt a Weixin 4.x SQLCipher DB to plain SQLite.

    Page layout (4096 bytes):
      Page 1:  [salt(16)] [AES-CBC encrypted plaintext[16:4016](4000B)] [IV(16)] [HMAC(64)]
      Page N:  [AES-CBC encrypted plaintext[0:4016](4016B)]             [IV(16)] [HMAC(64)]

    enc_key is used directly as the AES key (raw-key mode, no PBKDF2).
    """
    PAGE_SZ = 4096

    temporary_output: Optional[Path] = None
    try:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=str(output_path.parent),
        )
        os.close(fd)
        temporary_output = Path(temporary_name)
        # Decrypt page-by-page so peak memory stays at a single 4 KB page.
        # Reading the whole DB into memory at once can exhaust RAM (same
        # streaming approach as qq_db).
        pages = 0
        with open(db_path, "rb") as f, open(temporary_output, "wb") as out:
            first = f.read(PAGE_SZ)
            if len(first) < PAGE_SZ:
                logger.warning(f"DB too small to decrypt: {db_path.name}")
                return False
            # Derive the actual AES page key from page-1 salt (handles 4.1.10.31 password
            # mode where enc_key is the master key needing PBKDF2-256000; raw-key for older).
            page_key = _effective_page_key(enc_key, first)
            if page_key is None:
                logger.warning(f"Decryption: enc_key does not fit {db_path.name} (page-1 HMAC fail)")
                return False
            # Authenticate every main page before publishing any plaintext.
            plain = _decrypt_wechat_page(first, page_key, first[:16], 1)
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
                plain = _decrypt_wechat_page(
                    page,
                    page_key,
                    first[:16],
                    page_no,
                )
                if plain is None:
                    raise OSError(f"page {page_no} authentication failed")
                out.write(plain)
                pages += 1

        wal_frames = _apply_wechat_wal(
            db_path.with_name(db_path.name + "-wal"),
            page_key,
            first[:16],
            temporary_output,
        )
        os.replace(temporary_output, output_path)
        temporary_output = None
        logger.info(
            "Decrypted %d main pages + %d committed WAL frames (streaming) → %s",
            pages,
            wal_frames,
            output_path,
        )
        return True
    except Exception as e:
        logger.warning(f"Decryption failed for {db_path.name}: {e}")
        return False
    finally:
        if temporary_output is not None:
            try:
                temporary_output.unlink(missing_ok=True)
            except OSError:
                pass


def _decrypt_wechat_page(
    page: bytes,
    page_key: bytes,
    salt: bytes,
    page_no: int,
) -> Optional[bytes]:
    """HMAC-verify and decrypt one SQLCipher-4 main/WAL page image."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            return None
    page_size = 4096
    reserve = 80
    if len(page) != page_size or page_no <= 0:
        return None
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", page_key, mac_salt, 2, dklen=32)
    prefix = 16 if page_no == 1 else 0
    hm = hmac_mod.new(mac_key, page[prefix: page_size - 64], hashlib.sha512)
    hm.update(struct.pack("<I", page_no))
    if not hmac_mod.compare_digest(hm.digest(), page[page_size - 64:]):
        return None
    iv = page[page_size - reserve: page_size - 64]
    body = AES.new(page_key, AES.MODE_CBC, iv).decrypt(
        page[prefix: page_size - reserve]
    )
    if page_no == 1:
        return b"SQLite format 3\x00" + body + page[page_size - reserve:]
    return body + page[page_size - reserve:]


def _decrypt_wal_page(page: bytes, page_key: bytes, salt: bytes, page_no: int) -> Optional[bytes]:
    """Backward-compatible wrapper for one authenticated SQLCipher WAL page."""
    return _decrypt_wechat_page(page, page_key, salt, page_no)


def _apply_wechat_wal(
    wal_path: Path,
    page_key: bytes,
    salt: bytes,
    output_path: Path,
) -> int:
    """Apply authenticated frames, rebuilding only a stale copied WAL index.

    A live WeChat snapshot can contain a stable but obsolete ``-shm`` cache
    beside a newer WAL generation.  If indexed inspection fails, or a WAL-only
    scan proves a later complete commit, recover exactly as SQLite does without
    ``-shm``: require a valid header, salts, cumulative frame checksums, and a
    last complete commit.  WAL corruption and SQLCipher page-HMAC failures
    remain fail-closed.
    """
    from chatlog_keeper.core import _wal

    shm_path = wal_path.with_name(
        wal_path.name[:-4] + "-shm"
        if wal_path.name.endswith("-wal")
        else wal_path.name + "-shm"
    )
    decrypt_page = lambda page, page_no: _decrypt_wal_page(
        page, page_key, salt, page_no
    )
    try:
        indexed_plan = _wal.inspect_wal(
            wal_path,
            shm_path=shm_path,
            expected_page_size=4096,
        )
    except _wal.WalIndexValidationError:
        return _wal._apply_wal_without_index(
            wal_path,
            output_path,
            decrypt_page,
            expected_page_size=4096,
        )

    # A checksummed SHM header can still lag a newer complete WAL commit (for
    # example after a crash between the WAL fsync and WAL-index publication).
    # Only ignore that otherwise-valid index when a WAL-only checksum scan can
    # prove a strictly later complete commit.  Invalid or uncommitted tails do
    # not advance ``frames_to_apply`` and therefore remain ignored.
    if (
        indexed_plan.used_shm
        and indexed_plan.physical_frames > indexed_plan.frames_to_apply
    ):
        recovered_plan = _wal._inspect_wal_without_index(
            wal_path,
            expected_page_size=4096,
        )
        if recovered_plan.frames_to_apply > indexed_plan.frames_to_apply:
            return _wal._apply_wal_without_index(
                wal_path,
                output_path,
                decrypt_page,
                expected_page_size=4096,
            )

    return _wal.apply_wal(
        wal_path,
        output_path,
        decrypt_page,
        shm_path=shm_path,
        expected_page_size=4096,
    )


# ─── Message reading ──────────────────────────────────────────────────────────

def _decompress_message(data) -> str:
    """
    Decompress a message that may be zstd-compressed.
    Weixin 4.x stores some message_content as zstd bytes (magic: 0x28 0xB5 0x2F 0xFD).
    """
    if not data:
        return ""
    if isinstance(data, bytes):
        if data[:4] == b"\x28\xb5\x2f\xfd":
            try:
                import zstandard as zstd
                cctx = zstd.ZstdDecompressor()
                return cctx.decompress(data).decode("utf-8", errors="replace")
            except Exception:
                return data.decode("utf-8", errors="replace")
        return data.decode("utf-8", errors="replace")
    return str(data)


# ─── WeChat 4.x rich-content extraction ────────────────────────────────────────
# Live-decoded message_content sample inventory:
#   type=1     plain text                    handled by _decompress_message
#   type=3     <msg><img aeskey=...>          [图片]
#   type=43    <msg><videomsg playlength=N>  [视频 Ns]
#   type=47    <msg><emoji md5=... len=N>    [表情]
#   type=49    <msg><appmsg type=N>...        sub-type dispatch
#   type=10000 plain UTF-8 system notice      raw text
# Keeping only type=1 dropped 30-50% of messages → narrative quality degraded,
# so the other text-bearing types are handled below.

# Plain text type
_WX_MSG_TYPE_TEXT = 1
_WX_MSG_TYPE_IMAGE = 3
_WX_MSG_TYPE_VOICE = 34       # voice
_WX_MSG_TYPE_BUSINESS_CARD = 42  # 名片
_WX_MSG_TYPE_VIDEO = 43
_WX_MSG_TYPE_EMOJI = 47
_WX_MSG_TYPE_LOCATION = 48    # 位置
_WX_MSG_TYPE_APPMSG = 49
_WX_MSG_TYPE_VOIP = 50        # 语音/视频通话
_WX_MSG_TYPE_SYSTEM = 10000

# WeChat appmsg sub-types (the <appmsg type=N> integer)
_WX_APPMSG_TEXT_LINK = 1     # legacy text-link
_WX_APPMSG_IMAGE = 2
_WX_APPMSG_VOICE = 3
_WX_APPMSG_VIDEO = 4
_WX_APPMSG_LINK = 5          # 网页链接卡片
_WX_APPMSG_FILE = 6          # 文件
_WX_APPMSG_LOCATION = 17
_WX_APPMSG_MERGED_FORWARD = 19  # 合并转发
_WX_APPMSG_MINIPROGRAM = 33  # 小程序
_WX_APPMSG_VIDEOACCT = 35    # 视频号
_WX_APPMSG_REFERMSG = 57     # 引用消息 (回复)
_WX_APPMSG_TRANSFER = 2000   # 转账
_WX_APPMSG_REDPACKET = 2001  # 红包
# Wechat extends appmsg type to ~1000s; we cover the high-frequency ones and
# fall back to a generic [卡片 type=N: <title>] for the rest.


def _parse_xml_strict(xml_str: str):
    """Try to parse an XML string into an ElementTree. Returns None on failure.

    WeChat XML occasionally has stray characters / no XML declaration / ampersands
    in URLs. We try defusedxml → stdlib → None.
    """
    if not xml_str:
        return None
    s = xml_str.strip()
    if not s.startswith("<"):
        return None
    try:
        import xml.etree.ElementTree as ET
        return ET.fromstring(s)
    except Exception:
        # Common breakage: lone & in URLs — patch & try once.
        try:
            import xml.etree.ElementTree as ET
            patched = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;|#\d+;)", "&amp;", s)
            return ET.fromstring(patched)
        except Exception:
            return None


def _xml_findtext(elem, path, default=""):
    """Find text at path; empty string fallback. Defensive against None elem."""
    if elem is None:
        return default
    try:
        node = elem.find(path)
        if node is None or node.text is None:
            return default
        return node.text.strip()[:200]
    except Exception:
        return default


def _xml_findattr(elem, path, attr, default=""):
    """Find attribute value at path; defensive."""
    if elem is None:
        return default
    try:
        node = elem.find(path)
        if node is None:
            return default
        return (node.get(attr) or default).strip()[:120]
    except Exception:
        return default


def _extract_appmsg(root, app_sub_type: int) -> str:
    """Extract one <appmsg> node's human-readable summary based on sub-type.

    Returns a string like '[引用 张三: 内容] 我的回复' or '[文件: 报告.pdf]'.

    Deep enrichment:
    - REFERMSG (57): recursively parse refermsg.content if it's image/video XML
    - LINK (5): include des + sourcedisplayname + truncated url
    - MERGED_FORWARD (19): expand recorditem into nested narrative
    """
    appmsg = root.find("appmsg")
    if appmsg is None:
        return ""
    title = _xml_findtext(appmsg, "title")
    if app_sub_type == _WX_APPMSG_REFERMSG:
        return _format_refermsg(appmsg, title)
    if app_sub_type == _WX_APPMSG_TRANSFER:
        return "[转账]"
    if app_sub_type == _WX_APPMSG_REDPACKET:
        return "[红包]"
    if app_sub_type == _WX_APPMSG_FILE:
        # 加 md5+size 锚点供 doc card 反向检索命中
        appattach = appmsg.find("appattach")
        bits = [title or "?"]
        if appattach is not None:
            md5 = (_xml_findtext(appattach, "md5") or "")[:12]
            if md5:
                bits.append(f"md5:{md5}")
            try:
                size_b = int(_xml_findtext(appattach, "totallen") or 0)
                if size_b >= 102400:  # ≥100KB
                    bits.append(f"{size_b / 1_048_576:.1f}MB")
            except (ValueError, TypeError):
                pass
        return f"[文件: {' | '.join(bits)}]"
    if app_sub_type == _WX_APPMSG_LINK or app_sub_type == _WX_APPMSG_TEXT_LINK:
        return _format_link_card(appmsg, title)
    if app_sub_type == _WX_APPMSG_MINIPROGRAM:
        sourcename = _xml_findtext(appmsg, "sourcedisplayname") or _xml_findtext(appmsg, "weappinfo/appname")
        if title and sourcename:
            return f"[小程序 {sourcename}: {title}]"
        return f"[小程序: {title}]" if title else "[小程序]"
    if app_sub_type == _WX_APPMSG_VIDEOACCT:
        return f"[视频号: {title}]" if title else "[视频号]"
    if app_sub_type == _WX_APPMSG_MERGED_FORWARD:
        return _format_merged_forward(appmsg, title)
    if app_sub_type == _WX_APPMSG_LOCATION:
        return f"[位置: {title}]" if title else "[位置]"
    if app_sub_type == _WX_APPMSG_VOICE:
        return f"[语音: {title}]" if title else "[语音]"
    if app_sub_type == _WX_APPMSG_VIDEO:
        return f"[视频: {title}]" if title else "[视频]"
    if app_sub_type == _WX_APPMSG_IMAGE:
        return f"[图片: {title}]" if title else "[图片]"
    # Unknown sub-type: keep title with type hint so reviewer can debug
    return f"[卡片 type={app_sub_type}: {title}]" if title else f"[卡片 type={app_sub_type}]"


def _format_link_card(appmsg, title: str) -> str:
    """Format AppMsg sub_type=5 (link card) with des + url + source + body.

    Emits:
      1. Always: title + des + source publisher + url host
      2. If the link is mp.weixin.qq.com (公众号 article) AND we have a cached
         fetch result, inject the author + the first chars of the article body.
    Thumb is CDN-only — vision not feasible.
    """
    des = _xml_findtext(appmsg, "des")
    sourcename = (_xml_findtext(appmsg, "sourcedisplayname")
                  or _xml_findtext(appmsg, "appinfo/appname"))
    url_full = appmsg.findtext("url", "") or ""
    url_full = url_full.strip()
    url = url_full[:120]
    parts = ["[链接"]
    if sourcename:
        parts.append(f"|{sourcename}")
    # URL sha anchor — 8 char hex prefix. Lets the article doc card
    # (data/wechat_article_docs/<sha>.md → linked_from_chat.url_sha) match
    # both ways. The cache JSON and the doc card share the same sha.
    url_sha_short = ""
    if url_full:
        import hashlib as _hash
        url_sha_short = _hash.sha256(
            url_full.encode("utf-8", errors="replace")
        ).hexdigest()[:8]
        parts.append(f"|sha:{url_sha_short}")
    parts.append("]")
    if title:
        parts.append(f" {title}")
    if des and des != title:
        parts.append(f" — {des[:150]}")
    if url:
        import re as _re
        m = _re.match(r"https?://([^/]+)", url)
        host = m.group(1) if m else url[:40]
        parts.append(f" ({host})")
    # Article body inject (cache-only — never block on HTTP); expand inline up
    # to ~1200 chars for richer recall.
    if url_full and "mp.weixin.qq.com/s/" in url_full:
        try:
            from chatlog_keeper.wechat_link_fetcher import (
                load_cached, format_article_for_narrative,
            )
            cached = load_cached(url_full)
            if cached and cached.get("ok") and cached.get("body"):
                summary = format_article_for_narrative(cached, max_chars=1200)
                if summary:
                    parts.append(f" ⏵ {summary}")
        except Exception:
            pass  # fetch infra broken; fall back to metadata-only
    return "".join(parts).strip()


def _format_refermsg(appmsg, title: str) -> str:
    """Format AppMsg sub_type=57 (quote/reply) with recursive content resolve.

    If refermsg.content is itself XML (image/video/sticker), recursively
    extract its narrative. The original msg_type is stored in `refermsg/type`.
    """
    refer = appmsg.find("refermsg")
    if refer is None:
        return f"[引用] {title}".strip() if title else "[引用]"
    quoted_name = (_xml_findtext(refer, "displayname")
                   or _xml_findtext(refer, "fromusr"))
    quoted_raw = _xml_findtext(refer, "content")
    orig_type_str = _xml_findtext(refer, "type")
    try:
        orig_type = int(orig_type_str) if orig_type_str else 0
    except ValueError:
        orig_type = 0

    # If quoted content is XML (image/video/sticker/appmsg), recurse via
    # _extract_wechat_xml to get rich narrative
    quoted_narrative = quoted_raw
    if quoted_raw and quoted_raw.lstrip().startswith("<"):
        try:
            inner = _extract_wechat_xml(quoted_raw, orig_type)
            if inner:
                quoted_narrative = inner
        except Exception:
            pass  # fall back to raw

    quoted_short = (quoted_narrative or "")[:120]
    if quoted_short:
        prefix = (f"[引用 {quoted_name}: {quoted_short}]"
                  if quoted_name else f"[引用: {quoted_short}]")
    else:
        prefix = f"[引用 {quoted_name}]" if quoted_name else "[引用]"
    # refermsg/svrid + createtime → ↳svrid:NNNN @date anchor so a quote-trace
    # recall can match back to the original msg card.
    ref_svrid_full = _xml_findtext(refer, "svrid") or ""
    ref_svrid = ref_svrid_full[-6:] if ref_svrid_full else ""
    ref_ct = _xml_findtext(refer, "createtime") or ""
    ts_iso = ""
    if ref_ct and ref_ct.isdigit():
        try:
            ts_iso = datetime.fromtimestamp(
                int(ref_ct), tz=timezone.utc
            ).strftime("@%Y-%m-%d")
        except (ValueError, OSError):
            pass
    anchor_bits = []
    if ref_svrid:
        anchor_bits.append(f"↳svrid:{ref_svrid}")
    if ts_iso:
        anchor_bits.append(ts_iso)
    anchor = (" " + " ".join(anchor_bits)) if anchor_bits else ""
    if title and title != quoted_short:
        return f"{prefix}{anchor} {title}".strip()
    return prefix + anchor


def _format_merged_forward(appmsg, title: str) -> str:
    """Format AppMsg sub_type=19 (merged forward / 合并转发).

    Parse recorditem (which may be raw XML or CDATA-wrapped) and inline each
    forwarded dataitem with `<sourcename>` + `<datadesc>`. Keeps the total under
    500 chars for token budget (a mergedmsg can be hundreds of items in extreme
    cases).
    """
    head_title = title or "聊天记录"
    record_node = appmsg.find("recorditem")
    if record_node is None:
        return f"[合并转发: {head_title}]"
    # recorditem text may contain CDATA-wrapped <recordinfo>...</recordinfo>
    inner_text = (record_node.text or "").strip()
    if not inner_text:
        return f"[合并转发: {head_title}]"
    inner_root = _parse_xml_strict(inner_text)
    if inner_root is None:
        return f"[合并转发: {head_title}]"
    # Find all dataitem nodes (datalist > dataitem OR direct children)
    dataitems = inner_root.findall(".//dataitem")
    if not dataitems:
        return f"[合并转发: {head_title}]"
    parts = [f"[合并转发: {head_title} | {len(dataitems)}条]"]
    used_chars = len(parts[0])
    MAX_CHARS = 500
    n_shown = 0
    for di in dataitems:
        if used_chars >= MAX_CHARS:
            parts.append(f"…+{len(dataitems) - n_shown}条略")
            break
        sourcename = (di.get("sourcename") or _xml_findtext(di, "sourcename"))[:20]
        # datadesc is the body (text content). For non-text dataitems
        # (image=3, video=4, voice=8) the body is just a tag like "[图片]"
        body = (_xml_findtext(di, "datadesc")
                or _xml_findtext(di, "datatitle"))
        if not body:
            # Maybe it's an image — show as tag
            datatype = di.get("datatype") or ""
            body = {"3": "[图片]", "4": "[视频]", "8": "[语音]",
                    "5": "[链接]"}.get(datatype, "[消息]")
        body = body[:80]
        # dataitem svrid anchor (if the XML has it)
        di_svrid = (di.get("datasvrid") or di.get("svrid") or "")
        svrid_tag = f"#{di_svrid[-6:]}" if di_svrid else ""
        item_str = (f" {sourcename}{svrid_tag}: {body}"
                    if sourcename else f"{svrid_tag} {body}")
        used_chars += len(item_str)
        if used_chars > MAX_CHARS + 50:  # last item too long → truncate
            break
        parts.append(item_str)
        n_shown += 1
    return "".join(parts)


def _decode_sticker_desc(desc_b64: str) -> Optional[str]:
    """Decode WeChat sticker desc protobuf (zh_cn locale → human label).

    The `desc` attribute of <emoji> is base64-encoded protobuf with locale-
    keyed labels. Schema (manually reverse-engineered):
      message StickerDesc {
        repeated LocaleEntry entries = 1;
      }
      message LocaleEntry {
        string locale = 1;  // "zh_cn", "zh_tw", "default"
        string label  = 2;
      }
    Wire format observed: `0a <len> 0a <locale_len> <locale_bytes> 12 <label_len> <label_bytes>`
    Returns the zh_cn label if present, else first non-empty label, else None.
    """
    if not desc_b64:
        return None
    try:
        import base64
        data = base64.b64decode(desc_b64, validate=False)
    except Exception:
        return None
    # Parse minimal protobuf — just look for tag 0x0A (field 1, length-delim)
    out: dict[str, str] = {}
    i = 0
    n = len(data)
    while i < n:
        if data[i] != 0x0A:  # field 1, wire type 2
            i += 1
            continue
        i += 1
        if i >= n:
            break
        entry_len = data[i]
        i += 1
        if i + entry_len > n:
            break
        entry = data[i:i + entry_len]
        i += entry_len
        # entry: 0a <locale_len> <locale> 12 <label_len> <label>
        j = 0
        locale = ""
        label = ""
        if j < len(entry) and entry[j] == 0x0A:
            j += 1
            if j >= len(entry):
                continue
            ll = entry[j]
            j += 1
            locale = entry[j:j + ll].decode("utf-8", errors="replace")
            j += ll
        if j < len(entry) and entry[j] == 0x12:
            j += 1
            if j >= len(entry):
                continue
            ll = entry[j]
            j += 1
            label = entry[j:j + ll].decode("utf-8", errors="replace")
        if locale and label:
            out[locale] = label
    return out.get("zh_cn") or out.get("default") or next(iter(out.values()), None)


def _extract_wechat_xml(content: str, msg_type: int) -> str:
    """Extract human-readable text from WeChat 4.x non-text message_content.

    Returns "" for unrecognizable / empty bodies (caller treats as skip).
    For msg_type=10000 (system notice), content can be either:
      - plain UTF-8 text ("X 邀请 Y 加入了群聊")
      - XML <sysmsg type="revokemsg"><revokemsg><content>X 撤回了一条消息</content></revokemsg></sysmsg>
      - XML <sysmsg type="..."><...></sysmsg> for other system events

    Covers type=34 voice / 48 location / 50 voip / 42 business_card. Voice STT
    is deferred (the WeChat 4.x voice file is an AES-encrypted .dat in
    msg/attach/<chatroom_hash>/<YYYY-MM>/, needing a separate decryption step).
    Tag-only extraction here: `[语音 Ns]` from the voicemsg XML.
    """
    if not content:
        return ""
    if msg_type == _WX_MSG_TYPE_SYSTEM:
        s = content.strip()
        # XML system message — extract human-readable content
        if s.startswith("<"):
            sys_root = _parse_xml_strict(s)
            if sys_root is not None:
                # revoke: <sysmsg type="revokemsg"><revokemsg><content>...</content>
                rev = sys_root.find(".//revokemsg/content")
                if rev is not None and rev.text:
                    return f"[系统] {rev.text.strip()[:200]}"
                # generic sysmsg: try to find any leaf text
                for elem in sys_root.iter():
                    if elem.text and elem.text.strip() and elem.tag not in ("revoketime",):
                        return f"[系统] {elem.text.strip()[:200]}"
                return ""
            return ""
        return s[:500]
    root = _parse_xml_strict(content)
    if root is None:
        return ""
    if msg_type == _WX_MSG_TYPE_IMAGE:
        return "[图片]"
    if msg_type == _WX_MSG_TYPE_VOICE:
        # voice: the voicelength attr is in ms
        voicemsg = root.find("voicemsg")
        if voicemsg is not None:
            vl_ms_str = voicemsg.get("voicelength") or ""
            try:
                vl_ms = int(vl_ms_str)
                vl_s = max(1, vl_ms // 1000)
                # NOTE: STT is deferred — the WeChat 4.x voice file is
                # AES-encrypted in msg/attach/<chatroom_hash>/<YYYY-MM>/.dat
                # (using the aeskey from voicemsg XML), then silk-v3 → wav →
                # ASR. Tag only for now.
                return f"[语音 {vl_s}s]"
            except (ValueError, TypeError):
                pass
        return "[语音]"
    if msg_type == _WX_MSG_TYPE_VIDEO:
        videomsg = root.find("videomsg")
        playlen = ""
        if videomsg is not None:
            playlen = videomsg.get("playlength") or ""
        if playlen and playlen.isdigit():
            return f"[视频 {playlen}s]"
        return "[视频]"
    if msg_type == _WX_MSG_TYPE_EMOJI:
        # Decode the `desc` protobuf for a human label (zh_cn). Stickers are a
        # large fraction of wechat msgs, so rather than a bare `[表情]` we
        # extract the localized name from the <emoji desc="<b64-protobuf>">
        # attribute.
        emoji = root.find("emoji")
        if emoji is not None:
            desc_b64 = emoji.get("desc") or ""
            label = _decode_sticker_desc(desc_b64)
            if label:
                return f"[表情: {label}]"
            # Fall back to md5 prefix for dedup tracking
            md5 = (emoji.get("md5") or "")[:8]
            if md5:
                return f"[表情#{md5}]"
        return "[表情]"
    if msg_type == _WX_MSG_TYPE_LOCATION:
        # <location x="..." y="..." poiname="..." label="..." />
        loc = root.find("location")
        if loc is not None:
            poi = loc.get("poiname") or loc.get("label") or ""
            if poi:
                return f"[位置: {poi[:80]}]"
        return "[位置]"
    if msg_type == _WX_MSG_TYPE_BUSINESS_CARD:
        # Root attrs hold nickname / username — <msg username="..." nickname="..." />
        nick = root.get("nickname") or root.get("alias") or ""
        if nick:
            return f"[名片: {nick[:60]}]"
        return "[名片]"
    if msg_type == _WX_MSG_TYPE_VOIP:
        # <voipmsg><VoIPBubbleMsg><msg>X</msg></VoIPBubbleMsg></voipmsg>
        # or text fallback "通话已结束 / 已取消"
        for path in (".//VoIPBubbleMsg/msg", ".//invitemsg/content", ".//roomtype"):
            n = root.find(path)
            if n is not None and n.text:
                return f"[通话] {n.text.strip()[:80]}"
        return "[通话]"
    if msg_type == _WX_MSG_TYPE_APPMSG:
        appmsg = root.find("appmsg")
        sub_type = 0
        if appmsg is not None:
            sub_type_str = _xml_findtext(appmsg, "type")
            try:
                sub_type = int(sub_type_str) if sub_type_str else 0
            except (ValueError, TypeError):
                sub_type = 0
        return _extract_appmsg(root, sub_type)
    return ""


def _extract_file_md5_from_packed_info(packed_info_data: Optional[bytes]) -> str:
    """Parse wechat 4.x Msg row's packed_info_data BLOB → image .dat filename md5.

    wechat 4.x stores the local .dat filename stem (32-char lowercase hex md5)
    inside this protobuf BLOB. Format observed:
      b'\\x08\\x01\\x10\\x02\\x1a"" <32 hex chars>'
    First 32 lowercase-hex run in the BLOB is the filename md5. ~43% of
    image msgs have non-empty packed_info_data with this pattern.

    Returns lowercase 32-char md5 string, or empty string if absent / malformed.
    """
    if not packed_info_data:
        return ""
    try:
        import re as _re
        m = _re.search(rb'([0-9a-f]{32})', packed_info_data)
        return m.group(1).decode("ascii") if m else ""
    except Exception:
        return ""


def _extract_attachment_meta(content: str, msg_type: int) -> Optional[dict]:
    """Extract IM attachment metadata for chat→doc linkage.

    For msg_type=49 sub=6 (file): {filename, md5, total_bytes, fileext}
    For msg_type=49 sub=2 (image card): {filename, md5}
    For msg_type=34 (voice): {voice_length_ms, aeskey, voiceformat}
      NOTE: WeChat 4.x voice files are CDN-only (no local cache after the
      client's short replay window). STT is architecturally infeasible
      from the PC side. We surface aeskey + voicelength so when/if WeChat
      changes to local caching, the metadata is already ready.
    For msg_type=3 (image): {aeskey, md5, encryver, length}
      Image .dat files in msg/attach/<chatroom>/<YYYY-MM>/Img/ can be
      OCR'd (V1 XOR shipped, V2 AES stub). See wechat_image.py.
    Returns None if not applicable.
    """
    if not content or msg_type not in (_WX_MSG_TYPE_VOICE, _WX_MSG_TYPE_APPMSG,
                                        _WX_MSG_TYPE_IMAGE, _WX_MSG_TYPE_VIDEO):
        return None
    root = _parse_xml_strict(content)
    if root is None:
        return None
    if msg_type == _WX_MSG_TYPE_VOICE:
        voicemsg = root.find("voicemsg")
        if voicemsg is None:
            return None
        return {
            "kind": "voice",
            "voice_length_ms": int(voicemsg.get("voicelength") or 0),
            "aeskey": (voicemsg.get("aeskey") or "")[:64],
            "voiceformat": voicemsg.get("voiceformat") or "",
            # CDN-only architecture; STT defer to upstream change
            "stt_status": "cdn_only_no_local_cache",
        }
    if msg_type == _WX_MSG_TYPE_IMAGE:
        img = root.find("img")
        if img is None:
            return None
        # NOTE: file_md5 (the local .dat filename stem) is populated by
        # the row-level extractor — wechat 4.x stores it in the row's
        # packed_info_data BLOB column, NOT in the message XML. The caller
        # (_query_messages_*) merges packed_info_data extraction into att_meta.
        return {
            "kind": "image",
            "aeskey": (img.get("aeskey") or "")[:64],
            "md5": (img.get("md5") or "")[:64],   # legacy: XML img md5 (content)
            "encryver": img.get("encryver") or "",
            "length": int(img.get("length") or 0),
            "ocr_status": "pending",  # picked up by wechat_image_ocr_worker
        }
    if msg_type == _WX_MSG_TYPE_VIDEO:
        # VIDEO attachment_meta for a downstream vision lookup.
        # <videomsg md5="..." length=N playlength=N aeskey=...>
        # File lands at msg/video/<YYYY-MM>/<md5>.mp4 + <md5>_thumb.jpg.
        # A vision worker can write per-video narrative keyed by f"{month}/{md5}".
        videomsg = root.find("videomsg")
        if videomsg is None:
            return None
        # Parse ints defensively
        def _safe_int(v):
            try:
                return int(v or 0)
            except (TypeError, ValueError):
                return 0
        return {
            "kind": "video",
            "md5": (videomsg.get("md5") or "").lower()[:64],
            "length": _safe_int(videomsg.get("length")),
            "playlength": _safe_int(videomsg.get("playlength")),
            "cdnthumblength": _safe_int(videomsg.get("cdnthumblength")),
            "aeskey": (videomsg.get("aeskey") or "")[:64],
            "cdnthumbwidth": _safe_int(videomsg.get("cdnthumbwidth")),
            "cdnthumbheight": _safe_int(videomsg.get("cdnthumbheight")),
            "vision_status": "pending",  # picked up by wechat_video_vision_worker
        }
    appmsg = root.find("appmsg")
    if appmsg is None:
        return None
    sub_str = _xml_findtext(appmsg, "type")
    try:
        sub = int(sub_str) if sub_str else 0
    except (ValueError, TypeError):
        sub = 0
    if sub == 6:  # file
        appattach = appmsg.find("appattach")
        if appattach is None:
            return None
        return {
            "kind": "file",
            "filename": _xml_findtext(appmsg, "title"),
            "md5": _xml_findtext(appattach, "md5"),
            "total_bytes": int(_xml_findtext(appattach, "totallen") or 0),
            "fileext": _xml_findtext(appattach, "fileext"),
        }
    return None


# Set of types we keep (extract a useful narrative-facing string for).
# Order doesn't matter; this is checked via `in`.
# Covers text/image/voice/video/emoji/location/appmsg/voip/businesscard/system.
_WX_KEPT_TYPES = {
    _WX_MSG_TYPE_TEXT,
    _WX_MSG_TYPE_IMAGE,
    _WX_MSG_TYPE_VOICE,
    _WX_MSG_TYPE_BUSINESS_CARD,
    _WX_MSG_TYPE_VIDEO,
    _WX_MSG_TYPE_EMOJI,
    _WX_MSG_TYPE_LOCATION,
    _WX_MSG_TYPE_APPMSG,
    _WX_MSG_TYPE_VOIP,
    _WX_MSG_TYPE_SYSTEM,
}


def _load_name_map(conn) -> dict:
    """
    Build a dict mapping real_sender_id → wxid/username from Name2Id table.
    Name2Id rowid corresponds to real_sender_id in message rows.
    """
    name_map = {}
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT rowid, user_name FROM Name2Id")
        for rowid, user_name in cursor.fetchall():
            name_map[rowid] = user_name or str(rowid)
    except Exception:
        pass
    return name_map


def _table_name_to_wxid(table_name: str, name_map: dict) -> str:
    """
    Reverse-map a Msg_<md5> table name to the corresponding wxid.
    Looks up the md5 hash against all known wxids.
    """
    import hashlib
    suffix = table_name[4:]  # remove "Msg_" prefix
    for wxid in name_map.values():
        if wxid and hashlib.md5(wxid.encode()).hexdigest() == suffix:
            return wxid
    return suffix[:8] + "..."


def _wechat_conversation_table_name(conversation_id: str) -> str:
    """Return the exact WeChat message table for one native conversation."""

    if (
        not isinstance(conversation_id, str)
        or not conversation_id
        or "\x00" in conversation_id
        or len(conversation_id) > 512
    ):
        raise ValueError("WeChat conversation_id is invalid")
    digest = hashlib.md5(conversation_id.encode("utf-8")).hexdigest()
    return f"Msg_{digest}"


def _wechat_message_shard_id(database: Path, *, root: Optional[Path]) -> str:
    """Build a stable opaque shard ID from a path relative to the account root."""

    path = Path(database)
    if root is not None:
        try:
            value = path.relative_to(Path(root)).as_posix()
        except ValueError:
            value = path.name
    else:
        value = path.name
    return hashlib.sha256(value.casefold().encode("utf-8")).hexdigest()[:24]


def _wechat_shard_bound_sender_id(shard_id: str, sender_id: Any) -> str:
    """Bind a shard-local ``Name2Id.rowid`` to its stable opaque shard.

    ``Name2Id.rowid`` has no account-wide meaning: the same integer can name
    different people in different message databases.  A missing/empty mapping
    must therefore never be exposed as a bare numeric participant ID.
    """

    if not isinstance(shard_id, str) or not _WECHAT_MESSAGE_SHARD_ID_RE.fullmatch(
        shard_id
    ):
        raise ValueError("WeChat message page shard is invalid")
    if isinstance(sender_id, bool):
        raise ValueError("WeChat sender identity is invalid")
    normalized = str(sender_id).strip()
    if not normalized or not normalized.isascii() or not normalized.isdecimal():
        raise ValueError("WeChat sender identity is invalid")
    value = f"wechat_sender:{shard_id}:{normalized}"
    if len(value) > 512 or any(ord(character) < 32 for character in value):
        raise ValueError("WeChat sender identity is invalid")
    return value


def _wechat_message_topology(shard_ids) -> str:
    """Fingerprint the readable shard set without retaining database paths."""

    normalized = tuple(sorted(str(value) for value in shard_ids))
    if len(normalized) != len(set(normalized)):
        raise ValueError("WeChat readable database shards are ambiguous")
    material = "\x00".join(normalized).encode("ascii")
    return hashlib.sha256(material).hexdigest()[:24]


def _wechat_message_page_scope(
    *,
    account_id: str,
    conversation_id: str,
    since_ts: int,
    until_ts: Optional[int],
) -> str:
    """Hash the immutable account/conversation/window part of a page request."""

    material = json.dumps(
        {
            "account_id": str(account_id or ""),
            "conversation_table": _wechat_conversation_table_name(conversation_id),
            "since_ts": since_ts,
            "until_ts": until_ts,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:24]


def _wechat_page_cancel_requested(
    cancel_requested: Optional[Callable[[], bool]],
) -> bool:
    """Read a best-effort cancellation callback without treating errors as cancel."""

    if cancel_requested is None:
        return False
    try:
        return bool(cancel_requested())
    except Exception:
        return False


def _raise_if_wechat_page_cancelled(
    cancel_requested: Optional[Callable[[], bool]],
) -> None:
    if _wechat_page_cancel_requested(cancel_requested):
        raise WeChatMessagePageCancelled("WeChat message page read cancelled")


def _validated_wechat_page_time(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"WeChat message page {field} is invalid")
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"WeChat message page {field} is invalid") from exc
    if not math.isfinite(numeric):
        raise ValueError(f"WeChat message page {field} is invalid")
    return int(numeric)


def _validated_wechat_page_size(value: Any, *, query_limit: bool = False) -> int:
    maximum = _WECHAT_MESSAGE_PAGE_MAX_ROWS + (1 if query_limit else 0)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError("WeChat message page_size is invalid")
    return value


def _load_sender_names_for_ids(
    conn,
    sender_ids,
    *,
    cancel_requested: Optional[Callable[[], bool]] = None,
) -> dict:
    """Read only sender names referenced by one bounded raw page."""

    normalized = sorted(
        {
            int(value)
            for value in sender_ids
            if isinstance(value, int) and not isinstance(value, bool)
        }
    )
    names = {}
    # Stay below conservative SQLite variable limits even at the 1000-row page cap.
    for start in range(0, len(normalized), 400):
        _raise_if_wechat_page_cancelled(cancel_requested)
        chunk = normalized[start:start + 400]
        if not chunk:
            continue
        placeholders = ",".join("?" for _ in chunk)
        try:
            rows = conn.execute(
                f"SELECT rowid, user_name FROM Name2Id "
                f"WHERE rowid IN ({placeholders}) LIMIT ?",
                [*chunk, len(chunk)],
            ).fetchall()
        except Exception:
            continue
        for row_id, user_name in rows:
            normalized = str(user_name or "").strip()
            if normalized:
                names[int(row_id)] = normalized
    return names


def _query_conversation_page_rows(
    conn,
    *,
    conversation_id: str,
    since_ts: float,
    until_ts: Optional[float],
    position: Optional[Tuple[int, int]],
    limit: int,
    shard_id: str,
    cancel_requested: Optional[Callable[[], bool]] = None,
) -> list:
    """Read one exact conversation with SQL keyset bounds and a hard LIMIT."""

    import sqlite3

    table = _wechat_conversation_table_name(conversation_id)
    if not isinstance(shard_id, str) or not _WECHAT_MESSAGE_SHARD_ID_RE.fullmatch(
        shard_id
    ):
        raise ValueError("WeChat message page shard is invalid")
    row_limit = _validated_wechat_page_size(limit, query_limit=True)
    since = _validated_wechat_page_time(since_ts, field="since_ts")
    until = (
        _validated_wechat_page_time(until_ts, field="until_ts")
        if until_ts is not None
        else None
    )
    if until is not None and until < since:
        return []
    keyset = None
    if position is not None:
        if (
            not isinstance(position, tuple)
            or len(position) != 2
            or isinstance(position[0], bool)
            or not isinstance(position[0], int)
            or isinstance(position[1], bool)
            or not isinstance(position[1], int)
            or position[1] < 0
        ):
            raise ValueError("WeChat message page cursor position is invalid")
        keyset = position

    _raise_if_wechat_page_cancelled(cancel_requested)
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (table,),
    ).fetchone()
    if exists is None:
        return []

    predicates = ["create_time > ?"]
    parameters = [since]
    if until is not None:
        predicates.append("create_time <= ?")
        parameters.append(until)
    if keyset is not None:
        predicates.append("(create_time > ? OR (create_time = ? AND rowid > ?))")
        parameters.extend([keyset[0], keyset[0], keyset[1]])
    parameters.append(row_limit)
    statement = (
        "SELECT rowid, local_type, create_time, real_sender_id, message_content, "
        f'server_id, packed_info_data FROM "{table}" WHERE '
        + " AND ".join(predicates)
        + " ORDER BY create_time ASC, rowid ASC LIMIT ?"
    )

    progress_handler_installed = False
    cancelled_during_query = False

    def _progress_handler() -> int:
        nonlocal cancelled_during_query
        cancelled_during_query = _wechat_page_cancel_requested(cancel_requested)
        return 1 if cancelled_during_query else 0

    if cancel_requested is not None and hasattr(conn, "set_progress_handler"):
        conn.set_progress_handler(_progress_handler, 1000)
        progress_handler_installed = True
    try:
        raw_rows = conn.execute(statement, parameters).fetchall()
    except sqlite3.OperationalError:
        if cancelled_during_query or _wechat_page_cancel_requested(cancel_requested):
            raise WeChatMessagePageCancelled(
                "WeChat message page read cancelled"
            ) from None
        raise
    finally:
        if progress_handler_installed:
            conn.set_progress_handler(None, 0)
    _raise_if_wechat_page_cancelled(cancel_requested)

    sender_names = _load_sender_names_for_ids(
        conn,
        (row[3] for row in raw_rows),
        cancel_requested=cancel_requested,
    )
    rows = []
    for row in raw_rows:
        row_id, local_type, create_time, sender_id, content, server_id, packed = row
        sender = sender_names.get(sender_id)
        if sender is None:
            sender = _wechat_shard_bound_sender_id(shard_id, sender_id)
        rows.append(
            _WeChatConversationPageRow(
                shard_id=shard_id,
                row_id=int(row_id),
                create_time=int(create_time or 0),
                msg_type=int(local_type or 0) & 0xFFFF,
                sender=sender,
                message_content=content,
                server_id=(
                    str(server_id) if server_id not in (None, 0, "") else ""
                ),
                packed_info_data=packed,
            )
        )
    return rows


def _wechat_message_from_page_row(
    row: _WeChatConversationPageRow,
    *,
    conversation_id: str,
) -> Optional[WxMessage]:
    """Apply the legacy content normalization to one bounded database row."""

    if row.msg_type not in _WX_KEPT_TYPES:
        return None
    raw = _decompress_message(row.message_content)
    if row.msg_type == _WX_MSG_TYPE_TEXT:
        first_line = raw.split("\n")[0].strip().rstrip(":")
        content = (
            raw.split("\n", 1)[1]
            if "\n" in raw and first_line == row.sender
            else raw
        ).strip()
        attachment_meta = None
    else:
        content = _extract_wechat_xml(raw, row.msg_type).strip()
        attachment_meta = _extract_attachment_meta(raw, row.msg_type)
        if attachment_meta and attachment_meta.get("kind") == "image":
            file_md5 = _extract_file_md5_from_packed_info(row.packed_info_data)
            if file_md5:
                attachment_meta["file_md5"] = file_md5
    if not content:
        return None
    return WxMessage(
        timestamp=datetime.fromtimestamp(row.create_time),
        sender=row.sender,
        content=content,
        chat_name=conversation_id,
        msg_type=row.msg_type,
        attachment_meta=attachment_meta,
        server_id=row.server_id,
    )


def _query_messages_by_date(conn, target_date: date, name_map: dict) -> list:
    """
    Query all Msg_* tables for messages on target_date.
    Returns list of WxMessage objects sorted by timestamp.
    """
    import sqlite3
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
    )
    tables = [r[0] for r in cursor.fetchall()]

    day_start = datetime(target_date.year, target_date.month, target_date.day, 0, 0, 0)
    day_end = day_start + timedelta(days=1)
    ts_start = int(day_start.timestamp())
    ts_end = int(day_end.timestamp())

    messages = []
    for tbl in tables:
        try:
            cursor.execute(
                f"SELECT local_type, create_time, real_sender_id, message_content, "
                f"server_id, packed_info_data "
                f"FROM {tbl} WHERE create_time >= ? AND create_time < ? ORDER BY create_time",
                (ts_start, ts_end)
            )
            rows = cursor.fetchall()
        except Exception as e:
            logger.debug(f"Query error in {tbl}: {e}")
            continue

        if not rows:
            continue

        chat_name = _table_name_to_wxid(tbl, name_map)

        for row in rows:
            msg_type_raw = row[0]
            msg_type = int(msg_type_raw) & 0xFFFF
            if msg_type not in _WX_KEPT_TYPES:
                continue

            create_time = row[1]
            real_sender_id = row[2]
            message_content = row[3]
            server_id_raw = row[4] if len(row) > 4 else None
            packed = row[5] if len(row) > 5 else None

            ts = int(create_time) if create_time else ts_start
            dt = datetime.fromtimestamp(ts)
            sender_wxid = name_map.get(real_sender_id, str(real_sender_id))
            raw = _decompress_message(message_content)

            if msg_type == _WX_MSG_TYPE_TEXT:
                # Group msgs may start "sender_wxid:\n<content>" — strip prefix
                first_line = raw.split("\n")[0].strip().rstrip(":")
                content = (raw.split("\n", 1)[1]
                           if ("\n" in raw and first_line == sender_wxid)
                           else raw)
                content = content.strip()
                att_meta = None
            else:
                content = _extract_wechat_xml(raw, msg_type).strip()
                att_meta = _extract_attachment_meta(raw, msg_type)
                # enrich image att with file_md5 from packed_info_data
                if att_meta and att_meta.get("kind") == "image":
                    fm = _extract_file_md5_from_packed_info(packed)
                    if fm:
                        att_meta["file_md5"] = fm

            if not content:
                continue

            # surface server_id as a string for the narrative anchor
            sv_id = str(server_id_raw) if server_id_raw not in (None, 0, "") else ""
            messages.append(WxMessage(
                timestamp=dt,
                sender=sender_wxid,
                content=content,
                chat_name=chat_name,
                msg_type=msg_type,
                attachment_meta=att_meta,
                server_id=sv_id,
            ))

    messages.sort(key=lambda m: m.timestamp)
    return messages


def _query_messages_since_inner(conn, since_ts: float, name_map: dict, chat_name: Optional[str] = None, until_ts: Optional[float] = None) -> list:
    """Query all Msg_* tables for messages with create_time > since_ts.

    If until_ts is given, also bounds create_time <= until_ts (window query) so a
    backfill tick reads only its [since, until] slice instead of [since, now] —
    prevents loading the entire history into memory (OOM root cause).

    Returns: List[WxMessage] sorted by timestamp asc.
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
    )
    tables = [r[0] for r in cursor.fetchall()]

    messages = []
    for tbl in tables:
        tbl_chat = _table_name_to_wxid(tbl, name_map)
        if chat_name is not None and chat_name not in tbl_chat:
            continue
        try:
            if until_ts is not None:
                cursor.execute(
                    f"SELECT local_type, create_time, real_sender_id, message_content, "
                    f"server_id, packed_info_data "
                    f"FROM {tbl} WHERE create_time > ? AND create_time <= ? ORDER BY create_time",
                    (int(since_ts), int(until_ts))
                )
            else:
                cursor.execute(
                    f"SELECT local_type, create_time, real_sender_id, message_content, "
                    f"server_id, packed_info_data "
                    f"FROM {tbl} WHERE create_time > ? ORDER BY create_time",
                    (int(since_ts),)
                )
            rows = cursor.fetchall()
        except Exception as e:
            logger.debug(f"Query error in {tbl}: {e}")
            continue

        for row in rows:
            msg_type = int(row[0]) & 0xFFFF
            if msg_type not in _WX_KEPT_TYPES:
                continue
            ts = int(row[1]) if row[1] else 0
            dt = datetime.fromtimestamp(ts)
            sender_wxid = name_map.get(row[2], str(row[2]))
            raw = _decompress_message(row[3])
            sv_raw = row[4] if len(row) > 4 else None
            packed = row[5] if len(row) > 5 else None
            if msg_type == _WX_MSG_TYPE_TEXT:
                first_line = raw.split("\n")[0].strip().rstrip(":")
                content = (raw.split("\n", 1)[1]
                           if ("\n" in raw and first_line == sender_wxid)
                           else raw)
                content = content.strip()
                att_meta = None
            else:
                content = _extract_wechat_xml(raw, msg_type).strip()
                att_meta = _extract_attachment_meta(raw, msg_type)
                # enrich image att with file_md5 from packed_info_data
                if att_meta and att_meta.get("kind") == "image":
                    fm = _extract_file_md5_from_packed_info(packed)
                    if fm:
                        att_meta["file_md5"] = fm
            if not content:
                continue
            sv_id = str(sv_raw) if sv_raw not in (None, 0, "") else ""
            messages.append(WxMessage(
                timestamp=dt, sender=sender_wxid, content=content,
                chat_name=tbl_chat, msg_type=msg_type,
                attachment_meta=att_meta, server_id=sv_id,
            ))
    messages.sort(key=lambda m: m.timestamp)
    return messages


# ─── Decrypt cache (30s idle TTL + DB-family invalidation) ────────────────────

_DECRYPT_CACHE_TTL = 30.0
_DECRYPT_DELETE_RETRY = 1.0
_DECRYPT_OWNER_FILE = ".chatlog-owner-v1"
_DECRYPT_LEGACY_SCAVENGE_AGE = 24 * 60 * 60.0
_DECRYPT_MAIN_NAME = re.compile(r"plain-[0-9a-f]{32}\.db")
_DECRYPT_CACHE_DIR_NAME = re.compile(r"chatlog_decrypted_[A-Za-z0-9_-]+")


@dataclass
class _DecryptCacheEntry:
    path: Path
    fingerprint: tuple
    last_access: float
    deadline: float
    timer: Any
    private_dir: Path
    generation: object


@dataclass
class _PendingDecryptDelete:
    private_dir: Path
    timer: Any
    generation: object


_DECRYPT_CACHE: dict[Path, _DecryptCacheEntry] = {}
_DECRYPT_PENDING_DELETES: dict[Path, _PendingDecryptDelete] = {}
_DECRYPT_CACHE_LOCK = threading.Lock()
_DECRYPT_SCAVENGE_DONE = False


def _emit_decrypt_trace(event: str, payload: dict) -> None:
    try:
        from chatlog_keeper.core.trace_sink import emit  # type: ignore
        emit(event, payload)
    except Exception:
        pass


def _db_family_fingerprint(db_path: Path) -> Optional[tuple]:
    """Return an identity/size/mtime fingerprint for main DB, WAL and SHM."""
    values = []
    for index, candidate in enumerate(
        (
            Path(db_path),
            Path(db_path).with_name(Path(db_path).name + "-wal"),
            Path(db_path).with_name(Path(db_path).name + "-shm"),
        )
    ):
        try:
            value = candidate.stat()
        except FileNotFoundError:
            if index == 0:
                return None
            values.append(None)
            continue
        except OSError:
            return None
        if not stat.S_ISREG(value.st_mode):
            return None
        values.append(
            (
                value.st_dev,
                value.st_ino,
                value.st_size,
                value.st_mtime_ns,
            )
        )
    return tuple(values)


def _private_decrypt_dir_is_safe(private_dir: Path) -> bool:
    try:
        value = Path(private_dir).lstat()
    except OSError:
        return False
    if (
        not stat.S_ISDIR(value.st_mode)
        or Path(private_dir).is_symlink()
        or getattr(value, "st_file_attributes", 0) & 0x0400
    ):
        return False
    if os.name == "nt":
        from chatlog_keeper.core._secrets import _windows_acl_is_private

        return _windows_acl_is_private(Path(private_dir))
    return value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700


def _private_decrypt_file_is_safe(path: Path, private_dir: Path) -> bool:
    path = Path(path)
    if path.parent != Path(private_dir) or not _private_decrypt_dir_is_safe(private_dir):
        return False
    try:
        value = path.lstat()
    except OSError:
        return False
    if (
        not stat.S_ISREG(value.st_mode)
        or path.is_symlink()
        or getattr(value, "st_file_attributes", 0) & 0x0400
    ):
        return False
    if os.name == "nt":
        from chatlog_keeper.core._secrets import _windows_acl_is_private

        return _windows_acl_is_private(path)
    return value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o600


def _cache_artifact_name_is_allowed(name: str, main_name: str) -> bool:
    return (
        name == _DECRYPT_OWNER_FILE
        or name == main_name
        or name in {
            main_name + "-wal",
            main_name + "-shm",
            main_name + "-journal",
        }
        or (name.startswith(f".{main_name}.") and name.endswith(".tmp"))
    )


def _remove_decrypted_cache_file(path: Path, private_dir: Path) -> bool:
    """Remove one exact private cache family without following links."""
    path = Path(path)
    private_dir = Path(private_dir)
    try:
        private_dir.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if (
        path.parent != private_dir
        or _DECRYPT_MAIN_NAME.fullmatch(path.name) is None
        or not _private_decrypt_dir_is_safe(private_dir)
    ):
        return False
    try:
        children = list(private_dir.iterdir())
    except FileNotFoundError:
        return True
    except OSError:
        return False
    checked = []
    for child in children:
        if not _cache_artifact_name_is_allowed(child.name, path.name):
            return False
        try:
            value = child.lstat()
        except OSError:
            return False
        if (
            not stat.S_ISREG(value.st_mode)
            or child.is_symlink()
            or getattr(value, "st_file_attributes", 0) & 0x0400
        ):
            return False
        if os.name != "nt" and value.st_uid != os.geteuid():
            return False
        checked.append(child)
    checked.sort(key=lambda item: item.name == _DECRYPT_OWNER_FILE)
    for child in checked:
        try:
            child.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            return False
    try:
        private_dir.rmdir()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def _queue_pending_decrypt_delete_locked(path: Path, private_dir: Path) -> None:
    """Keep ownership of a Windows-busy artifact until deletion succeeds."""
    previous = _DECRYPT_PENDING_DELETES.get(path)
    if previous is not None and previous.timer is not None:
        previous.timer.cancel()
    generation = object()
    timer = threading.Timer(
        _DECRYPT_DELETE_RETRY,
        _retry_pending_decrypt_delete,
        args=(path, generation),
    )
    timer.daemon = True
    _DECRYPT_PENDING_DELETES[path] = _PendingDecryptDelete(
        private_dir=private_dir,
        timer=timer,
        generation=generation,
    )
    timer.start()


def _retry_pending_decrypt_delete(path: Path, expected_generation: object) -> None:
    with _DECRYPT_CACHE_LOCK:
        pending = _DECRYPT_PENDING_DELETES.get(path)
        if pending is None or pending.generation is not expected_generation:
            return
        if _remove_decrypted_cache_file(path, pending.private_dir):
            _DECRYPT_PENDING_DELETES.pop(path, None)
            return
        _queue_pending_decrypt_delete_locked(path, pending.private_dir)


def _normalized_decrypt_ttl(ttl: float) -> float:
    try:
        value = float(ttl)
    except (TypeError, ValueError):
        value = _DECRYPT_CACHE_TTL
    if not math.isfinite(value):
        value = _DECRYPT_CACHE_TTL
    return max(0.01, value)


def _expire_decrypt_cache(
    db_path: Path,
    expected_path: Path,
    expected_generation: object,
) -> None:
    """Remove exactly one expired generation; cancelled timers cannot win."""
    with _DECRYPT_CACHE_LOCK:
        cached = _DECRYPT_CACHE.get(db_path)
        if (
            cached is None
            or cached.path != expected_path
            or cached.generation is not expected_generation
        ):
            return
        remaining = cached.deadline - _time.monotonic()
        if remaining > 0:
            timer = threading.Timer(
                max(0.01, remaining),
                _expire_decrypt_cache,
                args=(db_path, cached.path, cached.generation),
            )
            timer.daemon = True
            cached.timer = timer
            timer.start()
            return
        _DECRYPT_CACHE.pop(db_path, None)
        if not _remove_decrypted_cache_file(cached.path, cached.private_dir):
            _queue_pending_decrypt_delete_locked(cached.path, cached.private_dir)


def _refresh_decrypt_expiry(
    db_path: Path,
    entry: _DecryptCacheEntry,
    *,
    ttl: float,
    now: float,
) -> _DecryptCacheEntry:
    """Cancel an old timer and publish a distinct idle-expiry generation."""
    if entry.timer is not None:
        entry.timer.cancel()
    generation = object()
    lifetime = _normalized_decrypt_ttl(ttl)
    timer = threading.Timer(
        lifetime,
        _expire_decrypt_cache,
        args=(db_path, entry.path, generation),
    )
    timer.daemon = True
    refreshed = _DecryptCacheEntry(
        path=entry.path,
        fingerprint=entry.fingerprint,
        last_access=now,
        deadline=now + lifetime,
        timer=timer,
        private_dir=entry.private_dir,
        generation=generation,
    )
    _DECRYPT_CACHE[db_path] = refreshed
    timer.start()
    return refreshed


def _write_decrypt_owner_marker(private_dir: Path) -> bool:
    from chatlog_keeper.core._secrets import write_secret_text

    return write_secret_text(
        Path(private_dir) / _DECRYPT_OWNER_FILE,
        f"pid={os.getpid()}\n",
    )


def _decrypt_with_cache(
    db_path: Path,
    enc_key: bytes,
    ttl: float = _DECRYPT_CACHE_TTL,
) -> Optional[Path]:
    """Decrypt a DB family to one private, idle-expiring plaintext snapshot."""
    db_path = Path(db_path)
    with _DECRYPT_CACHE_LOCK:
        fingerprint = _db_family_fingerprint(db_path)
        if fingerprint is None:
            return None
        now = _time.monotonic()
        cached = _DECRYPT_CACHE.get(db_path)
        if cached is not None:
            if (
                cached.fingerprint == fingerprint
                and now < cached.deadline
                and _private_decrypt_file_is_safe(cached.path, cached.private_dir)
            ):
                age = now - cached.last_access
                cached = _refresh_decrypt_expiry(
                    db_path,
                    cached,
                    ttl=ttl,
                    now=now,
                )
                _emit_decrypt_trace(
                    "decrypt_cache_hit",
                    {"db": db_path.name, "age_sec": round(age, 2)},
                )
                return cached.path
            if cached.timer is not None:
                cached.timer.cancel()
            _DECRYPT_CACHE.pop(db_path, None)
            if not _remove_decrypted_cache_file(cached.path, cached.private_dir):
                _queue_pending_decrypt_delete_locked(
                    cached.path,
                    cached.private_dir,
                )

        private_dir = Path(tempfile.mkdtemp(prefix="chatlog_decrypted_"))
        try:
            from chatlog_keeper.core._secrets import _prepare_secret_parent

            _prepare_secret_parent(private_dir)
            if not _write_decrypt_owner_marker(private_dir):
                raise PermissionError("could not publish decrypt-cache owner marker")
        except (OSError, ValueError):
            try:
                private_dir.rmdir()
            except OSError:
                pass
            return None
        tmp_path = private_dir / f"plain-{secrets.token_hex(16)}.db"
        if not _decrypt_db_v4(db_path, enc_key, tmp_path):
            if not _remove_decrypted_cache_file(tmp_path, private_dir):
                _queue_pending_decrypt_delete_locked(tmp_path, private_dir)
            _emit_decrypt_trace(
                "decrypt_cache_miss",
                {"db": db_path.name, "result": "decrypt_failed"},
            )
            return None

        try:
            if os.name == "nt":
                from chatlog_keeper.core._secrets import (
                    _windows_acl_is_private,
                    _windows_apply_private_acl,
                )

                if not _windows_apply_private_acl(tmp_path, directory=False):
                    raise PermissionError("could not restrict decrypted cache ACL")
                if not _windows_acl_is_private(tmp_path):
                    raise PermissionError("decrypted cache ACL verification failed")
            else:
                os.chmod(tmp_path, 0o600, follow_symlinks=False)
        except OSError:
            if not _remove_decrypted_cache_file(tmp_path, private_dir):
                _queue_pending_decrypt_delete_locked(tmp_path, private_dir)
            return None
        if not _private_decrypt_file_is_safe(tmp_path, private_dir):
            if not _remove_decrypted_cache_file(tmp_path, private_dir):
                _queue_pending_decrypt_delete_locked(tmp_path, private_dir)
            return None

        published_at = _time.monotonic()
        entry = _DecryptCacheEntry(
            path=tmp_path,
            fingerprint=fingerprint,
            last_access=published_at,
            deadline=published_at,
            timer=None,
            private_dir=private_dir,
            generation=object(),
        )
        entry = _refresh_decrypt_expiry(
            db_path,
            entry,
            ttl=ttl,
            now=published_at,
        )
        _emit_decrypt_trace(
            "decrypt_cache_miss",
            {"db": db_path.name, "result": "decrypted_fresh"},
        )
        return entry.path


def _process_is_alive(pid: int) -> bool:
    """Use the shared fail-safe owner-PID check for orphan cleanup."""

    from chatlog_keeper.core._private_temp import process_is_alive

    return process_is_alive(pid)


def _scavenge_decrypt_cache(
    *,
    temp_root: Optional[Path] = None,
    force: bool = False,
) -> int:
    """Remove safely-identifiable cache dirs left by terminated processes."""
    global _DECRYPT_SCAVENGE_DONE
    with _DECRYPT_CACHE_LOCK:
        if _DECRYPT_SCAVENGE_DONE and not force:
            return 0
        _DECRYPT_SCAVENGE_DONE = True
    root = Path(temp_root) if temp_root is not None else Path(tempfile.gettempdir())
    try:
        candidates = list(root.glob("chatlog_decrypted_*"))
    except OSError:
        return 0
    removed = 0
    now = _time.time()
    from chatlog_keeper.core._secrets import read_secret_text

    for candidate in candidates:
        if (
            candidate.parent != root
            or _DECRYPT_CACHE_DIR_NAME.fullmatch(candidate.name) is None
            or not _private_decrypt_dir_is_safe(candidate)
        ):
            continue
        owner_text = read_secret_text(
            candidate / _DECRYPT_OWNER_FILE,
            max_bytes=128,
        )
        owner_match = re.fullmatch(r"pid=([0-9]+)\n?", owner_text or "")
        if owner_match is not None:
            if _process_is_alive(int(owner_match.group(1))):
                continue
        else:
            try:
                age = now - candidate.stat().st_mtime
            except OSError:
                continue
            if age < _DECRYPT_LEGACY_SCAVENGE_AGE:
                continue
        try:
            names = [item.name for item in candidate.iterdir()]
        except OSError:
            continue
        main_names = set()
        for name in names:
            direct = _DECRYPT_MAIN_NAME.fullmatch(name)
            if direct is not None:
                main_names.add(name)
                continue
            sidecar = re.fullmatch(
                r"(plain-[0-9a-f]{32}\.db)-(?:wal|shm|journal)",
                name,
            )
            if sidecar is not None:
                main_names.add(sidecar.group(1))
                continue
            temporary = re.fullmatch(
                r"\.(plain-[0-9a-f]{32}\.db)\..+\.tmp",
                name,
            )
            if temporary is not None:
                main_names.add(temporary.group(1))
        if len(main_names) > 1:
            continue
        main_name = next(iter(main_names), "plain-" + "0" * 32 + ".db")
        if _remove_decrypted_cache_file(candidate / main_name, candidate):
            removed += 1
    return removed


def _decrypt_cache_clear(*, retry_failed: bool = True):
    """Cancel timers and retain failed deletions for retry/startup scavenging."""
    with _DECRYPT_CACHE_LOCK:
        entries = list(_DECRYPT_CACHE.values())
        pending_entries = list(_DECRYPT_PENDING_DELETES.items())
        _DECRYPT_CACHE.clear()
        _DECRYPT_PENDING_DELETES.clear()
        for entry in entries:
            if entry.timer is not None:
                entry.timer.cancel()
        for _path, pending in pending_entries:
            if pending.timer is not None:
                pending.timer.cancel()
    artifacts = [(entry.path, entry.private_dir) for entry in entries]
    artifacts.extend(
        (path, pending.private_dir) for path, pending in pending_entries
    )
    failed = []
    for path, private_dir in artifacts:
        if not _remove_decrypted_cache_file(path, private_dir):
            failed.append((path, private_dir))
    if failed and retry_failed:
        with _DECRYPT_CACHE_LOCK:
            for path, private_dir in failed:
                _queue_pending_decrypt_delete_locked(path, private_dir)


_scavenge_decrypt_cache()

import atexit as _atexit
_atexit.register(_decrypt_cache_clear, retry_failed=False)


def _query_messages_since(db_path: Path, since_ts: float, enc_key: bytes, chat_name: Optional[str] = None, until_ts: Optional[float] = None) -> list:
    """Decrypt + query messages newer than since_ts (incremental). Returns [] on any failure.

    until_ts (optional): upper time bound → window query [since, until] instead of
    [since, now], so a backfill tick doesn't materialize the whole history (OOM fix).

    Uses _decrypt_with_cache so high-frequency watcher invocations skip the decrypt.
    """
    import sqlite3
    if not enc_key:
        return []
    tmp_path = _decrypt_with_cache(db_path, enc_key)
    if tmp_path is None:
        return []
    try:
        conn = sqlite3.connect(str(tmp_path))
        try:
            name_map = _load_name_map(conn)
            return _query_messages_since_inner(conn, since_ts, name_map, chat_name=chat_name, until_ts=until_ts)
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f"_query_messages_since failed for {db_path.name}: {e}")
        return []


def _query_conversation_counts(conn, candidate_ids=()) -> dict:
    """Return ``{native_conversation_id: message_count}`` without reading bodies."""
    cursor = conn.cursor()
    name_map = _load_name_map(conn)
    hash_to_id = {}
    for candidate in list(name_map.values()) + list(candidate_ids):
        if candidate:
            value = str(candidate)
            hash_to_id[hashlib.md5(value.encode()).hexdigest()] = value
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
    )
    counts: dict = {}
    for row in cursor.fetchall():
        table_name = str(row[0] or "")
        # Table names originate in sqlite_master, but validate the exact WeChat
        # shape before quoting them into SQL to keep this metadata path strict.
        if not re.fullmatch(r"Msg_[0-9a-fA-F]{32}", table_name):
            continue
        cursor.execute(f'SELECT COUNT(*) FROM "{table_name}"')
        count_row = cursor.fetchone()
        suffix = table_name[4:]
        conversation_id = hash_to_id.get(suffix, suffix[:8] + "...")
        if not conversation_id:
            continue
        counts[conversation_id] = counts.get(conversation_id, 0) + int(
            (count_row or (0,))[0] or 0
        )
    return counts


def _conversation_counts(db_path: Path, enc_key: bytes, candidate_ids=()) -> Optional[dict]:
    """Decrypt one message DB and read only its conversation directory metadata."""
    import sqlite3

    if not enc_key:
        return None
    decrypted = _decrypt_with_cache(db_path, enc_key)
    if decrypted is None:
        return None
    try:
        conn = sqlite3.connect(str(decrypted))
        try:
            return _query_conversation_counts(conn, candidate_ids=candidate_ids)
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("WeChat conversation directory is unavailable: %s", type(exc).__name__)
        return None


def query_messages_by_date(db_path: Path, target_date: date, enc_key: bytes = None) -> list:
    """
    Decrypt (if enc_key provided) and query a Weixin 4.x message_*.db file.
    Returns list of WxMessage objects.
    """
    import sqlite3

    if enc_key:
        # shared cache reduces a multi-second decrypt → <100ms for repeated date scans
        tmp_path = _decrypt_with_cache(db_path, enc_key)
        if tmp_path is None:
            return []
        try:
            conn = sqlite3.connect(str(tmp_path))
            name_map = _load_name_map(conn)
            return _query_messages_by_date(conn, target_date, name_map)
        except Exception as e:
            logger.warning(f"Query on decrypted {db_path.name} failed: {e}")
            return []
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # Plain SQLite (no encryption)
    try:
        conn = sqlite3.connect(str(db_path))
        name_map = _load_name_map(conn)
        result = _query_messages_by_date(conn, target_date, name_map)
        conn.close()
        return result
    except Exception as e:
        logger.warning(f"SQLite query failed for {db_path.name}: {e}")
        return []


# ─── High-level reader ────────────────────────────────────────────────────────

class WeChatDBReader:
    """
    High-level interface for reading Weixin 4.x messages by date.

    Usage:
        reader = WeChatDBReader()
        ok = reader.initialize()
        if ok:
            messages = reader.read_by_date('2026-03-27')
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
    ):
        """Create a reader, optionally scoped to one discovered wxid directory.

        The account identifier is compared with discovered directory names and
        is never used to construct a path.  Omitting it keeps the v0.2.0 first-
        account behavior. Directory-only callers disable live extraction so a
        metadata scan never opens or inspects a running WeChat process.
        """
        self._configured_data_root = Path(data_root) if data_root is not None else None
        self._configured_account_id = str(account_id) if account_id is not None else None
        self._allow_live_key_extract = bool(allow_live_key_extract)
        self.data_root = None
        self.wxid_dir = None
        self.account_id = None
        self.account_label = ""
        self.enc_key = None  # backward-compat: first DB's key (deprecated; prefer enc_keys)
        self.enc_keys: dict = {}  # NEW (2026-04-30): {Path: bytes} per-DB key map
        self._passive_key_error_code = None
        self._initialized = False
        # contact resolver lazy-loaded after initialize() succeeds
        self.contacts = None

    def initialize(self) -> bool:
        """Find data directory and extract per-DB encryption keys.

        WeChat 4.x stores per-DB keys in the process heap; each message_N.db has
        a unique enc_key. Extracting ONE global key (against ref_db only) makes
        message_1.db etc silently fail with "file is not a database", so the
        nested loop below builds a per-DB key dict.
        """
        self._passive_key_error_code = None
        _clear_passive_key_error()
        self.data_root = self._configured_data_root or find_weixin_data_root()
        if not self.data_root:
            logger.warning("Weixin data root not found")
            return False

        wxid_dirs = find_wxid_dirs(self.data_root)
        if not wxid_dirs:
            logger.warning("No wxid directories found")
            return False
        if self._configured_account_id is None:
            self.wxid_dir = wxid_dirs[0]
        else:
            self.wxid_dir = next(
                (item for item in wxid_dirs if item.name == self._configured_account_id),
                None,
            )
        if self.wxid_dir is None:
            logger.warning("WeChat account is unavailable for the requested scope")
            return False
        self.account_id = self.wxid_dir.name
        logger.info("Using the selected WeChat account directory")

        db_files = find_msg_databases(self.wxid_dir)
        if not db_files:
            logger.warning("No WeChat message databases are available for the requested scope")
            self._initialized = True
            return True

        # Cache-first — the selected account's key precedes the legacy global
        # fallback and decrypts its DBs without WeChat running. On WeChat
        # 4.1.10.31 this is the ONLY working path (the live heap scan below finds
        # nothing). One master key derives each DB's own page key from that DB's
        # salt (see _effective_page_key).
        cached = load_cached_wechat_key_for_account(self.account_id)
        if cached and len(cached) == 32:
            for db in db_files:
                page1 = _read_stable_page1(db)
                if not page1:
                    continue
                if _verify_key_v4(cached, page1):
                    self.enc_keys[db] = cached
            if self.enc_keys:
                logger.info(f"{len(self.enc_keys)}/{len(db_files)} WeChat DB(s) "
                            f"unlocked via cached master key (no live scan)")

        # DBs still without a key → live extraction (needs WeChat running; yields
        # nothing on 4.1.10.31). If all DBs are already unlocked via cache, skip.
        remaining = [db for db in db_files if db not in self.enc_keys]
        if not remaining:
            self._initialized = True
            return True

        if not self._allow_live_key_extract:
            if self.enc_keys:
                logger.info(
                    "Live WeChat key extraction is disabled; using verified cached databases only"
                )
            else:
                logger.warning(
                    "No verified cached WeChat key is available for the requested account"
                )
            self._initialized = True
            return True

        pids = _get_weixin_pids()
        if not pids:
            logger.warning("Weixin.exe not running; %d DB(s) without a key — run "
                           "`chatlog-keeper wechat extract-key` or `chatlog-keeper wechat set-key`.",
                           len(remaining))
            self._initialized = True
            return True

        # Per-DB key extraction with working_pid memoization: once a pid yields
        # a key for any DB, try it FIRST for subsequent DBs. This collapses the
        # repeated "Key extraction failed" spam to a couple of attempts.
        working_pid = None
        # WeChat 4.1.10.31+ keeps no plaintext key in the heap, so a passive scan
        # there finds nothing and burns its whole budget. TWO bounds keep this
        # from hanging the caller: a PER-pid budget (single scan) AND a TOTAL
        # budget across the entire DB×pid nested loop — without the latter, N DBs
        # × M pids multiply a 120s scan into many minutes (this was the "微信
        # passive 超时" hang). On exhaustion, enc_keys stays empty → `extract-key
        # --method auto` falls back to the active (debugger) path, and a status
        # probe never reaches here at all (it is cache-first, no scan). Older
        # builds whose key IS in the heap hit working_pid on the first DB in a
        # second or two, well within budget, so they are unaffected.
        import time as _time  # local import (mirrors the scan helpers above)
        scan_budget = float(os.environ.get("CHATLOG_WECHAT_SCAN_TIMEOUT_S", "10"))
        total_budget = float(os.environ.get("CHATLOG_WECHAT_SCAN_TOTAL_S", "25"))
        scan_start = _time.monotonic()
        for db in remaining:
            if _time.monotonic() - scan_start >= total_budget:
                left = sum(1 for d in remaining if d not in self.enc_keys)
                logger.warning(
                    "WeChat passive scan total budget %.0fs exhausted; %d DB(s) "
                    "left unscanned — likely 4.1.10.31+ (key not in heap). Use "
                    "`extract-key --method active` or `set-key`.", total_budget, left)
                break
            tried_pids = []
            ordered_pids = ([working_pid] if working_pid else []) + [p for p in pids if p != working_pid]
            for pid in ordered_pids:
                elapsed = _time.monotonic() - scan_start
                if elapsed >= total_budget:
                    break
                tried_pids.append(pid)
                eff_timeout = min(scan_budget, total_budget - elapsed)
                key = extract_key_from_weixin(
                    pid,
                    db_path=db,
                    timeout_s=eff_timeout,
                    account_id=self.account_id,
                )
                scan_error = _passive_key_error()
                if scan_error == PROCESS_ACCESS_DENIED:
                    self._passive_key_error_code = scan_error
                # A truthiness check is insufficient for crypto bytes: also
                # validate the length is 32 (AES-256).
                if key and isinstance(key, (bytes, bytearray)) and len(key) == 32:
                    self._passive_key_error_code = None
                    self.enc_keys[db] = bytes(key)
                    if working_pid is None:
                        logger.info(f"Weixin enc_key extraction working_pid={pid}")
                        working_pid = pid
                    break  # found valid key for this DB; next DB
            if db not in self.enc_keys:
                logger.debug(
                    f"No valid key found for {db.name} after trying pids {tried_pids}"
                )

        # Backward-compat: expose first DB's key as self.enc_key (deprecated)
        if self.enc_keys:
            first_db = next(iter(self.enc_keys))
            self.enc_key = self.enc_keys[first_db]
            logger.info(f"Per-DB keys extracted: {len(self.enc_keys)}/{len(db_files)} DBs")
        else:
            logger.warning("Weixin running but key extraction failed for all DBs.")

        self._initialized = True
        return True

    def _load_contacts(self):
        """Lazy-load WeChatContactResolver. Idempotent. Safe to call repeatedly.

        Returns the resolver (always truthy: empty resolver if contact.db missing).
        """
        if self.contacts is not None:
            return self.contacts
        try:
            from chatlog_keeper.wechat_contacts import WeChatContactResolver
            self.contacts = WeChatContactResolver(self)
            self.contacts.load()
        except Exception as e:
            logger.warning(
                "contact resolver init failed (%s); messages will use wxid as display",
                type(e).__name__,
            )
            # Use a stub that returns wxid as-is; never None, to keep contract.
            class _StubResolver:
                def resolve_display_name(self, w): return w or ""
                def is_group(self, w): return bool(w and w.endswith("@chatroom"))
            self.contacts = _StubResolver()
        return self.contacts

    def _decorate_with_displays(self, messages: list) -> list:
        """In-place: populate sender_display_name + chat_display_name + is_group_chat.

        Idempotent: messages already decorated keep their values.
        Returns the same list (for fluent chaining).
        """
        if not messages:
            return messages
        contacts = self._load_contacts()
        for m in messages:
            if not m.sender_display_name:
                m.sender_display_name = contacts.resolve_display_name(m.sender)
            if not m.chat_display_name:
                m.chat_display_name = contacts.resolve_display_name(m.chat_name)
            m.is_group_chat = contacts.is_group(m.chat_name)
        return messages

    def read_by_date(self, date_str: str) -> list:
        """
        Read all text messages from the specified date (YYYY-MM-DD).
        Returns list of WxMessage objects sorted by time.
        """
        if not self._initialized:
            self.initialize()

        if not self.wxid_dir:
            logger.warning("No wxid directory available")
            return []

        try:
            target_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            logger.error(f"Invalid date format: {date_str}")
            return []

        db_files = find_msg_databases(self.wxid_dir)
        if not db_files:
            logger.warning("No message databases found for the selected WeChat account")
            return []

        all_messages = []
        for db_file in db_files:
            # Per-DB key (2026-04-30 fix): each DB has unique key
            db_key = self.enc_keys.get(db_file)
            if db_key is None:
                logger.warning(f"Skipping {db_file.name}: no enc_key in self.enc_keys")
                continue
            logger.info("Querying %s with a verified cached key", db_file.name)
            msgs = query_messages_by_date(db_file, target_date, db_key)
            all_messages.extend(msgs)

        all_messages.sort(key=lambda m: m.timestamp)
        # decorate with display names so consumers see human-readable sender/chat
        self._decorate_with_displays(all_messages)
        logger.info(f"Total messages for {date_str}: {len(all_messages)}")
        return all_messages

    def read_conversation_page(
        self,
        *,
        conversation_id: str,
        since_ts: float,
        until_ts: Optional[float] = None,
        page_size: int = 500,
        cursor: Optional[Any] = None,
        cancel_requested: Optional[Callable[[], bool]] = None,
    ) -> WeChatMessagePage:
        """Read one deterministic, bounded keyset page for one conversation.

        The cursor records an independent ``(create_time, rowid)`` position for
        every readable message database.  Rows from those shards are merged by
        ``(create_time, opaque_shard_id, rowid)`` so filesystem enumeration
        order and equal timestamps cannot create gaps or duplicates.

        Cancellation raises before a new cursor is returned.  The caller can
        therefore retry with its previous cursor without consuming any rows.
        """

        import sqlite3

        _wechat_conversation_table_name(conversation_id)
        requested_page_size = _validated_wechat_page_size(page_size)
        since = _validated_wechat_page_time(since_ts, field="since_ts")
        until = (
            _validated_wechat_page_time(until_ts, field="until_ts")
            if until_ts is not None
            else None
        )
        if until is not None and until < since:
            raise ValueError("WeChat message page until_ts is before since_ts")
        page_cursor = (
            WeChatMessagePageCursor.from_value(cursor)
            if cursor is not None
            else None
        )
        _raise_if_wechat_page_cancelled(cancel_requested)

        if not self._initialized:
            self.initialize()
        _raise_if_wechat_page_cancelled(cancel_requested)

        readable_shards = []
        if self.wxid_dir:
            for database in find_msg_databases(self.wxid_dir):
                key = self.enc_keys.get(database)
                if key is None:
                    continue
                shard_id = _wechat_message_shard_id(
                    database,
                    root=self.wxid_dir,
                )
                readable_shards.append((shard_id, database, key))
        readable_shards.sort(key=lambda item: item[0])
        shard_ids = tuple(item[0] for item in readable_shards)
        topology = _wechat_message_topology(shard_ids)
        scope = _wechat_message_page_scope(
            account_id=str(self.account_id or ""),
            conversation_id=conversation_id,
            since_ts=since,
            until_ts=until,
        )

        if page_cursor is not None:
            if page_cursor.scope != scope:
                raise ValueError(
                    "WeChat message page cursor request scope changed"
                )
            if page_cursor.topology != topology:
                raise ValueError(
                    "WeChat message page cursor database topology changed"
                )
            readable_ids = set(shard_ids)
            if any(
                shard_id not in readable_ids
                for shard_id, _create_time, _row_id in page_cursor.positions
            ):
                raise ValueError(
                    "WeChat message page cursor database topology changed"
                )

        _raise_if_wechat_page_cancelled(cancel_requested)
        candidates = []
        query_limit = requested_page_size + 1
        for shard_id, database, key in readable_shards:
            _raise_if_wechat_page_cancelled(cancel_requested)
            decrypted = _decrypt_with_cache(database, key)
            if decrypted is None:
                raise RuntimeError(
                    "A readable WeChat message database could not be decrypted"
                )
            _raise_if_wechat_page_cancelled(cancel_requested)
            try:
                connection = sqlite3.connect(str(decrypted))
                try:
                    candidates.extend(
                        _query_conversation_page_rows(
                            connection,
                            conversation_id=conversation_id,
                            since_ts=since,
                            until_ts=until,
                            position=(
                                page_cursor.position_for(shard_id)
                                if page_cursor is not None
                                else None
                            ),
                            limit=query_limit,
                            shard_id=shard_id,
                            cancel_requested=cancel_requested,
                        )
                    )
                finally:
                    connection.close()
            except WeChatMessagePageCancelled:
                raise
            except Exception as exc:
                raise RuntimeError(
                    "A readable WeChat message database page could not be read"
                ) from exc

        candidates.sort(key=lambda row: row.order_key)
        scanned = candidates[:requested_page_size]
        has_more = len(candidates) > requested_page_size

        positions = {
            shard_id: (create_time, row_id)
            for shard_id, create_time, row_id in (
                page_cursor.positions if page_cursor is not None else ()
            )
        }
        for row in scanned:
            positions[row.shard_id] = (row.create_time, row.row_id)
        if scanned:
            next_cursor = WeChatMessagePageCursor(
                scope=scope,
                topology=topology,
                positions=tuple(
                    (shard_id, create_time, row_id)
                    for shard_id, (create_time, row_id) in sorted(positions.items())
                ),
            )
        else:
            next_cursor = page_cursor

        messages = []
        for row in scanned:
            message = _wechat_message_from_page_row(
                row,
                conversation_id=conversation_id,
            )
            if message is not None:
                messages.append(message)
        self._decorate_with_displays(messages)
        _raise_if_wechat_page_cancelled(cancel_requested)
        return WeChatMessagePage(
            messages=tuple(messages),
            next_cursor=next_cursor,
            has_more=has_more,
            scanned_rows=len(scanned),
        )

    def read_after(self, since_ts: float, chat_name: Optional[str] = None, until_ts: Optional[float] = None) -> list:
        """Read messages with create_time > since_ts (incremental).

        Args:
            since_ts: Unix timestamp (float); messages strictly newer returned
            chat_name: optional filter; if None, all chats included
            until_ts: optional upper time bound → window query [since, until]
                instead of [since, now] (prevents loading whole history = OOM fix)

        Returns: List[WxMessage] sorted by timestamp ascending. Empty if no
        keys / no DBs. Never raises; returns [] on infrastructure failure.
        """
        if not self._initialized:
            self.initialize()
        if not self.enc_keys or not self.wxid_dir:
            return []

        db_files = find_msg_databases(self.wxid_dir)
        all_messages = []
        for db_file in db_files:
            db_key = self.enc_keys.get(db_file)
            if db_key is None:
                continue
            msgs = _query_messages_since(db_file, since_ts, db_key, chat_name=chat_name, until_ts=until_ts)
            all_messages.extend(msgs)

        all_messages.sort(key=lambda m: m.timestamp)
        # decorate so the live watcher emits human-readable names
        self._decorate_with_displays(all_messages)
        return all_messages

    def read_conversation_directory(self) -> Optional[list]:
        """Return contacts/groups and counts without selecting message bodies.

        The contact resolver is the preferred directory.  When it cannot be
        loaded, native conversation identifiers are reconstructed from the
        ``Msg_<md5>`` table directory and ``Name2Id`` metadata.  ``None`` means
        neither source could be read; an empty list is a successful empty
        directory.
        """
        if not self._initialized:
            self.initialize()
        if not self.wxid_dir:
            return None

        contacts = self._load_contacts()
        try:
            displays = contacts.all_displays()
        except Exception:  # noqa: BLE001
            displays = {}
        try:
            directory_labels = contacts.all_directory_labels()
        except Exception:  # noqa: BLE001
            directory_labels = displays
        try:
            self.account_label = contacts.account_directory_label(str(self.account_id or ""))
        except Exception:  # noqa: BLE001
            account_id = " ".join(str(self.account_id or "").split()).strip()
            self.account_label = f"微信号：{account_id}" if account_id else "微信账号"

        counts: dict = {}
        metadata_read = False
        for db_file in find_msg_databases(self.wxid_dir):
            db_key = self.enc_keys.get(db_file)
            if db_key is None:
                continue
            db_counts = _conversation_counts(
                db_file,
                db_key,
                candidate_ids=displays,
            )
            if db_counts is None:
                continue
            metadata_read = True
            for conversation_id, message_count in db_counts.items():
                counts[conversation_id] = counts.get(conversation_id, 0) + int(message_count)

        entries = []
        if displays:
            metadata_read = True
            for conversation_id, display in displays.items():
                label = directory_labels.get(conversation_id) or display
                is_group = bool(contacts.is_group(conversation_id))
                entries.append({
                    "conversation_id": str(conversation_id),
                    "label": str(label or conversation_id),
                    "conversation_type": "group" if is_group else "direct",
                    "message_count": int(counts.get(conversation_id, 0)),
                })
            represented = set(displays)
            for conversation_id, message_count in counts.items():
                if conversation_id in represented:
                    continue
                if conversation_id.endswith("@chatroom"):
                    conversation_type = "group"
                elif conversation_id.endswith("..."):
                    conversation_type = "direct_or_group"
                else:
                    conversation_type = "direct"
                entries.append({
                    "conversation_id": str(conversation_id),
                    "label": str(conversation_id),
                    "conversation_type": conversation_type,
                    "message_count": int(message_count),
                })
        else:
            for conversation_id, message_count in counts.items():
                if conversation_id.endswith("@chatroom"):
                    conversation_type = "group"
                elif conversation_id.endswith("..."):
                    conversation_type = "direct_or_group"
                else:
                    conversation_type = "direct"
                entries.append({
                    "conversation_id": str(conversation_id),
                    "label": str(conversation_id),
                    "conversation_type": conversation_type,
                    "message_count": int(message_count),
                })

        if not metadata_read:
            return None
        entries.sort(key=lambda item: (item["conversation_type"], item["conversation_id"]))
        return entries

    def format_for_ai(self, messages: list) -> str:
        """Format messages as plain text for Claude."""
        if not messages:
            return ""
        lines = []
        for m in messages:
            t = m.timestamp.strftime("%H:%M")
            chat = f"[{m.chat_name}] " if m.chat_name else ""
            if m.content:
                lines.append(f"{t} {chat}{m.sender}: {m.content}")
        return "\n".join(lines)

    def diagnose(self) -> dict:
        """Return diagnostic info for troubleshooting."""
        self.initialize()
        pids = _get_weixin_pids()
        db_files = find_msg_databases(self.wxid_dir) if self.wxid_dir else []
        return {
            "data_root": str(self.data_root),
            "wxid_dir": str(self.wxid_dir) if self.wxid_dir else None,
            "weixin_pids": list(pids),
            "key_extracted": self.enc_key is not None,
            "key_length": len(self.enc_key) if self.enc_key else 0,
            "db_files_found": [str(f) for f in db_files],
            "per_db_keys_count": len(self.enc_keys),  # 2026-04-30
        }


# ─── Real-time watcher ─────────────────────────────────────────────────────────


class WeChatDBWatcher:
    """Watch message_*.db files for new messages; fire callback per arrival.

    Uses watchdog FileModifiedEvent (primary) + 5s poll fallback.
    Debounces 2s to coalesce burst events from SQLCipher rollover.

    Usage:
        reader = WeChatDBReader()
        reader.initialize()
        watcher = WeChatDBWatcher(reader, chat_name="Friend")
        def on_msg(msg):
            print(f"NEW: {msg.sender}: {msg.content}")
        watcher.start(on_msg)
        ...
        watcher.stop()
    """

    # State file persists _last_seen_ts across restarts so messages received
    # while the watcher was down are picked up on next start.
    _STATE_PATH = Path(__file__).resolve().parents[1] / "data" / "wechat_watcher_state.json"

    def __init__(self, reader: "WeChatDBReader", chat_name: Optional[str] = None,
                 debounce_sec: float = 2.0, poll_interval_sec: float = 5.0,
                 state_path: Optional[Path] = None):
        self.reader = reader
        self.chat_name = chat_name
        self.debounce_sec = debounce_sec
        self.poll_interval_sec = poll_interval_sec
        self._observer = None
        self._poll_thread = None
        self._stop_evt = None
        self._last_seen_ts: float = 0.0
        self._last_event_ts: float = 0.0
        self._callback = None
        self._running = False
        self._lock = None
        # allow override for testing; default to module-level state
        self._state_path = Path(state_path) if state_path else self._STATE_PATH

    def _load_persisted_ts(self) -> float:
        """Load _last_seen_ts from state file. Returns 0.0 if missing/corrupt."""
        try:
            if not self._state_path.exists():
                return 0.0
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            return float(data.get("last_seen_ts", 0.0))
        except (json.JSONDecodeError, OSError, ValueError) as e:
            logger.warning(f"watcher state load failed ({e}); starting fresh")
            return 0.0

    def _atomic_write_state(self, last_seen_ts: float) -> None:
        """Atomic-write {last_seen_ts, updated_at} to state file."""
        import os as _os
        from datetime import timezone as _tz
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "last_seen_ts": float(last_seen_ts),
                "updated_at": datetime.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "chat_name": self.chat_name or "",
            }
            tmp = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".json",
                delete=False, dir=str(self._state_path.parent),
            )
            try:
                json.dump(payload, tmp, ensure_ascii=False)
                tmp.flush()
                _os.fsync(tmp.fileno())
            finally:
                tmp.close()
            _os.replace(tmp.name, str(self._state_path))
            self._emit_trace("watcher_state_persisted", {
                "ts": last_seen_ts, "op": "atomic_write",
            })
        except OSError as e:
            logger.warning(f"watcher state write failed: {e}")

    def _emit_trace(self, event: str, payload: dict) -> None:
        try:
            from chatlog_keeper.core.trace_sink import emit  # type: ignore
            emit(event, payload)
        except Exception:
            pass

    def _process_change(self) -> None:
        """Read new messages since last_seen_ts; invoke callback per message.

        Persists _last_seen_ts after each batch so restart-resume works.
        """
        import time
        # Debounce: if event fired within last debounce window, skip
        now = time.time()
        if now - self._last_event_ts < self.debounce_sec:
            return
        self._last_event_ts = now
        try:
            since = self._last_seen_ts if self._last_seen_ts > 0 else (now - 60.0)
            msgs = self.reader.read_after(since, chat_name=self.chat_name)
        except Exception as e:
            logger.warning(f"watcher read_after failed: {e}")
            return
        if not msgs:
            return
        new_max = max(m.timestamp.timestamp() for m in msgs)
        if new_max > self._last_seen_ts:
            self._last_seen_ts = new_max
            # persist after each successful read so a restart picks up here
            self._atomic_write_state(self._last_seen_ts)
        self._emit_trace("wechat_realtime_event", {
            "new_count": len(msgs), "since": since, "max_ts": new_max,
        })
        for m in msgs:
            self._emit_trace("wechat_realtime_message", {
                "ts": m.timestamp.isoformat(), "sender": m.sender,
                "sender_display": m.sender_display_name,
                "chat": m.chat_name,
                "chat_display": m.chat_display_name,
                "is_group": m.is_group_chat,
                "len": len(m.content),
            })
            try:
                self._callback(m)
            except Exception as e:
                logger.warning(f"watcher callback exception: {e}")

    def _watchdog_setup(self) -> bool:
        """Try watchdog setup. Returns True if observer started; False if unavailable."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            return False

        watcher_self = self

        class _Handler(FileSystemEventHandler):
            def on_modified(self, event):
                if event.is_directory:
                    return
                p = Path(event.src_path)
                if p.name.startswith("message_") and p.suffix == ".db":
                    watcher_self._process_change()

        self._observer = Observer()
        self._observer.schedule(_Handler(), str(self.reader.wxid_dir), recursive=True)
        self._observer.start()
        return True

    def _poll_loop(self) -> None:
        """Fallback poll loop when watchdog unavailable."""
        import time
        while not self._stop_evt.is_set():
            self._process_change()
            self._stop_evt.wait(self.poll_interval_sec)

    def start(self, callback) -> None:
        """Start watching. Idempotent (no-op if already running).

        Baseline = max(persisted_ts, now - 60s). If persisted is fresh, we
        resume from there; otherwise start from "now minus a minute" so no
        single message is missed at the boundary.
        """
        if self._running:
            return
        import threading, time
        self._stop_evt = threading.Event()
        self._callback = callback
        # resume from persisted ts if available
        persisted = self._load_persisted_ts()
        floor = time.time() - 60.0
        self._last_seen_ts = max(persisted, floor)
        self._last_event_ts = 0.0
        self._emit_trace("watcher_started", {
            "persisted_ts": persisted,
            "resume_from": self._last_seen_ts,
            "fresh_start": persisted == 0.0,
        })

        # Try watchdog first; fallback to poll
        used_watchdog = self._watchdog_setup()
        if not used_watchdog:
            logger.info("watchdog unavailable; using 5s poll fallback")
            self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._poll_thread.start()
        self._running = True

    def stop(self) -> None:
        """Stop watching. Idempotent. Flushes state on shutdown."""
        if not self._running:
            return
        # ensure state survives shutdown
        if self._last_seen_ts > 0:
            self._atomic_write_state(self._last_seen_ts)
        if self._stop_evt:
            self._stop_evt.set()
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=5.0)
            except Exception:
                pass
            self._observer = None
        if self._poll_thread:
            self._poll_thread.join(timeout=6.0)
            self._poll_thread = None
        self._running = False
