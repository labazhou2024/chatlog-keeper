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
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import re
import struct
import subprocess
import tempfile
from datetime import datetime, date, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


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


# ─── WeChat process helpers ────────────────────────────────────────────────────

def _get_weixin_pids() -> list:
    """Return list of Weixin.exe PIDs.

    Sorted ASCENDING — smallest PID = oldest = likely parent process that holds
    the SQLCipher enc_keys in heap. This avoids the repeated "Key extraction
    failed" log spam that happens when descending order tries worker pids first.
    """
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

    The 4.x default is ``<drive>/wechat files/xwechat_files`` (user-relocatable to
    any drive); 3.x used ``<Documents>/WeChat Files``. No drive letter is assumed.

    Discovery order (nothing hardcoded):
      1. ``CHATLOG_WECHAT_DATA_ROOT`` env var (explicit override)
      2. every logical drive root: ``<drive>/wechat files/xwechat_files`` +
         ``<drive>/WeChat Files``
      3. real Documents + OneDrive variants
    """
    from chatlog_keeper.core._paths import all_drive_roots, candidate_documents_roots

    candidates: list = []
    env = os.environ.get("CHATLOG_WECHAT_DATA_ROOT", "").strip()
    if env:
        candidates.append(Path(env))
    for drive in all_drive_roots():
        candidates.append(drive / "wechat files" / "xwechat_files")
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
    for item in data_root.iterdir():
        if item.is_dir() and (item.name.startswith("wxid_") or len(item.name) > 10):
            dirs.append(item)
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


# ─── Persistent master-key cache (data/secrets/wechat_db.key, gitignored) ──────
# The WeChat 4.x master key (32 bytes) is per-install STABLE — it changes only on
# reinstall / account-switch, never on app restart or WeChat upgrade. A key
# obtained once (from WCDB setCipherKey or any extractor) is cached and reused
# indefinitely. On WeChat 4.1.10.31+ the plaintext key is no longer reachable in
# the heap, so live _scan_memory_for_key returns nothing — the cache is the ONLY
# working path. Mirrors qq_db.py's qq_db.key cache.
# Written by `chatlog-keeper wechat set-key` / `extract-key`; read here
# cache-first so the reader and the CLI stay in lockstep.

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


def load_cached_wechat_key() -> Optional[bytes]:
    """Read the cached 32-byte master key (64 hex on disk), persistent dir first.
    Never validates here — the caller HMAC-checks against the live DB so a stale
    key self-heals (it just fails _verify_key_v4 and a re-extract is attempted)."""
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
        try:
            if not p.exists():
                continue
            text = p.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
            try:
                return bytes.fromhex(text)
            except ValueError:
                continue
    return None


def save_cached_wechat_key(key: bytes) -> bool:
    """Persist a 32-byte master key (hex). Caller MUST have HMAC-verified it first."""
    if not key or len(key) != 32:
        return False
    p = _wechat_key_cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(bytes(key).hex(), encoding="utf-8")
        return True
    except OSError:
        return False


def _scan_memory_for_key(pid: int, db_path: Path = None,
                         timeout_s: Optional[float] = None) -> Optional[bytes]:
    """
    Scan Weixin.exe process memory for the SQLCipher enc_key.

    Weixin 4.x stores:  x'<64 hex enc_key><32 hex salt>'
    in process heap as plain ASCII.  We scan all readable regions for this
    pattern and validate each candidate with HMAC-SHA512 against db_path page 1.
    """
    kernel32 = ctypes.windll.kernel32
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
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
    except Exception as e:
        logger.error(f"Memory scan error for PID {pid}: {e}")
        return None
    finally:
        kernel32.CloseHandle(handle)


def extract_key_from_weixin(pid: int, db_path: Path = None,
                            timeout_s: Optional[float] = None) -> Optional[bytes]:
    """
    Obtain the Weixin 4.x master key for db_path. Returns 32-byte key or None.

    Acquisition order (cheapest first):
      1. Persistent cache (data/secrets/wechat_db.key), HMAC-validated against the
         live DB's page 1 — no scan, works without WeChat running. On 4.1.10.31 this
         is the only path that yields a key (seed it via `chatlog-keeper wechat set-key`).
      2. Live process-memory scan (works on 4.0.x/older where the plaintext key is
         in the heap; returns nothing on 4.1.10.31). A scanned key that verifies is
         persisted to the cache so future runs skip the scan.
    No key bytes are ever logged (privacy).
    """
    db_page1 = None
    if db_path and Path(db_path).exists():
        try:
            with open(db_path, "rb") as f:
                db_page1 = f.read(4096)
        except OSError:
            db_page1 = None

    # 1. Cache fast-path (self-healing: only used if it HMAC-verifies the live DB).
    if db_page1:
        cached = load_cached_wechat_key()
        if cached and len(cached) == 32 and _verify_key_v4(cached, db_page1):
            logger.info("Using cached Weixin master key (data/secrets/wechat_db.key)")
            return cached

    # 2. Live process-memory scan (fails on 4.1.10.31 — plaintext key not in heap).
    logger.info(f"Attempting key extraction from Weixin PID {pid}")
    key = _scan_memory_for_key(pid, db_path=db_path, timeout_s=timeout_s)
    if key and len(key) == 32:
        # _scan_memory_for_key already HMAC-validates; persist for future runs.
        if db_page1 and _verify_key_v4(key, db_page1):
            if save_cached_wechat_key(key):
                logger.info("Weixin master key extracted from memory and cached")
        return key
    # DEBUG not WARN — initialize batch-tries pids; per-pid failure is normal.
    logger.debug("Key extraction failed for this pid/db combination")
    return None


# ─── Database decryption ──────────────────────────────────────────────────────

def _decrypt_db_v4(db_path: Path, enc_key: bytes, output_path: Path) -> bool:
    """
    Decrypt a Weixin 4.x SQLCipher DB to plain SQLite.

    Page layout (4096 bytes):
      Page 1:  [salt(16)] [AES-CBC encrypted plaintext[16:4016](4000B)] [IV(16)] [HMAC(64)]
      Page N:  [AES-CBC encrypted plaintext[0:4016](4016B)]             [IV(16)] [HMAC(64)]

    enc_key is used directly as the AES key (raw-key mode, no PBKDF2).
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            logger.warning("pycryptodome not installed — cannot decrypt DB")
            return False

    PAGE_SZ = 4096
    SALT_SZ = 16
    RESERVE = 80   # 16 IV + 64 HMAC

    try:
        # Decrypt page-by-page so peak memory stays at a single 4 KB page.
        # Reading the whole DB into memory at once can exhaust RAM (same
        # streaming approach as qq_db).
        pages = 0
        with open(db_path, "rb") as f, open(output_path, "wb") as out:
            first = f.read(PAGE_SZ)
            if len(first) < PAGE_SZ:
                out.write(first)
                logger.warning(f"DB too small to decrypt: {db_path.name}")
                return False
            # Derive the actual AES page key from page-1 salt (handles 4.1.10.31 password
            # mode where enc_key is the master key needing PBKDF2-256000; raw-key for older).
            page_key = _effective_page_key(enc_key, first)
            if page_key is None:
                logger.warning(f"Decryption: enc_key does not fit {db_path.name} (page-1 HMAC fail)")
                return False
            # Page 1: salt(16) + encrypted body + reserve(80)
            iv = first[PAGE_SZ - RESERVE: PAGE_SZ - 64]
            dec = AES.new(page_key, AES.MODE_CBC, iv).decrypt(first[SALT_SZ: PAGE_SZ - RESERVE])
            out.write(b"SQLite format 3\x00" + dec + first[PAGE_SZ - RESERVE:])
            pages = 1
            while True:
                page = f.read(PAGE_SZ)
                if len(page) < PAGE_SZ:
                    if page:
                        out.write(page)
                    break
                iv = page[PAGE_SZ - RESERVE: PAGE_SZ - 64]
                dec = AES.new(page_key, AES.MODE_CBC, iv).decrypt(page[: PAGE_SZ - RESERVE])
                out.write(dec + page[PAGE_SZ - RESERVE:])
                pages += 1

        logger.info(f"Decrypted {pages} pages (streaming) → {output_path}")
        return True
    except Exception as e:
        logger.warning(f"Decryption failed for {db_path.name}: {e}")
        return False


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


# ─── Decrypt cache (30s TTL + mtime invalidate) ────────────────────────────────
# Module-level cache: {src_db_path: (decrypted_tmp_path, src_mtime, decrypted_at)}.
# Cache hit only if src.mtime unchanged AND age < TTL. Cleanup on miss + atexit.

_DECRYPT_CACHE: dict = {}
_DECRYPT_CACHE_TTL = 30.0  # seconds
_DECRYPT_CACHE_LOCK = None  # initialized lazily; threading import deferred


def _emit_decrypt_trace(event: str, payload: dict) -> None:
    try:
        from chatlog_keeper.core.trace_sink import emit  # type: ignore
        emit(event, payload)
    except Exception:
        pass


def _decrypt_with_cache(db_path: Path, enc_key: bytes, ttl: float = _DECRYPT_CACHE_TTL) -> Optional[Path]:
    """Decrypt db_path → reusable tempfile; cache hit if mtime same + age < ttl.

    Returns Path to decrypted tempfile (caller must NOT unlink — cache owns it),
    or None on decrypt failure.
    """
    import threading
    import time as _time

    global _DECRYPT_CACHE_LOCK
    if _DECRYPT_CACHE_LOCK is None:
        _DECRYPT_CACHE_LOCK = threading.Lock()

    if not db_path.exists():
        return None

    src_mtime = db_path.stat().st_mtime
    now = _time.time()

    with _DECRYPT_CACHE_LOCK:
        cached = _DECRYPT_CACHE.get(db_path)
        if cached is not None:
            cached_path, cached_mtime, cached_at = cached
            if (
                cached_mtime == src_mtime
                and (now - cached_at) < ttl
                and cached_path.exists()
            ):
                _emit_decrypt_trace("decrypt_cache_hit", {
                    "db": db_path.name, "age_sec": round(now - cached_at, 2),
                })
                return cached_path
            # Stale: remove old tempfile (best-effort)
            try:
                cached_path.unlink()
            except OSError:
                pass

        # Cache miss: decrypt fresh
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        tmp_path = Path(tmp.name)
        if not _decrypt_db_v4(db_path, enc_key, tmp_path):
            try:
                tmp_path.unlink()
            except OSError:
                pass
            _emit_decrypt_trace("decrypt_cache_miss", {"db": db_path.name, "result": "decrypt_failed"})
            return None

        _DECRYPT_CACHE[db_path] = (tmp_path, src_mtime, now)
        _emit_decrypt_trace("decrypt_cache_miss", {"db": db_path.name, "result": "decrypted_fresh"})
        return tmp_path


def _decrypt_cache_clear():
    """Cleanup all cached tempfiles (called by atexit)."""
    global _DECRYPT_CACHE
    for path, _, _ in list(_DECRYPT_CACHE.values()):
        try:
            path.unlink()
        except OSError:
            pass
    _DECRYPT_CACHE.clear()


import atexit as _atexit
_atexit.register(_decrypt_cache_clear)


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

    def __init__(self):
        self.data_root = None
        self.wxid_dir = None
        self.enc_key = None  # backward-compat: first DB's key (deprecated; prefer enc_keys)
        self.enc_keys: dict = {}  # NEW (2026-04-30): {Path: bytes} per-DB key map
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
        self.data_root = find_weixin_data_root()
        if not self.data_root:
            logger.warning("Weixin data root not found")
            return False

        wxid_dirs = find_wxid_dirs(self.data_root)
        if not wxid_dirs:
            logger.warning("No wxid directories found")
            return False
        self.wxid_dir = wxid_dirs[0]
        logger.info(f"Using wxid dir: {self.wxid_dir}")

        db_files = find_msg_databases(self.wxid_dir)
        if not db_files:
            logger.warning(f"No message databases under {self.wxid_dir}")
            self._initialized = True
            return True

        # Cache-first — a previously-seeded master key
        # (data/secrets/wechat_db.key) decrypts every DB without WeChat even
        # running. On WeChat 4.1.10.31 this is the ONLY working path (the live
        # heap scan below finds nothing). One master key derives each DB's own
        # page key from that DB's salt (see _effective_page_key).
        cached = load_cached_wechat_key()
        if cached and len(cached) == 32:
            for db in db_files:
                try:
                    with open(db, "rb") as f:
                        page1 = f.read(4096)
                except OSError:
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
                key = extract_key_from_weixin(pid, db_path=db, timeout_s=eff_timeout)
                # A truthiness check is insufficient for crypto bytes: also
                # validate the length is 32 (AES-256).
                if key and isinstance(key, (bytes, bytearray)) and len(key) == 32:
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
            logger.warning(f"contact resolver init failed: {e}; messages will use wxid as display")
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
            logger.warning(f"No message databases found under {self.wxid_dir}")
            return []

        all_messages = []
        for db_file in db_files:
            # Per-DB key (2026-04-30 fix): each DB has unique key
            db_key = self.enc_keys.get(db_file)
            if db_key is None:
                logger.warning(f"Skipping {db_file.name}: no enc_key in self.enc_keys")
                continue
            logger.info(f"Querying {db_file.name} (key={db_key.hex()[:16]}...) ...")
            msgs = query_messages_by_date(db_file, target_date, db_key)
            all_messages.extend(msgs)

        all_messages.sort(key=lambda m: m.timestamp)
        # decorate with display names so consumers see human-readable sender/chat
        self._decorate_with_displays(all_messages)
        logger.info(f"Total messages for {date_str}: {len(all_messages)}")
        return all_messages

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
            "key_hex": self.enc_key.hex() if self.enc_key else None,
            "db_files_found": [str(f) for f in db_files],
            "per_db_keys_count": len(self.enc_keys),  # 2026-04-30
            "per_db_keys": {db.name: k.hex()[:16] + "..." for db, k in self.enc_keys.items()},
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
