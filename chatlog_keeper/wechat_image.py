"""wechat_image_ocr.py — WeChat 4.x image .dat decrypt + OCR pipeline.

WeChat 4.x image storage:
  xwechat_files/wxid_xx/msg/attach/<chatroom_hash>/<YYYY-MM>/Img/<hash>.dat
Encryption variants observed:
  V1 (legacy 3.x compat): single-byte XOR with auto-derived key from
    JPEG/PNG/GIF magic. Header bytes are encrypted JPEG header. Direct
    pattern: bytes[0] ^ bytes[2] = 0x00 (JPEG `FF D8 FF` after XOR-key
    cancellation leaves identical 1st/3rd bytes). Solve key = bytes[0]
    ^ 0xFF (assuming JPEG).
  V2 (4.x new): AES-128-CBC wrapped. Header `07 08 56 32 ...` 16-byte
    metadata. Body = AES-encrypted JPEG. AES key derivation requires
    wxid hash, not msg-level aeskey. **Reverse engineering of full V2
    key derivation is a research-grade work item; framework here stubs
    V2 path so that when implemented elsewhere this pipeline just works.

Public API:
  - decrypt_wechat_dat(path: Path) → bytes | None
  - ocr_image_bytes(image_bytes: bytes) → str  (paddleocr, lazy init)
  - ocr_wechat_dat(path: Path) → dict {ok, text, error, ...}
  - ocr_cache_get / ocr_cache_set (sha256 cache)

Heavy paddleocr init is lazy (first call). Subsequent calls reuse the
loaded model. Cache: data/wechat_ocr_cache/<sha-prefix>/<sha>.json.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

_REPO = Path(__file__).resolve().parents[1]
_OCR_CACHE_DIR = _REPO / "data" / "wechat_ocr_cache"

# Image magic bytes for format detection + legacy XOR key recovery.
_JPEG_HEAD = b"\xff\xd8\xff"
_PNG_HEAD = b"\x89PNG"
_GIF_HEAD = b"GIF8"
_WEBP_HEAD = b"RIFF"
_WXGF_HEAD = b"wxgf"

# V1/V2 dat format magic. WeChat 4.x packed format:
#   [6B sig "07 08 V1/V2 08 07"] [4B aes_size LE] [4B xor_size LE] [1B pad] + body
_V1_SIG = b"\x07\x08V1\x08\x07"
_V2_SIG = b"\x07\x08V2\x08\x07"

# V1 fixed AES key (hardcoded by WeChat client across all installs; observed
# from open-source reverse engineering 2025-08+).
_V1_FIXED_AES_KEY = b"cfcd208495d565ef"

# Default XOR key for the trailing XOR section. V1 uses 0x88; V2 derives the
# key dynamically per WeChat account from `_t.dat` thumbnail tails (JPEG ends
# with FF D9, so xor_key = thumb_tail[0] ^ 0xFF, validated against thumb_tail[1]
# ^ 0xD9). The V2 key is account-specific. When integrating, prefer to call
# derive_v2_xor_key() at startup.
_DEFAULT_XOR_KEY = 0x88
_V2_XOR_KEY_OVERRIDE = None  # set via derive_v2_xor_key()


_V2_UIN_CACHE_PATH_FN = lambda: (
    Path(__file__).resolve().parents[1] / "data" / "secrets" / "wechat_v2_uin.txt"
)


def derive_v2_xor_key(attach_root: Path) -> Optional[int]:
    """Compute V2 XOR key. Three-tier strategy:

      1. Read cached UIN from data/secrets/wechat_v2_uin.txt → xor = uin & 0xFF
         (most accurate; UIN is invariant per WeChat account)
      2. Fall back to thumbnail-tail sampling (works only if thumbs are
         actually V2-encoded; legacy thumbs would mislead this heuristic)
      3. Return None → caller falls back to _DEFAULT_XOR_KEY (0x88, legacy)

    Tier 1 is preferred: tier 2 (thumbnail-tail) is OFTEN WRONG for large V2
    images because (a) thumbnails might be legacy, (b) the JPEG EOI
    `\xff\xd9` byte heuristic produces the same pair on multiple keys.
    """
    global _V2_XOR_KEY_OVERRIDE
    if _V2_XOR_KEY_OVERRIDE is not None:
        return _V2_XOR_KEY_OVERRIDE

    # Tier 1: cached UIN file → deterministic xor_key = uin & 0xFF
    uin_path = _V2_UIN_CACHE_PATH_FN()
    if uin_path.exists():
        try:
            uin_str = uin_path.read_text(encoding="utf-8").strip()
            if uin_str.isdigit():
                uin = int(uin_str)
                xor_key = uin & 0xFF
                _V2_XOR_KEY_OVERRIDE = xor_key
                logger.debug(f"derive_v2_xor_key tier1: uin={uin} → xor=0x{xor_key:02x}")
                return xor_key
        except (OSError, ValueError):
            pass

    if not attach_root.exists():
        return None
    candidates: dict[int, int] = {}
    n_seen = 0
    for chatroom in attach_root.iterdir():
        if not chatroom.is_dir():
            continue
        for month_dir in chatroom.iterdir():
            if not month_dir.is_dir():
                continue
            img_dir = month_dir / "Img"
            if not img_dir.exists():
                continue
            for dat in img_dir.glob("*_t.dat"):
                try:
                    sz = dat.stat().st_size
                    with open(dat, "rb") as f:
                        head = f.read(6)
                        f.seek(sz - 2)
                        tail = f.read(2)
                except OSError:
                    continue
                if head != _V2_SIG or len(tail) != 2:
                    continue
                xor_a = tail[0] ^ 0xFF
                xor_b = tail[1] ^ 0xD9
                if xor_a == xor_b:
                    candidates[xor_a] = candidates.get(xor_a, 0) + 1
                    n_seen += 1
                    if n_seen >= 50:
                        break
            if n_seen >= 50:
                break
        if n_seen >= 50:
            break
    if not candidates:
        return None
    best = max(candidates.items(), key=lambda x: x[1])
    if best[1] >= 5:
        _V2_XOR_KEY_OVERRIDE = best[0]
        return best[0]
    return None

# Path where V2 AES key is cached after first successful extraction.
# (key is extracted from Weixin.exe process memory; ASCII 16-char alphanumeric)
_V2_KEY_CACHE_PATH_FN = lambda: (
    Path(__file__).resolve().parents[1] / "data" / "secrets" / "wechat_v2_image_aes.key"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_encrypt_variant(head: bytes) -> str:
    """Inspect first 16 bytes of .dat. Returns one of:
      'legacy_xor' — single-byte XOR JPEG/PNG/GIF (legacy 3.x + early 4.x)
      'v1'         — 07 08 V1 08 07 header + fixed AES key cfcd208495d565ef
      'v2'         — 07 08 V2 08 07 header + memory-extracted AES key
      'unknown'

    Format reverse-engineered from ylytdeng/wechat-decrypt (2025-08+).
    Note: backward-compat 'v1' string was previously used for legacy_xor;
    callers should now check against the new names.
    """
    if len(head) < 6:
        return "unknown"
    if head[:6] == _V2_SIG:
        return "v2"
    if head[:6] == _V1_SIG:
        return "v1"
    # legacy: try single-byte XOR magic recovery
    if _derive_v1_key(head) is not None:
        return "legacy_xor"
    return "unknown"


def _xor_decrypt(data: bytes, key: int) -> bytes:
    """Single-byte XOR. WeChat V1 dat uses this with auto-derived key."""
    return bytes(b ^ key for b in data)


def _derive_v1_key(head: bytes) -> Optional[int]:
    """Recover XOR key from .dat first bytes assuming JPEG/PNG/GIF plaintext.

    Returns None if no recognized magic matches under any single-byte XOR.
    """
    if len(head) < 4:
        return None
    # Try JPEG: plain[0..2] = FF D8 FF → key = head[0] ^ 0xFF
    k = head[0] ^ 0xFF
    if (head[1] ^ k) == 0xD8 and (head[2] ^ k) == 0xFF:
        return k
    # Try PNG: plain[0..3] = 89 50 4E 47
    k = head[0] ^ 0x89
    if (head[1] ^ k) == 0x50 and (head[2] ^ k) == 0x4E and (head[3] ^ k) == 0x47:
        return k
    # Try GIF: plain[0..3] = 47 49 46 38
    k = head[0] ^ 0x47
    if (head[1] ^ k) == 0x49 and (head[2] ^ k) == 0x46 and (head[3] ^ k) == 0x38:
        return k
    return None


def _aligned_aes_size(aes_size: int) -> int:
    """V2 AES-ECB section is PKCS7-padded; align to next 16-byte boundary.

    wx-cli formula (verified 2026-05-18): aes_size + (16 - aes_size % 16).
    When aes_size is already a multiple of 16, this returns aes_size + 16
    (PKCS7 always pads a full block when input is block-aligned).
    """
    return aes_size + (16 - aes_size % 16)


def _parse_v1v2_header(data: bytes):
    """Parse 15-byte V1/V2 header. Returns (sig_bytes, aes_size, xor_size)."""
    import struct
    if len(data) < 15:
        return None, 0, 0
    sig = data[:6]
    aes_size, xor_size = struct.unpack_from("<LL", data, 6)
    return sig, aes_size, xor_size


def _decrypt_v1v2(data: bytes, aes_key: bytes, xor_key: int = _DEFAULT_XOR_KEY) -> Optional[bytes]:
    """Decrypt V1/V2 .dat data with given AES-128 key + XOR key.

    Layout: [15B header][aligned_aes_size AES-ECB][raw mid][xor_size XOR]
    """
    try:
        from Crypto.Cipher import AES
        from Crypto.Util import Padding
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
            from Cryptodome.Util import Padding
        except ImportError:
            logger.warning("pycryptodome not installed — cannot decrypt V1/V2 dat")
            return None

    sig, aes_size, xor_size = _parse_v1v2_header(data)
    if sig is None or sig not in (_V1_SIG, _V2_SIG):
        return None

    aligned = _aligned_aes_size(aes_size)
    offset = 15
    if offset + aligned > len(data):
        return None

    aes_chunk = data[offset:offset + aligned]
    try:
        cipher = AES.new(aes_key[:16], AES.MODE_ECB)
        dec_aes = Padding.unpad(cipher.decrypt(aes_chunk), AES.block_size)
    except (ValueError, KeyError) as e:
        logger.debug(f"V1/V2 AES decrypt failed: {e}")
        return None

    offset += aligned
    raw_end = len(data) - xor_size
    raw_mid = data[offset:raw_end] if offset < raw_end else b""
    xor_chunk = data[raw_end:]
    dec_xor = bytes(b ^ xor_key for b in xor_chunk)

    return dec_aes + raw_mid + dec_xor


# ─────────── V2 AES key extraction from Weixin.exe process memory ───────────
_V2_KEY_CACHE: Optional[bytes] = None


def _get_wechat_image_pids() -> list:
    """Return list of PIDs that may hold V2 image AES key.

    WeChat 4.x architecture: main Weixin.exe spawns multiple WeChatAppEx.exe
    CEF subprocesses for image preview / file panels. The image decrypt path
    runs inside WeChatAppEx.exe, so the V2 AES key (16/32-char ASCII alnum)
    only appears in the subprocess heap. Scanning Weixin.exe alone returns
    no candidates (verified empirically: tens of thousands of candidates, 0
    hits, when scanning Weixin.exe only).

    This enumerator returns BOTH image-names' PIDs sorted by likelihood:
      1. Weixin.exe (oldest first — historic key location, legacy path)
      2. WeChatAppEx.exe (oldest first — CEF subprocess where 4.x decrypts)
    """
    import subprocess as _sub
    pids: list[int] = []
    for img_name in ("Weixin.exe", "WeChatAppEx.exe"):
        try:
            r = _sub.run(
                ["tasklist", "/FO", "CSV", "/FI", f"IMAGENAME eq {img_name}"],
                capture_output=True, timeout=30,
            )
            text = r.stdout.decode("gbk", errors="replace")
            for line in text.strip().splitlines()[1:]:
                parts = line.split('","')
                if len(parts) >= 2:
                    try:
                        pids.append(int(parts[1]))
                    except ValueError:
                        pass
        except Exception as e:
            logger.warning(f"PID lookup {img_name} failed: {e}")
    # Stable order: sorted ascending (oldest first)
    return sorted(set(pids))


def load_cached_v2_key() -> Optional[bytes]:
    """Read V2 AES key from disk cache.

    The WeChat 4.x V2 image AES key is derived deterministically from UIN + wxid.
    Algorithm:
        aes_key = md5(f"{uin}{wxid_normalized}").hexdigest()[:16].encode('ascii')
        xor_key = uin & 0xFF
    The key is stored as the 16-char ASCII string (e.g. "0123456789abcdef"),
    which is just the first 16 hex chars of the md5 digest — i.e. ALPHANUMERIC
    alphabetic limited to 0-9a-f. This explains why earlier alphanumeric memory
    scans missed it: the key IS alphanumeric, but it lives transiently in the
    AES function stack frame during decryption — not in long-lived heap strings.

    Cache file format (preferred): 16-char lowercase hex ASCII string.
    Back-compat: 32-char hex (raw 16-byte binary representation).
    """
    p = _V2_KEY_CACHE_PATH_FN()
    if not p.exists():
        return None
    try:
        s = p.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    # Strip UTF-8 BOM if present (PowerShell Set-Content may add it)
    if s.startswith("﻿"):
        s = s.lstrip("﻿")
    # 2026-05-18 preferred format: 16-char ASCII hex prefix
    if len(s) == 16 and all(c in "0123456789abcdefABCDEF" for c in s):
        return s.encode("ascii")
    # Legacy fallback: 32-char hex → decode to 16 raw bytes
    if len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    # Other ASCII alphanumeric forms
    if 16 <= len(s) <= 32 and s.isalnum():
        return s.encode("ascii")[:16]
    return None


def save_cached_v2_key(key: bytes) -> bool:
    """Persist V2 AES key.

    Prefer 16-byte ASCII (e.g. md5-hex-prefix derived from UIN+wxid) since that's
    the WeChat 4.x native format. Falls back to 32-char hex for binary keys.
    """
    p = _V2_KEY_CACHE_PATH_FN()
    if not isinstance(key, (bytes, bytearray)) or len(key) != 16:
        logger.warning(f"save_cached_v2_key: invalid key (type={type(key).__name__}, "
                       f"len={len(key) if hasattr(key, '__len__') else '?'}); expected 16 bytes")
        return False
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        # If key bytes are all printable ASCII (alphanumeric incl. hex), save as-is
        if all(0x30 <= b <= 0x7A for b in key) and bytes(key).isalnum():
            p.write_text(bytes(key).decode("ascii"), encoding="utf-8")
        else:
            p.write_text(bytes(key).hex(), encoding="utf-8")
        return True
    except OSError:
        return False


_BLANK_NONWHITE_RATIO = 0.01  # < 1% non-white pixels → treat as blank placeholder frame


def _nonwhite_ratio(jpeg_bytes: bytes) -> float:
    """Fraction of non-white pixels in a JPEG (downsampled grayscale).

    Returns -1.0 if PIL is unavailable / decode fails (caller treats as
    "unknown" → keeps single-frame behavior, no regression). A pure-white
    placeholder frame returns ~0.0; a real screenshot returns >> 0.01.
    """
    try:
        import io as _io
        from PIL import Image
        im = Image.open(_io.BytesIO(jpeg_bytes)).convert("L")
        im.thumbnail((128, 128))
        px = list(im.getdata())
        if not px:
            return 0.0
        return sum(1 for p in px if p < 240) / len(px)
    except Exception:
        return -1.0


def wxgf_to_jpeg(wxgf_bytes: bytes, timeout_s: float = 15.0) -> Optional[bytes]:
    """Convert wxgf (WeChat custom HEVC Main Still Picture) to JPEG via ffmpeg.

    wxgf layout (reverse-engineered):
      [4B "wxgf"] [variable-len wechat metadata, can be 16B-1KB+]
      [HEVC NAL bitstream, may start with 4-byte (00 00 00 01) or 3-byte
       (00 00 01) Annex-B start code]

    Strategy (full coverage):
      1) Search the NAL start code in the first 8KB (metadata routinely runs
         > 256B, so a 256B window only transcoded ~60% of wxgf).
      2) Try both 4-byte and 3-byte Annex-B markers.
      3) Fallback A: feed entire wxgf (post-"wxgf" magic) to ffmpeg and let
         ffmpeg's stream-detect figure it out.
      4) Fallback B: append a synthesized HEVC SPS/PPS header (last-resort).
    """
    if wxgf_bytes[:4] != _WXGF_HEAD:
        return None

    # Strategy 1+2: scan first 8KB for NAL start code (4-byte or 3-byte)
    nal_off = -1
    head_search = wxgf_bytes[:8192]
    for i in range(4, len(head_search) - 4):
        if head_search[i:i+4] == b"\x00\x00\x00\x01":
            nal_off = i
            break
        if head_search[i:i+3] == b"\x00\x00\x01":
            nal_off = i
            break

    import subprocess
    import shutil
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        logger.warning("wxgf_to_jpeg: ffmpeg not in PATH; cannot transcode")
        return None

    def _try_ffmpeg(stream: bytes) -> Optional[bytes]:
        if not stream:
            return None
        try:
            r = subprocess.run(
                [ffmpeg, "-loglevel", "error", "-y",
                 "-f", "hevc", "-i", "pipe:0",
                 "-vframes", "1", "-q:v", "2",
                 "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1"],
                input=stream,
                capture_output=True,
                timeout=timeout_s,
            )
            if (r.returncode == 0 and len(r.stdout) > 1000
                    and r.stdout[:3] == _JPEG_HEAD):
                return r.stdout
            return None
        except (subprocess.TimeoutExpired, OSError):
            return None

    def _try_ffmpeg_multiframe(stream: bytes, n: int = 8) -> Optional[bytes]:
        # Some wxgf are 2-frame grayscale HEVC where frame-1 is a pure-white
        # placeholder and frame-2 carries the real content (e.g. some
        # screenshots). `-vframes 1` grabbed the white frame → vision saw blank.
        # Extract up to n frames and return the one with the most non-white
        # pixels. Single-frame wxgf never reaches here (frame-1 not blank).
        if not stream:
            return None
        import glob as _glob
        import os as _os
        import tempfile as _tf
        try:
            with _tf.TemporaryDirectory() as td:
                pat = _os.path.join(td, "f_%03d.jpg")
                subprocess.run(
                    [ffmpeg, "-loglevel", "error", "-y",
                     "-f", "hevc", "-i", "pipe:0",
                     "-frames:v", str(n), "-q:v", "2", pat],
                    input=stream, capture_output=True, timeout=timeout_s,
                )
                best, best_r = None, -1.0
                for fp in sorted(_glob.glob(_os.path.join(td, "f_*.jpg"))):
                    try:
                        b = open(fp, "rb").read()
                    except OSError:
                        continue
                    if len(b) <= 1000 or b[:3] != _JPEG_HEAD:
                        continue
                    rr = _nonwhite_ratio(b)
                    if rr > best_r:
                        best, best_r = b, rr
                return best
        except (subprocess.TimeoutExpired, OSError):
            return None

    def _extract(stream: bytes) -> Optional[bytes]:
        """Single-frame first (byte-identical to legacy for normal images);
        if that frame is blank-white, recover the best content frame."""
        out = _try_ffmpeg(stream)
        if not out:
            return None
        r = _nonwhite_ratio(out)
        if 0.0 <= r < _BLANK_NONWHITE_RATIO:  # frame-1 white (PIL ok) → try frame-2+
            better = _try_ffmpeg_multiframe(stream)
            if better is not None and _nonwhite_ratio(better) > r:
                return better
        return out  # r==-1 (no PIL) or non-blank → legacy behavior, zero regression

    # Attempt 1: stream from found NAL marker
    if nal_off >= 0:
        out = _extract(wxgf_bytes[nal_off:])
        if out:
            return out

    # Fallback A: feed entire payload after "wxgf" magic (skip 4-byte header)
    # — ffmpeg's HEVC demuxer may auto-detect later NAL markers in big files.
    out = _extract(wxgf_bytes[4:])
    if out:
        return out

    # Fallback B: try various metadata-size guesses (16/32/64 byte headers)
    for skip in (16, 32, 64, 128, 256, 512, 1024):
        if skip >= len(wxgf_bytes):
            break
        out = _extract(wxgf_bytes[skip:])
        if out:
            return out

    logger.debug(
        f"wxgf_to_jpeg: all fallbacks failed (size={len(wxgf_bytes)} "
        f"nal_off={nal_off} head_hex={wxgf_bytes[:32].hex()})"
    )
    return None


def derive_v2_key_from_uin(uin: int, wxid: str) -> bytes:
    """Compute V2 AES key from (uin, wxid) — deterministic, no memory scan.

    From jackwener/wx-cli macos.rs derive_image_key_material:
        digest = md5(f'{uin}{wxid}').hexdigest()
        aes_key = digest[:16].encode('ascii')  # 16 ASCII hex chars
        xor_key = uin & 0xFF
    `wxid` should be the normalized form (e.g. "wxid_exampleAAAAAAA",
    NOT the full "wxid_exampleAAAAAAA_6bae" with the _xxxx suffix).
    """
    import hashlib
    digest = hashlib.md5(f"{uin}{wxid}".encode("utf-8")).hexdigest()
    return digest[:16].encode("ascii")


def _validate_v2_key(candidate: bytes, v2_dat_path: Path) -> bool:
    """Test if a candidate AES key correctly decrypts a real V2 dat.

    Magic-byte validation: decrypted first 16 bytes should be one of
    JPEG / PNG / WEBP / WXGF / GIF.
    """
    try:
        with open(v2_dat_path, "rb") as f:
            data = f.read(15 + 64)  # header + small AES probe
    except OSError:
        return False
    if len(data) < 15 + 32:
        return False
    sig, aes_size, _xor_size = _parse_v1v2_header(data)
    if sig != _V2_SIG or aes_size < 16:
        return False
    try:
        from Crypto.Cipher import AES
    except ImportError:
        from Cryptodome.Cipher import AES
    aes_chunk = data[15:15 + 16]  # 1 AES block
    try:
        dec = AES.new(candidate[:16], AES.MODE_ECB).decrypt(aes_chunk)
    except (ValueError, KeyError):
        return False
    return (dec[:3] == _JPEG_HEAD
            or dec[:4] == _PNG_HEAD
            or dec[:4] == _WEBP_HEAD
            or dec[:4] == _WXGF_HEAD
            or dec[:3] == b"GIF")


def find_v2_key_in_weixin_memory(sample_v2_dat: Path,
                                    progress_cb=None) -> Optional[bytes]:
    """Scan Weixin.exe process memory for V2 image AES key.

    Algorithm (extended from ylytdeng/wechat-decrypt reverse):
      1. enumerate Weixin.exe PIDs
      2. walk readable memory regions (PROCESS_VM_READ + QUERY_INFORMATION)
      3. find both 16-char and 32-char alphanumeric byte runs (word boundary)
      4. validate each as direct ASCII key OR hex-decoded 16-byte key
      5. return first matching key

    NOTE: AES image key is only loaded in memory when user actively views an
    image in WeChat client. If no image was recently viewed, key won't be in
    memory and this returns None. Use `extract_v2_key_monitor` for continuous
    polling that catches the key window.

    Returns 16-byte AES key on success, None on failure.
    """
    import ctypes
    import ctypes.wintypes as wt

    # WeChat 4.x image render/decrypt runs in the WeChatAppEx.exe subprocess
    # (CEF browser frame), NOT in the main Weixin.exe. Scanning Weixin.exe only
    # keeps missing the key, so enumerate both image-names + scan all matching
    # PIDs.
    pids = _get_wechat_image_pids()
    if not pids:
        logger.warning(
            "Neither Weixin.exe nor WeChatAppEx.exe running — "
            "cannot extract V2 image key"
        )
        return None
    logger.info(
        f"Scanning {len(pids)} WeChat PIDs for V2 image key: {pids}"
    )

    kernel32 = ctypes.windll.kernel32
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    MEM_COMMIT = 0x1000
    READABLE_PROTECTS = {0x02, 0x04, 0x20, 0x40, 0x80}

    class MBI64(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_uint64),
            ("AllocationBase", ctypes.c_uint64),
            ("AllocationProtect", wt.DWORD),
            ("__a1", wt.DWORD),
            ("RegionSize", ctypes.c_uint64),
            ("State", wt.DWORD),
            ("Protect", wt.DWORD),
            ("Type", wt.DWORD),
            ("__a2", wt.DWORD),
        ]

    def _is_alnum_byte(b: int) -> bool:
        return (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A)

    def _is_hex_byte(b: int) -> bool:
        return (0x30 <= b <= 0x39) or (0x41 <= b <= 0x46) or (0x61 <= b <= 0x66)

    def _try_candidate(cand: bytes) -> Optional[bytes]:
        """Validate cand as direct ASCII key OR hex-decoded key."""
        # Direct 16-char ASCII
        if len(cand) == 16 and _validate_v2_key(cand, sample_v2_dat):
            return cand
        # 32-char hex → 16-byte binary key
        if len(cand) == 32 and all(_is_hex_byte(b) for b in cand):
            try:
                decoded = bytes.fromhex(cand.decode("ascii"))
                if _validate_v2_key(decoded, sample_v2_dat):
                    return decoded
            except (ValueError, UnicodeDecodeError):
                pass
        # 32-char alphanumeric as direct (test first 16 bytes only)
        if len(cand) == 32 and _validate_v2_key(cand[:16], sample_v2_dat):
            return cand[:16]
        return None

    seen = set()
    regions_scanned = 0
    for pid in pids:
        handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            mbi = MBI64()
            address = 0
            while address < 0x7FFFFFFFFFFF:
                ret = kernel32.VirtualQueryEx(
                    handle, ctypes.c_uint64(address),
                    ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not ret:
                    break
                if (mbi.State == MEM_COMMIT
                        and mbi.Protect in READABLE_PROTECTS
                        and 0 < mbi.RegionSize < 200 * 1024 * 1024):
                    buf = ctypes.create_string_buffer(mbi.RegionSize)
                    read_n = ctypes.c_size_t(0)
                    kernel32.ReadProcessMemory(
                        handle, ctypes.c_uint64(mbi.BaseAddress),
                        buf, mbi.RegionSize, ctypes.byref(read_n))
                    chunk = bytes(buf[:read_n.value])
                    n = len(chunk)
                    regions_scanned += 1
                    if progress_cb and regions_scanned % 100 == 0:
                        progress_cb(regions_scanned, len(seen))
                    i = 0
                    while i < n:
                        if _is_alnum_byte(chunk[i]):
                            j = i
                            while j < n and _is_alnum_byte(chunk[j]):
                                j += 1
                            run_len = j - i
                            # Try 16-char and 32-char runs
                            if run_len in (16, 32):
                                # Word boundary
                                if ((i == 0 or not _is_alnum_byte(chunk[i - 1]))
                                        and (j == n or not _is_alnum_byte(chunk[j]))):
                                    cand = chunk[i:j]
                                    if cand not in seen:
                                        seen.add(cand)
                                        result = _try_candidate(cand)
                                        if result:
                                            logger.info(
                                                f"V2 AES key found PID {pid} "
                                                f"(scanned {len(seen)} candidates) "
                                                f"preview={result[:4].hex()}")
                                            return result
                            i = j + 1
                        else:
                            i += 1
                nxt = mbi.BaseAddress + mbi.RegionSize
                if nxt <= address:
                    break
                address = nxt
        finally:
            kernel32.CloseHandle(handle)
    logger.warning(
        f"V2 key not found ({len(seen)} candidates tested in {regions_scanned} regions). "
        f"Action: in WeChat, open + view an image, then re-run."
    )
    return None


def extract_v2_key_monitor(sample_v2_dat: Path,
                            interval_sec: int = 30,
                            max_attempts: int = 120) -> Optional[bytes]:
    """Continuous monitor mode — repeatedly scan memory until V2 key found.

    Default: 120 attempts × 30s = 60min total window. User should open WeChat
    and view at least one image during this window.

    Returns 16-byte key on success, None after max_attempts.
    """
    import time
    for attempt in range(1, max_attempts + 1):
        logger.info(f"V2 key extract attempt {attempt}/{max_attempts}...")
        key = find_v2_key_in_weixin_memory(sample_v2_dat)
        if key:
            save_cached_v2_key(key)
            return key
        if attempt < max_attempts:
            time.sleep(interval_sec)
    return None


def decrypt_wechat_dat(path: Path) -> Optional[bytes]:
    """Decrypt a WeChat .dat → raw JPEG/PNG/GIF/WEBP/HEVC bytes.

    Handles all 3 known formats:
      legacy_xor — single-byte XOR (3.x + early 4.x)
      V1 (07 08 V1 08 07) — fixed AES key cfcd208495d565ef + XOR 0x88
      V2 (07 08 V2 08 07) — process-memory-extracted AES key + XOR 0x88

    Returns decrypted bytes or None if decrypt fails (e.g. V2 + no key cached
    and Weixin not running). For V2, the AES key is auto-extracted from
    Weixin.exe memory on first call, then cached to disk.
    """
    global _V2_KEY_CACHE
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        logger.debug(f"dat read failed {path}: {e}")
        return None
    if len(data) < 4:
        return None
    variant = _detect_encrypt_variant(data[:16])

    if variant == "legacy_xor":
        key = _derive_v1_key(data[:16])
        if key is None:
            return None
        decrypted = _xor_decrypt(data, key)
        if (decrypted[:3] == _JPEG_HEAD or decrypted[:4] == _PNG_HEAD
                or decrypted[:4] == _GIF_HEAD):
            return decrypted
        return None

    if variant == "v1":
        return _decrypt_v1v2(data, _V1_FIXED_AES_KEY, _DEFAULT_XOR_KEY)

    if variant == "v2":
        if _V2_KEY_CACHE is None:
            _V2_KEY_CACHE = load_cached_v2_key()
        if _V2_KEY_CACHE is None:
            logger.debug(
                f"V2 dat {path.name}: no AES key cached; "
                f"run scripts/_v2_uin_bruteforce.py to derive from wxid"
            )
            return None
        attach_root = path.parent.parent.parent
        xor_key = derive_v2_xor_key(attach_root) or _DEFAULT_XOR_KEY
        result = _decrypt_v1v2(data, _V2_KEY_CACHE, xor_key)
        if result is None:
            return None
        # A large fraction of V2 dat decrypt to `wxgf` (WeChat custom HEVC Main
        # Still Picture). Auto-transcode via ffmpeg so the vision API gets JPEG.
        if result[:4] == _WXGF_HEAD:
            jpeg = wxgf_to_jpeg(result)
            if jpeg is not None:
                return jpeg
            # ffmpeg unavailable / decode failed — return raw wxgf for caller
            # to handle (vision API won't recognize but at least bytes recovered)
        return result

    return None


# ─────────── OCR lazy init (easyocr primary, paddleocr fallback) ───────────
_OCR_INSTANCE = None
_OCR_BACKEND = None  # "easyocr" | "paddleocr" | "none"


def _get_ocr():
    """Lazy-init OCR. Tries rapidocr-onnxruntime (no torch, Win-stable),
    falls through to easyocr (torch-based) then paddleocr if needed.

    rapidocr is preferred: pure ONNX runtime + lightweight + no numpy ABI
    conflict (the easyocr/paddleocr torch binaries were compiled against
    older numpy and crash on numpy 2.x).
    """
    global _OCR_INSTANCE, _OCR_BACKEND
    if _OCR_INSTANCE is not None:
        return _OCR_INSTANCE if _OCR_INSTANCE is not False else None
    # Tier 1: rapidocr (ONNX, lightest)
    try:
        from rapidocr_onnxruntime import RapidOCR
        _OCR_INSTANCE = RapidOCR()
        _OCR_BACKEND = "rapidocr"
        logger.info("OCR backend: rapidocr-onnxruntime")
        return _OCR_INSTANCE
    except Exception as e:
        logger.warning(f"rapidocr init failed: {e}")
    # Tier 2: easyocr
    try:
        import easyocr
        _OCR_INSTANCE = easyocr.Reader(["ch_sim", "en"], gpu=False, verbose=False)
        _OCR_BACKEND = "easyocr"
        logger.info("OCR backend: easyocr")
        return _OCR_INSTANCE
    except Exception as e:
        logger.warning(f"easyocr init failed: {e}")
    # Tier 3: paddleocr
    try:
        from paddleocr import PaddleOCR
        _OCR_INSTANCE = PaddleOCR(lang="ch", use_textline_orientation=False)
        _OCR_BACKEND = "paddleocr"
        logger.info("OCR backend: paddleocr")
        return _OCR_INSTANCE
    except Exception as e:
        logger.warning(f"paddleocr fallback failed: {e}")
    _OCR_INSTANCE = False
    _OCR_BACKEND = "none"
    return None


def ocr_image_bytes(image_bytes: bytes) -> str:
    """Run OCR on raw image bytes. Returns extracted text (empty on failure).

    Backend auto-selected (easyocr ↔ paddleocr). Tolerant of either output
    shape: easyocr returns list of (bbox, text, conf), paddleocr returns
    list of dicts.
    """
    if not image_bytes:
        return ""
    ocr = _get_ocr()
    if ocr is None:
        return ""
    try:
        import numpy as np
        import cv2
        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return ""
        if _OCR_BACKEND == "rapidocr":
            # rapidocr __call__ returns (result, elapse). Result is list of
            # [bbox, text, confidence] or None.
            result, _elapse = ocr(img)
            if not result:
                return ""
            lines = [str(r[1]).strip() for r in result if r and len(r) >= 2]
            return " ".join(filter(None, lines))[:2000]
        elif _OCR_BACKEND == "easyocr":
            # easyocr returns list of (bbox, text, confidence) tuples
            results = ocr.readtext(img, detail=1, paragraph=False)
            lines = [str(r[1]).strip() for r in results if r and len(r) >= 2]
            return " ".join(filter(None, lines))[:2000]
        elif _OCR_BACKEND == "paddleocr":
            result = ocr.predict(img)
            lines = []
            for r in result or []:
                if isinstance(r, dict):
                    rec = r.get("rec_texts") or r.get("texts") or []
                    for txt in rec:
                        if txt:
                            lines.append(str(txt).strip())
            return " ".join(lines)[:2000]
        return ""
    except Exception as e:
        logger.debug(f"OCR fail: {e}")
        return ""


def ocr_cache_path(content_sha: str) -> Path:
    return _OCR_CACHE_DIR / content_sha[:2] / f"{content_sha}.json"


def ocr_cache_get(content_sha: str) -> Optional[str]:
    p = ocr_cache_path(content_sha)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("text", "")
    except Exception:
        return None


def ocr_cache_set(content_sha: str, text: str) -> None:
    p = ocr_cache_path(content_sha)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps({"text": text, "len": len(text)}, ensure_ascii=False),
                     encoding="utf-8")
    except Exception:
        pass


def ocr_wechat_dat(path: Path) -> Dict[str, Any]:
    """High-level: decrypt + OCR + cache. Returns dict with status."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return {"ok": False, "error": f"read_fail: {e}", "text": "",
                "path": str(path), "variant": "unknown"}
    if len(raw) < 4:
        return {"ok": False, "error": "too_small", "text": "",
                "path": str(path), "variant": "unknown"}
    sha = _sha256_bytes(raw)
    cached = ocr_cache_get(sha)
    if cached is not None:
        return {"ok": True, "text": cached, "cached": True,
                "path": str(path), "sha": sha, "variant": "cached"}
    variant = _detect_encrypt_variant(raw[:16])
    decrypted = decrypt_wechat_dat(path)
    if decrypted is None:
        # V2 or unknown — defer OCR
        result = {
            "ok": False,
            "error": "decrypt_unsupported" if variant == "v2" else "unknown_variant",
            "text": "",
            "path": str(path),
            "sha": sha,
            "variant": variant,
            "ocr_pending": variant == "v2",  # V2 OCR pending key availability
        }
        # Cache empty so re-runs skip
        if variant != "v2":
            ocr_cache_set(sha, "")
        return result
    text = ocr_image_bytes(decrypted)
    ocr_cache_set(sha, text)
    return {
        "ok": True,
        "text": text,
        "path": str(path),
        "sha": sha,
        "variant": variant,
        "decrypted_size": len(decrypted),
    }


__all__ = [
    "decrypt_wechat_dat",
    "ocr_image_bytes",
    "ocr_wechat_dat",
    "_detect_encrypt_variant",
    "_derive_v1_key",
    "_xor_decrypt",
]
