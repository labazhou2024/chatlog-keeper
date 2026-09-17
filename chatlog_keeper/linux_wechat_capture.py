"""Locate the native x86-64 WCDB KDF boundary without version RVAs.

These are instruction sequences, not keys. The first prepares the password
KDF arguments; the second prepares the two-iteration HMAC-key derivation in
the same codec routine. Runtime argument checks and the database HMAC are
still required. A signature match alone never establishes version support.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
from typing import Optional


PASSWORD_KDF = bytes.fromhex(
    "498b4678"          # mov rax,[r14+78] (provider)
    "498bbe80000000"    # mov rdi,[r14+80] (provider context)
    "458b5e04"          # mov r11d,[r14+04] (iterations)
    "418b7634"          # mov esi,[r14+34] (algorithm)
    "8b4b04"            # mov ecx,[rbx+04] (password length)
    "4d8b4648"          # mov r8,[r14+48] (salt)
    "4883ec08ff730841524153"  # stack: iterations, key length, output
    "ff5030"            # call provider->kdf
)
HMAC_KDF = bytes.fromhex(
    "498b4678498bbe80000000418b7634458b5608418b4e10"
    "4d8b4650488b53084883ec08ff7310514152ff5030"
)


@dataclass(frozen=True)
class KDFBoundary:
    virtual_address: int
    signature_address: int
    image_sha256: str


def locate_kdf_boundary(executable: Path) -> Optional[KDFBoundary]:
    """Fail closed on unknown/ambiguous ELF layouts; never use a fixed RVA."""
    try:
        image = Path(executable).read_bytes()
        if len(image) < 64 or image[:7] != b"\x7fELF\x02\x01\x01":
            return None
        kind, machine = struct.unpack_from("<HH", image, 16)
        if kind != 3 or machine != 62:  # PIE, AMD64
            return None
        phoff = struct.unpack_from("<Q", image, 32)[0]
        size, count = struct.unpack_from("<HH", image, 54)
        if size != 56 or not 0 < count <= 128 or phoff + size * count > len(image):
            return None
        matches = []
        password_matches = 0
        zero_load = False
        for i in range(count):
            typ, flags, off, va, _, filesz, memsz, _ = struct.unpack_from(
                "<IIQQQQQQ", image, phoff + i * size
            )
            if typ != 1:
                continue
            if filesz > memsz or off + filesz > len(image) or va + memsz > 1 << 63:
                return None
            if off == 0 and va == 0:
                zero_load = True
            if not flags & 1:
                continue
            segment = image[off:off + filesz]
            password_matches += segment.count(PASSWORD_KDF)
            start = 0
            while True:
                pos = segment.find(PASSWORD_KDF, start)
                if pos < 0:
                    break
                start = pos + 1
                # The companion HMAC KDF must follow inside the same local
                # routine. Do not select a lone coincidental byte sequence.
                after = segment[pos + len(PASSWORD_KDF):pos + 4096]
                if after.count(HMAC_KDF) == 1:
                    matches.append(va + pos)
        if len(matches) != 1 or password_matches != 1 or not zero_load:
            return None
        address = matches[0]
        return KDFBoundary(
            virtual_address=address + len(PASSWORD_KDF) - 3,
            signature_address=address,
            image_sha256=hashlib.sha256(image).hexdigest(),
        )
    except (OSError, ValueError, struct.error):
        return None
