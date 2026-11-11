"""Synthetic SQLCipher cases for QQ's committed image versus file capacity."""
from __future__ import annotations

import hashlib
import hmac
import struct

import pytest
from Crypto.Cipher import AES

from chatlog_keeper import qq_db


KEY = b"synthetic-qq-key"
SALT = bytes(range(16))
PAGE = 4096


def _plain(page_no, *, count=2, counter=7, valid_for=7):
    value = bytearray(bytes([64 + page_no]) * PAGE)
    if page_no == 1:
        value[:16] = b"SQLite format 3\0"
        struct.pack_into(">H", value, 16, PAGE)
        value[18:21] = bytes([2, 2, 48])
        struct.pack_into(">II", value, 24, counter, count)
        struct.pack_into(">I", value, 92, valid_for)
    return bytes(value)


def _encrypt(page_no, plain, *, kdf="sha512", auth="sha1", reserve=48):
    key = hashlib.pbkdf2_hmac(kdf, KEY, SALT, 4000, 32)
    mac = hashlib.pbkdf2_hmac(kdf, key, bytes(x ^ 0x3A for x in SALT), 2, 32)
    iv = bytes(reversed(range(16)))
    start = 16 if page_no == 1 else 0
    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(plain[start:PAGE - reserve])
    tag = hmac.new(mac, cipher + iv + struct.pack("<I", page_no), auth).digest()
    return (SALT if start else b"") + cipher + iv + tag + bytes(reserve - 16 - len(tag))


def _checksum(data, seed=(0, 0)):
    words = struct.unpack("<" + "I" * (len(data) // 4), data)
    first, second = seed
    for left, right in zip(words[::2], words[1::2]):
        first = (first + left + second) & 0xFFFFFFFF
        second = (second + right + first) & 0xFFFFFFFF
    return first, second


def _wal(frames):
    salt = struct.pack(">II", 123, 456)
    header = struct.pack(">IIII", 0x377F0682, 3007000, PAGE, 0) + salt
    checksum = _checksum(header)
    value = header + struct.pack(">II", *checksum)
    for number, size, encrypted in frames:
        prefix = struct.pack(">II", number, size)
        checksum = _checksum(prefix + encrypted, checksum)
        value += prefix + salt + struct.pack(">II", *checksum) + encrypted
    return value


def _decrypt(tmp_path, main, *, frames=None, raw_wal=None):
    source, output = tmp_path / "encrypted.db", tmp_path / "plain.db"
    source.write_bytes(b"".join(main))
    if frames is not None or raw_wal is not None:
        source.with_name(source.name + "-wal").write_bytes(
            _wal(frames) if raw_wal is None else raw_wal
        )
    result = qq_db._decrypt_db_qq(source, KEY, output)
    return result, output


@pytest.mark.parametrize("kdf,auth,reserve", [
    ("sha512", "sha1", 48), ("sha512", "sha1", 64),
    ("sha512", "sha1", 80), ("sha1", "sha1", 48),
    ("sha512", "sha512", 80),
])
def test_authenticated_header_excludes_zero_preallocation(tmp_path, kdf, auth, reserve):
    result, output = _decrypt(tmp_path, [
        _encrypt(1, _plain(1, count=1), kdf=kdf, auth=auth, reserve=reserve),
        bytes(PAGE), bytes(PAGE),
    ])
    assert result is True
    assert output.stat().st_size == PAGE
    assert output.read_bytes()[16:PAGE - reserve] == _plain(1, count=1)[16:PAGE - reserve]


@pytest.mark.parametrize("superseded", [bytes(PAGE), b"X" * PAGE], ids=["zero", "stale"])
def test_authenticated_wal_replaces_uninitialized_or_stale_main(tmp_path, superseded):
    result, output = _decrypt(tmp_path, [
        _encrypt(1, _plain(1)), superseded, bytes(PAGE),
    ], frames=[(2, 2, _encrypt(2, _plain(2)))])
    assert result is True
    assert output.stat().st_size == 2 * PAGE
    assert output.read_bytes()[PAGE:2 * PAGE - 48] == _plain(2)[:-48]


def test_wal_can_supply_a_new_page_absent_from_main(tmp_path):
    result, output = _decrypt(tmp_path, [_encrypt(1, _plain(1, count=1))], frames=[
        (1, 0, _encrypt(1, _plain(1, count=2))),
        (2, 2, _encrypt(2, _plain(2))),
    ])
    assert result is True
    assert output.stat().st_size == 2 * PAGE


@pytest.mark.parametrize("bad", [bytes(PAGE), b"X" * PAGE], ids=["zero", "corrupt"])
def test_bad_used_main_page_is_never_skipped(tmp_path, bad):
    result, output = _decrypt(tmp_path, [_encrypt(1, _plain(1)), bad, bytes(PAGE)])
    assert result is False
    assert not output.exists()


def test_missing_committed_main_page_is_not_zero_filled(tmp_path):
    result, output = _decrypt(tmp_path, [_encrypt(1, _plain(1, count=3))], frames=[
        (3, 3, _encrypt(3, _plain(3))),
    ])
    assert result is False
    assert not output.exists()


@pytest.mark.parametrize("count,counter,valid_for", [(2, 8, 7), (0, 7, 7)])
def test_wal_shrink_requires_valid_authenticated_extent(tmp_path, count, counter, valid_for):
    first = _encrypt(1, _plain(1, count=count, counter=counter, valid_for=valid_for))
    result, output = _decrypt(tmp_path, [first, bytes(PAGE)], frames=[(1, 1, first)])
    assert result is False
    assert not output.exists()


def test_no_wal_declared_extent_cannot_exceed_source(tmp_path):
    result, output = _decrypt(tmp_path, [_encrypt(1, _plain(1, count=2))])
    assert result is False
    assert not output.exists()


@pytest.mark.parametrize("count,counter,valid_for", [(1, 8, 7), (0, 7, 7)])
def test_stale_or_zero_size_field_cannot_hide_bad_physical_page(tmp_path, count, counter, valid_for):
    result, output = _decrypt(tmp_path, [
        _encrypt(1, _plain(1, count=count, counter=counter, valid_for=valid_for)), bytes(PAGE),
    ])
    assert result is False
    assert not output.exists()


def test_legacy_stale_size_header_keeps_authenticated_physical_pages(tmp_path):
    result, output = _decrypt(tmp_path, [
        _encrypt(1, _plain(1, count=1, counter=8, valid_for=7)),
        _encrypt(2, _plain(2)),
    ])
    assert result is True
    assert output.stat().st_size == 2 * PAGE


@pytest.mark.parametrize("kind", ["hmac", "checksum", "uncommitted"])
def test_invalid_wal_cannot_hide_bad_main_page(tmp_path, kind):
    page = bytearray(_encrypt(2, _plain(2)))
    if kind == "hmac":
        page[100] ^= 1
    wal = bytearray(_wal([(2, 0 if kind == "uncommitted" else 2, bytes(page))]))
    if kind == "checksum":
        wal[24] ^= 1
    result, output = _decrypt(tmp_path, [_encrypt(1, _plain(1)), bytes(PAGE)], raw_wal=wal)
    assert result is False
    assert not output.exists()


def test_superseded_wal_frame_still_requires_authentication(tmp_path):
    result, output = _decrypt(tmp_path, [_encrypt(1, _plain(1)), bytes(PAGE)], frames=[
        (2, 0, bytes(PAGE)), (2, 2, _encrypt(2, _plain(2))),
    ])
    assert result is False
    assert not output.exists()


def test_wal_commit_size_cannot_truncate_authenticated_header(tmp_path):
    result, output = _decrypt(tmp_path, [_encrypt(1, _plain(1, count=2))], frames=[
        (1, 1, _encrypt(1, _plain(1, count=2))),
    ])
    assert result is False
    assert not output.exists()


def test_authenticated_wal_page_one_can_shrink_database(tmp_path):
    result, output = _decrypt(tmp_path, [
        _encrypt(1, _plain(1, count=2)), bytes(PAGE),
    ], frames=[(1, 1, _encrypt(1, _plain(1, count=1)))])
    assert result is True
    assert output.stat().st_size == PAGE


def test_partial_trailing_page_remains_rejected(tmp_path):
    result, output = _decrypt(tmp_path, [_encrypt(1, _plain(1, count=1)), b"X"])
    assert result is False
    assert not output.exists()
