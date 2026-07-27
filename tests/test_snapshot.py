import hashlib
import hmac
import struct
import sys

import pytest
from Crypto.Cipher import AES

from chatlog_keeper import qq_db, wechat_db
from chatlog_keeper.core import _snapshot, _wal
from chatlog_keeper.core._snapshot import snapshot_db_family


def test_snapshot_copies_db_and_sidecars(tmp_path):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"db")
    db.with_name(db.name + "-wal").write_bytes(b"wal")
    db.with_name(db.name + "-shm").write_bytes(b"shm")
    with snapshot_db_family(db) as snap:
        assert snap.read_bytes() == b"db"
        assert snap.with_name(snap.name + "-wal").read_bytes() == b"wal"
        assert snap.with_name(snap.name + "-shm").read_bytes() == b"shm"


def test_snapshot_retries_when_family_changes_during_copy(tmp_path, monkeypatch):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"db")
    stable = (
        ("", True, 2, 3, "a"),
        ("-wal", False, 0, 0, ""),
        ("-shm", False, 0, 0, ""),
    )
    changed = (
        ("", True, 2, 4, "b"),
        ("-wal", False, 0, 0, ""),
        ("-shm", False, 0, 0, ""),
    )
    signatures = iter((stable, changed, changed, changed))
    monkeypatch.setattr(_snapshot, "_family_signature", lambda _path: next(signatures))

    with snapshot_db_family(db) as snap:
        assert snap.read_bytes() == b"db"


def test_stable_prefix_retries_checkpoint_race(tmp_path, monkeypatch):
    db = tmp_path / "message_0.db"
    db.write_bytes(b"A" * 4096)
    stable = (
        ("", True, 4096, 3, "a"),
        ("-wal", False, 0, 0, ""),
        ("-shm", False, 0, 0, ""),
    )
    changed = (
        ("", True, 4096, 4, "b"),
        ("-wal", True, 32, 4, "c"),
        ("-shm", False, 0, 0, ""),
    )
    signatures = iter((stable, changed, changed, changed))
    monkeypatch.setattr(
        _snapshot,
        "_family_signature",
        lambda _path: next(signatures),
    )

    assert _snapshot.read_stable_prefix(db, 4096) == b"A" * 4096


def _encrypted_page(page_key: bytes, salt: bytes, page_no: int, fill: bytes) -> bytes:
    reserve = 80
    prefix = salt if page_no == 1 else b""
    body_len = 4096 - reserve - len(prefix)
    plain = (fill * (body_len // len(fill) + 1))[:body_len]
    iv = bytes(range(16))
    cipher = AES.new(page_key, AES.MODE_CBC, iv).encrypt(plain)
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", page_key, mac_salt, 2, dklen=32)
    tag = hmac.new(
        mac_key, cipher + iv + struct.pack("<I", page_no), hashlib.sha512
    ).digest()
    return prefix + cipher + iv + tag


def _wal_bytes(frames, *, salt1=0x11223344, salt2=0x55667788):
    magic = 0x377F0682
    header_24 = struct.pack(
        ">6I", magic, 3007000, 4096, 1, salt1, salt2
    )
    checksum = _wal._checksum_bytes(
        header_24, big_endian=False
    )
    output = bytearray(header_24 + struct.pack(">II", *checksum))
    for page_no, db_size, page in frames:
        first = struct.pack(">II", page_no, db_size)
        checksum = _wal._checksum_bytes(
            first + page,
            checksum,
            big_endian=False,
        )
        output.extend(
            first
            + struct.pack(">II", salt1, salt2)
            + struct.pack(">II", *checksum)
            + page
        )
    return bytes(output), checksum


def _shm_bytes(
    *,
    mx_frame,
    n_page,
    frame_checksum,
    salt1=0x11223344,
    salt2=0x55667788,
):
    native = "<" if sys.byteorder == "little" else ">"
    header = bytearray(48)
    struct.pack_into(f"{native}I", header, 0, 3007000)
    header[12] = 1
    header[13] = 0
    struct.pack_into(f"{native}H", header, 14, 4096)
    struct.pack_into(f"{native}II", header, 16, mx_frame, n_page)
    struct.pack_into(f"{native}II", header, 24, *frame_checksum)
    header[32:40] = struct.pack(">II", salt1, salt2)
    checksum = _wal._checksum_bytes(
        bytes(header[:40]),
        big_endian=(sys.byteorder == "big"),
    )
    struct.pack_into(f"{native}II", header, 40, *checksum)
    return bytes(header + header + bytearray(40))


def test_wechat_wal_page_is_hmac_verified_and_decrypted():
    key = bytes(range(32))
    salt = bytes(range(16))
    page = _encrypted_page(key, salt, 2, b"A")
    plain = wechat_db._decrypt_wal_page(page, key, salt, 2)
    assert plain is not None
    assert plain[:4016] == b"A" * 4016
    tampered = bytearray(page)
    tampered[100] ^= 1
    assert wechat_db._decrypt_wal_page(bytes(tampered), key, salt, 2) is None


def test_apply_wechat_wal_committed_frame(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    output = tmp_path / "decrypted.db"
    output.write_bytes(b"\0" * 8192)
    wal = tmp_path / "message.db-wal"
    page = _encrypted_page(key, salt, 2, b"B")
    wal.write_bytes(_wal_bytes([(2, 2, page)])[0])
    assert wechat_db._apply_wechat_wal(wal, key, salt, output) == 1
    assert output.read_bytes()[4096:4096 + 4016] == b"B" * 4016


def test_wal_shm_mxframe_and_checksums_are_enforced(tmp_path):
    page = b"P" * 4096
    wal_bytes, frame_checksum = _wal_bytes([(2, 2, page)])
    wal = tmp_path / "message.db-wal"
    wal.write_bytes(wal_bytes)
    shm = tmp_path / "message.db-shm"
    shm.write_bytes(
        _shm_bytes(
            mx_frame=1,
            n_page=2,
            frame_checksum=frame_checksum,
        )
    )
    plan = _wal.inspect_wal(
        wal, shm_path=shm, expected_page_size=4096
    )
    assert plan.frames_to_apply == 1
    assert plan.commit_size == 2
    assert plan.used_shm is True

    broken = bytearray(shm.read_bytes())
    broken[16] = 2
    broken[64] = 2
    shm.write_bytes(broken)
    with pytest.raises(_wal.WalValidationError):
        _wal.inspect_wal(wal, shm_path=shm, expected_page_size=4096)


def test_wal_bad_header_checksum_fails_closed(tmp_path):
    wal = tmp_path / "message.db-wal"
    data = bytearray(_wal_bytes([(2, 2, b"P" * 4096)])[0])
    data[24] ^= 1
    wal.write_bytes(data)
    with pytest.raises(_wal.WalValidationError, match="header checksum"):
        _wal.inspect_wal(wal, expected_page_size=4096)


def test_wal_stale_preallocated_tail_after_commit_is_ignored(tmp_path):
    wal = tmp_path / "message.db-wal"
    committed = _wal_bytes([(2, 2, b"P" * 4096)])[0]
    stale_header = (
        struct.pack(">II", 3, 3)
        + struct.pack(">II", 0xDEADBEEF, 0xBAD0C0DE)
        + b"\0" * 8
    )
    wal.write_bytes(committed + stale_header + b"S" * 4096)
    plan = _wal.inspect_wal(wal, expected_page_size=4096)
    assert plan.frames_to_apply == 1
    assert plan.valid_frames == 1
    assert plan.physical_frames == 2


def test_wechat_wal_sqlcipher_hmac_failure_never_mutates_output(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    output = tmp_path / "decrypted.db"
    original = b"\0" * 8192
    output.write_bytes(original)
    encrypted = bytearray(_encrypted_page(key, salt, 2, b"B"))
    encrypted[100] ^= 1
    wal = tmp_path / "message.db-wal"
    # Recompute the outer SQLite WAL checksum around the tampered encrypted
    # page so only the SQLCipher HMAC gate detects the corruption.
    wal.write_bytes(_wal_bytes([(2, 2, bytes(encrypted))])[0])
    with pytest.raises(_wal.WalValidationError, match="SQLCipher"):
        wechat_db._apply_wechat_wal(wal, key, salt, output)
    assert output.read_bytes() == original


def _encrypted_qq_page(
    passphrase: bytes,
    salt: bytes,
    page_no: int,
    fill: bytes,
) -> bytes:
    reserve = 48
    prefix = salt if page_no == 1 else b""
    body_len = 4096 - reserve - len(prefix)
    plain = (fill * (body_len // len(fill) + 1))[:body_len]
    iv = bytes(reversed(range(16)))
    aes_key = hashlib.pbkdf2_hmac(
        "sha512", passphrase, salt, 4000, dklen=32
    )
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac(
        "sha512", aes_key, mac_salt, 2, dklen=32
    )
    cipher = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(plain)
    tag = hmac.new(
        mac_key,
        cipher + iv + struct.pack("<I", page_no),
        hashlib.sha1,
    ).digest()
    return prefix + cipher + iv + tag + b"\0" * 12


def test_qq_header_strip_preserves_and_applies_committed_wal(tmp_path):
    key = b"0123456789abcdef"
    salt = bytes(range(16))
    source = tmp_path / "nt_msg.db"
    source.write_bytes(
        b"H" * 1024
        + _encrypted_qq_page(key, salt, 1, b"A")
        + _encrypted_qq_page(key, salt, 2, b"C")
    )
    wal_page = _encrypted_qq_page(key, salt, 2, b"B")
    wal_bytes, frame_checksum = _wal_bytes([(2, 2, wal_page)])
    source.with_name(source.name + "-wal").write_bytes(wal_bytes)
    source.with_name(source.name + "-shm").write_bytes(
        _shm_bytes(
            mx_frame=1,
            n_page=2,
            frame_checksum=frame_checksum,
        )
    )

    stripped = tmp_path / "stripped.db"
    assert qq_db._skip_header(source, stripped) is True
    assert stripped.with_name(stripped.name + "-wal").read_bytes() == wal_bytes
    plain = tmp_path / "plain.db"
    assert qq_db._decrypt_db_qq(stripped, key, plain) is True
    value = plain.read_bytes()
    assert value[:16] == b"SQLite format 3\x00"
    assert value[4096:4096 + (4096 - 48)] == b"B" * (4096 - 48)
