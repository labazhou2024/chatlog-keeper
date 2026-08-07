"""Fail-closed contracts for NTQQ's >1 GiB Windows lock-byte page.

The encrypted fixtures use only three 4 KiB pages.  Tests temporarily move the
recognized page number from production's 262144 to page 2, so CI never creates
a gigabyte-scale file and never reads real QQ data.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import struct

import pytest
from Crypto.Cipher import AES

from chatlog_keeper import _qq_sqlite_helper, _qq_sqlite_proxy, qq_db


def _encrypted_qq_page(
    passphrase: bytes,
    salt: bytes,
    page_no: int,
    fill: bytes,
) -> bytes:
    reserve = 48
    prefix = salt if page_no == 1 else b""
    body_len = qq_db._NTQQ_PAGE_SIZE - reserve - len(prefix)
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


def _synthetic_encrypted_db(tmp_path, pages: list[bytes]):
    encrypted = tmp_path / "stripped.db"
    encrypted.write_bytes(b"".join(pages))
    return encrypted, tmp_path / "plain.db"


def test_pending_byte_derivation_matches_the_exact_ntqq_wrapper_shift() -> None:
    assert qq_db._NTQQ_WRAPPER_SIZE == 1024
    assert qq_db._SQLITE_STANDARD_PENDING_BYTE == 0x40000000
    assert qq_db._NTQQ_STRIPPED_PENDING_BYTE == 0x3FFFFC00
    assert qq_db._NTQQ_WRAPPED_LOCK_PAGE_NO == 262144
    assert (
        qq_db._NTQQ_STRIPPED_PENDING_BYTE // qq_db._NTQQ_PAGE_SIZE + 1
        == qq_db._NTQQ_WRAPPED_LOCK_PAGE_NO
    )
    assert (
        _qq_sqlite_helper._NTQQ_STRIPPED_PENDING_BYTE
        == _qq_sqlite_proxy._NTQQ_STRIPPED_PENDING_BYTE
        == qq_db._NTQQ_STRIPPED_PENDING_BYTE
    )
    assert (
        _qq_sqlite_helper._SUPPORTED_SQLITE_VERSIONS
        == _qq_sqlite_proxy._SUPPORTED_SQLITE_VERSIONS
        == frozenset({"3.53.2"})
    )


@pytest.mark.parametrize(
    ("platform_name", "wrapper_size", "page_no", "page", "expected"),
    [
        ("nt", 1024, 262144, b"\0" * 4096, True),
        ("posix", 1024, 262144, b"\0" * 4096, False),
        ("nt", 0, 262144, b"\0" * 4096, False),
        ("nt", 1024, 262145, b"\0" * 4096, False),
        ("nt", 1024, 262144, b"\0" * 4095, False),
        ("nt", 1024, 262144, b"\0" * 4095 + b"X", False),
    ],
)
def test_lock_placeholder_signature_is_exact(
    platform_name,
    wrapper_size,
    page_no,
    page,
    expected,
) -> None:
    assert qq_db._is_wrapped_windows_lock_placeholder(
        page,
        page_no=page_no,
        source_wrapper_size=wrapper_size,
        platform_name=platform_name,
    ) is expected


def test_exact_synthetic_lock_page_is_the_only_main_page_hmac_exception(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(qq_db, "_NTQQ_WRAPPED_LOCK_PAGE_NO", 2)
    key = b"0123456789abcdef"
    salt = bytes(range(16))
    encrypted, plain = _synthetic_encrypted_db(
        tmp_path,
        [
            _encrypted_qq_page(key, salt, 1, b"A"),
            b"\0" * qq_db._NTQQ_PAGE_SIZE,
            _encrypted_qq_page(key, salt, 3, b"C"),
        ],
    )

    result = qq_db._decrypt_db_qq_result(
        encrypted,
        key,
        plain,
        source_wrapper_size=qq_db._NTQQ_WRAPPER_SIZE,
        platform_name="nt",
    )

    assert result == qq_db._QQDecryptResult(ok=True, shifted_pending_byte=True)
    value = plain.read_bytes()
    assert value[:16] == b"SQLite format 3\x00"
    assert value[4096:8192] == b"\0" * 4096
    assert value[8192:8192 + (4096 - 48)] == b"C" * (4096 - 48)


@pytest.mark.parametrize(
    ("platform_name", "wrapper_size"),
    [("posix", 1024), ("nt", 0)],
)
def test_zero_page_is_rejected_without_both_windows_and_wrapper_attestation(
    monkeypatch,
    tmp_path,
    platform_name,
    wrapper_size,
) -> None:
    monkeypatch.setattr(qq_db, "_NTQQ_WRAPPED_LOCK_PAGE_NO", 2)
    key = b"0123456789abcdef"
    salt = bytes(range(16))
    encrypted, plain = _synthetic_encrypted_db(
        tmp_path,
        [
            _encrypted_qq_page(key, salt, 1, b"A"),
            b"\0" * qq_db._NTQQ_PAGE_SIZE,
        ],
    )

    result = qq_db._decrypt_db_qq_result(
        encrypted,
        key,
        plain,
        source_wrapper_size=wrapper_size,
        platform_name=platform_name,
    )

    assert result == qq_db._QQDecryptResult(ok=False, shifted_pending_byte=False)
    assert not plain.exists()


def test_wrong_zero_page_is_rejected_and_never_published(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(qq_db, "_NTQQ_WRAPPED_LOCK_PAGE_NO", 3)
    key = b"0123456789abcdef"
    salt = bytes(range(16))
    encrypted, plain = _synthetic_encrypted_db(
        tmp_path,
        [
            _encrypted_qq_page(key, salt, 1, b"A"),
            b"\0" * qq_db._NTQQ_PAGE_SIZE,
            _encrypted_qq_page(key, salt, 3, b"C"),
        ],
    )

    result = qq_db._decrypt_db_qq_result(
        encrypted,
        key,
        plain,
        source_wrapper_size=qq_db._NTQQ_WRAPPER_SIZE,
        platform_name="nt",
    )

    assert result == qq_db._QQDecryptResult(ok=False, shifted_pending_byte=False)
    assert not plain.exists()


def test_later_hmac_failure_still_rejects_after_exact_placeholder(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(qq_db, "_NTQQ_WRAPPED_LOCK_PAGE_NO", 2)
    key = b"0123456789abcdef"
    salt = bytes(range(16))
    corrupt = bytearray(_encrypted_qq_page(key, salt, 3, b"C"))
    corrupt[100] ^= 1
    encrypted, plain = _synthetic_encrypted_db(
        tmp_path,
        [
            _encrypted_qq_page(key, salt, 1, b"A"),
            b"\0" * qq_db._NTQQ_PAGE_SIZE,
            bytes(corrupt),
        ],
    )

    result = qq_db._decrypt_db_qq_result(
        encrypted,
        key,
        plain,
        source_wrapper_size=qq_db._NTQQ_WRAPPER_SIZE,
        platform_name="nt",
    )

    assert result == qq_db._QQDecryptResult(ok=False, shifted_pending_byte=True)
    assert not plain.exists()


def test_ordinary_database_still_uses_the_in_process_sqlite_path(tmp_path) -> None:
    path = tmp_path / "ordinary.db"
    original = sqlite3.connect(path)
    original.execute("CREATE TABLE sample(value TEXT)")
    original.execute("INSERT INTO sample VALUES ('ordinary')")
    original.commit()
    original.close()

    connection = qq_db._open_qq_sqlite_connection(
        qq_db._QQDecryptedDatabase(path=path, shifted_pending_byte=False)
    )
    try:
        assert connection.execute("SELECT value FROM sample").fetchone() == (
            "ordinary",
        )
    finally:
        connection.close()


def test_helper_probe_runs_in_a_different_isolated_process() -> None:
    probe = _qq_sqlite_proxy.probe_isolated_helper()
    assert probe["type"] == "probe"
    assert probe["pid"] != os.getpid()
    assert probe["isolated"] == 1


def test_helper_command_pins_python_isolated_mode() -> None:
    command = _qq_sqlite_proxy._helper_command("--probe")
    assert command[0] == os.sys.executable
    assert command[1:3] == ["-I", "-u"]
    assert command[-1] == "--probe"


def test_frozen_build_spawns_its_private_helper_entrypoint(monkeypatch) -> None:
    monkeypatch.setattr(_qq_sqlite_proxy.sys, "frozen", True, raising=False)

    command = _qq_sqlite_proxy._helper_command("--probe")

    assert command == [os.sys.executable, "--_qq-sqlite-helper", "--probe"]


@pytest.mark.skipif(os.name == "nt", reason="non-Windows refusal contract")
def test_shifted_reader_fails_closed_off_windows(tmp_path) -> None:
    path = tmp_path / "plain.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE sample(value INTEGER)")
    connection.commit()
    connection.close()

    with pytest.raises(OSError, match="Windows-only"):
        qq_db._open_qq_sqlite_connection(
            qq_db._QQDecryptedDatabase(path=path, shifted_pending_byte=True)
        )
