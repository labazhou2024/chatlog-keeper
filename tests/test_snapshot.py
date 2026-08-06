import hashlib
import hmac
import os
import struct
import sys
import time

import pytest
from Crypto.Cipher import AES

from chatlog_keeper import qq_db, wechat_db
from chatlog_keeper.core import _snapshot, _wal
from chatlog_keeper.core._snapshot import snapshot_db_families, snapshot_db_family


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


def test_aggregate_snapshot_retries_wal_only_change_across_families(
    tmp_path,
    monkeypatch,
):
    first = tmp_path / "message_0.db"
    second = tmp_path / "contact.db"
    first.write_bytes(b"message")
    second.write_bytes(b"contact")
    first_wal = first.with_name(first.name + "-wal")
    first_wal.write_bytes(b"wal-v1")

    original_copy = _snapshot._copy_file
    first_main_copies = 0
    changed = False

    def copy_with_wal_churn(source, destination):
        nonlocal changed, first_main_copies
        original_copy(source, destination)
        if source == first:
            first_main_copies += 1
        if source == second and not changed:
            # Only the already-copied WAL changes; neither main DB changes.
            first_wal.write_bytes(b"wal-v2")
            changed = True

    monkeypatch.setattr(_snapshot, "_copy_file", copy_with_wal_churn)

    with snapshot_db_families([first, second]) as snapshots:
        copied_wal = snapshots[first].with_name(snapshots[first].name + "-wal")
        assert copied_wal.read_bytes() == b"wal-v2"
        assert snapshots[second].read_bytes() == b"contact"

    assert first_main_copies == 2


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
    page_size=4096,
):
    native = "<" if sys.byteorder == "little" else ">"
    header = bytearray(48)
    struct.pack_into(f"{native}I", header, 0, 3007000)
    header[12] = 1
    header[13] = 0
    encoded_page_size = 1 if page_size == 65536 else page_size
    struct.pack_into(f"{native}H", header, 14, encoded_page_size)
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


@pytest.mark.parametrize("key_mode", ["raw", "password"])
def test_wechat_main_db_authenticates_every_page_before_atomic_publish(
    tmp_path,
    key_mode,
):
    master_key = bytes(range(32))
    salt = bytes(range(16))
    page_key = (
        master_key
        if key_mode == "raw"
        else hashlib.pbkdf2_hmac(
            "sha512",
            master_key,
            salt,
            wechat_db._WECHAT_KDF_ITER,
            dklen=32,
        )
    )
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(
        _encrypted_page(page_key, salt, 1, b"A")
        + _encrypted_page(page_key, salt, 2, b"B")
    )
    output = tmp_path / "plain.db"

    assert wechat_db._decrypt_db_v4_snapshot(encrypted, master_key, output)
    plain = output.read_bytes()
    assert len(plain) == 8192
    assert plain[:16] == b"SQLite format 3\x00"
    assert plain[16:4016] == b"A" * 4000
    assert plain[4096:8112] == b"B" * 4016


@pytest.mark.parametrize(
    "tamper_offset",
    [100, 4096 - 80, 4096 - 1],
    ids=["ciphertext", "iv", "hmac"],
)
def test_wechat_main_db_rejects_page_two_tampering_without_mutating_output(
    tmp_path,
    tamper_offset,
):
    key = bytes(range(32))
    salt = bytes(range(16))
    page_two = bytearray(_encrypted_page(key, salt, 2, b"B"))
    page_two[tamper_offset] ^= 1
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(
        _encrypted_page(key, salt, 1, b"A") + bytes(page_two)
    )
    output = tmp_path / "plain.db"
    original = b"existing-output-must-survive"
    output.write_bytes(original)

    assert not wechat_db._decrypt_db_v4_snapshot(encrypted, key, output)
    assert output.read_bytes() == original
    assert list(tmp_path.glob(".plain.db.*.tmp")) == []


def test_wechat_main_db_binds_hmac_to_physical_page_number(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(
        _encrypted_page(key, salt, 1, b"A")
        + _encrypted_page(key, salt, 3, b"B")
    )
    output = tmp_path / "plain.db"

    assert not wechat_db._decrypt_db_v4_snapshot(encrypted, key, output)
    assert not output.exists()


@pytest.mark.parametrize("tail_size", [1, 137, 4095])
def test_wechat_main_db_rejects_truncated_trailing_page(tmp_path, tail_size):
    key = bytes(range(32))
    salt = bytes(range(16))
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(
        _encrypted_page(key, salt, 1, b"A") + b"T" * tail_size
    )
    output = tmp_path / "plain.db"

    assert not wechat_db._decrypt_db_v4_snapshot(encrypted, key, output)
    assert not output.exists()


def test_wechat_plaintext_cache_is_private_and_expires_without_next_read(tmp_path):
    wechat_db._decrypt_cache_clear()
    key = bytes(range(32))
    salt = bytes(range(16))
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(_encrypted_page(key, salt, 1, b"A"))

    try:
        cached = wechat_db._decrypt_with_cache(encrypted, key, ttl=0.05)
        assert cached is not None and cached.exists()
        private_dir = cached.parent
        if os.name != "nt":
            assert cached.stat().st_mode & 0o777 == 0o600
            assert private_dir.stat().st_mode & 0o777 == 0o700

        deadline = time.monotonic() + 2
        while (
            (cached.exists() or private_dir.exists())
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert not cached.exists()
        assert not private_dir.exists()
        assert encrypted not in wechat_db._DECRYPT_CACHE
    finally:
        wechat_db._decrypt_cache_clear()


def test_wechat_plaintext_cache_hit_refreshes_idle_expiry(monkeypatch, tmp_path):
    wechat_db._decrypt_cache_clear()
    timer_type, timers = _manual_timer_type()
    monkeypatch.setattr(wechat_db.threading, "Timer", timer_type)
    now = [100.0]
    monkeypatch.setattr(wechat_db._time, "monotonic", lambda: now[0])
    key = bytes(range(32))
    salt = bytes(range(16))
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(_encrypted_page(key, salt, 1, b"A"))

    try:
        first = wechat_db._decrypt_with_cache(encrypted, key, ttl=10)
        assert first is not None
        first_timer = timers[-1]
        now[0] += 6
        second = wechat_db._decrypt_with_cache(encrypted, key, ttl=10)
        assert second == first
        assert first_timer.cancelled is True

        # A callback already queued before cancel() cannot expire the refreshed
        # generation.  Its replacement remains alive until ten idle seconds
        # after the cache hit, independent of runner scheduling latency.
        first_timer.fire()
        assert first.exists()
        now[0] += 11
        timers[-1].fire()
        assert not first.exists()
    finally:
        wechat_db._decrypt_cache_clear()


def _manual_timer_type():
    created = []

    class ManualTimer:
        def __init__(self, interval, function, args=()):
            self.interval = interval
            self.function = function
            self.args = args
            self.daemon = False
            self.cancelled = False
            self.started = False
            created.append(self)

        def start(self):
            self.started = True

        def cancel(self):
            self.cancelled = True

        def fire(self):
            self.function(*self.args)

    return ManualTimer, created


def test_wechat_cancelled_timer_cannot_expire_refreshed_generation(
    monkeypatch, tmp_path
):
    wechat_db._decrypt_cache_clear()
    timer_type, timers = _manual_timer_type()
    monkeypatch.setattr(wechat_db.threading, "Timer", timer_type)
    key = bytes(range(32))
    salt = bytes(range(16))
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(_encrypted_page(key, salt, 1, b"A"))

    try:
        first = wechat_db._decrypt_with_cache(encrypted, key, ttl=30)
        assert first is not None
        old_timer = timers[-1]
        assert wechat_db._decrypt_with_cache(encrypted, key, ttl=30) == first
        assert old_timer.cancelled is True

        # cancel() cannot stop a callback that already started and is waiting
        # for the cache lock. Its old generation must be harmless.
        old_timer.fire()
        assert first.exists()
        assert wechat_db._DECRYPT_CACHE[encrypted].path == first
    finally:
        wechat_db._decrypt_cache_clear()


def test_wechat_plaintext_cache_invalidates_when_only_wal_changes(
    monkeypatch, tmp_path
):
    wechat_db._decrypt_cache_clear()
    timer_type, _timers = _manual_timer_type()
    monkeypatch.setattr(wechat_db.threading, "Timer", timer_type)
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(b"unchanged-main")
    wal = encrypted.with_name(encrypted.name + "-wal")
    wal.write_bytes(b"wal-v1")
    decrypt_calls = []

    def fake_decrypt(_db_path, _enc_key, output_path):
        decrypt_calls.append(1)
        output_path.write_bytes(wal.read_bytes())
        return True

    monkeypatch.setattr(wechat_db, "_decrypt_db_v4", fake_decrypt)
    try:
        first = wechat_db._decrypt_with_cache(encrypted, b"k" * 32, ttl=30)
        assert first is not None and first.read_bytes() == b"wal-v1"
        wal.write_bytes(b"wal-v2-with-new-frame")

        second = wechat_db._decrypt_with_cache(encrypted, b"k" * 32, ttl=30)
        assert second is not None and second.read_bytes() == b"wal-v2-with-new-frame"
        assert second != first
        assert len(decrypt_calls) == 2
    finally:
        wechat_db._decrypt_cache_clear()


def test_wechat_busy_delete_remains_owned_until_retry_succeeds(
    monkeypatch, tmp_path
):
    wechat_db._decrypt_cache_clear()
    timer_type, _timers = _manual_timer_type()
    monkeypatch.setattr(wechat_db.threading, "Timer", timer_type)
    encrypted = tmp_path / "message.db"
    encrypted.write_bytes(b"first-family")

    def fake_decrypt(db_path, _enc_key, output_path):
        output_path.write_bytes(db_path.read_bytes())
        return True

    monkeypatch.setattr(wechat_db, "_decrypt_db_v4", fake_decrypt)
    original_remove = wechat_db._remove_decrypted_cache_file
    try:
        first = wechat_db._decrypt_with_cache(encrypted, b"k" * 32, ttl=30)
        assert first is not None
        encrypted.write_bytes(b"second-family-is-larger")
        failed_once = False

        def fail_first_windows_style_delete(path, private_dir):
            nonlocal failed_once
            if path == first and not failed_once:
                failed_once = True
                return False
            return original_remove(path, private_dir)

        monkeypatch.setattr(
            wechat_db,
            "_remove_decrypted_cache_file",
            fail_first_windows_style_delete,
        )
        second = wechat_db._decrypt_with_cache(encrypted, b"k" * 32, ttl=30)
        assert second is not None and second != first
        assert first.exists()
        assert first in wechat_db._DECRYPT_PENDING_DELETES

        pending_timer = wechat_db._DECRYPT_PENDING_DELETES[first].timer
        pending_timer.fire()
        assert not first.exists()
        assert first not in wechat_db._DECRYPT_PENDING_DELETES
    finally:
        monkeypatch.setattr(
            wechat_db,
            "_remove_decrypted_cache_file",
            original_remove,
        )
        wechat_db._decrypt_cache_clear()


def test_wechat_startup_scavenger_removes_dead_owner_but_skips_live_owner(
    monkeypatch, tmp_path
):
    from chatlog_keeper.core._secrets import (
        _prepare_secret_parent,
        write_secret_text,
    )

    def make_cache_dir(name, pid, token):
        private_dir = tmp_path / name
        _prepare_secret_parent(private_dir)
        assert write_secret_text(
            private_dir / wechat_db._DECRYPT_OWNER_FILE,
            f"pid={pid}\n",
        )
        plaintext = private_dir / f"plain-{token * 32}.db"
        assert write_secret_text(plaintext, "plaintext")
        return private_dir, plaintext

    dead_dir, _dead_plaintext = make_cache_dir(
        "chatlog_decrypted_dead123",
        424242,
        "a",
    )
    live_dir, live_plaintext = make_cache_dir(
        "chatlog_decrypted_live123",
        os.getpid(),
        "b",
    )
    monkeypatch.setattr(
        wechat_db,
        "_process_is_alive",
        lambda pid: pid == os.getpid(),
    )

    assert wechat_db._scavenge_decrypt_cache(temp_root=tmp_path, force=True) == 1
    assert not dead_dir.exists()
    assert live_plaintext.exists()
    assert wechat_db._remove_decrypted_cache_file(live_plaintext, live_dir)


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


def test_apply_wechat_wal_rebuilds_stale_index_from_authenticated_wal(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    output = tmp_path / "decrypted.db"
    output.write_bytes(b"\0" * 8192)
    wal = tmp_path / "message.db-wal"
    page = _encrypted_page(key, salt, 2, b"B")
    wal_bytes, frame_checksum = _wal_bytes([(2, 2, page)])
    wal.write_bytes(wal_bytes)
    wal.with_name("message.db-shm").write_bytes(
        _shm_bytes(
            mx_frame=1,
            n_page=2,
            frame_checksum=frame_checksum,
            page_size=8192,
        )
    )

    assert wechat_db._apply_wechat_wal(wal, key, salt, output) == 1
    assert output.read_bytes()[4096:4096 + 4016] == b"B" * 4016


def test_apply_wechat_wal_recovers_commit_after_valid_but_stale_index(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    output = tmp_path / "decrypted.db"
    output.write_bytes(b"\0" * 8192)
    wal = tmp_path / "message.db-wal"
    first_page = _encrypted_page(key, salt, 2, b"B")
    latest_page = _encrypted_page(key, salt, 2, b"C")
    wal_bytes, _latest_checksum = _wal_bytes(
        [(2, 2, first_page), (2, 2, latest_page)]
    )
    _first_wal, first_checksum = _wal_bytes([(2, 2, first_page)])
    wal.write_bytes(wal_bytes)
    wal.with_name("message.db-shm").write_bytes(
        _shm_bytes(
            mx_frame=1,
            n_page=2,
            frame_checksum=first_checksum,
        )
    )

    assert wechat_db._apply_wechat_wal(wal, key, salt, output) == 2
    assert output.read_bytes()[4096:4096 + 4016] == b"C" * 4016


def test_valid_stale_wechat_index_never_masks_later_page_hmac_failure(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    output = tmp_path / "decrypted.db"
    original = b"\0" * 8192
    output.write_bytes(original)
    wal = tmp_path / "message.db-wal"
    first_page = _encrypted_page(key, salt, 2, b"B")
    corrupt_page = bytearray(_encrypted_page(key, salt, 2, b"C"))
    corrupt_page[100] ^= 1
    wal_bytes, _latest_checksum = _wal_bytes(
        [(2, 2, first_page), (2, 2, bytes(corrupt_page))]
    )
    _first_wal, first_checksum = _wal_bytes([(2, 2, first_page)])
    wal.write_bytes(wal_bytes)
    wal.with_name("message.db-shm").write_bytes(
        _shm_bytes(
            mx_frame=1,
            n_page=2,
            frame_checksum=first_checksum,
        )
    )

    with pytest.raises(_wal.WalValidationError, match="SQLCipher"):
        wechat_db._apply_wechat_wal(wal, key, salt, output)
    assert output.read_bytes() == original


def test_valid_stale_wechat_index_does_not_apply_uncommitted_tail(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    output = tmp_path / "decrypted.db"
    output.write_bytes(b"\0" * 8192)
    wal = tmp_path / "message.db-wal"
    committed_page = _encrypted_page(key, salt, 2, b"B")
    uncommitted_page = _encrypted_page(key, salt, 2, b"C")
    wal_bytes, _latest_checksum = _wal_bytes(
        [(2, 2, committed_page), (2, 0, uncommitted_page)]
    )
    _first_wal, first_checksum = _wal_bytes([(2, 2, committed_page)])
    wal.write_bytes(wal_bytes)
    wal.with_name("message.db-shm").write_bytes(
        _shm_bytes(
            mx_frame=1,
            n_page=2,
            frame_checksum=first_checksum,
        )
    )

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


def test_wechat_stale_index_fallback_never_masks_corrupt_wal_frame(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    output = tmp_path / "decrypted.db"
    original = b"\0" * 8192
    output.write_bytes(original)
    wal = tmp_path / "message.db-wal"
    page = _encrypted_page(key, salt, 2, b"B")
    wal_bytes, frame_checksum = _wal_bytes([(2, 2, page)])
    corrupted = bytearray(wal_bytes)
    corrupted[-1] ^= 1
    wal.write_bytes(corrupted)
    wal.with_name("message.db-shm").write_bytes(
        _shm_bytes(
            mx_frame=1,
            n_page=2,
            frame_checksum=frame_checksum,
        )
    )

    with pytest.raises(_wal.WalValidationError, match="frame checksum"):
        wechat_db._apply_wechat_wal(wal, key, salt, output)
    assert output.read_bytes() == original


def test_wal_bad_header_checksum_fails_closed(tmp_path):
    wal = tmp_path / "message.db-wal"
    data = bytearray(_wal_bytes([(2, 2, b"P" * 4096)])[0])
    data[24] ^= 1
    wal.write_bytes(data)
    with pytest.raises(_wal.WalValidationError, match="header checksum"):
        _wal.inspect_wal(wal, expected_page_size=4096)

    output = tmp_path / "decrypted.db"
    original = b"\0" * 8192
    output.write_bytes(original)
    with pytest.raises(_wal.WalValidationError, match="header checksum"):
        wechat_db._apply_wechat_wal(
            wal,
            bytes(range(32)),
            bytes(range(16)),
            output,
        )
    assert output.read_bytes() == original


def test_wechat_stale_index_fallback_never_applies_uncommitted_wal(tmp_path):
    key = bytes(range(32))
    salt = bytes(range(16))
    output = tmp_path / "decrypted.db"
    original = b"\0" * 8192
    output.write_bytes(original)
    wal = tmp_path / "message.db-wal"
    page = _encrypted_page(key, salt, 2, b"B")
    wal_bytes, frame_checksum = _wal_bytes([(2, 0, page)])
    wal.write_bytes(wal_bytes)
    wal.with_name("message.db-shm").write_bytes(
        _shm_bytes(
            mx_frame=1,
            n_page=2,
            frame_checksum=frame_checksum,
            page_size=8192,
        )
    )

    assert wechat_db._apply_wechat_wal(wal, key, salt, output) == 0
    assert output.read_bytes() == original


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
