from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

from chatlog_keeper import linux_key
from chatlog_keeper.linux_wechat_capture import (
    HMAC_KDF, PASSWORD_KDF, KDFBoundary, locate_kdf_boundary,
)


def elf_image(*, text_va=0x5000, text_flags=5, copies=1, companion=True):
    image = bytearray(0x2000)
    image[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', image, 16, 3, 62)
    struct.pack_into('<Q', image, 32, 64)
    struct.pack_into('<HH', image, 54, 56, 2)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 4, 0, 0, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into('<IIQQQQQQ', image, 120, 1, text_flags, 0x1000,
                     text_va, 0, 0x1000, 0x1000, 0x1000)
    for i in range(copies):
        p = 0x1100 + i * 0x300
        image[p:p + len(PASSWORD_KDF)] = PASSWORD_KDF
        if companion:
            q = p + 128
            image[q:q + len(HMAC_KDF)] = HMAC_KDF
    return image


@pytest.mark.parametrize('text_va', [0x5000, 0x90000])
def test_locator_translates_file_offset_through_executable_segment(tmp_path, text_va):
    exe = tmp_path / 'wechat'
    image = elf_image(text_va=text_va)
    exe.write_bytes(image)
    result = locate_kdf_boundary(exe)
    assert result == KDFBoundary(text_va + 0x100 + len(PASSWORD_KDF) - 3,
                                text_va + 0x100, hashlib.sha256(image).hexdigest())


@pytest.mark.parametrize('kwargs', [
    {'text_flags': 4}, {'copies': 0}, {'copies': 2}, {'companion': False},
])
def test_locator_rejects_missing_non_executable_or_ambiguous_pattern(tmp_path, kwargs):
    exe = tmp_path / 'wechat'
    exe.write_bytes(elf_image(**kwargs))
    assert locate_kdf_boundary(exe) is None


@pytest.mark.parametrize('offset,value', [(4, b'\x01'), (18, b'\xb7\x00'),
                                         (54, b'\xff\xff'), (64 + 40, b'\xff' * 8)])
def test_locator_rejects_unsupported_or_malformed_elf(tmp_path, offset, value):
    image = elf_image()
    image[offset:offset + len(value)] = value
    exe = tmp_path / 'wechat'
    exe.write_bytes(image)
    assert locate_kdf_boundary(exe) is None


def setup_runner(monkeypatch, tmp_path, *, records=(), error='', exited=False):
    exe = tmp_path / 'wechat'
    exe.write_bytes(elf_image())
    boundary = locate_kdf_boundary(exe)
    monkeypatch.setattr(linux_key, 'data_dir', lambda: tmp_path)
    monkeypatch.setattr(linux_key, 'daily_client_running', lambda _: False)
    monkeypatch.setattr(linux_key, 'shutil_which', lambda _: '/usr/bin/gdb')
    observations = {}

    class Process:
        returncode = 0 if exited else None
        def poll(self):
            return self.returncode
        def send_signal(self, sig):
            # The helper's status dir must outlive the inferior cleanup.
            assert Path(observations['config']['status_path']).exists()
            observations['signal'] = sig
        def wait(self, timeout):
            self.returncode = 0
            return 0

    def popen(argv, **kwargs):
        config = json.loads(kwargs['env']['CHATLOG_KEEPER_GDB_CONFIG'])
        observations.update(argv=argv, kwargs=kwargs, config=config)
        assert kwargs['stdout'] == kwargs['stderr'] == subprocess.DEVNULL
        assert kwargs['start_new_session'] is True
        with open(config['fifo'], 'wb', buffering=0) as stream:
            for record in records:
                stream.write(record)
        Path(config['status_path']).write_text(json.dumps({'error': error}))
        return Process()

    monkeypatch.setattr(linux_key.subprocess, 'Popen', popen)
    return exe, boundary, observations


def test_runner_verifies_twice_and_keeps_key_out_of_command_or_environment(monkeypatch, tmp_path):
    candidate = bytes(range(32))
    exe, boundary, obs = setup_runner(monkeypatch, tmp_path, records=[b'WXK1' + candidate])
    checked = []
    result = linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda c: checked.append(c) or c == candidate,
        timeout=1, cancel_requested=None,
    )
    assert result == candidate
    assert checked == [candidate, candidate]
    assert obs['signal'] == signal.SIGINT
    assert candidate.hex() not in json.dumps(obs)
    assert not list((tmp_path / 'bin').iterdir())


def test_runner_never_accepts_unverified_candidate(monkeypatch, tmp_path):
    exe, boundary, obs = setup_runner(monkeypatch, tmp_path, records=[b'WXK1' + b'a' * 32], exited=True)
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda _: False, timeout=1, cancel_requested=None,
    ) is None
    assert linux_key.last_error() == 'capture_client_exited'
    assert not list((tmp_path / 'bin').iterdir())


def test_runner_accepts_final_verified_record_from_exited_helper(monkeypatch, tmp_path):
    exe, boundary, _ = setup_runner(
        monkeypatch, tmp_path, records=[b'WXK1' + b'a' * 32], exited=True,
    )
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda c: c == b'a' * 32, timeout=1, cancel_requested=None,
    ) == b'a' * 32


def test_runner_rejects_malformed_record_and_stops_helper(monkeypatch, tmp_path):
    exe, boundary, obs = setup_runner(monkeypatch, tmp_path, records=[b'BAD!' + b'a' * 32])
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda _: pytest.fail('invalid record'), timeout=1, cancel_requested=None,
    ) is None
    assert linux_key.last_error() == 'capture_channel_invalid'
    assert obs['signal'] == signal.SIGINT
    assert not list((tmp_path / 'bin').iterdir())


def test_runner_cleans_up_if_debugger_cannot_start(monkeypatch, tmp_path):
    exe, boundary, _ = setup_runner(monkeypatch, tmp_path)
    def fail(*a, **kw):
        raise OSError('launch failed')
    monkeypatch.setattr(linux_key.subprocess, 'Popen', fail)
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda _: False, timeout=1, cancel_requested=None,
    ) is None
    assert linux_key.last_error() == 'capture_debugger_launch_failed'
    assert not list((tmp_path / 'bin').iterdir())


def test_runner_rechecks_when_page_changes(monkeypatch, tmp_path):
    exe, boundary, _ = setup_runner(monkeypatch, tmp_path, records=[b'WXK1' + b'a' * 32], exited=True)
    answers = iter([True, False])
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda _: next(answers), timeout=1, cancel_requested=None,
    ) is None


@pytest.mark.parametrize('error,expected', [
    ('capture_image_changed', 'capture_image_changed'),
    ('untrusted diagnostic content', 'capture_client_exited'),
])
def test_runner_limits_error_output(monkeypatch, tmp_path, error, expected):
    exe, boundary, _ = setup_runner(monkeypatch, tmp_path, error=error, exited=True)
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda _: False, timeout=1, cancel_requested=None,
    ) is None
    assert linux_key.last_error() == expected


def test_runner_cancels_and_cleans_up(monkeypatch, tmp_path):
    exe, boundary, obs = setup_runner(monkeypatch, tmp_path)
    cancelled = iter([False, True])
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda _: pytest.fail('no candidates'), timeout=1,
        cancel_requested=lambda: next(cancelled),
    ) is None
    assert obs['signal'] == signal.SIGINT
    assert not list((tmp_path / 'bin').iterdir())


def test_runner_times_out_and_cleans_up(monkeypatch, tmp_path):
    exe, boundary, obs = setup_runner(monkeypatch, tmp_path)
    times = iter([0, 2])
    monkeypatch.setattr(linux_key.time, 'monotonic', lambda: next(times))
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda _: False, timeout=1, cancel_requested=None,
    ) is None
    assert linux_key.last_error() == 'capture_timeout'
    assert obs['signal'] == signal.SIGINT


def test_router_uses_native_boundary_and_existing_hmac(monkeypatch, tmp_path):
    exe, boundary, _ = setup_runner(monkeypatch, tmp_path, records=[b'WXK1' + b'a' * 32])
    db = tmp_path / 'message_0.db'
    db.write_bytes(b'page')
    monkeypatch.setattr(linux_key, 'official_client_executable', lambda _: exe)
    monkeypatch.setattr(linux_key, 'extract_verified', lambda *a, **kw: pytest.fail('no heap scan'))
    monkeypatch.setattr('chatlog_keeper.wechat_db._read_stable_page1', lambda _: b'page')
    monkeypatch.setattr('chatlog_keeper.wechat_db._verify_key_v4', lambda c, p: c == b'a' * 32 and p == b'page')
    assert linux_key.extract_wechat_key_active(db_path=str(db), timeout=1) == b'a' * 32


@pytest.mark.parametrize('running,debugger,expected', [
    (True, '/usr/bin/gdb', 'daily_client_single_instance_conflict'),
    (False, None, 'capture_debugger_missing'),
])
def test_runner_preflight_never_launches_when_unavailable(monkeypatch, tmp_path, running, debugger, expected):
    exe, boundary, obs = setup_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(linux_key, 'daily_client_running', lambda _: running)
    monkeypatch.setattr(linux_key, 'shutil_which', lambda _: debugger)
    assert linux_key._extract_wechat_key_gdb(
        exe, boundary, lambda _: False, timeout=1, cancel_requested=None,
    ) is None
    assert not obs
    assert linux_key.last_error() == expected


@pytest.mark.parametrize('wrong_field', [
    None, 'passlen', 'saltlen', 'iterations', 'outlen', 'algorithm',
    'signature', 'image_hash', 'interrupt',
])
def test_gdb_observer_checks_runtime_shape_and_uses_hardware_only(monkeypatch, tmp_path, wrong_field):
    exe = tmp_path / 'wechat'
    exe.write_bytes(elf_image())
    boundary = locate_kdf_boundary(exe)
    fifo = tmp_path / 'candidate.fifo'
    os.mkfifo(fifo, 0o600)
    fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    status = tmp_path / 'status.json'
    status.touch(mode=0o600)
    config = dict(executable=str(exe), image_sha256=boundary.image_sha256,
                  virtual_address=boundary.virtual_address, signature_address=boundary.signature_address,
                  signature=PASSWORD_KDF.hex(), fifo=str(fifo), status_path=str(status))
    if wrong_field == 'image_hash':
        config['image_sha256'] = '0' * 64
    monkeypatch.setenv('CHATLOG_KEEPER_GDB_CONFIG', json.dumps(config))
    values = dict(passlen=32, saltlen=16, iterations=256000, outlen=32, algorithm=2)
    if wrong_field in values:
        values[wrong_field] += 1
    registers = dict(ecx=values['passlen'], r9d=values['saltlen'], esi=values['algorithm'],
                     rsp=0x200000, rdx=0x300000)
    memory = {0x100000 + boundary.signature_address: PASSWORD_KDF,
              0x200000: struct.pack('<I', values['iterations']),
              0x200008: struct.pack('<I', values['outlen']),
              0x300000: b'c' * 32}
    if wrong_field == 'signature':
        memory[0x100000 + boundary.signature_address] = b'\0' * len(PASSWORD_KDF)
    commands = []
    bps = []
    inferior = SimpleNamespace(pid=0, read_memory=lambda a, n: memory[a][:n])

    class Breakpoint:
        def __init__(self, address, *, type, internal):
            assert type == 77
            assert address == '*%#x' % (0x100000 + boundary.virtual_address)
            bps.append(self)
        def delete(self):
            pass

    def execute(command, **kwargs):
        commands.append(command)
        if command == 'continue':
            if wrong_field == 'interrupt':
                raise KeyboardInterrupt
            assert bps[0].stop() is False
        elif command == 'starti':
            inferior.pid = 1234
        elif command == 'kill':
            inferior.pid = 0

    fake = SimpleNamespace(execute=execute, Breakpoint=Breakpoint, BP_HARDWARE_BREAKPOINT=77,
                           selected_inferior=lambda: inferior,
                           selected_frame=lambda: SimpleNamespace(read_register=lambda n: registers[n]),
                           current_progspace=lambda: SimpleNamespace(filename=str(exe)))
    monkeypatch.setitem(sys.modules, 'gdb', fake)
    read_text = Path.read_text
    def mock_text(path, *a, **kw):
        if str(path) == '/proc/1234/maps':
            return '100000-101000 r--p 00000000 00:00 1 %s\n' % exe
        return read_text(path, *a, **kw)
    monkeypatch.setattr(Path, 'read_text', mock_text)
    try:
        runpy.run_path(str(linux_key._scripts_dir() / 'linux_wechat_gdb_capture.py'))
        assert os.read(fd, 4096) == (b'WXK1' + b'c' * 32 if wrong_field is None else b'')
    finally:
        os.close(fd)
    if wrong_field == 'image_hash':
        assert 'starti' not in commands
    else:
        assert commands[-1] == 'kill'
    if wrong_field in ('image_hash', 'signature'):
        assert not bps
        assert json.loads(status.read_text())['error'] == 'capture_image_changed'
    assert 'set startup-with-shell off' in commands
    assert not any(c.startswith(('attach', 'break ', 'set {')) for c in commands)
