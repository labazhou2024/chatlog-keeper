"""Portable checks for the macOS startup-capture wire contract.

The native dylib tests require an arm64 Darwin host.  These checks still run in
CI on every platform so a status-frame change cannot silently break parsing or
diagnostic classification before it reaches a Mac.
"""

import os
from pathlib import Path

from chatlog_keeper import macos_wechat_capture as capture


def _channel_with_pipe() -> tuple[capture.CaptureChannel, int]:
    read_fd, write_fd = os.pipe()
    channel = capture.CaptureChannel(
        path=Path("/tmp/chatlog-keeper-test.fifo"),
        read_fd=read_fd,
        device=1,
        inode=2,
    )
    return channel, write_fd


def _status(code: int, detail: int = 0) -> bytes:
    frame = bytearray(capture._STATUS_SIZE)
    frame[:4] = capture._STATUS_MAGIC
    frame[4] = code
    frame[5:9] = detail.to_bytes(4, "little")
    return bytes(frame)


def test_status_and_candidate_frames_are_interleaved_without_key_logging():
    channel, write_fd = _channel_with_pipe()
    key = bytes(range(32))
    try:
        os.write(
            write_fd,
            _status(1) + _status(2, 1) + _status(6) + _status(7, 1)
            + _status(8) + b"WXK1" + key,
        )
        os.close(write_fd)
        write_fd = -1
        assert channel.read_candidates() == [key]
        assert channel.diagnostic_failure() is None
        snapshot = channel.diagnostic_snapshot()
        assert snapshot["counts"] == {
            "constructor": 1,
            "load": 1,
            "call": 1,
            "match": 1,
            "write_ok": 1,
        }
        assert key.hex() not in repr(snapshot)
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(channel.read_fd)


def test_status_diagnostics_distinguish_missing_environment_and_shape():
    channel, write_fd = _channel_with_pipe()
    try:
        os.write(write_fd, _status(1) + _status(2, 0))
        os.close(write_fd)
        write_fd = -1
        assert channel.read_candidates() == []
        assert channel.diagnostic_failure() == "capture_environment_missing"
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(channel.read_fd)

    channel, write_fd = _channel_with_pipe()
    try:
        os.write(write_fd, _status(1) + _status(2, 1) + _status(6))
        os.close(write_fd)
        write_fd = -1
        assert channel.read_candidates() == []
        assert channel.diagnostic_failure() == "capture_kdf_shape_unmatched"
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(channel.read_fd)
