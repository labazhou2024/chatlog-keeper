"""V1/V2 sections may touch, but may never overlap or exceed the input."""

import struct

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from chatlog_keeper import wechat_image


_KEY = b"0123456789abcdef"


def _image(signature, middle=b"middle", tail=b"tail"):
    head = b"synthetic-image-head"
    encrypted = AES.new(_KEY, AES.MODE_ECB).encrypt(pad(head, 16))
    header = signature + struct.pack("<II", len(head), len(tail)) + b"\0"
    return header + encrypted + middle + bytes(value ^ 0x88 for value in tail), head + middle + tail


@pytest.mark.parametrize("signature", [wechat_image._V1_SIG, wechat_image._V2_SIG])
@pytest.mark.parametrize("middle,tail", [(b"middle", b"tail"), (b"", b"tail"), (b"", b"")])
def test_valid_sections_preserve_every_plaintext_byte(signature, middle, tail):
    data, expected = _image(signature, middle, tail)
    assert wechat_image._decrypt_v1v2(data, _KEY) == expected


@pytest.mark.parametrize("signature", [wechat_image._V1_SIG, wechat_image._V2_SIG])
@pytest.mark.parametrize("excess", [1, 8, 0xFFFFFFFF])
def test_xor_section_may_not_overlap_aes_ciphertext(signature, excess):
    data, _ = _image(signature)
    mutated = bytearray(data)
    available = len(data) - 15 - wechat_image._aligned_aes_size(20)
    struct.pack_into("<I", mutated, 10, min(available + excess, 0xFFFFFFFF))
    assert wechat_image._decrypt_v1v2(bytes(mutated), _KEY) is None


@pytest.mark.parametrize("cut", [0, 5, 14, 15, 20, 46, 47])
def test_truncated_headers_and_aes_sections_are_refused(cut):
    data, _ = _image(wechat_image._V2_SIG)
    assert wechat_image._decrypt_v1v2(data[:cut], _KEY) is None


def test_public_v2_decoder_refuses_overlapping_sections(tmp_path, monkeypatch):
    data, _ = _image(wechat_image._V2_SIG)
    mutated = bytearray(data)
    struct.pack_into("<I", mutated, 10, len(data))
    source = tmp_path / "synthetic.dat"
    source.write_bytes(mutated)
    monkeypatch.setattr(wechat_image, "_V2_KEY_CACHE", _KEY)
    monkeypatch.setattr(wechat_image, "derive_v2_xor_key", lambda _root: 0x88)
    assert wechat_image.decrypt_wechat_dat(source) is None
