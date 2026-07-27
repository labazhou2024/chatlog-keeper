import json
import os

from chatlog_keeper import wechat_db
from chatlog_keeper.core._secrets import private_binary_writer, write_secret_text


def test_secret_write_is_atomic_and_restrictive(tmp_path):
    target = tmp_path / "secrets" / "key"
    assert write_secret_text(target, "first") is True
    assert write_secret_text(target, "second") is True
    assert target.read_text(encoding="utf-8") == "second"
    assert not list(target.parent.glob(".key.*"))
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600
        assert target.parent.stat().st_mode & 0o777 == 0o700


def test_private_binary_write_is_atomic_and_restrictive(tmp_path):
    target = tmp_path / "exports" / "image.jpg"
    with private_binary_writer(target) as handle:
        handle.write(b"\xff\xd8\xff")
    assert target.read_bytes() == b"\xff\xd8\xff"
    assert not list(target.parent.glob(".image.jpg.*"))
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


def test_wechat_diagnostics_never_include_key_bytes(
    monkeypatch, tmp_path
):
    secret = bytes(range(32))
    db = tmp_path / "message_0.db"
    db.write_bytes(b"x")
    reader = wechat_db.WeChatDBReader()
    reader.data_root = tmp_path
    reader.wxid_dir = tmp_path
    reader.enc_key = secret
    reader.enc_keys = {db: secret}
    monkeypatch.setattr(reader, "initialize", lambda: True)
    monkeypatch.setattr(wechat_db, "_get_weixin_pids", lambda: [])
    monkeypatch.setattr(
        wechat_db, "find_msg_databases", lambda root: [db]
    )

    encoded = json.dumps(reader.diagnose(), sort_keys=True)
    assert secret.hex() not in encoded
    assert secret.hex()[:16] not in encoded
    assert reader.diagnose()["per_db_keys_count"] == 1
