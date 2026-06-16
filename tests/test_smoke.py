"""Smoke tests that touch NO real chat data — safe to run anywhere, incl. CI.

They verify the package imports cleanly, the exporter renders correctly and
escapes HTML, and the pure helpers behave. Real decryption needs a logged-in
client and your own local data, so it is intentionally out of scope here.

Run:  python -m pytest -q   (or simply  python tests/test_smoke.py)
"""
import json
import sys
from pathlib import Path

# allow running both as `pytest` and as a plain script from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_imports():
    from chatlog_keeper import cli, export, qq_db, wechat_db, wechat_image  # noqa: F401
    from chatlog_keeper.core import _path_resolver  # noqa: F401


def test_data_dir_is_usable():
    from chatlog_keeper.core._path_resolver import data_dir
    d = data_dir()
    assert d.exists() and d.is_dir()


def test_export_json_and_html(tmp_path):
    from chatlog_keeper.export import export_html, export_json
    msgs = [
        {"chat_uid": "mom", "sender_name": "Mom", "content": "sleep early",
         "ts": 1700000000, "is_self": False},
        {"chat_uid": "mom", "sender_name": "me", "content": "ok <b>bold</b>",
         "ts": 1700000060, "is_self": True},
        {"chat_room": "old friends", "sender": "A", "content": "reunion?",
         "ts": 1700100000, "is_self": False},
    ]
    nj = export_json(msgs, tmp_path / "m.json")
    nh = export_html(msgs, tmp_path / "m.html", title="Keepsake")
    assert nj == 3 and nh == 3

    data = json.loads((tmp_path / "m.json").read_text(encoding="utf-8"))
    assert len(data) == 3

    html = (tmp_path / "m.html").read_text(encoding="utf-8")
    assert "bubble" in html
    assert "msg self" in html and "msg other" in html
    # user content must be HTML-escaped, never injected raw
    assert "&lt;b&gt;bold&lt;/b&gt;" in html
    assert "ok <b>bold</b>" not in html


def test_img_ext():
    from chatlog_keeper.cli import _img_ext
    assert _img_ext(b"\xff\xd8\xff\xe0\x00\x10") == ".jpg"
    assert _img_ext(b"\x89PNG\r\n\x1a\n") == ".png"
    assert _img_ext(b"GIF89a\x00\x00") == ".gif"
    assert _img_ext(b"RIFF\x00\x00\x00\x00WEBP") == ".webp"
    assert _img_ext(b"not-an-image") == ".bin"


if __name__ == "__main__":
    import tempfile
    test_imports()
    test_data_dir_is_usable()
    test_export_json_and_html(Path(tempfile.mkdtemp()))
    test_img_ext()
    print("all smoke tests passed")
