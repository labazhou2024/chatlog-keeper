from __future__ import annotations

import json
from pathlib import Path

from scripts.package_qq_media import package
from scripts.render_qq_chat_html import render


def test_package_qq_media_copies_exact_matches_and_reports_missing(tmp_path: Path):
    cache = tmp_path / "cache"
    image = cache / "Pic" / "2026-01" / "Ori" / "image.jpg"
    voice = cache / "Ptt" / "2026-01" / "Ori" / "voice.amr"
    image.parent.mkdir(parents=True)
    voice.parent.mkdir(parents=True)
    image.write_bytes(b"image-bytes")
    voice.write_bytes(b"voice-bytes")
    messages_path = tmp_path / "messages.json"
    messages_path.write_text(
        json.dumps(
            [
                {"attachment_meta": {"kind": "image", "filename": "image.jpg"}},
                {"attachment_meta": {"kind": "voice", "filename": "voice.amr"}},
                {"attachment_meta": {"kind": "image", "filename": "missing.jpg"}},
            ]
        ),
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"

    counts = package(messages_path, cache, out_dir)

    assert counts["attachment_records"] == 3
    assert counts["copied_records"] == 2
    assert counts["unique_media_files"] == 2
    assert counts["missing_records"] == 1
    assert (out_dir / "media/image/image.jpg").read_bytes() == b"image-bytes"
    assert (out_dir / "media/voice/voice.amr").read_bytes() == b"voice-bytes"
    manifest = json.loads((out_dir / "media_manifest.json").read_text(encoding="utf-8"))
    assert manifest["items"][2]["status"] == "missing"


def test_package_qq_media_does_not_guess_between_different_exact_name_matches(
    tmp_path: Path,
):
    cache = tmp_path / "cache"
    first = cache / "Pic" / "Ori" / "nested" / "same.jpg"
    second = cache / "Pic" / "Ori" / "same.jpg"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True, exist_ok=True)
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    messages_path = tmp_path / "messages.json"
    messages_path.write_text(
        json.dumps([{"attachment_meta": {"kind": "image", "filename": "same.jpg"}}]),
        encoding="utf-8",
    )

    counts = package(messages_path, cache, tmp_path / "out")

    assert counts["ambiguous_records"] == 1
    manifest = json.loads(
        (tmp_path / "out" / "media_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["items"][0]["status"] == "ambiguous"
    assert counts["unique_media_files"] == 0


def test_render_qq_chat_html_escapes_content_and_embeds_local_media(tmp_path: Path):
    messages_path = tmp_path / "messages.json"
    manifest_path = tmp_path / "manifest.json"
    output_path = tmp_path / "out.html"
    messages_path.write_text(
        json.dumps(
            [
                {
                    "ts": 1_700_000_000,
                    "sender_name": "<sender>",
                    "content": "<script>alert(1)</script>",
                    "is_self": False,
                }
            ]
        ),
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "message_index": 0,
                        "status": "copied",
                        "kind": "image",
                        "filename": "image.jpg",
                        "local_path": "media/image/image.jpg",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    render(messages_path, manifest_path, output_path, "<export>")
    rendered = output_path.read_text(encoding="utf-8")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;sender&gt;" in rendered
    assert "<img loading='lazy' src='media/image/image.jpg'" in rendered
    assert "http://" not in rendered and "https://" not in rendered
