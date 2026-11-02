#!/usr/bin/env python3
"""Render exported QQ JSON plus a media manifest as an offline HTML page."""

from __future__ import annotations

import argparse
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any


_CSS = """
body{font-family:system-ui,-apple-system,'Noto Sans CJK SC','Microsoft YaHei',sans-serif;background:#f1f2f3;margin:0;color:#1f2328}
.wrap{max-width:860px;margin:auto;padding:18px 12px 50px}.head{background:#fff;border-radius:8px;padding:20px;margin-bottom:16px;box-shadow:0 1px 4px #0001}
.msg{display:flex;margin:7px 0}.self{justify-content:flex-end}.bubble{max-width:78%;background:#fff;border-radius:8px;padding:9px 12px;white-space:pre-wrap;line-height:1.5;box-shadow:0 1px 3px #0001}.self .bubble{background:#c8f7a9}
.name{font-size:12px;color:#667085;margin-bottom:4px}.time{font-size:11px;color:#98a2b3;margin-top:5px;text-align:right}.day{text-align:center;color:#667085;font-size:12px;margin:20px}
.media img{max-width:100%;max-height:520px;border-radius:6px;margin-top:8px}.media video{max-width:100%;max-height:520px;margin-top:8px}.media audio{width:100%;margin-top:8px}.missing{color:#b54708;font-size:12px;margin-top:6px}.quote{border-left:3px solid #98a2b3;padding-left:8px;color:#667085}.meta{color:#667085;font-size:13px}
"""


def _escape(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def render(messages_path: Path, manifest_path: Path, output_path: Path, title: str) -> int:
    messages = json.loads(messages_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(messages, list) or not isinstance(manifest.get("items"), list):
        raise ValueError("invalid messages or media manifest format")
    by_index = {
        item.get("message_index"): item
        for item in manifest["items"]
        if isinstance(item, dict)
    }
    parts = [
        "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'\">",
        f"<title>{_escape(title)}</title><style>{_CSS}</style></head><body><div class='wrap'>",
        f"<div class='head'><h1>{_escape(title)}</h1><div class='meta'>{len(messages)} messages</div></div>",
    ]
    previous_day = None
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        timestamp = float(message.get("ts") or 0)
        moment = datetime.fromtimestamp(timestamp) if timestamp else None
        day = moment.strftime("%Y-%m-%d") if moment else "Unknown date"
        if day != previous_day:
            parts.append(f"<div class='day'>{_escape(day)}</div>")
            previous_day = day
        side = "self" if message.get("is_self") else "other"
        content = _escape(message.get("content"))
        if content.startswith("[引用:"):
            closing = content.find("]")
            if closing >= 0:
                content = f"<span class='quote'>{content[:closing + 1]}</span>{content[closing + 1:]}"
        body = f"<div class='name'>{_escape(message.get('sender_name'))}</div><div>{content}</div>"
        item = by_index.get(index)
        if item:
            if item.get("status") == "copied" and item.get("local_path"):
                relative = _escape(item["local_path"])
                kind = item.get("kind")
                filename = _escape(item.get("filename"))
                if kind == "image":
                    body += f"<div class='media'><a href='{relative}'><img loading='lazy' src='{relative}' alt='{filename}'></a></div>"
                elif kind == "voice":
                    body += f"<div class='media'><audio controls preload='none' src='{relative}'></audio></div>"
                elif Path(str(item.get("filename") or "")).suffix.lower() in {".mp4", ".mov", ".webm"}:
                    body += f"<div class='media'><video controls preload='metadata' src='{relative}'></video></div>"
                else:
                    body += f"<div class='media'><a href='{relative}'>Attachment: {filename}</a></div>"
            else:
                body += f"<div class='missing'>{_escape(item.get('status'))}: {_escape(item.get('filename'))}</div>"
        if moment:
            body += f"<div class='time'>{_escape(moment.strftime('%Y-%m-%d %H:%M:%S'))}</div>"
        parts.append(f"<div class='msg {side}'><div class='bubble'>{body}</div></div>")
    parts.append("</div></body></html>")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(parts), encoding="utf-8")
    return len(messages)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--messages", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--title", default="QQ Chat Export")
    args = parser.parse_args()
    try:
        count = render(args.messages, args.manifest, args.output, args.title)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"messages": count, "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
