"""Turn decrypted messages into a keepsake.

Two outputs, both fully local and offline:

* ``*_messages.json`` — the raw decrypted records, for archiving or feeding your
  own tools.
* ``*_messages.html`` — a single self-contained page you can open in any browser:
  a chat-bubble layout grouped by conversation and day, the way you remember it.

No network, no web fonts, no trackers — the CSS is inlined so the file still
opens, offline, on any machine, a decade from now.
"""
from __future__ import annotations

import html as _html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

__all__ = ["export_json", "export_html"]


# ── field accessors (tolerate both the QQ and WeChat dict shapes) ────────────

def _epoch(m: Dict[str, Any]) -> float:
    ts = m.get("ts")
    if isinstance(ts, (int, float)) and ts:
        return float(ts)
    iso = m.get("ts_iso")
    if iso:
        try:
            return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0
    return 0.0


def _chat_of(m: Dict[str, Any]) -> str:
    return str(m.get("chat_uid") or m.get("chat_room") or "（未命名会话）")


def _sender_of(m: Dict[str, Any]) -> str:
    return str(m.get("sender_name") or m.get("sender") or m.get("sender_wxid") or "?")


def _content_of(m: Dict[str, Any]) -> str:
    return str(m.get("content") or m.get("text") or "")


def _is_self(m: Dict[str, Any]) -> bool:
    return bool(m.get("is_self"))


# ── JSON ─────────────────────────────────────────────────────────────────────

def export_json(messages: List[Dict[str, Any]], path) -> int:
    """Write the raw message list to ``path`` as pretty UTF-8 JSON. Returns count."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(messages, f, ensure_ascii=False, indent=2)
    return len(messages)


# ── HTML ─────────────────────────────────────────────────────────────────────

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; background: #ededed; color: #1c1c1e;
  font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", Roboto, Helvetica, Arial, sans-serif; }
.wrap { max-width: 720px; margin: 0 auto; padding: 0 0 56px; }
header.keepsake { padding: 40px 24px 28px; text-align: center;
  background: linear-gradient(180deg, #f7f7f7 0%, #ededed 100%); }
header.keepsake h1 { margin: 0 0 6px; font-size: 22px; font-weight: 600; }
header.keepsake p.tag { margin: 0; color: #8a8a8e; font-size: 13px; line-height: 1.6; }
header.keepsake p.meta { margin: 10px 0 0; color: #b0b0b5; font-size: 12px; }
section.chat { margin: 22px 0 0; }
h2.chat-title { position: sticky; top: 0; z-index: 2; margin: 0;
  padding: 10px 24px; font-size: 14px; font-weight: 600; color: #576b95;
  background: rgba(237,237,237,.94); -webkit-backdrop-filter: blur(6px);
  backdrop-filter: blur(6px); border-bottom: 1px solid #e0e0e0; }
.day { text-align: center; margin: 18px 0 10px; }
.day span { background: #d6d6d6; color: #fff; font-size: 11px;
  padding: 2px 10px; border-radius: 4px; }
.msg { display: flex; padding: 3px 16px; }
.msg.self { justify-content: flex-end; }
.col { max-width: 76%; display: flex; flex-direction: column; }
.msg.self .col { align-items: flex-end; }
.name { font-size: 11px; color: #9a9a9e; margin: 6px 6px 2px; }
.bubble { padding: 8px 12px; border-radius: 8px; font-size: 15px; line-height: 1.5;
  word-wrap: break-word; white-space: pre-wrap; box-shadow: 0 1px 1px rgba(0,0,0,.04); }
.msg.other .bubble { background: #fff; border-top-left-radius: 2px; }
.msg.self  .bubble { background: #95ec69; border-top-right-radius: 2px; }
.time { font-size: 10px; color: #b8b8bd; margin: 2px 6px 0; }
footer { text-align: center; color: #b0b0b5; font-size: 12px;
  padding: 30px 24px 0; line-height: 1.7; }
"""


def _fmt_day(ts: float) -> str:
    if not ts:
        return "（未知日期）"
    return datetime.fromtimestamp(ts).strftime("%Y 年 %m 月 %d 日")


def _fmt_clock(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts).strftime("%H:%M")


def export_html(messages: List[Dict[str, Any]], path, *,
                title: str = "聊天记录留存", source: str = "chat") -> int:
    """Render messages into one self-contained, offline HTML keepsake.

    Messages are grouped by conversation, then ordered by time with day
    separators. Your own messages sit on the right (green bubble), like the app.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # group by conversation, each ordered by time
    chats: Dict[str, List[Dict[str, Any]]] = {}
    for m in messages:
        chats.setdefault(_chat_of(m), []).append(m)
    for lst in chats.values():
        lst.sort(key=_epoch)

    def _last_ts(chat: str) -> float:
        lst = chats[chat]
        return _epoch(lst[-1]) if lst else 0.0

    esc = _html.escape
    parts: List[str] = []
    parts.append("<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append(f"<title>{esc(title)}</title><style>{_CSS}</style></head><body><div class='wrap'>")
    parts.append("<header class='keepsake'>")
    parts.append(f"<h1>{esc(title)}</h1>")
    parts.append("<p class='tag'>留住对话框背后的那些故事<br>"
                 "Keep the stories behind every conversation</p>")
    parts.append(f"<p class='meta'>共 {len(messages)} 条 · {len(chats)} 个会话 · "
                 f"于 {datetime.now().strftime('%Y-%m-%d %H:%M')} 在本地生成</p>")
    parts.append("</header>")

    # conversations ordered by most-recent activity first
    for chat in sorted(chats, key=_last_ts, reverse=True):
        msgs = chats[chat]
        parts.append(f"<section class='chat'><h2 class='chat-title'>{esc(chat)}</h2>")
        last_day = None
        for m in msgs:
            ts = _epoch(m)
            day = _fmt_day(ts)
            if day != last_day:
                parts.append(f"<div class='day'><span>{esc(day)}</span></div>")
                last_day = day
            side = "self" if _is_self(m) else "other"
            body = esc(_content_of(m))
            clock = esc(_fmt_clock(ts))
            name_html = "" if _is_self(m) else f"<div class='name'>{esc(_sender_of(m))}</div>"
            parts.append(
                f"<div class='msg {side}'><div class='col'>{name_html}"
                f"<div class='bubble'>{body}</div>"
                f"<div class='time'>{clock}</div></div></div>"
            )
        parts.append("</section>")

    parts.append("<footer>本文件由 chatlog-keeper 在你自己的电脑上生成，"
                 "全程离线，未上传任何数据。<br>"
                 "Generated locally by chatlog-keeper — nothing was ever uploaded.</footer>")
    parts.append("</div></body></html>")

    with open(p, "w", encoding="utf-8") as f:
        f.write("".join(parts))
    return len(messages)
