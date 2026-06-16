"""WeChat 公众号链接正文抓取.

WeChat link cards (msg_type=49 sub_type=5) carry `<url>` pointing to either:
  - mp.weixin.qq.com/s/<token>  (公众号文章, public, no auth)
  - mp.weixin.qq.com/mp/...      (variants of public articles)
  - other host (skip — many short-lived CDN links not worth fetching)

LIVE-verified 2026-05-18: HTTP GET with browser UA returns 200 + full HTML
(no cookies / anti-bot required). Article body lives in `<div id="js_content">`.
og:title / og:image / author meta tags also present.

Public API:
  fetch_article(url) → dict {ok, title, author, body, og_image, fetched_at, ...}
  load_cached(url) → dict or None
  save_cache(url, data) → bool

Cache layout: data/wechat_link_cache/<sha-prefix>/<url_sha256>.json
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger(__name__)

_REPO = Path(__file__).resolve().parents[1]


def _data_root() -> Path:
    """Writable data root. Prefer the runtime data_dir() (= %LOCALAPPDATA%\\chatlog-keeper\\data
    on a frozen install) so the link cache lands exactly where
    chatlog_keeper.core.memory_query.link_body reads it (data_dir()/wechat_link_cache).
    Fail-soft to in-tree <repo>/data for a dev checkout. 2026-06-03: was _REPO/data
    which did NOT match link_body's read path → cache written but never found."""
    try:
        from chatlog_keeper.core._path_resolver import data_dir
        return data_dir()
    except Exception:
        return _REPO / "data"

# Only fetch URLs from these hosts. Everything else is skipped (we don't trust
# random short-link CDNs to be still alive / non-adversarial).
_FETCHABLE_HOSTS = (
    "mp.weixin.qq.com",
    "weixin.qq.com",
    "mp.weixinbridge.com",
)

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
_FETCH_TIMEOUT_S = 15.0
_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB safety cap


def _url_sha(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()


def _cache_path_for(url: str) -> Path:
    sha = _url_sha(url)
    return _data_root() / "wechat_link_cache" / sha[:2] / f"{sha}.json"


def is_fetchable(url: str) -> bool:
    """Return True iff url is in our whitelist of fetch-safe hosts."""
    if not url:
        return False
    m = re.match(r"https?://([^/]+)", url)
    if not m:
        return False
    host = m.group(1).lower()
    return any(host.endswith(h) for h in _FETCHABLE_HOSTS)


def load_cached(url: str) -> Optional[dict]:
    p = _cache_path_for(url)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_cache(url: str, data: dict) -> bool:
    p = _cache_path_for(url)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        tmp.replace(p)
        return True
    except OSError as e:
        logger.warning(f"link cache save fail {p}: {e}")
        return False


def _append_dead_letter(record: dict) -> None:
    try:
        dl_path = _data_root() / "wechat_link_dead_letter.json"
        existing = []
        if dl_path.exists():
            existing = json.loads(dl_path.read_text(encoding="utf-8"))
        existing.append(record)
        dl_path.parent.mkdir(parents=True, exist_ok=True)
        dl_path.write_text(
            json.dumps(existing, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


def _parse_article_html(html: str, url: str) -> dict:
    """Extract title/author/body/og_image from WeChat article HTML.

    Prefers BeautifulSoup; falls back to regex if bs4 unavailable.
    """
    out: dict[str, Any] = {
        "title": "",
        "author": "",
        "body": "",
        "og_image": "",
        "og_description": "",
        "site_name": "",
    }
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        # og:* + author meta
        for meta in soup.find_all("meta"):
            prop = meta.get("property", "") or meta.get("name", "")
            content = meta.get("content", "")
            if not content:
                continue
            if prop == "og:title":
                out["title"] = content.strip()[:200]
            elif prop == "og:description":
                out["og_description"] = content.strip()[:500]
            elif prop in ("og:image", "twitter:image"):
                if not out["og_image"]:
                    out["og_image"] = content.strip()[:400]
            elif prop == "og:site_name":
                out["site_name"] = content.strip()[:100]
            elif prop in ("author", "og:article:author"):
                if not out["author"]:
                    out["author"] = content.strip()[:60]
        # article body
        content_div = soup.find("div", id="js_content")
        if content_div:
            text = content_div.get_text(separator="\n", strip=True)
            # Normalize whitespace, collapse triple+ newlines
            text = re.sub(r"\n{3,}", "\n\n", text)
            out["body"] = text[:50000]  # 50KB cap (~ 25k Chinese chars)
        return out
    except ImportError:
        pass  # fall through to regex

    # Regex fallback (less reliable but works without bs4)
    def _re_meta(prop: str) -> str:
        m = re.search(
            rf'<meta[^>]+(?:property|name)=["\']({re.escape(prop)})["\'][^>]+content=["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        )
        if m:
            return m.group(2)[:200]
        m = re.search(
            rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']({re.escape(prop)})["\']',
            html, re.IGNORECASE,
        )
        return m.group(1)[:200] if m else ""

    out["title"] = _re_meta("og:title")
    out["og_image"] = _re_meta("og:image")
    out["og_description"] = _re_meta("og:description")[:500]
    out["site_name"] = _re_meta("og:site_name")
    out["author"] = _re_meta("author") or _re_meta("og:article:author")

    m = re.search(
        r'<div[^>]+id=["\']js_content["\'][^>]*>(.*?)</div>',
        html, re.IGNORECASE | re.DOTALL,
    )
    if m:
        inner = re.sub(r"<[^>]+>", "\n", m.group(1))
        inner = re.sub(r"\n{3,}", "\n\n", inner)
        inner = re.sub(r"\s+\n", "\n", inner).strip()
        out["body"] = inner[:50000]
    return out


def fetch_article(url: str, timeout: float = _FETCH_TIMEOUT_S,
                  use_cache: bool = True) -> dict:
    """Fetch + parse a WeChat article URL.

    Returns dict:
      {ok: bool, url, title, author, body, og_image, og_description,
       site_name, fetched_at, http_status, error?, from_cache?}
    """
    if not is_fetchable(url):
        return {"ok": False, "url": url, "error": "host_not_fetchable"}
    if use_cache:
        cached = load_cached(url)
        if cached and cached.get("ok"):
            cached["from_cache"] = True
            return cached
    import urllib.request
    import urllib.error
    t0 = time.time()
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status = r.status
            raw = r.read(_MAX_BODY_BYTES)
            # WeChat pages declare charset in meta; default utf-8
            html = raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        rec = {"ok": False, "url": url, "http_status": e.code,
               "error": f"http_{e.code}", "fetched_at": time.time()}
        _append_dead_letter({**rec, "ts": time.time()})
        return rec
    except Exception as e:
        rec = {"ok": False, "url": url, "error": f"{type(e).__name__}:{str(e)[:120]}",
               "fetched_at": time.time()}
        _append_dead_letter({**rec, "ts": time.time()})
        return rec
    parsed = _parse_article_html(html, url)
    result = {
        "ok": True,
        "url": url,
        "http_status": status,
        "fetched_at": time.time(),
        "elapsed_s": round(time.time() - t0, 2),
        "html_bytes": len(raw),
        **parsed,
        "from_cache": False,
    }
    if use_cache:
        save_cache(url, result)
    return result


# ─────────────────────────────────────────────────────────────────────
# save_as_doc — let the parsed article ride a downstream doc pipeline so its
# full body becomes searchable as a regular doc card. Writes a markdown file
# with YAML-ish front-matter containing origins (which chat msgs forwarded this
# URL). A doc builder can pick the path pattern and stamp
# linked_from_chat = {source:"wechat_link", url_sha, origins[]} so follow-links
# can jump both ways.
# ─────────────────────────────────────────────────────────────────────

def article_doc_path(url: str) -> Path:
    """Return the .md path where save_as_doc writes this URL's article."""
    sha = _url_sha(url)
    return _data_root() / "wechat_article_docs" / sha[:2] / f"{sha}.md"


def save_as_doc(url: str, data: dict,
                origins: Optional[list] = None) -> Optional[Path]:
    """Write parsed article as markdown into doc walk root.

    origins is an optional list of {chat_room, sender, ts, msg_svrid} dicts
    captured at collect_link_origins() time. Embedded in front-matter so that
    when a doc builder walks this .md it can read them into linked_from_chat,
    giving the article doc card back-link metadata.
    """
    if not data or not data.get("ok") or not (data.get("body") or "").strip():
        return None
    md_path = article_doc_path(url)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    title = (data.get("title") or "(无标题)").strip()
    author = (data.get("author") or "").strip()
    site = (data.get("site_name") or "").strip()
    body = data["body"].strip()
    fetched_at = data.get("fetched_at") or time.time()
    try:
        import datetime as _dt
        fetched_iso = _dt.datetime.fromtimestamp(
            float(fetched_at), tz=_dt.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        fetched_iso = "?"
    lines = [
        f"# {title}",
        "",
        f"- 来源: 公众号 / {author or '?'} / {site or '?'}",
        f"- URL: {url}",
        f"- url_sha: {_url_sha(url)}",
        f"- 抓取时间: {fetched_iso}",
    ]
    if origins:
        lines.append(f"- 转发记录 ({len(origins)} 条):")
        for o in origins[:20]:
            ts_o = o.get("ts") or ""
            try:
                import datetime as _dt
                ts_iso = _dt.datetime.fromtimestamp(
                    float(ts_o), tz=_dt.timezone.utc
                ).strftime("%Y-%m-%dT%H:%MZ")
            except Exception:
                ts_iso = str(ts_o)[:20]
            sender = (o.get("sender") or "?")[:32]
            room = (o.get("chat_room") or "?")[:32]
            svrid = (o.get("msg_svrid") or "")
            sv_tag = f" #{svrid[-6:]}" if svrid else ""
            lines.append(f"  - {sender} @{ts_iso} (群:{room}){sv_tag}")
    lines.extend(["", "---", "", body, ""])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return md_path


def format_article_for_narrative(parsed: dict, max_chars: int = 400) -> str:
    """Compact one-line article summary for chat narrative inject.

    Format: `<author> | <title>: <body[:max_chars]>`
    """
    if not parsed or not parsed.get("ok"):
        return ""
    title = (parsed.get("title") or "").strip()
    author = (parsed.get("author") or "").strip()
    site = (parsed.get("site_name") or "").strip()
    body = (parsed.get("body") or parsed.get("og_description") or "").strip()
    parts = []
    head = author or site
    if head and title:
        parts.append(f"{head} | {title}")
    elif title:
        parts.append(title)
    if body:
        body_short = re.sub(r"\s+", " ", body)[:max_chars]
        parts.append(f": {body_short}")
    return "".join(parts).strip()
