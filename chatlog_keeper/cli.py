"""chatlog-keeper — 留住对话框背后的那些故事 / Keep the stories behind every conversation.

Decrypt and export **your own** local QQ / WeChat chat history for personal
backup and nostalgia. Everything runs on your own machine, against the client
you are already logged into, for your own account. Nothing is ever uploaded.

Subcommands::

    chatlog-keeper probe                        what's available here + key status
    chatlog-keeper qq      --days N --out DIR    export your QQ history    -> json + html
    chatlog-keeper wechat  --days N --out DIR    export your WeChat history -> json + html
    chatlog-keeper images  --src DIR --out DIR   decrypt your WeChat .dat images -> jpg/png

Decryption is page-by-page streaming (peak memory ≈ one 4 KB page), so even a
multi-GB database never loads whole.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from chatlog_keeper import active_key, qq_db, wechat_db, wechat_image
from chatlog_keeper.export import export_html, export_json


def _print_json(obj: dict) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return 0 if obj.get("available", True) and not obj.get("error") else 1


# ─── QQ ──────────────────────────────────────────────────────────────────────

def _probe_qq() -> dict:
    try:
        reader = qq_db.QQDBReader()
        ok = reader.initialize()
        return {
            "source": "qq",
            "available": bool(ok and reader.key),
            "account": qq_db.detect_current_qq_account(),
            "db_path": str(reader.db_path) if reader.db_path else None,
            "key_present": bool(reader.key),
        }
    except Exception as e:  # noqa: BLE001
        return {"source": "qq", "available": False, "error": f"{type(e).__name__}:{e}"}


def _export_qq(days: int, out_dir: str) -> dict:
    reader = qq_db.QQDBReader()
    if not reader.initialize() or not reader.key:
        return {"source": "qq", "available": False, "error": "no_key_or_db",
                "hint": "Make sure QQ (NT) is installed and you are logged in on this machine."}
    self_qq = qq_db.detect_current_qq_account()
    until = time.time()
    since = until - days * 86400
    t0 = time.time()
    msgs = reader.read_recent_dicts(since, until)
    for m in msgs:
        m["is_self"] = bool(self_qq and m.get("sender_qq") == self_qq)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    export_json(msgs, out / "qq_messages.json")
    export_html(msgs, out / "qq_messages.html", title="QQ 聊天记录留存", source="qq")
    return {"source": "qq", "available": True, "n_messages": len(msgs), "days": days,
            "elapsed_s": round(time.time() - t0, 1),
            "out_json": str(out / "qq_messages.json"),
            "out_html": str(out / "qq_messages.html")}


# ─── WeChat ───────────────────────────────────────────────────────────────────

def _wx_msg_to_dict(m, self_wxid: str = "") -> dict:
    """Map a WxMessage to the export schema using its real fields.

    WxMessage exposes ``content`` (text), ``timestamp`` (datetime),
    ``sender`` (raw wxid), ``sender_display_name``, ``chat_name`` (raw),
    ``chat_display_name`` — there is no ``text`` / ``chat_room`` / ``is_sender``.
    """
    ts = getattr(m, "timestamp", None)
    ts_epoch = ts.timestamp() if hasattr(ts, "timestamp") else None
    sender_wxid = getattr(m, "sender", None)
    is_self = bool(self_wxid and sender_wxid and self_wxid.startswith(str(sender_wxid)))
    return {
        "ts": ts_epoch,
        "sender": getattr(m, "sender_display_name", "") or sender_wxid,
        "sender_wxid": sender_wxid,
        "chat_room": getattr(m, "chat_display_name", "") or getattr(m, "chat_name", None),
        "content": getattr(m, "content", None),
        "msg_type": getattr(m, "msg_type", None),
        "is_self": is_self,
    }


def _probe_wechat() -> dict:
    try:
        reader = wechat_db.WeChatDBReader()
        reader.initialize()
        enc = getattr(reader, "enc_keys", None)
        return {
            "source": "wechat",
            "available": bool(enc),
            "wxid_dir": str(reader.wxid_dir) if getattr(reader, "wxid_dir", None) else None,
            "enc_keys_present": bool(enc),
        }
    except Exception as e:  # noqa: BLE001
        return {"source": "wechat", "available": False, "error": f"{type(e).__name__}:{e}"}


def _export_wechat(days: int, out_dir: str) -> dict:
    reader = wechat_db.WeChatDBReader()
    reader.initialize()
    if not getattr(reader, "enc_keys", None):
        return {"source": "wechat", "available": False, "error": "no_enc_keys",
                "hint": "Make sure WeChat (Weixin) is running and you are logged in on this machine."}
    self_wxid = reader.wxid_dir.name if getattr(reader, "wxid_dir", None) else ""
    since = time.time() - days * 86400
    t0 = time.time()
    raw = reader.read_after(since, chat_name=None)
    msgs = []
    for m in raw:
        d = _wx_msg_to_dict(m, self_wxid)
        if d.get("content"):
            msgs.append(d)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    export_json(msgs, out / "wechat_messages.json")
    export_html(msgs, out / "wechat_messages.html", title="微信聊天记录留存", source="wechat")
    return {"source": "wechat", "available": True, "n_messages": len(msgs), "days": days,
            "elapsed_s": round(time.time() - t0, 1),
            "out_json": str(out / "wechat_messages.json"),
            "out_html": str(out / "wechat_messages.html")}


# ─── WeChat images ─────────────────────────────────────────────────────────────

def _img_ext(b: bytes) -> str:
    if b[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return ".webp"
    return ".bin"


def _decrypt_images(src_dir: str, out_dir: str) -> dict:
    src = Path(src_dir)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    n_ok = n_fail = 0
    for dat in src.rglob("*.dat"):
        try:
            raw = wechat_image.decrypt_wechat_dat(dat)
            if not raw:
                n_fail += 1
                continue
            ext = _img_ext(raw)
            if ext == ".bin":
                # likely wxgf (WeChat HEVC still); try transcoding to JPEG
                jpg = wechat_image.wxgf_to_jpeg(raw)
                if jpg:
                    raw, ext = jpg, ".jpg"
            (out / (dat.stem + ext)).write_bytes(raw)
            n_ok += 1
        except Exception:  # noqa: BLE001
            n_fail += 1
    return {"source": "wechat_images", "available": True,
            "decrypted": n_ok, "failed": n_fail, "out": str(out)}


# ─── manual key entry (fallback when auto-extract can't get the key) ──────────

def _set_key(source: str, key: str) -> dict:
    """Save a manually-supplied decryption key to the cache so a later export
    uses it cache-first (no memory scan needed).

    Use this when automatic extraction can't get the key — e.g. newer WeChat
    builds whose key is no longer kept in plaintext process memory. Obtain the
    key with an admin-level extractor and paste it here.
    """
    key = (key or "").strip()
    if source == "qq":
        ok = qq_db.save_cached_key(key)
        return {"source": "qq", "ok": bool(ok),
                "saved_to": str(qq_db._key_cache_path()) if ok else None,
                "error": None if ok else "invalid QQ key (expect a 16- or 32-char passphrase)"}
    if source == "wechat":
        try:
            kb = bytes.fromhex(key)
        except ValueError:
            return {"source": "wechat", "ok": False, "error": "invalid WeChat key (expect 64 hex chars)"}
        ok = wechat_db.save_cached_wechat_key(kb)
        return {"source": "wechat", "ok": bool(ok),
                "saved_to": str(wechat_db._wechat_key_cache_path()) if ok else None,
                "error": None if ok else "WeChat key must be 32 bytes (64 hex chars)"}
    return {"ok": False, "error": "unknown source: " + str(source)}


# ─── automatic key extraction (passive memory scan / active debugger) ─────────

def _extract_key(source: str, method: str) -> dict:
    """Acquire a decryption key and cache it for later cache-first exports.

    ``method="passive"`` (default) scans the live client's process memory — low
    ban risk, no debugger; works on older builds, may find nothing on newer
    WeChat. ``method="active"`` runs the bundled debugger script — higher ban
    risk (it attaches a debugger), needs Administrator and you logging into the
    freshly-launched client, but works on the newest builds. Active is opt-in:
    you accept the higher risk by choosing it explicitly.
    """
    if method == "auto":
        # Try passive first (low ban risk); fall back to active (newer builds)
        # ONLY if passive finds nothing. Export stays cache-first and never
        # triggers active on its own — active only runs inside this command,
        # which the user invoked deliberately.
        r = _extract_key(source, "passive")
        if r.get("ok"):
            return r
        r = _extract_key(source, "active")
        if isinstance(r, dict):
            r["fell_back_from_passive"] = True
        return r
    if source == "qq":
        if method == "active":
            key = active_key.extract_qq_key_active()
            if key and qq_db.save_cached_key(key):
                return {"source": "qq", "method": "active", "ok": True,
                        "key_len": len(key), "saved_to": str(qq_db._key_cache_path())}
            return {"source": "qq", "method": "active", "ok": False,
                    "error": "active extraction got no key (not logged into the popped-up QQ / "
                             "UAC declined / unsupported build)"}
        reader = qq_db.QQDBReader()
        reader.initialize()  # cache → passive (timeout-bounded) → cache fallback
        if reader.key and qq_db.save_cached_key(reader.key):
            return {"source": "qq", "method": "passive", "ok": True,
                    "key_len": len(reader.key), "saved_to": str(qq_db._key_cache_path())}
        return {"source": "qq", "method": "passive", "ok": False,
                "error": "passive scan found no key (QQ not running, or a newer build — "
                         "try `--method active` or `set-key`)"}
    if source == "wechat":
        if method == "active":
            key = active_key.extract_wechat_key_active()
            if key and wechat_db.save_cached_wechat_key(key):
                return {"source": "wechat", "method": "active", "ok": True,
                        "key_len": len(key), "saved_to": str(wechat_db._wechat_key_cache_path())}
            return {"source": "wechat", "method": "active", "ok": False,
                    "error": "active extraction got no key (not logged into the popped-up WeChat / "
                             "UAC declined / unsupported build)"}
        reader = wechat_db.WeChatDBReader()
        reader.initialize()
        enc = getattr(reader, "enc_keys", None)
        if enc:
            # 4.x derives every per-DB page key from one 32-byte master key.
            master = next(iter(enc.values()))
            if wechat_db.save_cached_wechat_key(master):
                return {"source": "wechat", "method": "passive", "ok": True,
                        "key_len": len(master),
                        "saved_to": str(wechat_db._wechat_key_cache_path())}
        return {"source": "wechat", "method": "passive", "ok": False,
                "error": "passive scan found no key (WeChat not running, or 4.1.10.31+ where the "
                         "key is no longer in plaintext memory — try `--method active` or `set-key`)"}
    return {"ok": False, "error": "unknown source: " + str(source)}


# ─── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="chatlog-keeper",
        description="Decrypt and export YOUR OWN local QQ / WeChat history for "
                    "personal backup and nostalgia. Local-only; nothing is uploaded.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("probe", help="report what's available on this machine + key status")

    p_qq = sub.add_parser("qq", help="export your QQ history -> json + html")
    p_qq.add_argument("--days", type=int, default=7, help="lookback window in days (default 7)")
    p_qq.add_argument("--out", type=str, required=True, help="output directory")
    p_qq.add_argument("--data-root", type=str, default=None,
                      help="override the QQ 'Tencent Files' folder (else auto-detected)")

    p_wx = sub.add_parser("wechat", help="export your WeChat history -> json + html")
    p_wx.add_argument("--days", type=int, default=7, help="lookback window in days (default 7)")
    p_wx.add_argument("--out", type=str, required=True, help="output directory")
    p_wx.add_argument("--data-root", type=str, default=None,
                      help="override the WeChat 'xwechat_files' folder (else auto-detected)")

    p_im = sub.add_parser("images", help="decrypt your WeChat image .dat files -> jpg/png")
    p_im.add_argument("--src", type=str, required=True, help="folder of WeChat .dat files")
    p_im.add_argument("--out", type=str, required=True, help="output directory")

    p_sk = sub.add_parser("set-key", help="manually supply a key when auto-extract can't get it")
    p_sk.add_argument("--source", choices=["qq", "wechat"], required=True)
    p_sk.add_argument("--key", type=str, required=True,
                      help="QQ: 16/32-char passphrase; WeChat: 64-hex master key")

    p_ek = sub.add_parser("extract-key",
                          help="acquire + cache a decryption key automatically")
    p_ek.add_argument("--source", choices=["qq", "wechat"], required=True)
    p_ek.add_argument("--method", choices=["auto", "passive", "active"], default="auto",
                      help="auto (default): passive first, fall back to active only if "
                           "passive finds nothing. passive: scan live process memory - low "
                           "ban risk, older builds. active: bundled debugger breakpoint - "
                           "higher ban risk, needs Administrator + login, newest builds.")
    p_ek.add_argument("--data-root", type=str, default=None,
                      help="override the data folder (else auto-detected)")

    args = ap.parse_args(argv)

    # An explicit --data-root wins over auto-detection (machine-neutral override).
    if getattr(args, "data_root", None):
        src = getattr(args, "source", None) or args.cmd
        if src == "qq":
            os.environ["CHATLOG_QQ_DATA_ROOT"] = args.data_root
        elif src == "wechat":
            os.environ["CHATLOG_WECHAT_DATA_ROOT"] = args.data_root

    if args.cmd == "probe":
        return _print_json({"qq": _probe_qq(), "wechat": _probe_wechat()})
    if args.cmd == "qq":
        return _print_json(_export_qq(args.days, args.out))
    if args.cmd == "wechat":
        return _print_json(_export_wechat(args.days, args.out))
    if args.cmd == "images":
        return _print_json(_decrypt_images(args.src, args.out))
    if args.cmd == "set-key":
        return _print_json(_set_key(args.source, args.key))
    if args.cmd == "extract-key":
        return _print_json(_extract_key(args.source, args.method))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
