"""WeChat 4.x contact resolver — wxid → display_name + group member resolution.

LIVE-verified schema (Weixin 4.x contact.db, 2026-04-30):
    contact (17184 rows): id, username, local_type (1=friend, 2=group), alias, encrypt_username,
                          flag, delete_flag, verify_flag, remark, remark_quan_pin,
                          remark_pin_yin_initial, nick_name, pin_yin_initial, quan_pin,
                          big_head_url, small_head_url, head_img_md5, chat_room_notify,
                          is_in_chat_room, description, extra_buffer, chat_room_type
    chat_room (224 rows): id, username (xxx@chatroom), owner (wxid), ext_buffer
    chatroom_member (19437 rows): room_id, member_id
    stranger (11 rows): same schema as contact

Display name priority: COALESCE(NULLIF(remark, ''), NULLIF(nick_name, ''),
                                 NULLIF(alias, ''), username)

Usage:
    from chatlog_keeper.wechat_db import WeChatDBReader
    from chatlog_keeper.wechat_contacts import WeChatContactResolver
    reader = WeChatDBReader()
    reader.initialize()
    resolver = WeChatContactResolver(reader)
    resolver.load()
    name = resolver.resolve_display_name("wxid_xxxx")
    is_grp = resolver.is_group("18461014732@chatroom")
"""
from __future__ import annotations

import json
import logging
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_CONTACT_DB_REL = Path("db_storage") / "contact" / "contact.db"


class WeChatContactResolver:
    """Read contact.db and provide wxid → display_name + group lookups."""

    def __init__(self, reader):
        """reader: WeChatDBReader (must be .initialize()'d)."""
        self.reader = reader
        self._wxid_to_display: dict = {}
        self._group_wxids: set = set()
        self._chatroom_owner: dict = {}
        self._loaded = False

    def _emit_trace(self, event: str, payload: dict) -> None:
        """Emit trace event (best-effort; stdlib import to avoid cycle)."""
        try:
            from chatlog_keeper.core.trace_sink import emit  # type: ignore
            emit(event, payload)
        except Exception:
            pass

    def _contact_db_path(self) -> Optional[Path]:
        if not self.reader or not self.reader.wxid_dir:
            return None
        p = self.reader.wxid_dir / _CONTACT_DB_REL
        return p if p.exists() else None

    def _extract_contact_key(self) -> Optional[bytes]:
        """Try every Weixin pid until contact.db key found. Returns 32-byte key or None."""
        from chatlog_keeper.wechat_db import _get_weixin_pids, extract_key_from_weixin

        db = self._contact_db_path()
        if db is None:
            return None
        for pid in _get_weixin_pids():
            k = extract_key_from_weixin(pid, db_path=db)
            if k and isinstance(k, (bytes, bytearray)) and len(k) == 32:
                return bytes(k)
        return None

    def load(self) -> bool:
        """Decrypt contact.db + load wxid maps. Idempotent. Returns True on success."""
        if self._loaded:
            return True
        db = self._contact_db_path()
        if db is None:
            logger.warning("contact.db not found; resolver returns wxid as display_name fallback")
            self._loaded = True
            return False

        key = self._extract_contact_key()
        if not key:
            logger.warning("contact.db key extraction failed; fallback to wxid")
            self._loaded = True
            return False

        from chatlog_keeper.wechat_db import _decrypt_db_v4

        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        decrypt_path = Path(tmp.name)
        try:
            ok = _decrypt_db_v4(db, key, decrypt_path)
            if not ok:
                logger.warning("contact.db decrypt failed")
                return False
            conn = sqlite3.connect(str(decrypt_path))
            cur = conn.cursor()
            # Load contact + stranger (same schema). Hard-coded queries — no
            # f-string with table-name variable, to avoid security_scanner false-positive
            # on sql_injection (table names are literal, not user input).
            _CONTACT_QUERIES = (
                "SELECT username, local_type, alias, remark, nick_name FROM contact",
                "SELECT username, local_type, alias, remark, nick_name FROM stranger",
            )
            for query in _CONTACT_QUERIES:
                try:
                    cur.execute(query)
                except sqlite3.Error as e:
                    logger.debug(f"query failed: {e}")
                    continue
                for username, local_type, alias, remark, nick_name in cur.fetchall():
                    if not username:
                        continue
                    display = (
                        (remark or "").strip()
                        or (nick_name or "").strip()
                        or (alias or "").strip()
                        or username
                    )
                    self._wxid_to_display[username] = display
                    if local_type == 2 or username.endswith("@chatroom"):
                        self._group_wxids.add(username)
            # Load chat_room owners
            try:
                cur.execute("SELECT username, owner FROM chat_room")
                for username, owner in cur.fetchall():
                    if username:
                        self._group_wxids.add(username)
                        if owner:
                            self._chatroom_owner[username] = owner
            except sqlite3.Error:
                pass
            conn.close()
        finally:
            try:
                decrypt_path.unlink()
            except OSError:
                pass

        self._loaded = True
        self._emit_trace("wechat_contacts_loaded", {
            "contact_count": len(self._wxid_to_display),
            "group_count": len(self._group_wxids),
        })
        logger.info(
            f"contacts loaded: {len(self._wxid_to_display)} entries, "
            f"{len(self._group_wxids)} groups"
        )
        return True

    def resolve_display_name(self, wxid: str) -> str:
        """Return display_name for wxid; falls back to wxid string itself."""
        if not wxid:
            return wxid or ""
        if not self._loaded:
            self.load()
        return self._wxid_to_display.get(wxid, wxid)

    def is_group(self, wxid: str) -> bool:
        """True if wxid is a group chat."""
        if not wxid:
            return False
        if wxid.endswith("@chatroom"):
            return True
        if not self._loaded:
            self.load()
        return wxid in self._group_wxids

    def search_by_name(self, name_substr: str) -> list:
        """Return [(wxid, display_name)] tuples whose display contains name_substr (case-insensitive)."""
        if not name_substr:
            return []
        if not self._loaded:
            self.load()
        ns = name_substr.lower()
        return [
            (wxid, display)
            for wxid, display in self._wxid_to_display.items()
            if ns in display.lower()
        ]

    def all_displays(self) -> dict:
        """Return copy of internal wxid → display dict."""
        if not self._loaded:
            self.load()
        return dict(self._wxid_to_display)
