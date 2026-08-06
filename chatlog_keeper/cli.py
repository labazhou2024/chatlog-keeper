"""chatlog-keeper — 留住对话框背后的那些故事 / Keep the stories behind every conversation.

Decrypt and export **your own** local QQ / WeChat chat history for personal
backup and nostalgia. Everything runs on your own machine, against the client
you are already logged into, for your own account. Nothing is ever uploaded.

Subcommands::

    chatlog-keeper probe                        what's available here + key status
    chatlog-keeper directory --source qq|wechat list accounts + conversations
    chatlog-keeper qq      --days N --out DIR    export your QQ history    -> json + html
    chatlog-keeper wechat  --days N --out DIR    export your WeChat history -> json + html
    chatlog-keeper images  --src DIR --out DIR   decrypt your WeChat .dat images -> jpg/png

Decryption is page-by-page streaming (peak memory ≈ one 4 KB page), so even a
multi-GB database never loads whole.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import signal
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Union, Any, Iterator

from chatlog_keeper import (
    active_key,
    participant_directory,
    participant_protocol,
    qq_db,
    stream_protocol,
    wechat_db,
    wechat_image,
)
from chatlog_keeper.core._secrets import private_binary_writer
from chatlog_keeper.export import export_html, export_json


def _print_json(obj: dict) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return 0 if obj.get("available", True) and not obj.get("error") else 1


def _prepare_output_dir(path: Path) -> None:
    """Create a new export directory owner-only without altering an existing one."""
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not existed and os.name != "nt":
        path.chmod(0o700)


class _SelectionError(Exception):
    """Raised for an invalid private selection without retaining its values."""


_MAX_SELECTION_STDIN_CHARS = 1_048_576
_MAX_KEY_STDIN_CHARS = 256
_CONVERSATION_SCOPE_VERSION = 2
_CONVERSATION_TYPES = frozenset({"direct", "group"})

_ConversationScope = Union[tuple[str, str], tuple[str, str, str]]


@dataclass(frozen=True)
class _ExportSelection:
    """Validated export scope.

    ``all_accounts`` is true only for an explicit stdin selection whose
    ``account_ids`` list is empty.  Omitting all selection options keeps the
    legacy single-account behavior.  When ``scopes_explicit`` is true,
    ``conversation_scopes`` takes precedence over legacy ``conversation_ids``;
    an empty scope list keeps the established empty-list-means-all behavior.
    """

    account_ids: tuple[str, ...] = ()
    conversation_ids: tuple[str, ...] = ()
    conversation_scopes: tuple[_ConversationScope, ...] = ()
    scopes_explicit: bool = False
    explicit: bool = False
    all_accounts: bool = False


def _validated_ids(value) -> tuple[str, ...]:
    """Validate opaque native IDs without interpreting them as paths."""
    if not isinstance(value, list):
        raise _SelectionError()
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            raise _SelectionError()
        normalized = item.strip()
        if (
            not normalized
            or normalized != item
            or len(normalized) > 512
            or any(ord(char) < 32 for char in normalized)
        ):
            raise _SelectionError()
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return tuple(result)


def _validated_conversation_scopes(value) -> tuple[_ConversationScope, ...]:
    """Validate legacy pairs or v2 typed scopes without retaining bad values."""
    if not isinstance(value, list):
        raise _SelectionError()
    result = []
    seen = set()
    pair_modes = {}
    for item in value:
        if not isinstance(item, dict):
            raise _SelectionError()
        keys = set(item)
        pair_keys = {"account_id", "conversation_id"}
        typed_keys = pair_keys | {"conversation_type"}
        if keys not in (pair_keys, typed_keys):
            raise _SelectionError()
        account_ids = _validated_ids([item["account_id"]])
        conversation_ids = _validated_ids([item["conversation_id"]])
        pair = (account_ids[0], conversation_ids[0])
        mode = "typed" if keys == typed_keys else "legacy"
        previous_mode = pair_modes.get(pair)
        if previous_mode is not None and previous_mode != mode:
            raise _SelectionError()
        pair_modes[pair] = mode
        scope: _ConversationScope
        if keys == typed_keys:
            conversation_type = item["conversation_type"]
            if (
                not isinstance(conversation_type, str)
                or conversation_type not in _CONVERSATION_TYPES
            ):
                raise _SelectionError()
            scope = (*pair, conversation_type)
        else:
            scope = pair
        if scope not in seen:
            seen.add(scope)
            result.append(scope)
    return tuple(result)


def _scope_account_id(scope: _ConversationScope) -> str:
    return scope[0]


def _scope_conversation_id(scope: _ConversationScope) -> str:
    return scope[1]


def _scope_conversation_type(scope: _ConversationScope) -> str | None:
    return scope[2] if len(scope) == 3 else None


def _normalized_conversation_type(value) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _CONVERSATION_TYPES else None


def _directory_scope_index(readers) -> tuple[set[tuple[str, str, str]], dict, bool]:
    """Read directory identities once; ``complete`` is false on any unreadable account."""
    typed_scopes: set[tuple[str, str, str]] = set()
    types_by_pair: dict[tuple[str, str], set[str]] = {}
    complete = True
    for reader in readers:
        read_directory = getattr(reader, "read_conversation_directory", None)
        if not callable(read_directory):
            complete = False
            continue
        directory = read_directory()
        if directory is None:
            complete = False
            continue
        account_id = str(getattr(reader, "account_id", None) or "")
        for item in directory:
            if not isinstance(item, dict):
                continue
            conversation_id = str(item.get("conversation_id") or "")
            conversation_type = _normalized_conversation_type(
                item.get("conversation_type")
            )
            if not conversation_id or conversation_type is None:
                continue
            pair = (account_id, conversation_id)
            typed_scopes.add((*pair, conversation_type))
            types_by_pair.setdefault(pair, set()).add(conversation_type)
    return typed_scopes, types_by_pair, complete


def _resolved_typed_scopes(
    scopes: tuple[_ConversationScope, ...],
    available_typed_scopes: set[tuple[str, str, str]],
    types_by_pair: dict[tuple[str, str], set[str]],
) -> set[tuple[str, str, str]] | None:
    """Resolve v1 pairs only when the directory proves a unique typed identity."""
    resolved: set[tuple[str, str, str]] = set()
    for scope in scopes:
        pair = (_scope_account_id(scope), _scope_conversation_id(scope))
        conversation_type = _scope_conversation_type(scope)
        if conversation_type is None:
            matching_types = types_by_pair.get(pair, set())
            if len(matching_types) != 1:
                return None
            conversation_type = next(iter(matching_types))
        typed_scope = (*pair, conversation_type)
        if typed_scope not in available_typed_scopes:
            return None
        resolved.add(typed_scope)
    return resolved


def _message_conversation_type(message: dict, fallback_types=()) -> str | None:
    conversation_type = _normalized_conversation_type(
        message.get("conversation_type")
    )
    if conversation_type is not None:
        return conversation_type
    if message.get("is_group_chat") is True:
        return "group"
    if message.get("is_group_chat") is False:
        return "direct"
    chat_kind = str(message.get("chat_kind") or "").strip().lower()
    if chat_kind in {"group", "room", "chatroom"}:
        return "group"
    if chat_kind in {"direct", "friend", "private"}:
        return "direct"
    fallback_types = set(fallback_types)
    return next(iter(fallback_types)) if len(fallback_types) == 1 else None


def _selection_from_args(args) -> _ExportSelection:
    """Read a CLI or stdin selection while keeping raw IDs out of errors."""
    cli_accounts = list(getattr(args, "account", None) or [])
    cli_conversations = list(getattr(args, "conversation", None) or [])
    if getattr(args, "selection_stdin", False):
        if cli_accounts or cli_conversations:
            raise _SelectionError()
        try:
            raw_payload = sys.stdin.read(_MAX_SELECTION_STDIN_CHARS + 1)
            if len(raw_payload) > _MAX_SELECTION_STDIN_CHARS:
                raise _SelectionError()
            payload = json.loads(raw_payload)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            raise _SelectionError() from None
        legacy_keys = {"account_ids", "conversation_ids"}
        scoped_keys = legacy_keys | {"conversation_scopes"}
        if not isinstance(payload, dict) or set(payload) not in (legacy_keys, scoped_keys):
            raise _SelectionError()
        account_ids = _validated_ids(payload["account_ids"])
        conversation_ids = _validated_ids(payload["conversation_ids"])
        scopes_explicit = "conversation_scopes" in payload
        conversation_scopes = _validated_conversation_scopes(
            payload["conversation_scopes"]
        ) if scopes_explicit else ()
        scope_accounts = {
            _scope_account_id(scope) for scope in conversation_scopes
        }
        if account_ids and not scope_accounts.issubset(account_ids):
            raise _SelectionError()
        return _ExportSelection(
            account_ids=account_ids,
            conversation_ids=conversation_ids,
            conversation_scopes=conversation_scopes,
            scopes_explicit=scopes_explicit,
            explicit=True,
            all_accounts=not account_ids,
        )

    account_ids = _validated_ids(cli_accounts)
    conversation_ids = _validated_ids(cli_conversations)
    return _ExportSelection(
        account_ids=account_ids,
        conversation_ids=conversation_ids,
        explicit=bool(account_ids or conversation_ids),
        all_accounts=False,
    )


def _invalid_selection_result(source: str) -> dict:
    """Return a stable failure without echoing native selection values."""
    return {"source": source, "available": False, "error": "invalid_selection"}


def _directory_result(source: str, available: bool, accounts: list, conversations: list) -> dict:
    """Build the exact public directory shape; never include paths or secrets."""
    return {
        "source": source,
        "available": bool(available),
        "conversation_scope_version": _CONVERSATION_SCOPE_VERSION,
        "accounts": accounts,
        "conversations": conversations,
    }


def _directory_qq(data_root: str | None = None, account_ids: tuple[str, ...] | None = None) -> dict:
    """List QQ accounts and conversations using metadata-only database queries."""
    root = Path(data_root).expanduser() if data_root else qq_db.find_qq_data_root()
    if root is None:
        return _directory_result("qq", False, [], [])
    discovered = qq_db.find_qq_account_databases(root)
    if account_ids is not None and not set(account_ids).issubset(discovered):
        return _directory_result("qq", False, [], [])
    selected_ids = list(account_ids) if account_ids is not None else list(discovered)

    accounts = []
    conversations = []
    available = False
    for account_id in selected_ids:
        reader = qq_db.QQDBReader(
            data_root=root,
            account_id=account_id,
            allow_live_key_extract=False,
        )
        if not reader.initialize() or not reader.key:
            directory = None
        else:
            directory = reader.read_conversation_directory()
        if directory is None:
            continue
        available = True
        label = qq_db._normalize_qq_number(getattr(reader, "account_label", ""))
        normalized_account_id = str(account_id or "").strip()
        if not label:
            label = qq_db._normalize_qq_number(normalized_account_id)
        if not label:
            display_index = len(accounts) + 1
            label = f"QQ account {display_index}" if len(selected_ids) > 1 else "QQ account"
        accounts.append({
            "account_id": account_id,
            "label": label,
            "conversation_count": len(directory),
        })
        for item in directory:
            conversations.append({
                "account_id": account_id,
                "conversation_id": item["conversation_id"],
                "label": item["label"],
                "conversation_type": item["conversation_type"],
                "message_count": int(item["message_count"]),
            })
    return _directory_result("qq", available, accounts, conversations)


def _directory_wechat(data_root: str | None = None, account_ids: tuple[str, ...] | None = None) -> dict:
    """List WeChat accounts and conversations without selecting message bodies."""
    root = Path(data_root).expanduser() if data_root else wechat_db.find_weixin_data_root()
    if root is None:
        return _directory_result("wechat", False, [], [])
    discovered = {item.name: item for item in wechat_db.find_wxid_dirs(root)}
    if account_ids is not None and not set(account_ids).issubset(discovered):
        return _directory_result("wechat", False, [], [])
    selected_ids = list(account_ids) if account_ids is not None else list(discovered)

    accounts = []
    conversations = []
    available = False
    for account_id in selected_ids:
        reader = wechat_db.WeChatDBReader(
            data_root=root,
            account_id=account_id,
            allow_live_key_extract=False,
        )
        if not reader.initialize() or not reader.enc_keys:
            directory = None
        else:
            directory = reader.read_conversation_directory()
        if directory is None:
            continue
        available = True
        label = " ".join(str(getattr(reader, "account_label", "") or "").split()).strip()
        if not label:
            normalized_account_id = " ".join(str(account_id or "").split()).strip()
            label = f"微信号：{normalized_account_id}" if normalized_account_id else "微信账号"
        accounts.append({
            "account_id": account_id,
            "label": label,
            "conversation_count": len(directory),
        })
        for item in directory:
            conversations.append({
                "account_id": account_id,
                "conversation_id": item["conversation_id"],
                "label": item["label"],
                "conversation_type": item["conversation_type"],
                "message_count": int(item["message_count"]),
            })
    return _directory_result("wechat", available, accounts, conversations)


# ─── QQ ──────────────────────────────────────────────────────────────────────

def _probe_qq() -> dict:
    """Lightweight status probe — NEVER scans process memory.

    A status probe must be instant. It reports what is *locatable* (a QQ data
    root + live ``nt_msg.db``) and whether a working key is *already cached* — it
    must NOT run the passive memory scan (a multi-GB ``QQ.exe`` heap can take
    minutes per pid). Acquiring a key is the separate, explicit ``extract-key``
    step. ``available`` is true only when a cached key exists, so the GUI 检测
    button stays sub-second; "running but no key yet" surfaces as
    ``available=False`` + ``needs_key=True`` so the UI guides the user to
    「自动获取密钥」 instead of hanging on a scan.
    """
    try:
        running = bool(qq_db._get_qq_pids())
        root = qq_db.find_qq_data_root()
        db = qq_db.find_msg_database(root) if root else None
        account = qq_db.detect_current_qq_account()
        account_databases = qq_db.find_qq_account_databases(root) if root else {}
        preferred_account = str(account) if account not in (None, "") else ""
        ordered_accounts = sorted(
            account_databases,
            key=lambda account_id: (account_id != preferred_account, account_id),
        )
        readable_account = None
        readable_db = None
        for account_id in ordered_accounts:
            candidate_db = account_databases[account_id]
            cached = qq_db.load_cached_key_for_account(account_id)
            verification = (
                qq_db._read_qq_verification_bytes(candidate_db) if cached else None
            )
            if (
                cached
                and verification
                and qq_db._verify_key_qq(cached, verification)
            ):
                readable_account = account_id
                readable_db = candidate_db
                break

        # Preserve archived/single-database compatibility when no account
        # directory can be resolved. This still only validates cached keys.
        if readable_db is None and db is not None and not account_databases:
            cached = (
                qq_db.load_cached_key_for_account(preferred_account)
                if preferred_account
                else qq_db.load_cached_key()
            )
            verification = qq_db._read_qq_verification_bytes(db) if cached else None
            if (
                cached
                and verification
                and qq_db._verify_key_qq(cached, verification)
            ):
                readable_account = account
                readable_db = db

        has_key = readable_db is not None
        return {
            "source": "qq",
            "available": has_key,
            "client_running": running,
            "account": readable_account if readable_account is not None else account,
            "db_path": str(readable_db or db) if (readable_db or db) else None,
            "key_present": has_key,
            "needs_key": bool((account_databases or db) and not has_key),
        }
    except Exception as e:  # noqa: BLE001
        return {"source": "qq", "available": False, "error": f"{type(e).__name__}:{e}"}


def _export_qq(
    days: int,
    out_dir: str,
    selection: _ExportSelection | None = None,
    data_root: str | None = None,
) -> dict:
    selection = selection or _ExportSelection()
    root = Path(data_root).expanduser() if data_root else qq_db.find_qq_data_root()

    if selection.explicit and (
        selection.account_ids
        or selection.all_accounts
        or selection.conversation_scopes
    ):
        if root is None:
            return _invalid_selection_result("qq")
        discovered = qq_db.find_qq_account_databases(root)
        scope_accounts = tuple(dict.fromkeys(
            _scope_account_id(scope) for scope in selection.conversation_scopes
        ))
        if (
            scope_accounts
            and selection.account_ids
            and not set(scope_accounts).issubset(selection.account_ids)
        ):
            return _invalid_selection_result("qq")
        if scope_accounts:
            requested = list(scope_accounts)
        else:
            requested = list(selection.account_ids) if selection.account_ids else list(discovered)
        if not requested or not set(requested).issubset(discovered):
            return _invalid_selection_result("qq")
        readers = [
            qq_db.QQDBReader(data_root=root, account_id=account_id)
            for account_id in requested
        ]
    else:
        # No account scope preserves v0.2.0: use the active/most-recent account.
        readers = [qq_db.QQDBReader(data_root=root)]

    for reader in readers:
        if not reader.initialize() or not reader.key:
            return {"source": "qq", "available": False, "error": "no_key_or_db",
                    "hint": "Make sure QQ (NT) is installed and you are logged in on this machine."}

    available_typed_scopes, types_by_pair, directory_complete = (
        _directory_scope_index(readers)
    )
    selected_typed_scopes: set[tuple[str, str, str]] = set()
    if selection.scopes_explicit and selection.conversation_scopes:
        if not directory_complete:
            return {"source": "qq", "available": False,
                    "error": "directory_unavailable"}
        resolved_scopes = _resolved_typed_scopes(
            selection.conversation_scopes,
            available_typed_scopes,
            types_by_pair,
        )
        if resolved_scopes is None:
            return _invalid_selection_result("qq")
        selected_typed_scopes = resolved_scopes
    elif not selection.scopes_explicit and selection.conversation_ids:
        if not directory_complete:
            return {"source": "qq", "available": False,
                    "error": "directory_unavailable"}
        available_conversations = {
            conversation_id
            for _account_id, conversation_id, _conversation_type
            in available_typed_scopes
        }
        if not set(selection.conversation_ids).issubset(available_conversations):
            return _invalid_selection_result("qq")

    until = time.time()
    since = until - days * 86400
    t0 = time.time()
    prepared_messages = []
    selected_conversations = (
        set() if selection.scopes_explicit else set(selection.conversation_ids)
    )
    for reader in readers:
        account_messages = reader.read_recent_dicts(since, until)
        self_qq = (
            qq_db._normalize_qq_number(getattr(reader, "account_label", ""))
            or qq_db._normalize_qq_number(getattr(reader, "account_id", ""))
        )
        for message in account_messages:
            account_id = str(reader.account_id or message.get("account_id") or "")
            conversation_id = str(
                message.get("conversation_id") or message.get("chat_uid") or ""
            )
            pair = (account_id, conversation_id)
            conversation_type = _message_conversation_type(
                message,
                fallback_types=types_by_pair.get(pair, ()),
            )
            typed_scope = (
                (*pair, conversation_type)
                if conversation_type is not None
                else None
            )
            if selected_typed_scopes and typed_scope not in selected_typed_scopes:
                continue
            if (
                selected_conversations
                and conversation_id not in selected_conversations
            ):
                continue
            message["account_id"] = account_id
            message["conversation_id"] = conversation_id
            if conversation_type is not None:
                message["conversation_type"] = conversation_type
                message["is_group_chat"] = conversation_type == "group"
                types_by_pair.setdefault(pair, set()).add(conversation_type)
            sender_id = qq_db._normalize_qq_number(message.get("sender_qq"))
            message["is_self"] = bool(self_qq and sender_id == self_qq)
            prepared_messages.append((message, pair, conversation_type))

    collision_pairs = {
        pair for pair, conversation_types in types_by_pair.items()
        if len(conversation_types) > 1
    }
    msgs = []
    for message, pair, conversation_type in prepared_messages:
        if pair in collision_pairs:
            identity_type = conversation_type or "unknown"
            account_id, conversation_id = pair
            message["thread_id"] = (
                f"{account_id}::{identity_type}::{conversation_id}"
            )
            source_offset = str(message.get("source_offset") or "")
            if source_offset:
                message["source_offset"] = f"{source_offset}:{identity_type}"
            else:
                message["source_offset"] = (
                    f"qq_db:{account_id}:{conversation_id}:"
                    f"{message.get('ts')}:{identity_type}"
                )
        msgs.append(message)
    msgs.sort(key=lambda item: item.get("ts") or 0)
    out = Path(out_dir)
    _prepare_output_dir(out)
    export_json(msgs, out / "qq_messages.json")
    export_html(msgs, out / "qq_messages.html", title="QQ 聊天记录留存", source="qq")
    return {"source": "qq", "available": True, "n_messages": len(msgs), "days": days,
            "elapsed_s": round(time.time() - t0, 1),
            "out_json": str(out / "qq_messages.json"),
            "out_html": str(out / "qq_messages.html")}


# ─── WeChat ───────────────────────────────────────────────────────────────────

def _wx_msg_to_dict(m, self_wxid: str = "", account_id: str = "") -> dict:
    """Map a WxMessage to the export schema using its real fields.

    WxMessage exposes ``content`` (text), ``timestamp`` (datetime),
    ``sender`` (raw wxid), ``sender_display_name``, ``chat_name`` (raw),
    ``chat_display_name`` — there is no ``text`` / ``chat_room`` / ``is_sender``.
    """
    ts = getattr(m, "timestamp", None)
    ts_epoch = ts.timestamp() if hasattr(ts, "timestamp") else None
    sender_wxid = getattr(m, "sender", None)
    is_self = bool(self_wxid and sender_wxid and self_wxid.startswith(str(sender_wxid)))
    conversation_id = str(getattr(m, "chat_name", None) or "")
    is_group_chat = bool(
        getattr(m, "is_group_chat", False) or conversation_id.endswith("@chatroom")
    )
    stable_account_id = str(account_id or self_wxid or "unknown")
    server_id = str(getattr(m, "server_id", "") or "").strip()
    fallback_identity = json.dumps(
        {
            "account_id": stable_account_id,
            "conversation_id": conversation_id,
            "timestamp": ts_epoch,
            "sender": str(sender_wxid or ""),
            "content": str(getattr(m, "content", None) or ""),
            "msg_type": getattr(m, "msg_type", None),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    source_offset = (
        f"wechat_server:{server_id}"
        if server_id
        else "wechat_export:"
        + hashlib.sha256(fallback_identity.encode("utf-8")).hexdigest()
    )
    return {
        "ts": ts_epoch,
        "sender": getattr(m, "sender_display_name", "") or sender_wxid,
        "sender_wxid": sender_wxid,
        "chat_room": getattr(m, "chat_display_name", "") or getattr(m, "chat_name", None),
        "conversation_id": conversation_id,
        "content": getattr(m, "content", None),
        "msg_type": getattr(m, "msg_type", None),
        "is_self": is_self,
        "account_id": stable_account_id,
        "thread_id": f"{stable_account_id}::{conversation_id}",
        "server_id": server_id or None,
        "source_offset": source_offset,
        "conversation_type": "group" if is_group_chat else "direct",
        "is_group_chat": is_group_chat,
    }


def _probe_wechat() -> dict:
    """Lightweight status probe — NEVER scans process memory.

    Mirror of :func:`_probe_qq`. WeChat 4.1.10.31+ keeps no plaintext key in the
    heap, so a passive scan there always burns its full per-pid budget and finds
    nothing — catastrophic latency for a status probe (this was the "检测微信
    检测不到" hang). We report ``available`` only when a cached master key already
    unlocks the DBs; "running but no key" → ``needs_key=True`` so the GUI guides
    the user to 「自动获取密钥」 (which runs the scan/debugger explicitly).
    """
    try:
        running = bool(wechat_db._get_weixin_pids())
        root = wechat_db.find_weixin_data_root()
        wxid_dirs = wechat_db.find_wxid_dirs(root) if root else []
        readable_wxid_dir = None
        for wxid_dir in wxid_dirs:
            account_id = wxid_dir.name
            cached = wechat_db.load_cached_wechat_key_for_account(account_id)
            if not cached or len(cached) != 32:
                continue
            for database in wechat_db.find_msg_databases(wxid_dir):
                page1 = wechat_db._read_stable_page1(database)
                if page1 and wechat_db._verify_key_v4(cached, page1):
                    readable_wxid_dir = wxid_dir
                    break
            if readable_wxid_dir is not None:
                break
        has_key = readable_wxid_dir is not None
        return {
            "source": "wechat",
            "available": has_key,
            "client_running": running,
            "wxid_dir": str(readable_wxid_dir or wxid_dirs[0]) if wxid_dirs else None,
            "enc_keys_present": has_key,
            "needs_key": bool(running and wxid_dirs and not has_key),
        }
    except Exception as e:  # noqa: BLE001
        return {"source": "wechat", "available": False, "error": f"{type(e).__name__}:{e}"}


def _export_wechat(
    days: int,
    out_dir: str,
    selection: _ExportSelection | None = None,
    data_root: str | None = None,
) -> dict:
    selection = selection or _ExportSelection()
    root = Path(data_root).expanduser() if data_root else wechat_db.find_weixin_data_root()

    if selection.explicit and (
        selection.account_ids
        or selection.all_accounts
        or selection.conversation_scopes
    ):
        if root is None:
            return _invalid_selection_result("wechat")
        discovered = {item.name: item for item in wechat_db.find_wxid_dirs(root)}
        scope_accounts = tuple(dict.fromkeys(
            _scope_account_id(scope) for scope in selection.conversation_scopes
        ))
        if (
            scope_accounts
            and selection.account_ids
            and not set(scope_accounts).issubset(selection.account_ids)
        ):
            return _invalid_selection_result("wechat")
        if scope_accounts:
            requested = list(scope_accounts)
        else:
            requested = list(selection.account_ids) if selection.account_ids else list(discovered)
        if not requested or not set(requested).issubset(discovered):
            return _invalid_selection_result("wechat")
        readers = [
            wechat_db.WeChatDBReader(data_root=root, account_id=account_id)
            for account_id in requested
        ]
    else:
        # No account scope preserves v0.2.0: use the first discovered wxid.
        readers = [wechat_db.WeChatDBReader(data_root=root)]

    for reader in readers:
        reader.initialize()
        if not getattr(reader, "enc_keys", None):
            return {"source": "wechat", "available": False, "error": "no_enc_keys",
                    "hint": "Make sure WeChat (Weixin) is running and you are logged in on this machine."}

    available_typed_scopes: set[tuple[str, str, str]] = set()
    types_by_pair: dict[tuple[str, str], set[str]] = {}
    directory_complete = True
    if (
        (selection.scopes_explicit and selection.conversation_scopes)
        or (not selection.scopes_explicit and selection.conversation_ids)
    ):
        available_typed_scopes, types_by_pair, directory_complete = (
            _directory_scope_index(readers)
        )

    selected_typed_scopes: set[tuple[str, str, str]] = set()
    if selection.scopes_explicit and selection.conversation_scopes:
        if not directory_complete:
            return {"source": "wechat", "available": False,
                    "error": "directory_unavailable"}
        resolved_scopes = _resolved_typed_scopes(
            selection.conversation_scopes,
            available_typed_scopes,
            types_by_pair,
        )
        if resolved_scopes is None:
            return _invalid_selection_result("wechat")
        selected_typed_scopes = resolved_scopes
    elif not selection.scopes_explicit and selection.conversation_ids:
        if not directory_complete:
            return {"source": "wechat", "available": False,
                    "error": "directory_unavailable"}
        available_conversations = {
            conversation_id
            for _account_id, conversation_id, _conversation_type
            in available_typed_scopes
        }
        if not set(selection.conversation_ids).issubset(available_conversations):
            return _invalid_selection_result("wechat")

    since = time.time() - days * 86400
    t0 = time.time()
    msgs = []
    selected_conversations = (
        set() if selection.scopes_explicit else set(selection.conversation_ids)
    )
    for reader in readers:
        account_id = str(reader.account_id or "")
        self_wxid = reader.wxid_dir.name if getattr(reader, "wxid_dir", None) else account_id
        if selected_typed_scopes:
            requested_conversations = sorted(
                {
                    conversation_id
                    for selected_account, conversation_id, _conversation_type
                    in selected_typed_scopes
                    if selected_account == account_id
                }
            )
            if not requested_conversations:
                continue
        elif selected_conversations:
            requested_conversations = sorted(selected_conversations)
        else:
            requested_conversations = []
        raw = []
        if requested_conversations:
            for requested_conversation in requested_conversations:
                raw.extend(reader.read_after(since, chat_name=requested_conversation))
        else:
            raw = reader.read_after(since, chat_name=None)
        for message in raw:
            native_conversation = str(getattr(message, "chat_name", None) or "")
            if selected_conversations and native_conversation not in selected_conversations:
                continue
            item = _wx_msg_to_dict(message, self_wxid, account_id=account_id)
            typed_scope = (
                account_id,
                native_conversation,
                str(item["conversation_type"]),
            )
            if selected_typed_scopes and typed_scope not in selected_typed_scopes:
                continue
            if item.get("content"):
                msgs.append(item)
    msgs.sort(key=lambda item: item.get("ts") or 0)
    out = Path(out_dir)
    _prepare_output_dir(out)
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
    _prepare_output_dir(out)
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
            with private_binary_writer(out / (dat.stem + ext)) as handle:
                handle.write(raw)
            n_ok += 1
        except Exception:  # noqa: BLE001
            n_fail += 1
    return {"source": "wechat_images", "available": True,
            "decrypted": n_ok, "failed": n_fail, "out": str(out)}


# ─── manual key entry (fallback when auto-extract can't get the key) ──────────


def _wechat_verification_databases(data_root: str | None = None) -> list[Path]:
    """Return one message-database HMAC oracle per discovered account.

    ``data_root`` may be either the shared ``xwechat_files`` directory or one
    account directory.  Paths remain internal: callers only return stable,
    path-free verification errors.
    """
    try:
        root = (
            Path(data_root).expanduser()
            if data_root
            else wechat_db.find_weixin_data_root()
        )
        if root is None:
            return []
        direct_account = root / "db_storage" / "message"
        account_roots = (
            [root]
            if direct_account.is_dir()
            else sorted(wechat_db.find_wxid_dirs(root), key=lambda item: item.name)
        )
    except (OSError, RuntimeError):
        return []

    databases: list[Path] = []
    for account_root in account_roots:
        try:
            candidates = [
                Path(candidate)
                for candidate in wechat_db.find_msg_databases(account_root)
                if Path(candidate).is_file()
            ]
        except OSError:
            continue
        if not candidates:
            continue
        candidates.sort(
            key=lambda candidate: (
                candidate.name.lower() != "message_0.db",
                candidate.name.lower(),
            )
        )
        databases.append(candidates[0])
    return databases


def _set_key(source: str, key: str, data_root: str | None = None) -> dict:
    """Save a manually-supplied decryption key to the cache so a later export
    uses it cache-first (no memory scan needed).

    Use this when automatic extraction can't get the key — e.g. newer WeChat
    builds whose key is no longer kept in plaintext process memory. WeChat keys
    are HMAC-verified against a stable local database page before being saved.
    """
    key = (key or "").strip()
    if source == "qq":
        ok = qq_db.save_cached_key(key)
        return {"source": "qq", "ok": bool(ok),
                "saved_to": str(qq_db._key_cache_path()) if ok else None,
                "error": None if ok else "invalid QQ key (expect a 16- or 32-char passphrase)"}
    if source == "wechat":
        if len(key) != 64 or any(char not in "0123456789abcdefABCDEF" for char in key):
            return {"source": "wechat", "ok": False, "error": "invalid WeChat key (expect 64 hex chars)"}
        kb = bytes.fromhex(key)
        databases = _wechat_verification_databases(data_root)
        if not databases:
            return {
                "source": "wechat",
                "ok": False,
                "saved_to": None,
                "error": "could not locate a WeChat message database for key verification",
            }

        stable_page_found = False
        verified_databases = []
        for database in databases:
            page1 = wechat_db._read_stable_page1(database)
            if not page1:
                continue
            stable_page_found = True
            if wechat_db._verify_key_v4(kb, page1):
                verified_databases.append(database)

        if not stable_page_found:
            return {
                "source": "wechat",
                "ok": False,
                "saved_to": None,
                "error": "could not read a stable WeChat database page for key verification",
            }
        if not verified_databases:
            return {
                "source": "wechat",
                "ok": False,
                "saved_to": None,
                "error": "WeChat key did not pass local database verification",
            }

        saved_paths = []
        account_databases = {}
        for database in verified_databases:
            account_id = wechat_db.wechat_account_id_for_database(database)
            if account_id:
                account_databases.setdefault(account_id, database)
        if account_databases:
            for account_id, database in account_databases.items():
                if wechat_db.save_cached_wechat_key_for_account(
                    kb, account_id, database
                ):
                    saved_paths.append(
                        wechat_db._wechat_account_key_cache_path(account_id)
                    )
            ok = len(saved_paths) == len(account_databases)
        else:
            # Compatibility for callers supplying a legacy/non-canonical oracle.
            # Never touch this global cache when a matching account is known.
            ok = wechat_db.save_cached_wechat_key(kb)
            if ok:
                saved_paths.append(wechat_db._wechat_key_cache_path())
        return {"source": "wechat", "ok": bool(ok),
                "saved_to": str(saved_paths[0]) if ok else None,
                "error": None if ok else "verified WeChat key could not be stored"}
    return {"ok": False, "error": "unknown source: " + str(source)}


def _read_key_stdin() -> str | None:
    """Read one bounded non-empty key line without retaining invalid content."""
    try:
        supplied = sys.stdin.read(_MAX_KEY_STDIN_CHARS + 1)
    except (OSError, UnicodeError):
        return None
    if len(supplied) > _MAX_KEY_STDIN_CHARS:
        return None
    non_empty_lines = [line for line in supplied.splitlines() if line.strip()]
    if len(non_empty_lines) != 1:
        return None
    return supplied


# ─── automatic key extraction (passive memory scan / active debugger) ─────────

def _wechat_message_db_for_active(data_root: str | None = None) -> str | None:
    """Resolve the HMAC oracle DB for the active WeChat debugger.

    The PowerShell debugger accepts ``-DbPath`` rather than ``--data-root``.
    Resolve that path in Python so a profile relocated directly under any drive
    root works the same way for export and active key extraction.
    """

    roots: list[Path] = []
    if data_root:
        roots.append(Path(data_root).expanduser())
    else:
        root = wechat_db.find_weixin_data_root()
        if root:
            roots.append(root)

    for root in roots:
        try:
            wxid_dirs = [root] if (root / "db_storage" / "message").exists() else wechat_db.find_wxid_dirs(root)
        except OSError:
            continue
        for wxid_dir in wxid_dirs:
            exact = wxid_dir / "db_storage" / "message" / "message_0.db"
            try:
                if exact.exists():
                    return str(exact)
                for db in wechat_db.find_msg_databases(wxid_dir):
                    if db.name.lower() == "message_0.db":
                        return str(db)
                dbs = wechat_db.find_msg_databases(wxid_dir)
                if dbs:
                    return str(dbs[0])
            except OSError:
                continue
    return None


def _extract_key(source: str, method: str, data_root: str | None = None) -> dict:
    """Acquire a decryption key and cache it for later cache-first exports.

    ``method="passive"`` (default) scans the live client's process memory — low
    ban risk, no debugger; works on older builds, may find nothing on newer
    WeChat. ``method="active"`` runs the platform helper — a debugger
    breakpoint on Windows or a signature-verified isolated app copy on macOS.
    The macOS WeChat copy loads a fixed startup observer before automatic login
    and retains the same-user read-only Mach scan as a compatibility fallback;
    QQ retains its Hardened Runtime signing preflight. Active is always opt-in,
    and every candidate is DB-HMAC verified before it can be cached.
    """
    force_extract = os.environ.get("CHATLOG_FORCE_EXTRACT", "").strip().lower() in (
        "1", "true", "yes", "on",
    )

    def _active_failure(default: str) -> str:
        if sys.platform != "darwin":
            return default
        try:
            from chatlog_keeper.macos_debug_app import last_error as launch_error
            reason = launch_error()
        except Exception:
            reason = ""
        client_name = "WeChat" if source == "wechat" else "QQ"
        if reason == "daily_client_single_instance_conflict":
            return (
                "the daily WeChat client is still running; quit WeChat normally from "
                "its menu, wait for it to close completely, then retry Active Key "
                "(do not force-quit it)"
            )
        if reason == "debug_copy_ephemeral_exit":
            return (
                f"the isolated {client_name} copy exited before it became ready; "
                f"confirm the daily {client_name} client is fully closed, then retry "
                "Active Key"
            )
        if reason == "debug_copy_launch_failed":
            return (
                f"macOS could not start the isolated {client_name} copy; retry from "
                "the logged-in Mac desktop session"
            )
        if reason == "debug_copy_library_validation_incompatible":
            return (
                f"macOS blocked the isolated {client_name} copy before launch because "
                "its required embedded libraries do not share a compatible code-signing "
                "identity; Active Key cannot run for this installed client without "
                "weakening macOS security, so use a DB-verified manual master key"
            )
        if reason == "debug_copy_library_validation_unverifiable":
            return (
                f"macOS could not safely verify the isolated {client_name} copy's "
                "embedded-library signing relationship, so it was not launched; update "
                "the connector/client or use a DB-verified manual master key"
            )
        if reason == "debug_copy_prepare_failed":
            return f"macOS could not prepare a verified isolated {client_name} copy"
        if reason == "debug_copy_already_running":
            return (
                f"an isolated {client_name} copy is already running; close that copy "
                "normally, then retry Active Key"
            )
        if reason == "debug_copy_identity_changed":
            return (
                f"the isolated {client_name} process identity changed before the "
                "read-only scan; retry Active Key"
            )
        if reason == "debug_copy_busy":
            return (
                f"another isolated {client_name} Active Key run is in progress; "
                "wait for it to finish, then retry"
            )
        if reason == "debug_copy_cleanup_failed":
            return (
                f"the isolated {client_name} copy did not close cleanly; close only "
                "that isolated copy, then retry Active Key"
            )
        if reason == "capture_launch_configuration_invalid":
            return (
                "the private WeChat startup capture channel changed before launch; "
                "nothing was started, so retry Active Key"
            )
        try:
            from chatlog_keeper.macos_wechat_capture import (
                last_error as capture_error,
            )
            capture_reason = capture_error()
        except Exception:
            capture_reason = ""
        if capture_reason in {
            "capture_source_missing",
            "capture_compile_failed",
            "capture_codesign_failed",
            "capture_validation_failed",
            "capture_build_timeout",
        } or capture_reason.startswith("capture_build_failed:"):
            return (
                "macOS could not prepare the private WeChat startup capture helper; "
                "update or reinstall the connector, then retry Active Key"
            )
        if capture_reason == "capture_sandbox_path_unavailable":
            return (
                "the selected WeChat database is outside the current WeChat data "
                "container, so a private startup capture channel could not be created"
            )
        if capture_reason.startswith("capture_channel_"):
            return (
                "the private WeChat startup capture channel failed its security or "
                "cleanup checks; retry Active Key"
            )
        if capture_reason:
            return f"macOS WeChat startup capture failed: {capture_reason}"
        try:
            from chatlog_keeper.macos_key import last_error
            reason = last_error()
        except Exception:
            reason = ""
        if reason == "process_access_denied":
            return (
                "macOS denied same-user read-only process access "
                "(SIP/taskgated policy); the client was not modified"
            )
        if reason:
            return f"macOS key helper failed: {reason}"
        if source == "wechat":
            return (
                "the private WeChat session produced no DB-verified key before the "
                "authentication window expired; no account switching is required"
            )
        return "macOS memory scan produced no DB-verified key candidate"
    if method == "auto":
        # Try passive first (low ban risk); fall back to active (newer builds)
        # ONLY if passive finds nothing. Export stays cache-first and never
        # triggers active on its own — active only runs inside this command,
        # which the user invoked deliberately.
        r = _extract_key(source, "passive", data_root=data_root)
        if r.get("ok"):
            return r
        r = _extract_key(source, "active", data_root=data_root)
        if isinstance(r, dict):
            r["fell_back_from_passive"] = True
        return r
    if source == "qq":
        if method == "active":
            root = qq_db.find_qq_data_root()
            account = qq_db.detect_current_qq_account()
            account_databases = qq_db.find_qq_account_databases(root) if root else {}
            verification_db = (
                account_databases.get(str(account))
                if account not in (None, "")
                else None
            )
            if verification_db is None and root is not None:
                verification_db = qq_db.find_msg_database(root)
            key = active_key.extract_qq_key_active(
                db_path=str(verification_db) if verification_db else None
            )
            saved = bool(key) and (
                qq_db.save_cached_key_for_account(key, str(account))
                if account not in (None, "")
                else qq_db.save_cached_key(key)
            )
            if key and saved:
                saved_path = (
                    qq_db._account_key_cache_path(str(account))
                    if account not in (None, "")
                    else qq_db._key_cache_path()
                )
                return {"source": "qq", "method": "active", "ok": True,
                        "key_len": len(key), "saved_to": str(saved_path),
                        "fresh_extraction": True}
            return {"source": "qq", "method": "active", "ok": False,
                    "error": _active_failure(
                        "active extraction got no key (not logged into the popped-up QQ / "
                        "local security policy blocked child debugging / unsupported build)"
                    )}
        reader = qq_db.QQDBReader()
        reader.initialize()  # cache → passive (timeout-bounded) → cache fallback
        key_source = getattr(reader, "key_source", None)
        if force_extract and key_source != "live":
            return {"source": "qq", "method": "passive", "ok": False,
                    "error": "fresh extraction was required but no live QQ key was obtained"}
        account = getattr(reader, "account_id", None)
        saved = bool(reader.key) and (
            qq_db.save_cached_key_for_account(reader.key, str(account))
            if account not in (None, "")
            else qq_db.save_cached_key(reader.key)
        )
        if reader.key and saved:
            saved_path = (
                qq_db._account_key_cache_path(str(account))
                if account not in (None, "")
                else qq_db._key_cache_path()
            )
            return {"source": "qq", "method": "passive", "ok": True,
                    "key_len": len(reader.key), "saved_to": str(saved_path),
                    "fresh_extraction": key_source == "live"}
        return {"source": "qq", "method": "passive", "ok": False,
                "error": "passive scan found no key (QQ not running, or a newer build — "
                         "try `--method active` or `set-key`)"}
    if source == "wechat":
        if method == "active":
            db_path = _wechat_message_db_for_active(data_root)
            key = active_key.extract_wechat_key_active(db_path=db_path)
            saved = False
            saved_path = wechat_db._wechat_key_cache_path()
            verified_db = Path(db_path) if db_path else None
            account_databases = {}
            if key:
                for database in _wechat_verification_databases(data_root):
                    page1 = wechat_db._read_stable_page1(database)
                    if not page1 or not wechat_db._verify_key_v4(key, page1):
                        continue
                    account_id = wechat_db.wechat_account_id_for_database(database)
                    if account_id:
                        account_databases.setdefault(account_id, database)
            if account_databases:
                saved_paths = []
                for account_id, database in account_databases.items():
                    if wechat_db.save_cached_wechat_key_for_account(
                        key, account_id, database
                    ):
                        saved_paths.append(
                            wechat_db._wechat_account_key_cache_path(account_id)
                        )
                saved = len(saved_paths) == len(account_databases)
                if saved_paths:
                    saved_path = saved_paths[0]
                    verified_db = next(iter(account_databases.values()))
            elif key and db_path:
                # Preserve support for a direct legacy/non-canonical DB oracle.
                page1 = wechat_db._read_stable_page1(Path(db_path))
                if page1 and wechat_db._verify_key_v4(key, page1):
                    saved = wechat_db.save_cached_wechat_key(key)
            if key and saved:
                return {"source": "wechat", "method": "active", "ok": True,
                        "key_len": len(key), "saved_to": str(saved_path),
                        "db_path": str(verified_db) if verified_db else db_path,
                        "fresh_extraction": True}
            if not db_path:
                return {"source": "wechat", "method": "active", "ok": False,
                        "error": "active extraction could not locate message_0.db for HMAC "
                                 "verification (set --data-root to the xwechat_files folder)"}
            return {"source": "wechat", "method": "active", "ok": False,
                    "error": _active_failure(
                        "active extraction got no DB-verified key before the login window "
                        "expired (no account switching is required)"
                    ),
                    "db_path": db_path}
        if force_extract:
            return {"source": "wechat", "method": "passive", "ok": False,
                    "error": "fresh WeChat extraction requires --method active"}
        reader = wechat_db.WeChatDBReader()
        reader.initialize()
        enc = getattr(reader, "enc_keys", None)
        if enc:
            # 4.x derives every per-DB page key from one 32-byte master key.
            verification_db, master = next(iter(enc.items()))
            account_id = getattr(reader, "account_id", None)
            if account_id:
                saved = wechat_db.save_cached_wechat_key_for_account(
                    master, str(account_id), verification_db
                )
                saved_path = wechat_db._wechat_account_key_cache_path(str(account_id))
            else:
                saved = wechat_db.save_cached_wechat_key(master)
                saved_path = wechat_db._wechat_key_cache_path()
            if saved:
                return {"source": "wechat", "method": "passive", "ok": True,
                        "key_len": len(master),
                        "saved_to": str(saved_path)}
        return {"source": "wechat", "method": "passive", "ok": False,
                "error": "passive scan found no key (WeChat not running, or 4.1.10.31+ where the "
                         "key is no longer in plaintext memory — try `--method active` or `set-key`)"}
    return {"ok": False, "error": "unknown source: " + str(source)}


# ─── message-stream-v1 ────────────────────────────────────────────────────────


class _MessageStreamSourceUnavailable(RuntimeError):
    """The exact local source account cannot currently produce bounded pages."""


@dataclass
class _MessageStreamTotals:
    records: int = 0
    pages: int = 0


def _raise_if_message_stream_cancelled(
    cancellation: stream_protocol.MessageStreamCancellation,
) -> None:
    if cancellation():
        raise stream_protocol.MessageStreamProtocolError("cancelled")


@contextmanager
def _message_stream_signal_handlers(
    cancellation: stream_protocol.MessageStreamCancellation,
) -> Iterator[None]:
    """Turn SIGINT/SIGTERM into the same cooperative local cancellation token."""

    previous = []

    def request_cancel(_signum, _frame) -> None:
        cancellation.cancel()

    for name in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            old_handler = signal.getsignal(signum)
            signal.signal(signum, request_cancel)
        except (OSError, RuntimeError, ValueError):
            continue
        previous.append((signum, old_handler))
    try:
        yield
    finally:
        for signum, old_handler in reversed(previous):
            try:
                signal.signal(signum, old_handler)
            except (OSError, RuntimeError, ValueError):
                pass


@contextmanager
def _message_stream_silent_logs() -> Iterator[None]:
    """Keep native IDs and database paths out of the protocol's stderr channel."""

    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(previous)


def _qq_cursor_from_stream(
    request: stream_protocol.MessageStreamRequest,
    scope: stream_protocol.MessageStreamScope,
):
    value = scope.page_cursor
    if value is None:
        return None
    return qq_db._QQMessagePageCursor(
        account_id=scope.account_id,
        conversation_id=scope.conversation_id,
        conversation_type=scope.conversation_type,
        since_ts=request.since_ts,
        until_ts=request.until_ts,
        msg_time=value["msg_time"],
        table_rank=value["table_rank"],
        rowid=value["rowid"],
    )


def _qq_cursor_for_stream(
    cursor,
    *,
    request: stream_protocol.MessageStreamRequest,
    scope: stream_protocol.MessageStreamScope,
) -> dict | None:
    if cursor is None:
        return None
    try:
        value = {
            "version": stream_protocol.VERSION,
            "since_ts": cursor.since_ts,
            "until_ts": cursor.until_ts,
            "msg_time": cursor.msg_time,
            "table_rank": cursor.table_rank,
            "rowid": cursor.rowid,
        }
    except AttributeError:
        raise stream_protocol.MessageStreamProtocolError("invalid_cursor") from None
    return stream_protocol.normalize_page_cursor(
        "qq",
        value,
        conversation_type=scope.conversation_type,
        since_ts=request.since_ts,
        until_ts=request.until_ts,
    )


def _wechat_cursor_for_stream(
    cursor,
    *,
    request: stream_protocol.MessageStreamRequest,
    scope: stream_protocol.MessageStreamScope,
) -> dict | None:
    if cursor is None:
        return None
    if hasattr(cursor, "to_dict") and callable(cursor.to_dict):
        try:
            value = cursor.to_dict()
        except Exception:
            raise stream_protocol.MessageStreamProtocolError("invalid_cursor") from None
    else:
        value = cursor
    return stream_protocol.normalize_page_cursor(
        "wechat",
        value,
        conversation_type=scope.conversation_type,
        since_ts=request.since_ts,
        until_ts=request.until_ts,
    )


def _message_stream_record(
    record: Any,
    *,
    scope: stream_protocol.MessageStreamScope,
) -> dict:
    """Fail closed if a bounded reader returns a row outside its exact scope."""

    if not isinstance(record, dict):
        raise stream_protocol.MessageStreamProtocolError("invalid_record")
    if str(record.get("account_id") or "") != scope.account_id:
        raise stream_protocol.MessageStreamProtocolError("scope_mismatch")
    if str(record.get("conversation_id") or "") != scope.conversation_id:
        raise stream_protocol.MessageStreamProtocolError("scope_mismatch")
    if str(record.get("conversation_type") or "") != scope.conversation_type:
        raise stream_protocol.MessageStreamProtocolError("scope_mismatch")
    return record


def _emit_message_stream_record(
    writer: stream_protocol.NDJSONFrameWriter,
    *,
    scope_index: int,
    scope_record_count: int,
    totals: _MessageStreamTotals,
    record: dict,
) -> int:
    if totals.records >= stream_protocol.MAX_TOTAL_RECORDS:
        raise stream_protocol.MessageStreamProtocolError("record_limit_exceeded")
    writer.emit("record", scope_index=scope_index, record=record)
    totals.records += 1
    return scope_record_count + 1


def _emit_message_stream_checkpoint(
    writer: stream_protocol.NDJSONFrameWriter,
    *,
    scope_index: int,
    page_index: int,
    cursor: dict | None,
    has_more: bool,
    record_count: int,
    totals: _MessageStreamTotals,
) -> None:
    if (
        page_index >= stream_protocol.MAX_PAGES_PER_SCOPE
        or totals.pages >= stream_protocol.MAX_TOTAL_PAGES
    ):
        raise stream_protocol.MessageStreamProtocolError("page_limit_exceeded")
    writer.emit(
        "checkpoint",
        scope_index=scope_index,
        page_index=page_index,
        cursor=cursor,
        has_more=has_more,
        record_count=record_count,
    )
    totals.pages += 1


def _qq_message_stream_scope(
    reader,
    *,
    request: stream_protocol.MessageStreamRequest,
    scope: stream_protocol.MessageStreamScope,
    scope_index: int,
    writer: stream_protocol.NDJSONFrameWriter,
    cancellation: stream_protocol.MessageStreamCancellation,
    totals: _MessageStreamTotals,
) -> tuple[int, int]:
    availability = getattr(reader, "is_available", None)
    if callable(availability) and not availability():
        raise _MessageStreamSourceUnavailable()
    initial_cursor = _qq_cursor_from_stream(request, scope)
    iterator = reader.iter_message_dict_pages(
        request.since_ts,
        request.until_ts,
        account_id=scope.account_id,
        conversation_id=scope.conversation_id,
        conversation_type=scope.conversation_type,
        page_size=request.page_size,
        cursor=initial_cursor,
        cancel_requested=cancellation,
    )
    page_index = 0
    record_count = 0
    saw_page = False
    terminal = False
    previous_checkpoint = scope.page_cursor
    try:
        while True:
            _raise_if_message_stream_cancelled(cancellation)
            if (
                page_index >= stream_protocol.MAX_PAGES_PER_SCOPE
                or totals.pages >= stream_protocol.MAX_TOTAL_PAGES
            ):
                raise stream_protocol.MessageStreamProtocolError(
                    "page_limit_exceeded"
                )
            try:
                page = next(iterator)
            except StopIteration:
                break
            saw_page = True
            records = getattr(page, "records", None)
            has_more = getattr(page, "has_more", None)
            if not isinstance(records, (tuple, list)) or len(records) > request.page_size:
                raise stream_protocol.MessageStreamProtocolError("read_failed")
            if not isinstance(has_more, bool):
                raise stream_protocol.MessageStreamProtocolError("read_failed")
            for raw_record in records:
                record = _message_stream_record(raw_record, scope=scope)
                record_count = _emit_message_stream_record(
                    writer,
                    scope_index=scope_index,
                    scope_record_count=record_count,
                    totals=totals,
                    record=record,
                )
            checkpoint = _qq_cursor_for_stream(
                getattr(page, "cursor_after", None),
                request=request,
                scope=scope,
            )
            if has_more and checkpoint is None:
                raise stream_protocol.MessageStreamProtocolError("invalid_cursor")
            if has_more and checkpoint == previous_checkpoint:
                raise stream_protocol.MessageStreamProtocolError("invalid_cursor")
            _emit_message_stream_checkpoint(
                writer,
                scope_index=scope_index,
                page_index=page_index,
                cursor=checkpoint,
                has_more=has_more,
                record_count=record_count,
                totals=totals,
            )
            page_index += 1
            previous_checkpoint = checkpoint
            if not has_more:
                terminal = True
                break
        if not saw_page:
            _emit_message_stream_checkpoint(
                writer,
                scope_index=scope_index,
                page_index=0,
                cursor=scope.page_cursor,
                has_more=False,
                record_count=0,
                totals=totals,
            )
            page_index = 1
            terminal = True
        if not terminal:
            raise stream_protocol.MessageStreamProtocolError("read_failed")
        return page_index, record_count
    finally:
        close = getattr(iterator, "close", None)
        if callable(close):
            close()


def _wechat_message_stream_scope(
    reader,
    *,
    request: stream_protocol.MessageStreamRequest,
    scope: stream_protocol.MessageStreamScope,
    scope_index: int,
    writer: stream_protocol.NDJSONFrameWriter,
    cancellation: stream_protocol.MessageStreamCancellation,
    totals: _MessageStreamTotals,
) -> tuple[int, int]:
    if scope.conversation_id.endswith("@chatroom") != (
        scope.conversation_type == "group"
    ):
        raise stream_protocol.MessageStreamProtocolError("scope_mismatch")
    initialize = getattr(reader, "initialize", None)
    if callable(initialize) and not getattr(reader, "_initialized", False):
        initialized = initialize()
        if initialized is False:
            raise _MessageStreamSourceUnavailable()
    if hasattr(reader, "enc_keys") and not reader.enc_keys:
        raise _MessageStreamSourceUnavailable()
    cursor = scope.page_cursor
    page_index = 0
    record_count = 0
    self_wxid = (
        reader.wxid_dir.name
        if getattr(reader, "wxid_dir", None) is not None
        else scope.account_id
    )
    while True:
        _raise_if_message_stream_cancelled(cancellation)
        previous_checkpoint = _wechat_cursor_for_stream(
            cursor,
            request=request,
            scope=scope,
        )
        if (
            page_index >= stream_protocol.MAX_PAGES_PER_SCOPE
            or totals.pages >= stream_protocol.MAX_TOTAL_PAGES
        ):
            raise stream_protocol.MessageStreamProtocolError("page_limit_exceeded")
        page = reader.read_conversation_page(
            conversation_id=scope.conversation_id,
            since_ts=request.since_ts,
            until_ts=request.until_ts,
            page_size=request.page_size,
            cursor=cursor,
            cancel_requested=cancellation,
        )
        messages = getattr(page, "messages", None)
        has_more = getattr(page, "has_more", None)
        if not isinstance(messages, (tuple, list)) or len(messages) > request.page_size:
            raise stream_protocol.MessageStreamProtocolError("read_failed")
        if not isinstance(has_more, bool):
            raise stream_protocol.MessageStreamProtocolError("read_failed")
        for message in messages:
            record = _message_stream_record(
                _wx_msg_to_dict(
                    message,
                    self_wxid,
                    account_id=scope.account_id,
                ),
                scope=scope,
            )
            record_count = _emit_message_stream_record(
                writer,
                scope_index=scope_index,
                scope_record_count=record_count,
                totals=totals,
                record=record,
            )
        next_cursor = getattr(page, "next_cursor", None)
        checkpoint = _wechat_cursor_for_stream(
            next_cursor,
            request=request,
            scope=scope,
        )
        if has_more and checkpoint is None:
            raise stream_protocol.MessageStreamProtocolError("invalid_cursor")
        if has_more and checkpoint == previous_checkpoint:
            raise stream_protocol.MessageStreamProtocolError("invalid_cursor")
        _emit_message_stream_checkpoint(
            writer,
            scope_index=scope_index,
            page_index=page_index,
            cursor=checkpoint,
            has_more=has_more,
            record_count=record_count,
            totals=totals,
        )
        page_index += 1
        if not has_more:
            return page_index, record_count
        cursor = next_cursor


def _message_stream_reader(source: str, *, data_root: str | None, account_id: str):
    root = Path(data_root).expanduser() if data_root else None
    if source == "qq":
        return qq_db.QQDBReader(data_root=root, account_id=account_id)
    return wechat_db.WeChatDBReader(data_root=root, account_id=account_id)


def _run_message_stream_v1(
    request: stream_protocol.MessageStreamRequest,
    *,
    data_root: str | None,
    writer: stream_protocol.NDJSONFrameWriter,
    cancellation: stream_protocol.MessageStreamCancellation,
) -> None:
    writer.emit(
        "ready",
        source=request.source,
        scope_count=len(request.scopes),
        page_size=request.page_size,
    )
    readers = {}
    totals = _MessageStreamTotals()
    for scope_index, scope in enumerate(request.scopes):
        _raise_if_message_stream_cancelled(cancellation)
        writer.emit("scope_begin", scope_index=scope_index)
        reader = readers.get(scope.account_id)
        if reader is None:
            reader = _message_stream_reader(
                request.source,
                data_root=data_root,
                account_id=scope.account_id,
            )
            readers[scope.account_id] = reader
        if request.source == "qq":
            page_count, record_count = _qq_message_stream_scope(
                reader,
                request=request,
                scope=scope,
                scope_index=scope_index,
                writer=writer,
                cancellation=cancellation,
                totals=totals,
            )
        else:
            page_count, record_count = _wechat_message_stream_scope(
                reader,
                request=request,
                scope=scope,
                scope_index=scope_index,
                writer=writer,
                cancellation=cancellation,
                totals=totals,
            )
        writer.emit(
            "scope_end",
            scope_index=scope_index,
            page_count=page_count,
            record_count=record_count,
        )
    writer.emit(
        "complete",
        scope_count=len(request.scopes),
        page_count=totals.pages,
        record_count=totals.records,
    )


def _emit_message_stream_error(
    writer: stream_protocol.NDJSONFrameWriter,
    code: str,
) -> bool:
    try:
        writer.emit_payload(stream_protocol.error_frame(code))
    except stream_protocol.MessageStreamBrokenPipe:
        return False
    return True


def _message_stream_v1_command(args) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")  # type: ignore[attr-defined]
    except Exception:
        pass
    writer = stream_protocol.NDJSONFrameWriter(sys.stdout)
    if args.capabilities:
        try:
            writer.emit_payload(stream_protocol.message_stream_capabilities_frame())
        except stream_protocol.MessageStreamBrokenPipe:
            return 0
        return 0
    try:
        request = stream_protocol.read_message_stream_request(sys.stdin)
    except stream_protocol.MessageStreamProtocolError as exc:
        _emit_message_stream_error(writer, exc.code)
        return 2

    cancellation = stream_protocol.MessageStreamCancellation()
    try:
        with _message_stream_silent_logs(), _message_stream_signal_handlers(cancellation):
            _run_message_stream_v1(
                request,
                data_root=args.data_root,
                writer=writer,
                cancellation=cancellation,
            )
        return 0
    except stream_protocol.MessageStreamBrokenPipe:
        cancellation.cancel()
        return 0
    except stream_protocol.MessageStreamProtocolError as exc:
        _emit_message_stream_error(writer, exc.code)
        return 130 if exc.code == "cancelled" else 1
    except (qq_db.QQMessagePageCancelled, wechat_db.WeChatMessagePageCancelled):
        _emit_message_stream_error(writer, "cancelled")
        return 130
    except _MessageStreamSourceUnavailable:
        _emit_message_stream_error(writer, "source_unavailable")
        return 1
    except ValueError:
        _emit_message_stream_error(writer, "invalid_cursor")
        return 1
    except Exception:  # noqa: BLE001 - never expose private reader values or paths
        _emit_message_stream_error(writer, "read_failed")
        return 1


def _participant_directory_v1_command(args) -> int:
    """Run one bounded metadata-only participant page without logging IDs."""

    if getattr(args, "capabilities", False):
        return _print_json(participant_protocol.capabilities_payload())
    try:
        with _message_stream_silent_logs():
            request = participant_protocol.read_request(sys.stdin)
            payload = participant_directory.read_page(
                request,
                data_root=getattr(args, "data_root", None),
            )
    except participant_protocol.ParticipantProtocolError as exc:
        payload = participant_protocol.error_payload(exc.code)
    except Exception:  # noqa: BLE001 - private values must never enter diagnostics
        payload = participant_protocol.error_payload("read_failed")
    return _print_json(payload)


# ─── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="chatlog-keeper",
        description="Decrypt and export YOUR OWN local QQ / WeChat history for "
                    "personal backup and nostalgia. Local-only; nothing is uploaded.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("probe", help="report what's available on this machine + key status")

    p_stream = sub.add_parser(
        "message-stream-v1",
        help="stream bounded QQ/WeChat message pages as local NDJSON",
    )
    stream_mode = p_stream.add_mutually_exclusive_group(required=True)
    stream_mode.add_argument(
        "--capabilities",
        action="store_true",
        help="emit the frozen message-stream-v1 capability contract",
    )
    stream_mode.add_argument(
        "--selection-stdin",
        action="store_true",
        help="read one strict message-stream-v1 request from standard input",
    )
    p_stream.add_argument(
        "--data-root",
        type=str,
        default=None,
        help="override the selected source's local data root",
    )

    p_participants = sub.add_parser(
        "participant-directory-v1",
        help="page metadata-only QQ/WeChat members or observed senders",
    )
    participant_mode = p_participants.add_mutually_exclusive_group(required=True)
    participant_mode.add_argument(
        "--capabilities",
        action="store_true",
        help="emit the participant-directory-v1 capability contract",
    )
    participant_mode.add_argument(
        "--selection-stdin",
        action="store_true",
        help="read one strict private participant request from standard input",
    )
    p_participants.add_argument(
        "--data-root",
        type=str,
        default=None,
        help="override the selected source's local data root",
    )

    p_qq = sub.add_parser("qq", help="export your QQ history -> json + html")
    p_qq.add_argument("--days", type=int, default=7, help="lookback window in days (default 7)")
    p_qq.add_argument("--out", type=str, required=True, help="output directory")
    p_qq.add_argument("--data-root", type=str, default=None,
                      help="override the QQ 'Tencent Files' folder (else auto-detected)")
    p_qq.add_argument("--account", action="append", default=[],
                      help="export one discovered account; repeat for multiple accounts")
    p_qq.add_argument("--conversation", action="append", default=[],
                      help="export one native conversation; repeat for multiple conversations")
    p_qq.add_argument(
        "--selection-stdin",
        action="store_true",
        help="read account_ids/conversation_ids JSON, with optional exact "
             "conversation_scopes, from standard input",
    )

    p_wx = sub.add_parser("wechat", help="export your WeChat history -> json + html")
    p_wx.add_argument("--days", type=int, default=7, help="lookback window in days (default 7)")
    p_wx.add_argument("--out", type=str, required=True, help="output directory")
    p_wx.add_argument("--data-root", type=str, default=None,
                      help="override the WeChat 'xwechat_files' folder (else auto-detected)")
    p_wx.add_argument("--account", action="append", default=[],
                      help="export one discovered account; repeat for multiple accounts")
    p_wx.add_argument("--conversation", action="append", default=[],
                      help="export one native conversation; repeat for multiple conversations")
    p_wx.add_argument(
        "--selection-stdin",
        action="store_true",
        help="read account_ids/conversation_ids JSON, with optional exact "
             "conversation_scopes, from standard input",
    )

    p_dir = sub.add_parser(
        "directory",
        help="list local accounts and conversations without reading message bodies",
    )
    p_dir.add_argument("--source", choices=["wechat", "qq"], required=True)
    p_dir.add_argument("--data-root", type=str, default=None,
                       help="override the source data folder (else auto-detected)")
    p_dir.add_argument("--account", action="append", default=[],
                       help="limit directory lookup to an exact discovered account")

    p_im = sub.add_parser("images", help="decrypt your WeChat image .dat files -> jpg/png")
    p_im.add_argument("--src", type=str, required=True, help="folder of WeChat .dat files")
    p_im.add_argument("--out", type=str, required=True, help="output directory")

    p_sk = sub.add_parser(
        "set-key",
        help="manually supply a key when auto-extract can't get it",
    )
    p_sk.add_argument("--source", choices=["qq", "wechat"], required=True)
    p_sk.add_argument(
        "--data-root",
        type=str,
        default=None,
        help="override the WeChat data folder used for local key verification",
    )
    key_input = p_sk.add_mutually_exclusive_group(required=True)
    key_input.add_argument(
        "--key",
        type=str,
        help="compatibility only: key is exposed in argv/shell history; "
        "prefer --key-stdin",
    )
    key_input.add_argument(
        "--key-stdin",
        action="store_true",
        help="read one bounded non-empty key line from standard input so it is "
        "not exposed in the process list",
    )

    p_ek = sub.add_parser("extract-key",
                          help="acquire + cache a decryption key automatically")
    p_ek.add_argument("--source", choices=["qq", "wechat"], required=True)
    p_ek.add_argument("--method", choices=["auto", "passive", "active"], default="auto",
                      help="auto (default): passive first, fall back to active only if "
                           "passive finds nothing. passive: read-only scan of the running "
                           "client. active: Windows debugger or signature-preflighted "
                           "isolated macOS copy; incompatible macOS clients fail closed "
                           "before launch and require a DB-verified manual key.")
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
    if args.cmd == "message-stream-v1":
        return _message_stream_v1_command(args)
    if args.cmd == "participant-directory-v1":
        return _participant_directory_v1_command(args)
    if args.cmd == "qq":
        try:
            selection = _selection_from_args(args)
        except _SelectionError:
            return _print_json(_invalid_selection_result("qq"))
        try:
            result = _export_qq(
                args.days,
                args.out,
                selection=selection,
                data_root=args.data_root,
            )
        except Exception:  # noqa: BLE001 - selection values must never reach a traceback
            result = {"source": "qq", "available": False, "error": "export_failed"}
        return _print_json(result)
    if args.cmd == "wechat":
        try:
            selection = _selection_from_args(args)
        except _SelectionError:
            return _print_json(_invalid_selection_result("wechat"))
        try:
            result = _export_wechat(
                args.days,
                args.out,
                selection=selection,
                data_root=args.data_root,
            )
        except Exception:  # noqa: BLE001 - selection values must never reach a traceback
            result = {"source": "wechat", "available": False, "error": "export_failed"}
        return _print_json(result)
    if args.cmd == "directory":
        try:
            accounts = _validated_ids(list(args.account or []))
        except _SelectionError:
            return _print_json(_directory_result(args.source, False, [], []))
        account_scope = accounts if accounts else None
        try:
            if args.source == "qq":
                result = _directory_qq(args.data_root, account_scope)
            else:
                result = _directory_wechat(args.data_root, account_scope)
        except Exception:  # noqa: BLE001 - directory stdout has an exact safe shape
            result = _directory_result(args.source, False, [], [])
        return _print_json(result)
    if args.cmd == "images":
        return _print_json(_decrypt_images(args.src, args.out))
    if args.cmd == "set-key":
        supplied = _read_key_stdin() if args.key_stdin else args.key
        if supplied is None:
            return _print_json({
                "source": args.source,
                "ok": False,
                "saved_to": None,
                "error": "invalid key input",
            })
        return _print_json(_set_key(args.source, supplied, data_root=args.data_root))
    if args.cmd == "extract-key":
        return _print_json(_extract_key(args.source, args.method, data_root=getattr(args, "data_root", None)))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
