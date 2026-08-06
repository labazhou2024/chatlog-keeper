"""Metadata-only QQ/WeChat participant directory readers.

This module deliberately keeps member rosters and observed message senders as
separate views.  Its SQL never selects a message body column.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Iterable

from chatlog_keeper import participant_protocol, qq_db, wechat_db
from chatlog_keeper.core._snapshot import snapshot_db_families


def _single_line(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()[: participant_protocol.MAX_LABEL_CHARS]


def _sqlite_columns(connection: sqlite3.Connection, table: str) -> set[str] | None:
    try:
        rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    except sqlite3.Error:
        return None
    return {str(row[1]) for row in rows if len(row) > 1 and row[1] is not None}


def _qq_group_members(
    connection: sqlite3.Connection,
    *,
    conversation_id: str,
    profile_identities: dict[int, Any],
) -> list[dict[str, Any]]:
    """Read current QQ group members, preserving entries without nicknames."""

    columns = _sqlite_columns(connection, "group_member3")
    required = {
        qq_db._NTQQ_GROUP_MEMBER_COL_GROUP,
        qq_db._NTQQ_GROUP_MEMBER_COL_UIN,
    }
    if columns is None or not required.issubset(columns):
        raise participant_protocol.ParticipantProtocolError("bad_schema")
    nickname_expression = (
        f'MAX("{qq_db._NTQQ_PROFILE_COL_NICKNAME}")'
        if qq_db._NTQQ_PROFILE_COL_NICKNAME in columns
        else "NULL"
    )
    rows = connection.execute(
        f'SELECT "{qq_db._NTQQ_GROUP_MEMBER_COL_UIN}", '
        f'{nickname_expression} FROM group_member3 '
        f'WHERE "{qq_db._NTQQ_GROUP_MEMBER_COL_GROUP}" = ? '
        f'AND "{qq_db._NTQQ_GROUP_MEMBER_COL_UIN}" IS NOT NULL '
        f'GROUP BY "{qq_db._NTQQ_GROUP_MEMBER_COL_UIN}"',
        (conversation_id,),
    ).fetchall()
    if not rows:
        raise participant_protocol.ParticipantProtocolError("conversation_not_found")
    participants = []
    for raw_uin, group_nickname in rows:
        participant_id = str(raw_uin or "").strip()
        if not participant_id:
            raise participant_protocol.ParticipantProtocolError("bad_schema")
        identity = None
        try:
            identity = profile_identities.get(int(raw_uin))
        except (TypeError, ValueError):
            identity = None
        label = _single_line(group_nickname)
        if not label and identity is not None:
            label = _single_line(getattr(identity, "directory_label", ""))
        participants.append(
            {
                "participant_id": participant_id,
                "label": label,
                "label_provenance": (
                    "current_membership" if label else "anonymous"
                ),
                "observed_message_count": 0,
            }
        )
    return participants


def _qq_observed_senders(
    connection: sqlite3.Connection,
    *,
    conversation_id: str,
    conversation_type: str,
    profile_identities: dict[int, Any],
    group_labels: dict[tuple[int, int], str],
) -> list[dict[str, Any]]:
    """Aggregate QQ sender identity metadata without selecting message bodies."""

    if conversation_type == "group":
        table = "group_msg_table"
        conversation_column = qq_db._NTQQ_COL_GROUP_CODE
    else:
        table = "c2c_msg_table"
        conversation_column = qq_db._NTQQ_COL_PEER_UIN
    columns = _sqlite_columns(connection, table)
    required = {conversation_column, qq_db._NTQQ_COL_SENDER_UIN}
    if columns is None or not required.issubset(columns):
        raise participant_protocol.ParticipantProtocolError("bad_schema")
    sender_name_expression = (
        f'MAX("{qq_db._NTQQ_COL_SENDER_NAME}")'
        if qq_db._NTQQ_COL_SENDER_NAME in columns
        else "NULL"
    )
    sender_uid_expression = (
        f'NULLIF(TRIM(CAST("{qq_db._NTQQ_COL_SENDER_UID}" AS TEXT)), \'\')'
        if qq_db._NTQQ_COL_SENDER_UID in columns
        else "NULL"
    )
    missing = connection.execute(
        f'SELECT COUNT(*) FROM "{table}" '
        f'WHERE "{conversation_column}" = ? '
        f'AND ("{qq_db._NTQQ_COL_SENDER_UIN}" IS NULL '
        f'OR CAST("{qq_db._NTQQ_COL_SENDER_UIN}" AS TEXT) = \'\')',
        (conversation_id,),
    ).fetchone()
    if missing and int(missing[0] or 0) > 0:
        raise participant_protocol.ParticipantProtocolError("bad_schema")
    missing_stable_identity = connection.execute(
        f'SELECT COUNT(*) FROM "{table}" '
        f'WHERE "{conversation_column}" = ? '
        f'AND CAST("{qq_db._NTQQ_COL_SENDER_UIN}" AS INTEGER) = 0 '
        f'AND {sender_uid_expression} IS NULL',
        (conversation_id,),
    ).fetchone()
    if missing_stable_identity and int(missing_stable_identity[0] or 0) > 0:
        raise participant_protocol.ParticipantProtocolError("bad_schema")
    rows = connection.execute(
        f'SELECT "{qq_db._NTQQ_COL_SENDER_UIN}", '
        f'CASE WHEN CAST("{qq_db._NTQQ_COL_SENDER_UIN}" AS INTEGER) = 0 '
        f'THEN {sender_uid_expression} ELSE NULL END, '
        f'{sender_name_expression}, COUNT(*) '
        f'FROM "{table}" WHERE "{conversation_column}" = ? '
        f'AND "{qq_db._NTQQ_COL_SENDER_UIN}" IS NOT NULL '
        f'GROUP BY "{qq_db._NTQQ_COL_SENDER_UIN}", '
        f'CASE WHEN CAST("{qq_db._NTQQ_COL_SENDER_UIN}" AS INTEGER) = 0 '
        f'THEN {sender_uid_expression} ELSE NULL END',
        (conversation_id,),
    ).fetchall()
    participants: list[dict[str, Any]] = []
    for raw_uin, raw_uid, raw_name, raw_count in rows:
        try:
            numeric_uin = int(str(raw_uin).strip())
        except (TypeError, ValueError):
            raise participant_protocol.ParticipantProtocolError("bad_schema")
        if numeric_uin < 0:
            raise participant_protocol.ParticipantProtocolError("bad_schema")
        participant_id = (
            str(numeric_uin)
            if numeric_uin != 0
            else str(raw_uid or "").strip()
        )
        if not participant_id:
            raise participant_protocol.ParticipantProtocolError("bad_schema")
        label = _single_line(raw_name)
        label_provenance = "historical_message" if label else "anonymous"
        if (
            numeric_uin != 0
            and not label
            and conversation_type == "group"
        ):
            try:
                label = _single_line(
                    group_labels.get((int(conversation_id), numeric_uin), "")
                )
            except (TypeError, ValueError):
                label = ""
        identity = profile_identities.get(numeric_uin) if numeric_uin != 0 else None
        if not label and identity is not None:
            label = _single_line(getattr(identity, "directory_label", ""))
        if label and label_provenance == "anonymous":
            label_provenance = "current_contact_fallback"
        participants.append(
            {
                "participant_id": participant_id,
                "label": label,
                "label_provenance": label_provenance,
                "observed_message_count": int(raw_count or 0),
            }
        )
    return participants


def _read_qq(request: participant_protocol.ParticipantRequest, data_root: str | None) -> list[dict[str, Any]]:
    if request.view == "member" and request.conversation_type != "group":
        raise participant_protocol.ParticipantProtocolError("unsupported_view")
    root = Path(data_root).expanduser() if data_root else qq_db.find_qq_data_root()
    if root is None:
        raise participant_protocol.ParticipantProtocolError("source_unavailable")
    reader = qq_db.QQDBReader(
        data_root=root,
        account_id=request.account_id,
        allow_live_key_extract=False,
    )
    if not reader.initialize() or not reader.db_path or not reader.key:
        raise participant_protocol.ParticipantProtocolError("source_unavailable")

    primary = Path(reader.db_path)
    profile_source = primary.parent / "profile_info.db"
    group_source = primary.parent / "group_info.db"
    relevant = [primary]
    if profile_source.is_file():
        relevant.append(profile_source)
    if group_source.is_file():
        relevant.append(group_source)
    temporary_root = Path(tempfile.mkdtemp(prefix="qq_participants_"))
    try:
        with snapshot_db_families(relevant) as snapshots:
            profile_decrypted = (
                qq_db._decrypt_aux_db(
                    snapshots[profile_source],
                    reader.key,
                    temporary_root,
                )
                if profile_source in snapshots
                else None
            )
            group_decrypted = (
                qq_db._decrypt_aux_db(
                    snapshots[group_source],
                    reader.key,
                    temporary_root,
                )
                if group_source in snapshots
                else None
            )
            profile_identities = (
                qq_db._build_buddy_identity_map(profile_decrypted)
                if profile_decrypted is not None
                else {}
            )
            if request.view == "member":
                if group_decrypted is None:
                    raise participant_protocol.ParticipantProtocolError("bad_schema")
                connection = sqlite3.connect(str(group_decrypted))
                try:
                    return _qq_group_members(
                        connection,
                        conversation_id=request.conversation_id,
                        profile_identities=profile_identities,
                    )
                finally:
                    connection.close()
            no_header = temporary_root / "nt_msg_no_header.db"
            if not qq_db._skip_header(snapshots[primary], no_header):
                raise participant_protocol.ParticipantProtocolError("source_unavailable")
            decrypted = temporary_root / "nt_msg_decrypted.db"
            if not qq_db._decrypt_db_qq(no_header, reader.key, decrypted):
                decrypted = no_header
            group_labels = (
                qq_db._build_group_member_map(group_decrypted)
                if group_decrypted is not None
                else {}
            )
            connection = sqlite3.connect(str(decrypted))
            try:
                return _qq_observed_senders(
                    connection,
                    conversation_id=request.conversation_id,
                    conversation_type=request.conversation_type,
                    profile_identities=profile_identities,
                    group_labels=group_labels,
                )
            finally:
                connection.close()
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def _wechat_current_members(
    connection: sqlite3.Connection,
    *,
    conversation_id: str,
) -> list[dict[str, Any]]:
    chat_room_columns = _sqlite_columns(connection, "chat_room")
    member_columns = _sqlite_columns(connection, "chatroom_member")
    contact_columns = _sqlite_columns(connection, "contact")
    if (
        chat_room_columns is None
        or not {"id", "username"}.issubset(chat_room_columns)
        or member_columns is None
        or not {"room_id", "member_id"}.issubset(member_columns)
        or contact_columns is None
        or not {"id", "username", "alias", "remark", "nick_name"}.issubset(contact_columns)
    ):
        raise participant_protocol.ParticipantProtocolError("bad_schema")
    exists = connection.execute(
        "SELECT 1 FROM chat_room WHERE username = ? LIMIT 1",
        (conversation_id,),
    ).fetchone()
    if exists is None:
        raise participant_protocol.ParticipantProtocolError("conversation_not_found")
    rows = connection.execute(
        "SELECT cm.member_id, c.username, c.remark, c.nick_name, c.alias "
        "FROM chat_room AS cr "
        "JOIN chatroom_member AS cm ON cm.room_id = cr.id "
        "LEFT JOIN contact AS c ON c.id = cm.member_id "
        "WHERE cr.username = ? GROUP BY cm.member_id, c.username, c.remark, c.nick_name, c.alias",
        (conversation_id,),
    ).fetchall()
    participants = []
    for member_id, username, remark, nickname, alias in rows:
        participant_id = str(username or f"contact_id:{member_id}").strip()
        if not participant_id or participant_id == "contact_id:None":
            raise participant_protocol.ParticipantProtocolError("bad_schema")
        label = _single_line(remark) or _single_line(nickname) or _single_line(alias)
        participants.append(
            {
                "participant_id": participant_id,
                "label": label,
                "label_provenance": (
                    "current_membership" if label else "anonymous"
                ),
                "observed_message_count": 0,
            }
        )
    return participants


def _wechat_contact_labels(connection: sqlite3.Connection) -> dict[str, str]:
    """Read current display fallbacks without mutating historical messages."""

    columns = _sqlite_columns(connection, "contact")
    if columns is None or not {
        "username",
        "alias",
        "remark",
        "nick_name",
    }.issubset(columns):
        raise participant_protocol.ParticipantProtocolError("bad_schema")
    rows = connection.execute(
        "SELECT username, remark, nick_name, alias FROM contact "
        "WHERE username IS NOT NULL AND username != ''"
    ).fetchall()
    return {
        str(username): (
            _single_line(remark)
            or _single_line(nickname)
            or _single_line(alias)
        )
        for username, remark, nickname, alias in rows
    }


def _wechat_observed_senders(
    connections: Iterable[tuple[str, sqlite3.Connection]],
    *,
    conversation_id: str,
) -> list[dict[str, Any]]:
    table = wechat_db._wechat_conversation_table_name(conversation_id)
    aggregated: dict[str, int] = {}
    found_table = False
    for shard_id, connection in connections:
        try:
            wechat_db._wechat_shard_bound_sender_id(shard_id, 0)
        except ValueError:
            raise participant_protocol.ParticipantProtocolError("bad_schema") from None
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (table,),
        ).fetchone()
        if exists is None:
            continue
        found_table = True
        message_columns = _sqlite_columns(connection, table)
        name_columns = _sqlite_columns(connection, "Name2Id")
        if (
            message_columns is None
            or "real_sender_id" not in message_columns
            or name_columns is None
            or not {"user_name"}.issubset(name_columns)
        ):
            raise participant_protocol.ParticipantProtocolError("bad_schema")
        missing_sender = connection.execute(
            f'SELECT COUNT(*) FROM "{table}" '
            "WHERE real_sender_id IS NULL"
        ).fetchone()
        if missing_sender and int(missing_sender[0] or 0) > 0:
            raise participant_protocol.ParticipantProtocolError("bad_schema")
        rows = connection.execute(
            f'SELECT m.real_sender_id, n.user_name, COUNT(*) '
            f'FROM "{table}" AS m '
            "LEFT JOIN Name2Id AS n ON n.rowid = m.real_sender_id "
            "WHERE m.real_sender_id IS NOT NULL "
            "GROUP BY m.real_sender_id, n.user_name"
        ).fetchall()
        for raw_sender_id, username, raw_count in rows:
            mapped_id = str(username or "").strip()
            try:
                participant_id = mapped_id or wechat_db._wechat_shard_bound_sender_id(
                    shard_id,
                    raw_sender_id,
                )
            except ValueError:
                raise participant_protocol.ParticipantProtocolError(
                    "bad_schema"
                ) from None
            aggregated[participant_id] = (
                aggregated.get(participant_id, 0) + int(raw_count or 0)
            )
    if not found_table:
        raise participant_protocol.ParticipantProtocolError("conversation_not_found")

    return [
        {
            "participant_id": participant_id,
            "label": "",
            "label_provenance": "anonymous",
            "observed_message_count": count,
        }
        for participant_id, count in aggregated.items()
    ]


def _read_wechat(
    request: participant_protocol.ParticipantRequest,
    data_root: str | None,
) -> list[dict[str, Any]]:
    if request.view == "member" and request.conversation_type != "group":
        raise participant_protocol.ParticipantProtocolError("unsupported_view")
    if request.conversation_id.endswith("@chatroom") != (
        request.conversation_type == "group"
    ):
        raise participant_protocol.ParticipantProtocolError("bad_schema")
    root = Path(data_root).expanduser() if data_root else wechat_db.find_weixin_data_root()
    if root is None:
        raise participant_protocol.ParticipantProtocolError("source_unavailable")
    reader = wechat_db.WeChatDBReader(
        data_root=root,
        account_id=request.account_id,
        allow_live_key_extract=False,
    )
    if not reader.initialize() or not reader.wxid_dir:
        raise participant_protocol.ParticipantProtocolError("source_unavailable")
    contact_database = reader.wxid_dir / "db_storage" / "contact" / "contact.db"
    contact_key: bytes | None = None
    message_databases: tuple[Path, ...] = ()
    if request.view == "sender":
        message_databases = tuple(wechat_db.find_msg_databases(reader.wxid_dir))
        if not message_databases or any(
            reader.enc_keys.get(path) is None for path in message_databases
        ):
            raise participant_protocol.ParticipantProtocolError("source_unavailable")
        relevant = list(message_databases)
    else:
        relevant = []

    from chatlog_keeper.wechat_contacts import WeChatContactResolver

    contact_key = (
        WeChatContactResolver(reader)._extract_contact_key()
        if contact_database.is_file()
        else None
    )
    if request.view == "member" and not contact_key:
        raise participant_protocol.ParticipantProtocolError("source_unavailable")
    if contact_key:
        relevant.append(contact_database)
    if not relevant:
        raise participant_protocol.ParticipantProtocolError("source_unavailable")

    connections: list[sqlite3.Connection] = []
    temporary_root = Path(tempfile.mkdtemp(prefix="wechat_participants_"))
    try:
        with snapshot_db_families(relevant) as snapshots:
            # A new shard appearing while the aggregate snapshot was copied
            # means the complete observed-sender set was not proven.
            if request.view == "sender" and tuple(
                wechat_db.find_msg_databases(reader.wxid_dir)
            ) != message_databases:
                raise participant_protocol.ParticipantProtocolError("source_unavailable")
            contact_connection: sqlite3.Connection | None = None
            if contact_database in snapshots:
                contact_decrypted = temporary_root / "contact.db"
                contact_decrypted_ok = wechat_db._decrypt_db_v4(
                    snapshots[contact_database],
                    contact_key,
                    contact_decrypted,
                )
                if not contact_decrypted_ok and request.view == "member":
                    raise participant_protocol.ParticipantProtocolError(
                        "source_unavailable"
                    )
                if contact_decrypted_ok:
                    contact_connection = sqlite3.connect(str(contact_decrypted))
                    connections.append(contact_connection)
            if request.view == "member":
                if contact_connection is None:
                    raise participant_protocol.ParticipantProtocolError(
                        "source_unavailable"
                    )
                return _wechat_current_members(
                    contact_connection,
                    conversation_id=request.conversation_id,
                )

            message_connections: list[tuple[str, sqlite3.Connection]] = []
            for index, database in enumerate(message_databases):
                decrypted = temporary_root / f"message_{index:04d}.db"
                if not wechat_db._decrypt_db_v4(
                    snapshots[database],
                    reader.enc_keys[database],
                    decrypted,
                ):
                    raise participant_protocol.ParticipantProtocolError(
                        "source_unavailable"
                    )
                connection = sqlite3.connect(str(decrypted))
                connections.append(connection)
                message_connections.append(
                    (
                        wechat_db._wechat_message_shard_id(
                            database,
                            root=reader.wxid_dir,
                        ),
                        connection,
                    )
                )
            participants = _wechat_observed_senders(
                message_connections,
                conversation_id=request.conversation_id,
            )
            try:
                labels = (
                    _wechat_contact_labels(contact_connection)
                    if contact_connection is not None
                    else {}
                )
            except participant_protocol.ParticipantProtocolError:
                # Current-contact names are optional presentation fallbacks for
                # sender view; their schema cannot invalidate proven sender IDs.
                labels = {}
            for item in participants:
                item["label"] = labels.get(item["participant_id"], "")
                if item["label"]:
                    item["label_provenance"] = "current_contact_fallback"
            return participants
    finally:
        for connection in connections:
            try:
                connection.close()
            except sqlite3.Error:
                pass
        shutil.rmtree(temporary_root, ignore_errors=True)


def read_page(
    request: participant_protocol.ParticipantRequest,
    *,
    data_root: str | None = None,
) -> dict[str, Any]:
    """Read one private page with complete metadata-only snapshot semantics."""

    values = (
        _read_qq(request, data_root)
        if request.source == "qq"
        else _read_wechat(request, data_root)
    )
    coverage = (
        "current_members_complete"
        if request.view == "member"
        else "observed_senders_complete"
    )
    return participant_protocol.build_page(request, values, coverage=coverage)


__all__ = ["read_page"]
