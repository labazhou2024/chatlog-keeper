"""Private producer for the additive WeChat ``key-identity-v1`` protocol.

Filesystem account names are routing hints, never identity evidence.  This
module emits an opaque account ref only after one 32-byte master key
authenticates a frozen SQLCipher page target.  It has no network or client-UI
surface and never returns the key, a native account ID, or a database path in
the identity envelope.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from chatlog_keeper import native_account_binding, wechat_db
from chatlog_keeper.core._secrets import read_secret_text, write_secret_text


PROTOCOL = "key-identity-v1"
SCHEMA = "chatlog-keeper.key-identity.v1"
AUTHORITY = "database-master-key-proof"
ACCOUNT_REF_FORMAT = "chatlog-account-ref-v1-sha256"
ACCOUNT_REF_PREFIX = "chatlog-account-ref-v1:"
ACCOUNT_REF_DOMAIN = (
    b"chatlog-keeper\x00key-identity-v1\x00wechat\x00database-master-key-proof\x00"
)
MAX_TARGETS = 64
_WINDOWS_REPARSE_POINT = 0x0400
_ACCOUNT_REF_RE = re.compile(r"chatlog-account-ref-v1:[0-9a-f]{64}")
_EXPECTED_ACCOUNT_REF_UNSET = object()

_CAPABILITY = {
    "capability": PROTOCOL,
    "schema": SCHEMA,
    "source": "wechat",
    "authority": AUTHORITY,
    "account_ref_format": ACCOUNT_REF_FORMAT,
}


@dataclass(frozen=True)
class TargetSnapshot:
    """One frozen HMAC oracle used only inside a key action or probe.

    ``account_id`` is retained solely for routing the existing account-scoped
    key cache.  It never contributes to ``account_ref``.
    """

    path: Path
    device: int
    inode: int
    salt: bytes
    page1: bytes
    account_id: str | None


class TargetError(RuntimeError):
    """Path-free reason for refusing a key identity proof."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def capabilities_payload() -> dict[str, str]:
    """Return the exact no-input ``key-identity-v1`` capability contract."""

    return dict(_CAPABILITY)


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _is_reparse_point(value: os.stat_result) -> bool:
    return bool(
        getattr(value, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    )


def target_snapshots(databases: Iterable[Path]) -> tuple[TargetSnapshot, ...]:
    """Freeze canonical account oracles before a key operation.

    A final symlink/reparse point, unstable page, target replacement, or an
    excessive target set invalidates the whole proof.  Skipping only the bad
    target would make a key look unique merely because a second account could
    not be checked.
    """

    candidates = tuple(dict.fromkeys(Path(item) for item in databases))
    if not candidates:
        raise TargetError("database_unavailable")
    if len(candidates) > MAX_TARGETS:
        raise TargetError("target_limit_exceeded")

    snapshots: list[TargetSnapshot] = []
    seen_paths: set[str] = set()
    for candidate in candidates:
        try:
            unresolved = os.lstat(candidate)
            if (
                _is_reparse_point(unresolved)
                or not stat.S_ISREG(unresolved.st_mode)
            ):
                raise OSError("unsafe target")
            path = candidate.resolve(strict=True)
            path_key = os.path.normcase(str(path))
            if path_key in seen_paths:
                continue
            before = os.lstat(path)
            if _is_reparse_point(before) or not stat.S_ISREG(before.st_mode):
                raise OSError("unsafe target")
            page1 = wechat_db._read_stable_page1(path)
            after = os.lstat(path)
            if (
                not page1
                or not _same_file_identity(before, after)
                or _is_reparse_point(after)
                or not stat.S_ISREG(after.st_mode)
            ):
                raise OSError("unstable target")
        except (OSError, RuntimeError, TypeError, ValueError):
            raise TargetError("database_unstable") from None
        seen_paths.add(path_key)
        snapshots.append(
            TargetSnapshot(
                path=path,
                device=after.st_dev,
                inode=after.st_ino,
                salt=bytes(page1[:16]),
                page1=bytes(page1),
                account_id=wechat_db.wechat_account_id_for_database(path),
            )
        )
    if not snapshots:
        raise TargetError("database_unstable")
    return tuple(snapshots)


def _target_group(target: TargetSnapshot) -> tuple[str, str]:
    """Group canonical DBs by account without using the value as identity."""

    if target.account_id:
        return "account", target.account_id
    return "database", os.path.normcase(str(target.path))


def matching_target(
    key: bytes,
    snapshots: tuple[TargetSnapshot, ...],
) -> TargetSnapshot:
    """Return one account target iff ``key`` authenticates exactly one account."""

    if not isinstance(key, bytes) or len(key) != 32:
        raise TargetError("key_mismatch")
    matches = [
        target
        for target in snapshots
        if wechat_db._verify_key_v4(key, target.page1)
    ]
    groups = {_target_group(target) for target in matches}
    if not matches:
        raise TargetError("key_mismatch")
    if len(groups) != 1:
        raise TargetError("ambiguous_account")
    return min(matches, key=lambda target: os.path.normcase(str(target.path)))


def _current_target_page(target: TargetSnapshot) -> bytes | None:
    """Return a fresh page only while the frozen file identity/salt remains."""

    try:
        before = os.lstat(target.path)
        if (
            (before.st_dev, before.st_ino) != (target.device, target.inode)
            or _is_reparse_point(before)
            or not stat.S_ISREG(before.st_mode)
        ):
            return None
        page1 = wechat_db._read_stable_page1(target.path)
        after = os.lstat(target.path)
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if not (
        page1
        and _same_file_identity(before, after)
        and (after.st_dev, after.st_ino) == (target.device, target.inode)
        and bytes(page1[:16]) == target.salt
    ):
        return None
    return bytes(page1)


def target_still_matches(target: TargetSnapshot, key: bytes) -> bool:
    """Recheck canonical file identity, SQLCipher salt, and key HMAC."""

    page1 = _current_target_page(target)
    return bool(page1 and wechat_db._verify_key_v4(key, page1))


def live_matching_target(
    key: bytes,
    snapshots: tuple[TargetSnapshot, ...],
) -> TargetSnapshot:
    """Re-read the complete frozen set and prove one live account group."""

    matches: list[TargetSnapshot] = []
    for target in snapshots:
        page1 = _current_target_page(target)
        if page1 is None:
            raise TargetError("database_changed")
        if wechat_db._verify_key_v4(key, page1):
            matches.append(target)
    groups = {_target_group(target) for target in matches}
    if not matches:
        raise TargetError("key_mismatch")
    if len(groups) != 1:
        raise TargetError("ambiguous_account")
    return min(matches, key=lambda target: os.path.normcase(str(target.path)))


def envelope(key: bytes) -> dict[str, str]:
    """Build an opaque identity after the caller completed DB HMAC proof."""

    if not isinstance(key, bytes) or len(key) != 32:
        raise TargetError("key_mismatch")
    digest = hashlib.sha256(ACCOUNT_REF_DOMAIN + key).hexdigest()
    return {
        "schema": SCHEMA,
        "source": "wechat",
        "authority": AUTHORITY,
        "account_ref": ACCOUNT_REF_PREFIX + digest,
    }


def protocol_payload(
    payload: dict[str, Any],
    *,
    key: bytes | None = None,
) -> dict[str, Any]:
    """Add the frozen producer capability and an optional proven envelope."""

    result = dict(payload)
    result["protocol_capabilities"] = [PROTOCOL]
    if key is not None:
        result["key_identity"] = envelope(key)
    return result


def _selection_marker_path() -> Path | None:
    """Return the private, native-ID-free automatic account selection file."""

    persistent = wechat_db._persistent_wechat_key_cache_path()
    if persistent is None:
        return None
    return persistent.parent / "wechat_key_identity.ref"


def selected_ref() -> str | None:
    """Read one strictly formatted opaque selection; corruption is ignored."""

    path = _selection_marker_path()
    if path is None:
        return None
    value = read_secret_text(path, max_bytes=256)
    if value is None:
        return None
    normalized = value.strip()
    if _ACCOUNT_REF_RE.fullmatch(normalized) is None:
        return None
    return normalized


def write_selected_key(key: bytes) -> bool:
    """Atomically select a proven key without persisting a path or native ID."""

    try:
        account_ref = envelope(key)["account_ref"]
    except TargetError:
        return False
    path = _selection_marker_path()
    if path is None:
        return False
    return write_secret_text(path, account_ref + "\n")


def verified_cached_target(
    snapshots: tuple[TargetSnapshot, ...],
) -> tuple[bytes, TargetSnapshot] | None:
    """Prove one cached master key against exactly one current account target."""

    matches: list[tuple[bytes, TargetSnapshot]] = []
    for target in snapshots:
        cached = (
            wechat_db.load_cached_wechat_key_for_account(target.account_id)
            if target.account_id
            else wechat_db.load_cached_wechat_key()
        )
        if (
            isinstance(cached, bytes)
            and len(cached) == 32
            and wechat_db._verify_key_v4(cached, target.page1)
        ):
            matches.append((cached, target))
    if not matches:
        return None
    groups = {_target_group(target) for _key, target in matches}
    keys = {key for key, _target in matches}
    if len(groups) == 1 and len(keys) == 1:
        key = next(iter(keys))
    else:
        selection = selected_ref()
        selected_keys = {
            key
            for key, _target in matches
            if envelope(key)["account_ref"] == selection
        }
        if len(selected_keys) != 1:
            raise TargetError("ambiguous_account")
        key = next(iter(selected_keys))
    target = live_matching_target(key, snapshots)
    return key, target


def save_for_target(
    key: bytes,
    target: TargetSnapshot,
    snapshots: tuple[TargetSnapshot, ...],
    *,
    expected_account_ref: str | None | object = _EXPECTED_ACCOUNT_REF_UNSET,
) -> tuple[str, Path | None]:
    """Persist and select only between complete-set account proofs.

    An exact-pinned consumer may constrain the write with an expected opaque
    account ref.  A string requires the submitted key to derive that exact ref;
    explicit ``None`` is the first-configuration contract and is accepted only
    while no cached key currently proves an account.  Both checks happen before
    either the account cache or selection marker can be modified.  Omitting the
    argument preserves the standalone CLI's established explicit-switch flow.
    """

    try:
        candidate_ref = envelope(key)["account_ref"]
    except TargetError:
        return "account_ref_mismatch", None
    if expected_account_ref is not _EXPECTED_ACCOUNT_REF_UNSET:
        if expected_account_ref is None:
            try:
                current = verified_cached_target(snapshots)
            except TargetError:
                return "account_ref_mismatch", None
            if current is not None:
                return "account_ref_mismatch", None
        elif (
            type(expected_account_ref) is not str
            or _ACCOUNT_REF_RE.fullmatch(expected_account_ref) is None
            or candidate_ref != expected_account_ref
        ):
            return "account_ref_mismatch", None

    try:
        before = live_matching_target(key, snapshots)
    except TargetError:
        return "database_changed", None
    if _target_group(before) != _target_group(target):
        return "database_changed", None
    if target.account_id:
        saved = wechat_db.save_cached_wechat_key_for_account(
            key, target.account_id, target.path
        )
        saved_path = wechat_db._wechat_account_key_cache_path(target.account_id)
    else:
        saved = wechat_db.save_cached_wechat_key(key)
        saved_path = wechat_db._wechat_key_cache_path()
    if not saved:
        return "save_failed", None
    try:
        after = live_matching_target(key, snapshots)
    except TargetError:
        return "database_changed", None
    if _target_group(after) != _target_group(target):
        return "database_changed", None
    if not write_selected_key(key):
        return "selection_failed", None
    try:
        published = live_matching_target(key, snapshots)
    except TargetError:
        # The marker is only a selection hint.  Leaving a successfully written
        # marker behind is safe because every probe re-authenticates it against
        # the complete current target set before emitting an identity.
        return "database_changed", None
    if _target_group(published) != _target_group(target):
        return "database_changed", None
    if target.account_id and (
        native_account_binding.select_account(
            "wechat",
            target.account_id,
            proof="database-key-proof",
            account_ref_value=candidate_ref,
        )
        is None
    ):
        return "binding_failed", None
    return "ok", Path(saved_path)
