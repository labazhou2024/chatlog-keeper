"""Device-local opaque account binding for QQ and WeChat connector actions.

The connector must sometimes recover an OS-stored key before it can prove a
database master key.  Raw QQ/WeChat account identifiers are therefore the
wrong cross-process lookup key: they are private, and a plain digest of a QQ
number is trivially enumerable.  This module derives a stable opaque ref with
an owner-only random device secret, and persists only that ref plus an
irreversible routing digest.

The routing digest is never returned.  It is used only to resolve a previously
selected ref against the connector's freshly enumerated local account set.
The selected account is still re-verified by the normal database-key path
before any key is accepted.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from chatlog_keeper.core._secrets import (
    _prepare_secret_parent,
    _windows_acl_is_private,
    _windows_apply_private_acl,
    read_secret_text,
    write_secret_text,
)


PROTOCOL = "native-account-binding-v1"
SCHEMA = "chatlog-keeper.native-account-binding.v1"
STORAGE_SCHEMA = "chatlog-keeper.native-account-binding-record.v1"
AUTHORITY = "device-local-canonical-account-binding"
ACCOUNT_REF_FORMAT = "chatlog-native-account-ref-v1-hmac-sha256"
KEY_ACCOUNT_REF_FORMAT = "chatlog-account-ref-v1-sha256"
ACCOUNT_REF_PREFIX = "chatlog-native-account-ref-v1:"
KEY_ACCOUNT_REF_PREFIX = "chatlog-account-ref-v1:"
ACCOUNT_REF_DOMAIN = b"chatlog-keeper\x00native-account-binding-v1\x00account-ref\x00"
ACCOUNT_HASH_DOMAIN = b"chatlog-keeper\x00native-account-binding-v1\x00routing-hash\x00"

_NATIVE_ACCOUNT_REF_RE = re.compile(
    r"chatlog-native-account-ref-v1:[0-9a-f]{64}"
)
_KEY_ACCOUNT_REF_RE = re.compile(r"chatlog-account-ref-v1:[0-9a-f]{64}")
_ACCOUNT_HASH_RE = re.compile(r"[0-9a-f]{64}")
_SOURCES = frozenset({"qq", "wechat"})
_PROOFS = frozenset(
    {
        "database-key-proof",
        "single-account-enumeration",
        "current-account-routing",
    }
)
_STATES = (
    "verified",
    "verified_unpersisted",
    "restored",
    "single_account",
    "current_account",
    "selection_required",
    "unavailable",
)
_MAX_ACCOUNT_ID_BYTES = 512
_MAX_BINDING_BYTES = 1024
_SECRET_BYTES = 32
_SECRET_READ_RETRIES = 8


@dataclass(frozen=True)
class AccountBinding:
    """One owner-private selected account binding."""

    source: str
    account_ref: str
    account_ref_format: str
    account_hash: str
    proof: str


@dataclass(frozen=True)
class ResolvedAccountBinding:
    """A selected opaque ref resolved against a current canonical account set."""

    source: str
    account_id: str
    account_ref: str
    proof: str


def capabilities_payload() -> dict[str, Any]:
    """Return the exact no-input capability contract."""

    return {
        "capability": PROTOCOL,
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "account_ref_formats": [KEY_ACCOUNT_REF_FORMAT, ACCOUNT_REF_FORMAT],
        "sources": ["qq", "wechat"],
        "states": list(_STATES),
    }


def _normalize_source(source: object) -> str | None:
    normalized = str(source or "").strip().lower()
    return normalized if normalized in _SOURCES else None


def _normalize_account_id(value: object) -> str | None:
    """Accept one native routing identifier without accepting a path."""

    if type(value) is not str:
        return None
    normalized = value.strip()
    try:
        encoded = normalized.encode("utf-8", errors="strict")
    except UnicodeError:
        return None
    if (
        not normalized
        or normalized != value
        or len(encoded) > _MAX_ACCOUNT_ID_BYTES
        or normalized in {".", ".."}
        or "/" in normalized
        or "\\" in normalized
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in normalized)
    ):
        return None
    return normalized


def _normalized_account_ids(values: Iterable[object]) -> tuple[str, ...]:
    normalized = []
    seen = set()
    for value in values:
        account_id = _normalize_account_id(value)
        if account_id is None or account_id in seen:
            continue
        seen.add(account_id)
        normalized.append(account_id)
    return tuple(sorted(normalized))


def _state_root() -> Path:
    """Return the shared persistent private-state directory."""

    from chatlog_keeper.core._path_resolver import data_dir

    return data_dir() / "secrets"


def _secret_path() -> Path:
    return _state_root() / "native_account_binding.secret"


def _binding_path(source: str) -> Path:
    return _state_root() / f"{source}_native_account_binding.json"


def _parse_secret(text: str | None) -> bytes | None:
    normalized = str(text or "").strip()
    if len(normalized) != _SECRET_BYTES * 2 or any(
        char not in "0123456789abcdef" for char in normalized
    ):
        return None
    try:
        return bytes.fromhex(normalized)
    except ValueError:
        return None


def _read_secret_with_retry(path: Path) -> bytes | None:
    for attempt in range(_SECRET_READ_RETRIES):
        secret = _parse_secret(read_secret_text(path, max_bytes=128))
        if secret is not None:
            return secret
        if attempt + 1 < _SECRET_READ_RETRIES:
            time.sleep(0.01)
    return None


def _create_secret_exclusive(path: Path) -> bytes | None:
    """Create the device secret once without a replace race."""

    candidate = os.urandom(_SECRET_BYTES)
    fd = -1
    created = False
    created_identity: tuple[int, int] | None = None
    try:
        parent_before = _prepare_secret_parent(path.parent)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            return _read_secret_with_retry(path)
        created = True
        opened = os.fstat(fd)
        created_identity = (opened.st_dev, opened.st_ino)
        raw = candidate.hex().encode("ascii") + b"\n"
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise OSError("device secret write failed")
            offset += written
        os.fsync(fd)
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        os.close(fd)
        fd = -1
        if os.name == "nt":
            if not _windows_apply_private_acl(path, directory=False):
                raise PermissionError("device secret ACL could not be restricted")
            if not _windows_acl_is_private(path):
                raise PermissionError("device secret ACL verification failed")
        parent_after = os.lstat(path.parent)
        file_after = os.lstat(path)
        if (
            (parent_before.st_dev, parent_before.st_ino)
            != (parent_after.st_dev, parent_after.st_ino)
            or not stat.S_ISREG(file_after.st_mode)
            or path.is_symlink()
            or getattr(file_after, "st_file_attributes", 0) & 0x0400
        ):
            raise PermissionError("device secret identity changed")
        published = _read_secret_with_retry(path)
        return candidate if published == candidate else None
    except (OSError, PermissionError, ValueError):
        if created and created_identity is not None:
            try:
                current = os.lstat(path)
                if (current.st_dev, current.st_ino) == created_identity:
                    path.unlink()
            except OSError:
                pass
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _device_secret(*, create: bool) -> bytes | None:
    path = _secret_path()
    secret = _parse_secret(read_secret_text(path, max_bytes=128))
    if secret is not None or not create:
        return secret
    return _create_secret_exclusive(path)


def _account_hash(
    source: str,
    account_id: str,
    *,
    create_secret: bool,
) -> str | None:
    secret = _device_secret(create=create_secret)
    if secret is None:
        return None
    value = source.encode("ascii") + b"\x00" + account_id.encode("utf-8")
    return hmac.new(
        secret,
        ACCOUNT_HASH_DOMAIN + value,
        hashlib.sha256,
    ).hexdigest()


def _account_ref_format(value: object) -> str | None:
    if type(value) is not str:
        return None
    if _KEY_ACCOUNT_REF_RE.fullmatch(value) is not None:
        return KEY_ACCOUNT_REF_FORMAT
    if _NATIVE_ACCOUNT_REF_RE.fullmatch(value) is not None:
        return ACCOUNT_REF_FORMAT
    return None


def account_ref(
    source: str,
    account_id: str,
    *,
    create_secret: bool = True,
) -> str | None:
    """Derive a stable opaque ref without returning or persisting the raw ID."""

    normalized_source = _normalize_source(source)
    normalized_id = _normalize_account_id(account_id)
    if normalized_source is None or normalized_id is None:
        return None
    secret = _device_secret(create=create_secret)
    if secret is None:
        return None
    value = normalized_source.encode("ascii") + b"\x00" + normalized_id.encode("utf-8")
    digest = hmac.new(secret, ACCOUNT_REF_DOMAIN + value, hashlib.sha256).hexdigest()
    return ACCOUNT_REF_PREFIX + digest


def candidate_refs(source: str, account_ids: Iterable[object]) -> tuple[str, ...]:
    """Return deterministic opaque refs for the complete canonical candidate set."""

    refs = []
    for account_id in _normalized_account_ids(account_ids):
        ref = account_ref(source, account_id)
        if ref is None:
            return ()
        refs.append(ref)
    return tuple(refs)


def _binding_payload(binding: AccountBinding) -> str:
    return json.dumps(
        {
            "schema": STORAGE_SCHEMA,
            "source": binding.source,
            "account_ref": binding.account_ref,
            "account_ref_format": binding.account_ref_format,
            "native_account_hash": binding.account_hash,
            "proof": binding.proof,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def select_account(
    source: str,
    account_id: str,
    *,
    proof: str,
    account_ref_value: str | None = None,
) -> str | None:
    """Persist one selected opaque ref after a trusted local selection event."""

    normalized_source = _normalize_source(source)
    normalized_id = _normalize_account_id(account_id)
    if (
        normalized_source is None
        or normalized_id is None
        or proof not in _PROOFS
    ):
        return None
    ref = account_ref_value or account_ref(normalized_source, normalized_id)
    ref_format = _account_ref_format(ref)
    if (
        ref_format is None
        or (
            ref_format == KEY_ACCOUNT_REF_FORMAT
            and (
                normalized_source != "wechat"
                or proof != "database-key-proof"
            )
        )
    ):
        return None
    account_hash = _account_hash(
        normalized_source,
        normalized_id,
        create_secret=True,
    )
    if account_hash is None:
        return None
    binding = AccountBinding(
        source=normalized_source,
        account_ref=ref,
        account_ref_format=ref_format,
        account_hash=account_hash,
        proof=proof,
    )
    if not write_secret_text(_binding_path(normalized_source), _binding_payload(binding)):
        return None
    resolved = resolve_selected(normalized_source, (normalized_id,))
    return ref if resolved is not None and resolved.account_ref == ref else None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def selected_binding(source: str) -> AccountBinding | None:
    """Read one strict selected binding; malformed or unsafe state is ignored."""

    normalized_source = _normalize_source(source)
    if normalized_source is None:
        return None
    raw = read_secret_text(
        _binding_path(normalized_source),
        max_bytes=_MAX_BINDING_BYTES,
    )
    if raw is None:
        return None
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        type(payload) is not dict
        or set(payload)
        != {
            "schema",
            "source",
            "account_ref",
            "account_ref_format",
            "native_account_hash",
            "proof",
        }
        or payload.get("schema") != STORAGE_SCHEMA
        or payload.get("source") != normalized_source
        or type(payload.get("account_ref")) is not str
        or _account_ref_format(payload["account_ref"]) is None
        or payload.get("account_ref_format")
        != _account_ref_format(payload["account_ref"])
        or (
            payload.get("account_ref_format") == KEY_ACCOUNT_REF_FORMAT
            and (
                normalized_source != "wechat"
                or payload.get("proof") != "database-key-proof"
            )
        )
        or type(payload.get("native_account_hash")) is not str
        or _ACCOUNT_HASH_RE.fullmatch(payload["native_account_hash"]) is None
        or payload.get("proof") not in _PROOFS
    ):
        return None
    return AccountBinding(
        source=normalized_source,
        account_ref=payload["account_ref"],
        account_ref_format=payload["account_ref_format"],
        account_hash=payload["native_account_hash"],
        proof=payload["proof"],
    )


def resolve_selected(
    source: str,
    account_ids: Iterable[object],
) -> ResolvedAccountBinding | None:
    """Resolve a selected ref only when exactly one current account matches."""

    normalized_source = _normalize_source(source)
    if normalized_source is None:
        return None
    binding = selected_binding(normalized_source)
    if binding is None:
        return None
    matches = []
    for account_id in _normalized_account_ids(account_ids):
        candidate_hash = _account_hash(
            normalized_source,
            account_id,
            create_secret=False,
        )
        if candidate_hash is None:
            return None
        if candidate_hash != binding.account_hash:
            continue
        ref_matches = binding.account_ref_format == KEY_ACCOUNT_REF_FORMAT
        if not ref_matches:
            ref_matches = (
                account_ref(
                    normalized_source,
                    account_id,
                    create_secret=False,
                )
                == binding.account_ref
            )
        if ref_matches:
            matches.append(account_id)
    if len(matches) != 1:
        return None
    return ResolvedAccountBinding(
        source=normalized_source,
        account_id=matches[0],
        account_ref=binding.account_ref,
        proof=binding.proof,
    )


def envelope(
    source: str,
    *,
    state: str,
    account_ref_value: str | None = None,
    account_refs: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the fixed-shape cross-process envelope without a native ID."""

    normalized_source = _normalize_source(source)
    if normalized_source is None or state not in _STATES:
        raise ValueError("invalid native account binding envelope")
    refs = tuple(account_refs)
    if (
        any(_account_ref_format(value) is None for value in refs)
        or len(set(refs)) != len(refs)
    ):
        raise ValueError("invalid native account binding refs")
    if account_ref_value is not None and (
        _account_ref_format(account_ref_value) is None
    ):
        raise ValueError("invalid native account binding ref")
    if account_ref_value is not None and refs and account_ref_value not in refs:
        raise ValueError("selected native account binding ref is not a candidate")
    selection_required = state == "selection_required"
    if selection_required and (account_ref_value is not None or len(refs) < 2):
        raise ValueError("selection-required envelope is inconsistent")
    if state in {"verified", "restored", "single_account", "current_account"} and (
        account_ref_value is None
    ):
        raise ValueError("selected native account binding ref is required")
    if state == "unavailable" and account_ref_value is not None:
        raise ValueError("unavailable native account binding has a selected ref")
    if not selection_required and account_ref_value is not None and not refs:
        refs = (account_ref_value,)
    formats = {
        value
        for value in (_account_ref_format(ref) for ref in refs)
        if value is not None
    }
    if account_ref_value is not None:
        formats.add(_account_ref_format(account_ref_value))
    if len(formats) > 1:
        raise ValueError("mixed native account binding ref formats")
    if selection_required and formats != {ACCOUNT_REF_FORMAT}:
        raise ValueError("selection-required refs must be native opaque refs")
    ref_format = next(iter(formats)) if formats else None
    return {
        "schema": SCHEMA,
        "source": normalized_source,
        "authority": AUTHORITY,
        "account_ref_format": ref_format,
        "state": state,
        "account_ref": account_ref_value,
        "account_refs": list(refs),
        "account_selection_required": selection_required,
    }


def attach(
    payload: dict[str, Any],
    source: str,
    *,
    state: str,
    account_ref_value: str | None = None,
    account_refs: Iterable[str] = (),
) -> dict[str, Any]:
    """Add the versioned opaque binding envelope to an existing result."""

    result = dict(payload)
    result["native_account_binding"] = envelope(
        source,
        state=state,
        account_ref_value=account_ref_value,
        account_refs=account_refs,
    )
    return result


__all__ = [
    "ACCOUNT_REF_FORMAT",
    "ACCOUNT_REF_PREFIX",
    "KEY_ACCOUNT_REF_FORMAT",
    "KEY_ACCOUNT_REF_PREFIX",
    "AUTHORITY",
    "PROTOCOL",
    "SCHEMA",
    "AccountBinding",
    "ResolvedAccountBinding",
    "account_ref",
    "attach",
    "candidate_refs",
    "capabilities_payload",
    "envelope",
    "resolve_selected",
    "select_account",
    "selected_binding",
]
