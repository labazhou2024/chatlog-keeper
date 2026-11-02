#!/usr/bin/env python3
"""Copy exact-name QQ media cache matches for an exported message JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _priority(path: Path, kind: str) -> int:
    parts = {part.lower() for part in path.parts}
    score = 0
    if "ori" in parts:
        score += 100
    if kind == "image" and "pic" in parts:
        score += 30
    elif kind == "image" and "emoji" in parts:
        score += 20
    elif kind == "voice" and "ptt" in parts:
        score += 30
    elif kind == "file" and "video" in parts:
        score += 30
    return score


def _index_files(root: Path) -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            path.resolve().relative_to(root)
        except ValueError:
            continue
        index.setdefault(path.name.casefold(), []).append(path)
    return index


def _resolve_match(candidates: list[Path], kind: str) -> tuple[Path | None, str]:
    if not candidates:
        return None, "missing"
    ranked = sorted(candidates, key=lambda path: _priority(path, kind), reverse=True)
    best_score = _priority(ranked[0], kind)
    best = [path for path in ranked if _priority(path, kind) == best_score]
    if len(best) == 1:
        return best[0], "copied"
    hashes = {_sha256(path) for path in best}
    if len(hashes) == 1:
        return best[0], "copied"
    return None, "ambiguous"


def package(messages_path: Path, data_root: Path, out_dir: Path) -> dict[str, Any]:
    root = data_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("data root must be a directory")
    messages = json.loads(messages_path.read_text(encoding="utf-8"))
    if not isinstance(messages, list):
        raise ValueError("message JSON must contain a list")
    index = _index_files(root)
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    copied_paths: set[str] = set()
    statuses: Counter[str] = Counter()
    kinds: Counter[str] = Counter()

    for message_index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        metadata = message.get("attachment_meta")
        if not isinstance(metadata, dict):
            continue
        raw_name = str(metadata.get("filename") or "").strip()
        kind = str(metadata.get("kind") or "other")
        record: dict[str, Any] = {
            "message_index": message_index,
            "source_offset": message.get("source_offset"),
            "ts_iso": message.get("ts_iso"),
            "kind": kind,
            "filename": raw_name,
        }
        safe_name = Path(raw_name).name
        candidates = index.get(safe_name.casefold(), []) if safe_name else []
        source, status = _resolve_match(candidates, kind)
        record["status"] = status
        statuses[status] += 1
        kinds[kind] += 1

        if source is not None:
            destination_dir = out_dir / "media" / kind
            destination_dir.mkdir(parents=True, exist_ok=True)
            destination = destination_dir / source.name
            digest = _sha256(source)
            if destination.exists() and _sha256(destination) != digest:
                destination = destination_dir / f"{source.stem}_{digest[:10]}{source.suffix}"
            if not destination.exists():
                shutil.copy2(source, destination)
            relative_path = destination.relative_to(out_dir).as_posix()
            record.update(
                local_path=relative_path,
                cache_path=source.relative_to(root).as_posix(),
                bytes=source.stat().st_size,
                sha256=digest,
            )
            copied_paths.add(relative_path)
        records.append(record)

    manifest = {
        "generated_from": messages_path.name,
        "counts": {
            "attachment_records": len(records),
            "copied_records": statuses["copied"],
            "unique_media_files": len(copied_paths),
            "missing_records": statuses["missing"],
            "ambiguous_records": statuses["ambiguous"],
            "copied_by_kind": dict(kinds),
        },
        "items": records,
    }
    (out_dir / "media_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest["counts"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--messages", required=True, type=Path, help="exported QQ message JSON")
    parser.add_argument("--data-root", required=True, type=Path, help="read-only QQ media cache root")
    parser.add_argument("--out-dir", required=True, type=Path, help="message export directory")
    args = parser.parse_args()
    try:
        counts = package(args.messages, args.data_root, args.out_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(counts, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
