#!/usr/bin/env python3
"""Build and validate immutable chatlog-keeper release metadata.

The release workflow calls this module only against a checked-out, frozen Git
commit.  It deliberately uses the standard library so the provenance path does
not acquire dependencies beyond Git itself.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import importlib
import importlib.metadata
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence


DESCRIPTOR_SCHEMA = "memexa.approved_artifact_descriptor.v2"
DESCRIPTOR_KIND = "chatlog_keeper"
PROTOCOL_CAPABILITIES = ("message-stream-v1", "participant-directory-v1")
SOURCE_BUNDLE_TEMPLATE = "chatlog-keeper-v{version}-source.tar.gz"
DESCRIPTOR_TEMPLATE = "chatlog-keeper-v{version}-{platform}-{arch}.artifact.json"

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?$")
_MAX_CAPABILITY_BYTES = 64 * 1024
_CAPABILITY_TIMEOUT_SECONDS = 30
_MESSAGE_STREAM_CAPABILITY = {
    "protocol": "message-stream-v1",
    "version": 1,
    "frame": "capabilities",
    "sources": ["qq", "wechat"],
    "frames": [
        "ready",
        "scope_begin",
        "record",
        "checkpoint",
        "scope_end",
        "complete",
        "error",
    ],
    "ordering": "scope_index,page_index,record_order",
    "checkpoint": "after_each_page",
    "limits": {
        "max_request_bytes": 262_144,
        "max_frame_bytes": 1_048_576,
        "max_cursor_bytes": 65_536,
        "max_scopes": 128,
        "max_page_size": 1_000,
        "max_total_records": 2_000_000,
        "max_total_pages": 200_000,
        "max_pages_per_scope": 50_000,
    },
}
_PARTICIPANT_DIRECTORY_CAPABILITY = {
    "protocol": "participant-directory-v1",
    "version": 1,
    "sources": ["qq", "wechat"],
    "views": ["member", "sender"],
    "limits": {
        "max_request_bytes": 65_536,
        "max_page_size": 200,
        "max_participants": 50_000,
    },
}
_SUPPORTED_TARGETS = {
    ("macos", "arm64"): "chatlog-keeper-macos-arm64",
    ("windows", "x86_64"): "chatlog-keeper.exe",
}


class ReleaseMetadataError(RuntimeError):
    """A release input or generated output failed its frozen contract."""


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError):
        raise ReleaseMetadataError("release metadata is not canonical JSON") from None


def _validated_version(value: str) -> str:
    version = str(value or "").strip()
    if not _VERSION_RE.fullmatch(version):
        raise ReleaseMetadataError("release version is invalid")
    return version


def _validated_commit(value: str) -> str:
    commit = str(value or "").strip().lower()
    if not _COMMIT_RE.fullmatch(commit):
        raise ReleaseMetadataError("release commit must be a full lowercase SHA-1")
    return commit


def _regular_file_size_and_sha256(path: Path) -> tuple[int, str]:
    try:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
            raise ReleaseMetadataError("release input must be a non-empty regular file")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except ReleaseMetadataError:
        raise
    except OSError:
        raise ReleaseMetadataError("release input could not be read") from None
    return info.st_size, digest.hexdigest()


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise ReleaseMetadataError("release output already exists")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def write_sha256_sidecar(path: Path) -> Path:
    """Write ``<sha256>  <basename>`` beside one immutable release file."""

    _size, digest = _regular_file_size_and_sha256(path)
    sidecar = path.with_name(path.name + ".sha256")
    _atomic_write(sidecar, f"{digest}  {path.name}\n".encode("ascii"))
    return sidecar


def verify_sha256_sidecar(path: Path, sidecar: Path) -> None:
    """Verify a bounded checksum sidecar and its bound basename."""

    try:
        raw = sidecar.read_bytes()
    except OSError:
        raise ReleaseMetadataError("release checksum could not be read") from None
    if len(raw) > 512:
        raise ReleaseMetadataError("release checksum is invalid")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ReleaseMetadataError("release checksum is invalid") from None
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\r?\n?", text)
    if match is None or match.group(2) != path.name:
        raise ReleaseMetadataError("release checksum is invalid")
    _size, actual = _regular_file_size_and_sha256(path)
    if not hmac.compare_digest(match.group(1), actual):
        raise ReleaseMetadataError("release checksum does not match")


def validate_version_contract(*, tag: str, module_version: str, metadata_version: str) -> str:
    """Require tag, imported module, and installed wheel metadata to agree."""

    normalized_tag = str(tag or "").strip()
    if not normalized_tag.startswith("v"):
        raise ReleaseMetadataError("release tag must start with v")
    expected = _validated_version(normalized_tag[1:])
    if module_version != expected or metadata_version != expected:
        raise ReleaseMetadataError("tag, module version, and installed metadata version differ")
    return expected


def verify_installed_version(tag: str) -> str:
    """Validate the installed package using both public version authorities."""

    repository_root = str(Path(__file__).resolve().parents[1])
    inserted = repository_root not in sys.path
    if inserted:
        sys.path.insert(0, repository_root)
    try:
        chatlog_keeper = importlib.import_module("chatlog_keeper")
        metadata_version = importlib.metadata.version("chatlog-keeper")
    except (ImportError, AttributeError, importlib.metadata.PackageNotFoundError):
        raise ReleaseMetadataError("module or installed package metadata is unavailable") from None
    finally:
        if inserted:
            sys.path.remove(repository_root)

    return validate_version_contract(
        tag=tag,
        module_version=str(chatlog_keeper.__version__),
        metadata_version=metadata_version,
    )


def _decode_one_json_object(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > _MAX_CAPABILITY_BYTES:
        raise ReleaseMetadataError("capability output size is invalid")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ReleaseMetadataError("capability output is not UTF-8") from None
    stripped = text.lstrip()
    try:
        value, end = json.JSONDecoder().raw_decode(stripped)
    except json.JSONDecodeError:
        raise ReleaseMetadataError("capability output is not one JSON object") from None
    if stripped[end:].strip() or not isinstance(value, dict):
        raise ReleaseMetadataError("capability output is not one JSON object")
    return value


def validate_message_stream_capability(value: Mapping[str, Any]) -> None:
    if set(value) != set(_MESSAGE_STREAM_CAPABILITY):
        raise ReleaseMetadataError("message-stream capability fields drifted")
    if _canonical_json(dict(value)) != _canonical_json(_MESSAGE_STREAM_CAPABILITY):
        raise ReleaseMetadataError("message-stream capability identity drifted")


def validate_participant_directory_capability(value: Mapping[str, Any]) -> None:
    if set(value) != set(_PARTICIPANT_DIRECTORY_CAPABILITY):
        raise ReleaseMetadataError("participant-directory capability fields drifted")
    if _canonical_json(dict(value)) != _canonical_json(_PARTICIPANT_DIRECTORY_CAPABILITY):
        raise ReleaseMetadataError("participant-directory capability identity drifted")


def validate_executable_header(
    executable: Path,
    *,
    target_platform: str,
    target_arch: str,
) -> None:
    """Reject renamed or wrong-architecture artifacts before approving a digest."""

    expected_name = _SUPPORTED_TARGETS.get((target_platform, target_arch))
    if expected_name is None or executable.name != expected_name:
        raise ReleaseMetadataError("release target or executable name is invalid")
    try:
        file_size = executable.lstat().st_size
        with executable.open("rb") as handle:
            if target_platform == "windows":
                dos_header = handle.read(64)
                if len(dos_header) != 64 or dos_header[:2] != b"MZ":
                    raise ReleaseMetadataError("Windows artifact is not PE32+ AMD64")
                pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
                if pe_offset < 64 or pe_offset > file_size - 26 or pe_offset > 16 * 1024 * 1024:
                    raise ReleaseMetadataError("Windows artifact is not PE32+ AMD64")
                handle.seek(pe_offset)
                pe_header = handle.read(26)
                if (
                    len(pe_header) != 26
                    or pe_header[:4] != b"PE\x00\x00"
                    or struct.unpack_from("<H", pe_header, 4)[0] != 0x8664
                    or struct.unpack_from("<H", pe_header, 24)[0] != 0x020B
                ):
                    raise ReleaseMetadataError("Windows artifact is not PE32+ AMD64")
            else:
                mach_header = handle.read(8)
                if (
                    len(mach_header) != 8
                    or struct.unpack_from("<I", mach_header, 0)[0] != 0xFEEDFACF
                    or struct.unpack_from("<I", mach_header, 4)[0] != 0x0100000C
                ):
                    raise ReleaseMetadataError("macOS artifact is not Mach-O 64 arm64")
    except ReleaseMetadataError:
        raise
    except (OSError, struct.error):
        raise ReleaseMetadataError("release executable header could not be read") from None


def _run_capability(executable: Path, protocol: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [str(executable), protocol, "--capabilities"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=_CAPABILITY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseMetadataError("frozen capability process failed") from None
    if completed.returncode != 0 or completed.stderr:
        raise ReleaseMetadataError("frozen capability process was not clean")
    return _decode_one_json_object(completed.stdout)


def validate_frozen_capabilities(executable: Path) -> None:
    """Execute and strictly validate both no-input frozen IPC capabilities."""

    _regular_file_size_and_sha256(executable)
    message_stream = _run_capability(executable, "message-stream-v1")
    participant_directory = _run_capability(executable, "participant-directory-v1")
    validate_message_stream_capability(message_stream)
    validate_participant_directory_capability(participant_directory)


def build_source_bundle(
    *,
    repository: Path,
    commit: str,
    version: str,
    output: Path,
) -> Path:
    """Create a timestamp-free gzip of ``git archive`` for one exact commit."""

    frozen_commit = _validated_commit(commit)
    frozen_version = _validated_version(version)
    expected_name = SOURCE_BUNDLE_TEMPLATE.format(version=frozen_version)
    if output.name != expected_name:
        raise ReleaseMetadataError("source bundle filename is not canonical")
    try:
        resolved = subprocess.run(
            ["git", "rev-parse", "--verify", f"{frozen_commit}^{{commit}}"],
            cwd=repository,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReleaseMetadataError("release commit could not be resolved") from None
    if resolved.returncode != 0 or resolved.stdout.strip().lower() != frozen_commit:
        raise ReleaseMetadataError("release commit is not the exact checked-out object")

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise ReleaseMetadataError("release output already exists")
    with tempfile.TemporaryDirectory(prefix="chatlog-source-", dir=str(output.parent)) as temp:
        temporary_root = Path(temp)
        tar_path = temporary_root / "source.tar"
        with tar_path.open("xb") as tar_handle:
            archived = subprocess.run(
                [
                    "git",
                    "archive",
                    "--format=tar",
                    f"--prefix=chatlog-keeper-v{frozen_version}/",
                    frozen_commit,
                ],
                cwd=repository,
                stdin=subprocess.DEVNULL,
                stdout=tar_handle,
                stderr=subprocess.PIPE,
                check=False,
                timeout=120,
            )
        if archived.returncode != 0:
            raise ReleaseMetadataError("git archive failed")
        gzip_path = temporary_root / expected_name
        with tar_path.open("rb") as source, gzip_path.open("xb") as destination:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=destination,
                mtime=0,
            ) as compressed:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    compressed.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(gzip_path, output)
    write_sha256_sidecar(output)
    return output


def build_artifact_descriptor(
    *,
    commit: str,
    version: str,
    target_platform: str,
    target_arch: str,
    executable: Path,
    source_bundle: Path,
    output: Path,
) -> Path:
    """Write one canonical v2 descriptor and its bound checksum sidecar."""

    frozen_commit = _validated_commit(commit)
    frozen_version = _validated_version(version)
    target = (str(target_platform), str(target_arch))
    expected_executable = _SUPPORTED_TARGETS.get(target)
    if expected_executable is None or executable.name != expected_executable:
        raise ReleaseMetadataError("release target or executable name is invalid")
    expected_source_name = SOURCE_BUNDLE_TEMPLATE.format(version=frozen_version)
    if source_bundle.name != expected_source_name:
        raise ReleaseMetadataError("source bundle filename is not canonical")
    expected_descriptor_name = DESCRIPTOR_TEMPLATE.format(
        version=frozen_version,
        platform=target[0],
        arch=target[1],
    )
    if output.name != expected_descriptor_name:
        raise ReleaseMetadataError("artifact descriptor filename is not canonical")

    validate_executable_header(
        executable,
        target_platform=target[0],
        target_arch=target[1],
    )
    executable_size, executable_sha = _regular_file_size_and_sha256(executable)
    _source_size, source_sha = _regular_file_size_and_sha256(source_bundle)
    descriptor = {
        "approved": True,
        "commit": frozen_commit,
        "executable": executable.name,
        "kind": DESCRIPTOR_KIND,
        "protocol_capabilities": list(PROTOCOL_CAPABILITIES),
        "schema": DESCRIPTOR_SCHEMA,
        "sha256": executable_sha,
        "size_bytes": executable_size,
        "source_bundle": source_bundle.name,
        "source_bundle_sha256": source_sha,
        "target_arch": target[1],
        "target_platform": target[0],
        "version": frozen_version,
    }
    _atomic_write(output, _canonical_json(descriptor))
    write_sha256_sidecar(output)
    return output


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    version = subparsers.add_parser("verify-version")
    version.add_argument("--tag", required=True)

    capabilities = subparsers.add_parser("validate-capabilities")
    capabilities.add_argument("--executable", type=Path, required=True)

    checksum = subparsers.add_parser("checksum")
    checksum.add_argument("--file", type=Path, required=True)

    verify_checksum = subparsers.add_parser("verify-checksum")
    verify_checksum.add_argument("--file", type=Path, required=True)
    verify_checksum.add_argument("--checksum", type=Path, required=True)

    source = subparsers.add_parser("build-source-bundle")
    source.add_argument("--repository", type=Path, default=Path.cwd())
    source.add_argument("--commit", required=True)
    source.add_argument("--version", required=True)
    source.add_argument("--output", type=Path, required=True)

    descriptor = subparsers.add_parser("build-descriptor")
    descriptor.add_argument("--commit", required=True)
    descriptor.add_argument("--version", required=True)
    descriptor.add_argument("--platform", choices=("macos", "windows"), required=True)
    descriptor.add_argument("--arch", choices=("arm64", "x86_64"), required=True)
    descriptor.add_argument("--executable", type=Path, required=True)
    descriptor.add_argument("--source-bundle", type=Path, required=True)
    descriptor.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "verify-version":
            version = verify_installed_version(args.tag)
            print(f"release version verified: {version}")
        elif args.command == "validate-capabilities":
            validate_frozen_capabilities(args.executable)
            print("frozen protocol capabilities verified")
        elif args.command == "checksum":
            write_sha256_sidecar(args.file)
        elif args.command == "verify-checksum":
            verify_sha256_sidecar(args.file, args.checksum)
        elif args.command == "build-source-bundle":
            build_source_bundle(
                repository=args.repository,
                commit=args.commit,
                version=args.version,
                output=args.output,
            )
        else:
            build_artifact_descriptor(
                commit=args.commit,
                version=args.version,
                target_platform=args.platform,
                target_arch=args.arch,
                executable=args.executable,
                source_bundle=args.source_bundle,
                output=args.output,
            )
    except ReleaseMetadataError as exc:
        print(f"release metadata error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
