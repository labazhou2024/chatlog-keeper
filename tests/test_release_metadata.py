from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "chatlog_keeper_release_metadata",
    ROOT / "packaging" / "release_metadata.py",
)
assert SPEC is not None and SPEC.loader is not None
release_metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_metadata)


def test_version_contract_requires_tag_module_and_installed_metadata_agreement() -> None:
    assert release_metadata.validate_version_contract(
        tag="v0.3.3",
        module_version="0.3.3",
        metadata_version="0.3.3",
    ) == "0.3.3"

    with pytest.raises(release_metadata.ReleaseMetadataError, match="differ"):
        release_metadata.validate_version_contract(
            tag="v0.3.3",
            module_version="0.3.3",
            metadata_version="0.3.2",
        )


def _message_capability() -> dict:
    return {
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


def _participant_capability() -> dict:
    return {
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


def test_frozen_capability_validator_executes_both_exact_no_input_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "chatlog-keeper"
    executable.write_bytes(b"frozen fixture")
    calls: list[tuple[str, ...]] = []

    def fake_run(argv, **kwargs):
        calls.append(tuple(str(item) for item in argv))
        assert kwargs["stdin"] is subprocess.DEVNULL
        protocol = argv[1]
        payload = _message_capability() if protocol == "message-stream-v1" else _participant_capability()
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n",
            stderr=b"",
        )

    monkeypatch.setattr(release_metadata.subprocess, "run", fake_run)

    release_metadata.validate_frozen_capabilities(executable)

    assert calls == [
        (str(executable), "message-stream-v1", "--capabilities"),
        (str(executable), "participant-directory-v1", "--capabilities"),
    ]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(protocol="message-stream-v2"), "identity"),
        (lambda value: value.update(version=True), "identity"),
        (lambda value: value.update(sources=["wechat"]), "identity"),
        (lambda value: value.update(ordering="rowid"), "identity"),
        (lambda value: value.update(checkpoint="at_end"), "identity"),
        (lambda value: value["frames"].reverse(), "identity"),
        (lambda value: value["limits"].update(max_page_size=999), "identity"),
        (lambda value: value["limits"].update(max_page_size=1_000.0), "identity"),
        (lambda value: value.update(extra=True), "fields"),
    ],
)
def test_message_capability_validator_fails_closed_on_identity_or_schema_drift(
    mutate,
    message: str,
) -> None:
    payload = _message_capability()
    mutate(payload)
    with pytest.raises(release_metadata.ReleaseMetadataError, match=message):
        release_metadata.validate_message_stream_capability(payload)


def test_capability_json_decoder_rejects_appended_process_output() -> None:
    raw = json.dumps(_message_capability()).encode("utf-8") + b"\ntraceback"
    with pytest.raises(release_metadata.ReleaseMetadataError, match="one JSON object"):
        release_metadata._decode_one_json_object(raw)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(protocol="participant-directory-v2"),
        lambda value: value.update(version=True),
        lambda value: value.update(sources=["qq"]),
        lambda value: value["views"].reverse(),
        lambda value: value["limits"].update(max_participants=49_999),
        lambda value: value["limits"].update(max_participants=50_000.0),
    ],
)
def test_participant_capability_validator_fails_closed_on_any_drift(mutate) -> None:
    payload = _participant_capability()
    mutate(payload)
    with pytest.raises(release_metadata.ReleaseMetadataError, match="identity"):
        release_metadata.validate_participant_directory_capability(payload)


def _windows_executable() -> bytes:
    payload = bytearray(512)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    payload[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", payload, 0x84, 0x8664)
    struct.pack_into("<H", payload, 0x98, 0x020B)
    return bytes(payload)


def _macos_executable() -> bytes:
    return struct.pack("<II", 0xFEEDFACF, 0x0100000C) + bytes(504)


@pytest.mark.parametrize(
    ("platform", "arch", "name", "payload", "offset", "replacement", "message"),
    [
        (
            "windows",
            "x86_64",
            "chatlog-keeper.exe",
            _windows_executable(),
            0x84,
            struct.pack("<H", 0x014C),
            "PE32\\+ AMD64",
        ),
        (
            "windows",
            "x86_64",
            "chatlog-keeper.exe",
            _windows_executable(),
            0x98,
            struct.pack("<H", 0x010B),
            "PE32\\+ AMD64",
        ),
        (
            "macos",
            "arm64",
            "chatlog-keeper-macos-arm64",
            _macos_executable(),
            4,
            struct.pack("<I", 0x01000007),
            "Mach-O 64 arm64",
        ),
        (
            "macos",
            "arm64",
            "chatlog-keeper-macos-arm64",
            _macos_executable(),
            0,
            bytes(4),
            "Mach-O 64 arm64",
        ),
    ],
)
def test_executable_header_gate_rejects_architecture_or_format_spoofing(
    tmp_path: Path,
    platform: str,
    arch: str,
    name: str,
    payload: bytes,
    offset: int,
    replacement: bytes,
    message: str,
) -> None:
    tampered = bytearray(payload)
    tampered[offset : offset + len(replacement)] = replacement
    executable = tmp_path / name
    executable.write_bytes(tampered)

    with pytest.raises(release_metadata.ReleaseMetadataError, match=message):
        release_metadata.validate_executable_header(
            executable,
            target_platform=platform,
            target_arch=arch,
        )


def test_descriptor_is_canonical_and_binds_both_artifacts_to_one_source_bundle(
    tmp_path: Path,
) -> None:
    version = "0.3.1"
    commit = "1" * 40
    source_bundle = tmp_path / f"chatlog-keeper-v{version}-source.tar.gz"
    source_bundle.write_bytes(b"canonical source bundle")
    windows = tmp_path / "chatlog-keeper.exe"
    macos = tmp_path / "chatlog-keeper-macos-arm64"
    windows.write_bytes(_windows_executable())
    macos.write_bytes(_macos_executable())
    windows_descriptor = tmp_path / (
        f"chatlog-keeper-v{version}-windows-x86_64.artifact.json"
    )
    macos_descriptor = tmp_path / f"chatlog-keeper-v{version}-macos-arm64.artifact.json"

    release_metadata.build_artifact_descriptor(
        commit=commit,
        version=version,
        target_platform="windows",
        target_arch="x86_64",
        executable=windows,
        source_bundle=source_bundle,
        output=windows_descriptor,
    )
    release_metadata.build_artifact_descriptor(
        commit=commit,
        version=version,
        target_platform="macos",
        target_arch="arm64",
        executable=macos,
        source_bundle=source_bundle,
        output=macos_descriptor,
    )

    windows_payload = json.loads(windows_descriptor.read_text(encoding="utf-8"))
    macos_payload = json.loads(macos_descriptor.read_text(encoding="utf-8"))
    assert windows_descriptor.read_bytes() == release_metadata._canonical_json(windows_payload)
    assert macos_descriptor.read_bytes() == release_metadata._canonical_json(macos_payload)
    assert windows_payload == {
        "approved": True,
        "commit": commit,
        "executable": "chatlog-keeper.exe",
        "kind": "chatlog_keeper",
        "protocol_capabilities": [
            "message-stream-v1",
            "participant-directory-v1",
        ],
        "schema": "memexa.approved_artifact_descriptor.v2",
        "sha256": hashlib.sha256(windows.read_bytes()).hexdigest(),
        "size_bytes": windows.stat().st_size,
        "source_bundle": source_bundle.name,
        "source_bundle_sha256": hashlib.sha256(source_bundle.read_bytes()).hexdigest(),
        "target_arch": "x86_64",
        "target_platform": "windows",
        "version": version,
    }
    assert macos_payload["source_bundle"] == windows_payload["source_bundle"]
    assert macos_payload["source_bundle_sha256"] == windows_payload["source_bundle_sha256"]
    assert macos_payload["commit"] == windows_payload["commit"]
    assert macos_payload["protocol_capabilities"] == windows_payload["protocol_capabilities"]
    release_metadata.verify_sha256_sidecar(
        windows_descriptor,
        windows_descriptor.with_name(windows_descriptor.name + ".sha256"),
    )
    release_metadata.verify_sha256_sidecar(
        macos_descriptor,
        macos_descriptor.with_name(macos_descriptor.name + ".sha256"),
    )


def _git(repository: Path, *args: str, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    return completed.stdout.strip()


def test_source_bundle_is_deterministic_and_contains_only_the_frozen_commit(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")
    (repository / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (repository / "tracked.txt").write_text("frozen\n", encoding="utf-8")
    (repository / "ignored.txt").write_text("private working tree value\n", encoding="utf-8")
    _git(repository, "add", ".gitignore", "tracked.txt")
    fixed_env = dict(release_metadata.os.environ)
    fixed_env.update(
        {
            "GIT_AUTHOR_DATE": "2026-08-07T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-08-07T00:00:00+00:00",
        }
    )
    _git(repository, "commit", "--quiet", "-m", "frozen", env=fixed_env)
    commit = _git(repository, "rev-parse", "HEAD")
    first = tmp_path / "first" / "chatlog-keeper-v0.3.1-source.tar.gz"
    second = tmp_path / "second" / "chatlog-keeper-v0.3.1-source.tar.gz"

    release_metadata.build_source_bundle(
        repository=repository,
        commit=commit,
        version="0.3.1",
        output=first,
    )
    release_metadata.build_source_bundle(
        repository=repository,
        commit=commit,
        version="0.3.1",
        output=second,
    )

    assert first.read_bytes() == second.read_bytes()
    assert first.with_name(first.name + ".sha256").read_text(encoding="ascii") == (
        f"{hashlib.sha256(first.read_bytes()).hexdigest()}  {first.name}\n"
    )
    with tarfile.open(first, mode="r:gz") as archive:
        names = archive.getnames()
    assert names == [
        "chatlog-keeper-v0.3.1",
        "chatlog-keeper-v0.3.1/.gitignore",
        "chatlog-keeper-v0.3.1/tracked.txt",
    ]
    assert not any("ignored.txt" == Path(name).name for name in names)
