"""Private key-recovery-v1 lifecycle and non-disclosure contracts."""

from __future__ import annotations

import ctypes
import io
import json
import os
import stat
import sys
from ctypes import wintypes
from pathlib import Path
from types import SimpleNamespace

import pytest

from chatlog_keeper import cli, key_recovery_protocol as protocol
from chatlog_keeper.core import _private_temp
from chatlog_keeper.core._secrets import write_secret_text


def _request(operation_id: str, *, confirmed: bool = True, timeout: int = 60) -> str:
    return json.dumps(
        {
            "schema": protocol.REQUEST_SCHEMA,
            "operation_id": operation_id,
            "timeout_seconds": timeout,
            "confirmed": confirmed,
        }
    )


@pytest.fixture
def private_runtime(monkeypatch, tmp_path):
    root = tmp_path / "private-machine-state"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(protocol, "_machine_recovery_root", lambda: root)
    monkeypatch.setattr(cli, "scavenge_private_temp_dirs", lambda _prefixes: 0)
    return root


def test_request_is_bounded_exact_and_rejects_duplicates():
    operation_id = "a" * 64
    request = protocol.read_request(io.StringIO(_request(operation_id)))
    assert request == protocol.KeyRecoveryRequest(operation_id, 60, True)

    duplicate = (
        '{"schema":"%s","operation_id":"%s","operation_id":"%s",'
        '"timeout_seconds":60,"confirmed":true}'
        % (protocol.REQUEST_SCHEMA, operation_id, operation_id)
    )
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="invalid_request"):
        protocol.read_request(io.StringIO(duplicate))
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="invalid_request"):
        protocol.read_request(io.StringIO(_request("predictable-id")))
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="invalid_request"):
        protocol.read_request(io.StringIO("{" + "x" * 1100))


def test_status_is_atomic_private_bounded_and_keeps_verifiable_history(
    private_runtime,
):
    operation_id = "b" * 64
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.client_opened()
    session.emit("verified")

    operation_dir = protocol.operation_directory(operation_id)
    status_path = operation_dir / "status.json"
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert set(payload) == {
        "schema",
        "operation_id",
        "sequence",
        "phase",
        "terminal",
        "error_code",
        "elapsed_ms",
        "lease_state",
        "events",
    }
    assert payload["schema"] == protocol.STATUS_SCHEMA
    assert payload["operation_id"] == operation_id
    assert payload["phase"] == "verified"
    assert payload["terminal"] is True
    assert [event["phase"] for event in payload["events"]] == [
        "preparing",
        "client_open",
        "waiting_key",
        "verified",
    ]
    for event in payload["events"]:
        assert set(event) == {
            "sequence",
            "phase",
            "terminal",
            "error_code",
            "elapsed_ms",
        }
    serialized = status_path.read_text(encoding="utf-8")
    assert "wxid_" not in serialized
    assert "message_0.db" not in serialized
    assert len(serialized.encode("utf-8")) < 4096
    assert not list(operation_dir.glob(".status.json.*"))
    if os.name != "nt":
        assert stat.S_IMODE(operation_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(status_path.stat().st_mode) == 0o600
        assert stat.S_IMODE((operation_dir / "cancel.json").stat().st_mode) == 0o600


def test_operation_id_is_non_replayable(private_runtime):
    request = protocol.KeyRecoveryRequest("c" * 64, 60, True)
    first = protocol.KeyRecoverySession(request, source="wechat")
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="operation_exists"):
        protocol.KeyRecoverySession(request, source="qq")
    first.release_active_lease()


def test_cancel_file_requires_exact_private_schema(private_runtime):
    operation_id = "d" * 64
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    cancel_path = protocol.operation_directory(operation_id) / "cancel.json"
    assert write_secret_text(
        cancel_path,
        json.dumps(
            {
                "schema": protocol.CANCEL_SCHEMA,
                "operation_id": "e" * 64,
                "cancel": True,
            }
        ),
    )
    assert session.cancel_requested() is False
    assert write_secret_text(
        cancel_path,
        json.dumps(
            {
                "schema": protocol.CANCEL_SCHEMA,
                "operation_id": operation_id,
                "cancel": True,
            }
        ),
    )
    assert session.cancel_requested() is True
    assert session.cancel_reason == "cancelled"


def test_cancel_reader_rejects_symlink(private_runtime, tmp_path):
    operation_id = "e" * 64
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    cancel_path = protocol.operation_directory(operation_id) / "cancel.json"
    external = tmp_path / "external-cancel.json"
    external.write_text(
        json.dumps(
            {
                "schema": protocol.CANCEL_SCHEMA,
                "operation_id": operation_id,
                "cancel": True,
            }
        ),
        encoding="utf-8",
    )
    cancel_path.unlink()
    try:
        cancel_path.symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    assert session.cancel_requested() is False


def test_deadline_is_monotonic_and_terminal_error_is_exact(private_runtime):
    operation_id = "f" * 64
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 1, True),
        source="wechat",
    )
    session.emit("preparing")
    session._deadline = protocol.time.monotonic() - 1
    assert session.cancel_requested() is True
    assert session.cancel_reason == "timed_out"
    session.terminal_error(session.cancel_reason)
    payload = json.loads(
        (protocol.operation_directory(operation_id) / "status.json").read_text(
            encoding="utf-8"
        )
    )
    assert payload["phase"] == "terminal_error"
    assert payload["error_code"] == "timed_out"
    assert payload["terminal"] is True


def test_private_cli_success_exposes_only_whitelisted_result_and_phases(
    monkeypatch,
    private_runtime,
    tmp_path,
    capsys,
):
    operation_id = "1" * 64
    database = tmp_path / "wxid_private" / "message_0.db"
    database.parent.mkdir()
    database.write_bytes(b"page")
    key = bytes(range(32))
    saved_path = tmp_path / "secrets" / "wxid_private.key"
    seen = {}

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(_request(operation_id)))
    monkeypatch.setattr(cli.wechat_db, "_get_weixin_pids", lambda: [])
    monkeypatch.setattr(cli, "_wechat_message_db_for_active", lambda _root: str(database))
    monkeypatch.setattr(cli, "_wechat_key_target_snapshots", lambda _root: (object(),))

    def extract(**kwargs):
        seen.update(kwargs)
        kwargs["_recovery_notify"]()
        return key

    monkeypatch.setattr(cli.active_key, "extract_wechat_key_active", extract)
    monkeypatch.setattr(
        cli.wechat_key_identity,
        "matching_target",
        lambda _key, _snapshots: SimpleNamespace(
            path=database,
            account_id="wxid_private",
        ),
    )
    monkeypatch.setattr(
        cli.wechat_key_identity,
        "save_for_target",
        lambda _key, _target, _snapshots: ("ok", saved_path),
    )

    exit_code = cli.main(
        [
            "extract-key",
            "--source",
            "wechat",
            "--method",
            "active",
            "--key-recovery-v1-stdin",
        ]
    )

    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert exit_code == 0
    assert result == {
        "schema": protocol.RESULT_SCHEMA,
        "operation_id": operation_id,
        "ok": True,
        "terminal": True,
        "error_code": None,
    }
    assert captured.err == ""
    forbidden = [str(tmp_path), "wxid_private", key.hex(), "message_0.db"]
    assert not any(value in captured.out or value in captured.err for value in forbidden)
    assert seen["_require_closed_client"] is True
    assert callable(seen["_cancel_requested"])
    status = json.loads(
        (protocol.operation_directory(operation_id) / "status.json").read_text(
            encoding="utf-8"
        )
    )
    assert [item["phase"] for item in status["events"]] == [
        "preparing",
        "client_open",
        "waiting_key",
        "verified",
    ]


def test_private_cli_requires_confirmation_before_any_helper_launch(
    monkeypatch,
    private_runtime,
    capsys,
):
    operation_id = "2" * 64
    monkeypatch.setattr(
        cli.sys,
        "stdin",
        io.StringIO(_request(operation_id, confirmed=False)),
    )
    monkeypatch.setattr(
        cli.active_key,
        "extract_wechat_key_active",
        lambda **_kwargs: pytest.fail("unconfirmed recovery launched a helper"),
    )

    exit_code = cli.main(
        [
            "extract-key",
            "--source",
            "wechat",
            "--method",
            "active",
            "--key-recovery-v1-stdin",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert result["error_code"] == "confirmation_required"
    status = json.loads(
        (protocol.operation_directory(operation_id) / "status.json").read_text(
            encoding="utf-8"
        )
    )
    assert status["phase"] == "terminal_error"
    assert status["error_code"] == "confirmation_required"


def test_private_cli_never_kills_or_launches_while_daily_client_is_running(
    monkeypatch,
    private_runtime,
    capsys,
):
    operation_id = "3" * 64
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(_request(operation_id)))
    monkeypatch.setattr(cli.wechat_db, "_get_weixin_pids", lambda: [1234])
    monkeypatch.setattr(
        cli.active_key,
        "extract_wechat_key_active",
        lambda **_kwargs: pytest.fail("running daily client was disturbed"),
    )

    exit_code = cli.main(
        [
            "extract-key",
            "--source",
            "wechat",
            "--method",
            "active",
            "--key-recovery-v1-stdin",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert result["error_code"] == "client_running"
    status = json.loads(
        (protocol.operation_directory(operation_id) / "status.json").read_text(
            encoding="utf-8"
        )
    )
    assert [item["phase"] for item in status["events"]] == [
        "preparing",
        "terminal_error",
    ]


def test_windows_scripts_have_non_killing_private_preflight_and_open_marker():
    scripts = (
        Path(cli.active_key.__file__).parent / "scripts" / "windows_ntqq_get_key.ps1",
        Path(cli.active_key.__file__).parent / "scripts" / "windows_wechat_get_key.ps1",
    )
    for script in scripts:
        text = script.read_text(encoding="utf-8-sig")
        assert "RequireClosedClient" in text
        assert "CHATLOG_KEY_RECOVERY_CLIENT_OPEN_V1" in text
        assert "$KillExisting -and -not $RequireClosedClient" in text


def test_capabilities_and_control_request_are_exact_path_free(private_runtime):
    capabilities = protocol.capabilities_payload()
    assert capabilities == {
        "schema": protocol.CAPABILITIES_SCHEMA,
        "version": 1,
        "operation_id_format": "lowercase-hex-64",
        "actions": ["start", "status", "cancel", "cleanup"],
        "phases": sorted(protocol._PHASES),
        "error_codes": sorted(protocol._ERROR_CODES),
        "terminal_phases": sorted(protocol._TERMINAL_PHASES),
    }
    operation_id = "4" * 64
    parsed = protocol.read_control_request(
        io.StringIO(
            json.dumps(
                {
                    "schema": protocol.CONTROL_REQUEST_SCHEMA,
                    "operation_id": operation_id,
                }
            )
        )
    )
    assert parsed.operation_id == operation_id
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="invalid_request"):
        protocol.read_control_request(
            io.StringIO(
                json.dumps(
                    {
                        "schema": protocol.CONTROL_REQUEST_SCHEMA,
                        "operation_id": operation_id,
                        "path": "/private/database",
                    }
                )
            )
        )


def test_machine_journal_cannot_fork_with_data_dir_override(
    monkeypatch,
    private_runtime,
):
    operation_id = "5" * 64
    first = protocol.operation_directory(operation_id)
    monkeypatch.setenv("CHATLOG_KEEPER_DATA_DIR", "/tmp/attacker-selected-root")
    second = protocol.operation_directory(operation_id)
    assert first == second == private_runtime / "operations" / operation_id


def test_source_lease_serializes_across_config_overrides(
    monkeypatch,
    private_runtime,
):
    first = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest("6" * 64, 60, True),
        source="wechat",
    )
    monkeypatch.setenv("CHATLOG_KEEPER_DATA_DIR", "/tmp/a-second-config-root")
    with pytest.raises(
        protocol.KeyRecoveryProtocolError,
        match="active_operation_exists",
    ):
        protocol.KeyRecoverySession(
            protocol.KeyRecoveryRequest("7" * 64, 60, True),
            source="wechat",
        )
    first.release_active_lease()


def test_damaged_status_after_owner_crash_recovers_and_deletes_key_transcript(
    private_runtime,
    tmp_path,
):
    operation_id = "8" * 64
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    transcript_dir = _private_temp.create_private_temp_dir("chatlog_active_")
    transcript = transcript_dir / "result-secret.txt"
    transcript.write_text("master key: 001122-secret", encoding="utf-8")
    transcript.chmod(0o600)
    identity = transcript_dir.lstat()
    session.record_private_temp(
        {
            "path": str(transcript_dir),
            "device": identity.st_dev,
            "inode": identity.st_ino,
            "owner_pid": os.getpid(),
        }
    )
    status_path = protocol.operation_directory(operation_id) / "status.json"
    assert write_secret_text(status_path, "damaged\n")
    session.release_active_lease()  # deterministic stand-in for owner SIGKILL

    recovered = protocol.status_operation(operation_id)

    assert recovered["phase"] == "terminal_error"
    assert recovered["error_code"] == "owner_lost"
    assert recovered["lease_state"] == "terminal"
    assert not transcript_dir.exists()
    assert "secret" not in json.dumps(recovered)


def test_status_does_not_repair_or_delete_a_live_owners_damaged_journal(
    private_runtime,
):
    operation_id = "9" * 64
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    status_path = protocol.operation_directory(operation_id) / "status.json"
    assert write_secret_text(status_path, "damaged\n")

    with pytest.raises(protocol.KeyRecoveryProtocolError, match="status_unavailable"):
        protocol.status_operation(operation_id)
    assert status_path.exists()
    session.release_active_lease()


def test_crashed_nonterminal_operation_becomes_owner_lost_then_cleans_up(
    private_runtime,
):
    operation_id = "0" * 64
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="qq",
    )
    session.emit("preparing")
    session.release_active_lease()

    status = protocol.status_operation(operation_id)
    assert status["terminal"] is True
    assert status["error_code"] == "owner_lost"
    result = protocol.cleanup_operation(operation_id)
    assert result == protocol.control_result(
        operation_id,
        action="cleanup",
        ok=True,
        terminal=True,
        error_code=None,
        lease_state="terminal",
    )
    assert not protocol.operation_directory(operation_id).exists()
    assert protocol._owner_payload("qq") is None
    assert protocol.status_operation(operation_id)["error_code"] == "owner_lost"
    assert protocol.cleanup_operation(operation_id) == result


def test_cleanup_receipt_survives_crash_after_owner_and_metadata_delete(
    monkeypatch,
    private_runtime,
):
    operation_id = "d" * 63 + "1"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.terminal_error("verification_failed")
    session.release_active_lease()
    real_remove = protocol._remove_operation_directory_locked

    def crash_after_commit(op_id, source, *, remove_owner):
        assert op_id == operation_id
        assert source == "wechat"
        assert remove_owner is True
        protocol._unlink_private_regular(protocol._source_owner_path(source))
        protocol._unlink_private_regular(
            protocol.operation_directory(op_id) / "metadata.json"
        )
        raise protocol.KeyRecoveryProtocolError("cleanup_failed")

    monkeypatch.setattr(
        protocol,
        "_remove_operation_directory_locked",
        crash_after_commit,
    )
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="cleanup_failed"):
        protocol.cleanup_operation(operation_id)
    receipt = protocol._cleanup_receipt_payload(operation_id)
    assert receipt is not None
    assert receipt["status"]["error_code"] == "verification_failed"

    monkeypatch.setattr(protocol, "_remove_operation_directory_locked", real_remove)
    retry = protocol.cleanup_operation(operation_id)
    assert retry["ok"] is True
    assert retry["error_code"] is None
    assert not protocol.operation_directory(operation_id).exists()
    assert protocol.cleanup_operation(operation_id) == retry


def test_never_existing_operation_is_distinct_from_cleaned_receipt(private_runtime):
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="not_found"):
        protocol.cleanup_operation("e" * 63 + "1")


def test_cancel_exact_orphan_helper_then_terminalizes(monkeypatch, private_runtime):
    operation_id = "a" * 63 + "1"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.release_active_lease()
    active = {"value": True}
    monkeypatch.setattr(
        protocol,
        "_windows_job_is_active",
        lambda _operation_id: active["value"],
    )

    def terminate(_operation_id):
        active["value"] = False
        return True

    monkeypatch.setattr(protocol, "_terminate_windows_job", terminate)
    result = protocol.cancel_operation(operation_id)
    assert result["ok"] is True
    assert result["terminal"] is True
    assert result["error_code"] is None
    assert protocol.status_operation(operation_id)["error_code"] == "cancelled"


def test_terminal_retention_removes_exact_old_owner_and_operation(
    private_runtime,
):
    operation_id = "b" * 63 + "1"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.terminal_error("verification_failed")
    session.release_active_lease()
    metadata_path = protocol.operation_directory(operation_id) / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["started_at_unix_ms"] = 1
    assert write_secret_text(
        metadata_path,
        json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
    )

    removed = protocol.prune_expired_operations(
        now_unix_ms=(protocol._TERMINAL_RETENTION_SECONDS + 1) * 1000,
    )

    assert removed == 1
    assert not protocol.operation_directory(operation_id).exists()
    assert protocol._owner_payload("wechat") is None
    assert protocol.status_operation(operation_id)["error_code"] == "verification_failed"
    assert protocol.cleanup_operation(operation_id)["ok"] is True


def test_cleanup_receipt_reuse_requires_exact_source_and_status(private_runtime):
    operation_id = "b" * 63 + "2"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.terminal_error("verification_failed")
    status = protocol._validated_status_payload(operation_id)
    session.release_active_lease()

    first = protocol._write_cleanup_receipt(operation_id, "wechat", status)
    assert protocol._write_cleanup_receipt(operation_id, "wechat", status) == first
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="status_unavailable"):
        protocol._write_cleanup_receipt(operation_id, "qq", status)

    changed = json.loads(json.dumps(status))
    changed["error_code"] = "cancelled"
    changed["events"][-1]["error_code"] = "cancelled"
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="status_unavailable"):
        protocol._write_cleanup_receipt(operation_id, "wechat", changed)


@pytest.mark.parametrize(
    ("terminal_phase", "terminal_error"),
    [
        ("verified", None),
        ("terminal_error", "verification_failed"),
        ("terminal_error", "cancelled"),
    ],
)
def test_repeat_controls_keep_action_success_separate_from_terminal_outcome(
    private_runtime,
    terminal_phase,
    terminal_error,
):
    suffix = {
        ("verified", None): "3",
        ("terminal_error", "verification_failed"): "4",
        ("terminal_error", "cancelled"): "5",
    }[(terminal_phase, terminal_error)]
    operation_id = "b" * 63 + suffix
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.emit(terminal_phase, error_code=terminal_error)
    session.release_active_lease()
    protocol.cleanup_operation(operation_id)

    repeated_status = protocol.status_operation(operation_id)
    assert repeated_status["phase"] == terminal_phase
    assert repeated_status["error_code"] == terminal_error
    repeated_cancel = protocol.cancel_operation(operation_id)
    repeated_cleanup = protocol.cleanup_operation(operation_id)
    for action_result in (repeated_cancel, repeated_cleanup):
        assert action_result["ok"] is True
        assert action_result["terminal"] is True
        assert action_result["error_code"] is None


def test_cancel_terminal_error_while_owner_lease_is_still_held(private_runtime):
    operation_id = "b" * 63 + "6"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.terminal_error("verification_failed")

    result = protocol.cancel_operation(operation_id)
    assert result == protocol.control_result(
        operation_id,
        action="cancel",
        ok=True,
        terminal=True,
        error_code=None,
        lease_state="held",
    )
    session.release_active_lease()


@pytest.mark.parametrize("offline_seconds", [2 * 60 * 60, 30 * 24 * 60 * 60])
def test_owner_lost_elapsed_supports_long_offline_recovery(
    private_runtime,
    offline_seconds,
):
    operation_id = ("b" * 62) + ("7" if offline_seconds < 86400 else "8") + "1"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    metadata_path = protocol.operation_directory(operation_id) / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["started_at_unix_ms"] = int(protocol.time.time() * 1000) - (
        offline_seconds * 1000
    )
    assert write_secret_text(
        metadata_path,
        json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
    )
    session.release_active_lease()

    recovered = protocol.status_operation(operation_id)
    assert recovered["error_code"] == "owner_lost"
    assert offline_seconds * 1000 <= recovered["elapsed_ms"] <= (
        offline_seconds * 1000 + 2000
    )
    assert recovered["elapsed_ms"] <= protocol._MAX_ELAPSED_MS


@pytest.mark.parametrize("invalid_elapsed", [-1, 1 << 53])
def test_status_rejects_elapsed_outside_json_safe_range(
    private_runtime,
    invalid_elapsed,
):
    operation_id = "b" * 63 + "9"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    status_path = protocol.operation_directory(operation_id) / "status.json"
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    payload["elapsed_ms"] = invalid_elapsed
    payload["events"][-1]["elapsed_ms"] = invalid_elapsed
    assert write_secret_text(
        status_path,
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    )
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="status_unavailable"):
        protocol._validated_status_payload(operation_id)
    session.release_active_lease()


def test_control_cli_not_found_echoes_only_valid_operation_id(
    monkeypatch,
    private_runtime,
    capsys,
):
    operation_id = "c" * 63 + "1"
    monkeypatch.setattr(
        cli.sys,
        "stdin",
        io.StringIO(
            json.dumps(
                {
                    "schema": protocol.CONTROL_REQUEST_SCHEMA,
                    "operation_id": operation_id,
                }
            )
        ),
    )
    exit_code = cli.main(
        ["key-recovery-v1", "--request-stdin", "--action", "status"]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload == protocol.control_result(
        operation_id,
        action="status",
        ok=False,
        terminal=False,
        error_code="not_found",
        lease_state=None,
    )


def test_windows_artifact_validation_never_calls_posix_geteuid(
    monkeypatch,
    tmp_path,
):
    artifact = tmp_path / "capture.bin"
    artifact.write_bytes(b"x")
    value = artifact.lstat()
    item = {
        "path": str(artifact),
        "kind": "file",
        "mode": 0o700,
        "device": value.st_dev,
        "inode": value.st_ino,
    }
    monkeypatch.setattr(protocol, "_windows_acl_is_private", lambda _path: True)
    monkeypatch.setattr(
        protocol.os,
        "geteuid",
        lambda: pytest.fail("Windows artifact cleanup called os.geteuid"),
    )
    assert protocol._recorded_artifact_is_safe(
        artifact,
        value,
        item,
        _windows=True,
    )


def test_windows_job_is_created_atomically_before_resume_and_uses_kill_on_close():
    source = Path(cli.active_key.__file__).read_text(encoding="utf-8")
    job_attribute = source.index("0x0002000D")
    create_process = source.index("kernel32.CreateProcessW(", job_attribute)
    resume = source.index("process.resume()", create_process)
    assert job_attribute < create_process < resume
    assert "recovery_job.assign(process)" not in source
    assert "EXTENDED_STARTUPINFO_PRESENT" in source
    assert "PROC_THREAD_ATTRIBUTE_JOB_LIST" in source
    assert "CREATE_SUSPENDED" in source
    assert "limits.BasicLimitInformation.LimitFlags = 0x00002000" in source


class _FakeWinCall:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class _FakeJobKernel:
    def __init__(self, fail_stage=None):
        self.fail_stage = fail_stage
        self.error = 50 if fail_stage == "job_attribute" else 5
        self.events = []
        self.closed = []
        self.InitializeProcThreadAttributeList = _FakeWinCall(
            self._initialize_attributes
        )
        self.UpdateProcThreadAttribute = _FakeWinCall(self._update_attribute)
        self.DeleteProcThreadAttributeList = _FakeWinCall(self._delete_attributes)
        self.CreateFileW = _FakeWinCall(self._create_file)
        self.CreateProcessW = _FakeWinCall(self._create_process)
        self.CloseHandle = _FakeWinCall(self._close_handle)
        self.GetLastError = _FakeWinCall(lambda: self.error)
        self.ResumeThread = _FakeWinCall(self._resume_thread)
        self.WaitForSingleObject = _FakeWinCall(lambda *_args: 0x00000102)
        self.GetExitCodeProcess = _FakeWinCall(lambda *_args: 1)
        self.TerminateProcess = _FakeWinCall(lambda *_args: 1)
        self.TerminateJobObject = _FakeWinCall(self._terminate_job)

    def _initialize_attributes(self, attribute_list, _count, _flags, size):
        self.events.append("initialize")
        if attribute_list is None:
            size._obj.value = 256
            return 0
        return 0 if self.fail_stage == "initialize" else 1

    def _update_attribute(
        self,
        _attribute_list,
        _flags,
        attribute,
        _value,
        _size,
        _previous,
        _return_size,
    ):
        self.events.append(f"attribute:{attribute:#x}")
        if self.fail_stage == "job_attribute" and attribute == 0x0002000D:
            return 0
        if self.fail_stage == "handle_attribute" and attribute == 0x00020002:
            return 0
        return 1

    def _delete_attributes(self, _attribute_list):
        self.events.append("delete")

    def _create_file(self, *_args):
        self.events.append("nul")
        return 77

    def _create_process(
        self,
        application_name,
        _command_line,
        _process_security,
        _thread_security,
        inherit_handles,
        creation_flags,
        _environment,
        _current_directory,
        _startup,
        process_info,
    ):
        self.events.append("create")
        self.application_name = application_name
        self.inherit_handles = inherit_handles
        self.creation_flags = creation_flags
        if self.fail_stage == "create":
            return 0
        process_info._obj.hProcess = 101
        process_info._obj.hThread = 102
        process_info._obj.dwProcessId = 103
        process_info._obj.dwThreadId = 104
        return 1

    def _resume_thread(self, _thread):
        self.events.append("resume")
        return 0xFFFFFFFF if self.fail_stage == "resume" else 1

    def _terminate_job(self, _job, _exit_code):
        self.events.append("terminate-job")
        self.WaitForSingleObject = _FakeWinCall(lambda *_args: 0)
        return 1

    def _close_handle(self, handle):
        self.closed.append(int(handle))
        return 1


def _fake_windows_job(kernel):
    job = cli.active_key._WindowsRecoveryJob.__new__(
        cli.active_key._WindowsRecoveryJob
    )
    job._ctypes = ctypes
    job._wintypes = wintypes
    job._kernel32 = kernel
    job.handle = 55
    return job


@pytest.mark.parametrize(
    "stage",
    ["initialize", "job_attribute", "handle_attribute", "create"],
)
def test_windows_atomic_create_failures_never_return_an_unbound_process(stage):
    kernel = _FakeJobKernel(stage)
    job = _fake_windows_job(kernel)
    with pytest.raises(OSError):
        job.create_suspended_process(
            [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile"],
            env={"SYSTEMROOT": r"C:\Windows"},
        )
    assert "resume" not in kernel.events
    assert "create" not in kernel.events or stage == "create"
    if "nul" in kernel.events:
        assert 77 in kernel.closed
    if stage != "initialize":
        assert "delete" in kernel.events


def test_windows_atomic_create_binds_job_and_handle_lists_before_create():
    kernel = _FakeJobKernel()
    process = _fake_windows_job(kernel).create_suspended_process(
        [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile"],
        env={"SYSTEMROOT": r"C:\Windows"},
    )
    assert kernel.events.index("attribute:0x2000d") < kernel.events.index("create")
    assert kernel.events.index("attribute:0x20002") < kernel.events.index("create")
    assert kernel.inherit_handles is True
    assert kernel.creation_flags & 0x00000004
    assert kernel.creation_flags & 0x00080000
    assert kernel.application_name.endswith(r"WindowsPowerShell\v1.0\powershell.exe")
    assert 77 in kernel.closed
    process.resume()
    assert 102 in kernel.closed
    process.close()
    assert 101 in kernel.closed


def test_windows_resume_failure_closes_primary_thread_and_stays_suspended():
    kernel = _FakeJobKernel("resume")
    process = _fake_windows_job(kernel).create_suspended_process(
        [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"],
        env={"SYSTEMROOT": r"C:\Windows"},
    )
    with pytest.raises(OSError, match="ResumeThread"):
        process.resume()
    assert 102 in kernel.closed
    cli.active_key._abort_windows_recovery_process(
        process,
        _fake_windows_job(kernel),
    )
    assert {55, 77, 101, 102}.issubset(set(kernel.closed))
    assert "delete" in kernel.events
    assert "terminate-job" in kernel.events


def test_windows_process_wrapper_constructor_failure_closes_raw_handles(
    monkeypatch,
):
    kernel = _FakeJobKernel()
    monkeypatch.setattr(
        cli.active_key,
        "_WindowsAtomicRecoveryProcess",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("wrapper failed")),
    )
    with pytest.raises(RuntimeError, match="wrapper failed"):
        _fake_windows_job(kernel).create_suspended_process(
            [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"],
            env={"SYSTEMROOT": r"C:\Windows"},
        )
    assert {77, 101, 102}.issubset(set(kernel.closed))
    assert "delete" in kernel.events


class _FakeJobProbeKernel:
    def __init__(self, *, error, handle=0):
        self.error = error
        self.OpenJobObjectW = _FakeWinCall(lambda *_args: handle)
        self.CloseHandle = _FakeWinCall(lambda *_args: 1)
        self.SetLastError = _FakeWinCall(lambda value: setattr(self, "error", value))
        self.GetLastError = _FakeWinCall(lambda: self.error)


def test_windows_job_probe_only_file_not_found_is_inactive(monkeypatch):
    monkeypatch.setattr(cli.active_key, "_is_windows_host", lambda: True)
    missing = _FakeJobProbeKernel(error=2)
    # SetLastError(0) runs before OpenJobObjectW, so emulate the real call
    # assigning its configured failure after the open attempt.
    missing.OpenJobObjectW = _FakeWinCall(
        lambda *_args: (setattr(missing, "error", 2), 0)[1]
    )
    monkeypatch.setattr(
        cli.active_key,
        "_windows_job_api",
        lambda: (missing, SimpleNamespace(DWORD=object, BOOL=object, LPCWSTR=object, HANDLE=object)),
    )
    assert cli.active_key.windows_recovery_job_is_active("1" * 64) is False

    denied = _FakeJobProbeKernel(error=5)
    denied.OpenJobObjectW = _FakeWinCall(
        lambda *_args: (setattr(denied, "error", 5), 0)[1]
    )
    monkeypatch.setattr(
        cli.active_key,
        "_windows_job_api",
        lambda: (denied, SimpleNamespace(DWORD=object, BOOL=object, LPCWSTR=object, HANDLE=object)),
    )
    with pytest.raises(OSError) as exc_info:
        cli.active_key.windows_recovery_job_is_active("1" * 64)
    assert exc_info.value.errno == 5


def test_protocol_windows_job_probe_uncertainty_is_fail_closed(monkeypatch):
    monkeypatch.setattr(protocol, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        cli.active_key,
        "windows_recovery_job_is_active",
        lambda _operation_id: (_ for _ in ()).throw(PermissionError("denied")),
    )
    with pytest.raises(protocol.KeyRecoveryProtocolError, match="status_unavailable"):
        protocol._windows_job_is_active("2" * 64)


def test_system_powershell_path_ignores_path_and_rejects_reparse(monkeypatch):
    class Kernel:
        def __init__(self):
            self.attributes = 0x20
            self.GetSystemDirectoryW = _FakeWinCall(self.system_directory)
            self.GetFileAttributesW = _FakeWinCall(lambda _path: self.attributes)
            self.GetLastError = _FakeWinCall(lambda: 5)

        @staticmethod
        def system_directory(buffer, _size):
            buffer.value = r"C:\Windows\System32"
            return len(buffer.value)

    kernel = Kernel()
    monkeypatch.setattr(cli.active_key, "_is_windows_host", lambda: True)
    monkeypatch.setattr(
        cli.active_key,
        "_windows_job_api",
        lambda: (kernel, SimpleNamespace(LPWSTR=object, UINT=object, LPCWSTR=object, DWORD=object)),
    )
    monkeypatch.setenv("PATH", r"C:\attacker-first")
    assert cli.active_key._trusted_windows_powershell_path() == (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    kernel.attributes = 0x00000400
    with pytest.raises(OSError, match="trusted Windows PowerShell"):
        cli.active_key._trusted_windows_powershell_path()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS recovery contract")
def test_cancel_exact_macos_helper_then_client_and_rechecks(
    monkeypatch,
    private_runtime,
):
    from chatlog_keeper import macos_debug_app, macos_key

    operation_id = "3" * 63 + "1"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.record_macos_process(
        {
            "state": "running",
            "source": "wechat",
            "path_hex": b"/private/debug/WeChat".hex(),
            "pid": 7001,
            "start_sec": 10,
            "start_usec": 20,
        }
    )
    session.record_macos_helper(
        {
            "source": "wechat",
            "path_hex": b"/private/bin/macos-memory-scan-test".hex(),
            "pid": 7002,
            "start_sec": 11,
            "start_usec": 21,
            "file_digest_hex": "00" * 32,
            "file_device": 1,
            "file_inode": 2,
        }
    )
    session.client_opened()
    session.release_active_lease()
    live = {"helper": True, "client": True}
    calls = []
    monkeypatch.setattr(
        macos_key,
        "recorded_helper_is_running",
        lambda _record: live["helper"],
    )

    def terminate_helper(_record):
        calls.append("helper")
        live["helper"] = False
        return True

    def terminate_client(_record):
        calls.append("client")
        live["client"] = False
        return True

    monkeypatch.setattr(macos_key, "terminate_recorded_helper", terminate_helper)
    monkeypatch.setattr(
        macos_debug_app,
        "recorded_debug_copy_is_running",
        lambda _record: live["client"],
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_recorded_debug_copy",
        terminate_client,
    )

    result = protocol.cancel_operation(operation_id)
    assert result["terminal"] is True
    assert calls == ["helper", "client"]
    assert live == {"helper": False, "client": False}


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS recovery contract")
def test_cancel_armed_watchdog_cleans_before_source_release(
    monkeypatch,
    private_runtime,
):
    from chatlog_keeper import macos_debug_app, macos_key

    operation_id = "3" * 63 + "2"
    session = protocol.KeyRecoverySession(
        protocol.KeyRecoveryRequest(operation_id, 60, True),
        source="wechat",
    )
    session.emit("preparing")
    session.record_macos_process(
        {
            "state": "launching",
            "source": "wechat",
            "path_hex": b"/private/debug/WeChat".hex(),
            "pid": None,
            "start_sec": None,
            "start_usec": None,
        }
    )
    session.record_macos_watchdog(
        {
            "source": "wechat",
            "path_hex": b"/private/bin/macos-memory-scan-0123456789ab".hex(),
            "pid": 7201,
            "start_sec": 11,
            "start_usec": 21,
            "file_digest_hex": "00" * 32,
            "file_device": 1,
            "file_inode": 2,
        }
    )
    session.release_active_lease()
    active = {"watchdog": True}
    calls = []
    monkeypatch.setattr(
        macos_key,
        "recorded_helper_is_running",
        lambda record: active["watchdog"]
        if record["schema"] == protocol.MACOS_WATCHDOG_SCHEMA
        else False,
    )

    def terminate(record):
        assert record["schema"] == protocol.MACOS_WATCHDOG_SCHEMA
        calls.append("watchdog-cleanup")
        active["watchdog"] = False
        return True

    monkeypatch.setattr(macos_key, "terminate_recorded_helper", terminate)
    monkeypatch.setattr(
        macos_debug_app,
        "recorded_debug_copy_is_running",
        lambda _record: False,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "terminate_recorded_debug_copy",
        lambda _record: calls.append("client-recheck") or True,
    )

    result = protocol.cancel_operation(operation_id)
    assert result["ok"] is True
    assert result["error_code"] is None
    assert calls == ["watchdog-cleanup", "client-recheck"]
    assert active["watchdog"] is False


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS recovery contract")
def test_dead_recorded_helper_does_not_require_deleted_artifact(monkeypatch):
    from chatlog_keeper import macos_key

    record = {
        "schema": protocol.MACOS_HELPER_SCHEMA,
        "operation_id": "4" * 64,
        "source": "wechat",
        "path_hex": b"/private/bin/macos-memory-scan-0123456789ab".hex(),
        "pid": 7101,
        "start_sec": 10,
        "start_usec": 20,
        "file_digest_hex": "00" * 32,
        "file_device": 1,
        "file_inode": 2,
    }
    monkeypatch.setattr(macos_key, "_recorded_pid_is_absent", lambda _pid: True)
    monkeypatch.setattr(
        macos_key,
        "_validated_recorded_helper",
        lambda _record: pytest.fail("dead PID required deleted helper artifact"),
    )
    assert macos_key.recorded_helper_is_running(record) is False
    assert macos_key.terminate_recorded_helper(record) is True


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS recovery contract")
def test_live_or_reused_helper_with_artifact_drift_fails_closed(monkeypatch):
    from chatlog_keeper import macos_key

    record = {
        "schema": protocol.MACOS_HELPER_SCHEMA,
        "operation_id": "5" * 64,
        "source": "wechat",
        "path_hex": b"/private/bin/macos-memory-scan-0123456789ab".hex(),
        "pid": 7102,
        "start_sec": 10,
        "start_usec": 20,
        "file_digest_hex": "00" * 32,
        "file_device": 1,
        "file_inode": 2,
    }
    monkeypatch.setattr(macos_key, "_recorded_pid_is_absent", lambda _pid: False)
    monkeypatch.setattr(
        macos_key,
        "_validated_recorded_helper",
        lambda _record: (_ for _ in ()).throw(ValueError("artifact drift")),
    )
    with pytest.raises(ValueError, match="artifact drift"):
        macos_key.recorded_helper_is_running(record)
    with pytest.raises(ValueError, match="artifact drift"):
        macos_key.terminate_recorded_helper(record)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS recovery contract")
def test_dead_recorded_debug_copy_survives_cache_or_client_update(monkeypatch):
    from chatlog_keeper import macos_debug_app

    record = {
        "schema": protocol.MACOS_PROCESS_SCHEMA,
        "operation_id": "6" * 64,
        "state": "running",
        "source": "wechat",
        "path_hex": (
            b"/private/debug-apps/WeChat-0123456789ab.app/Contents/MacOS/WeChat"
        ).hex(),
        "pid": 7103,
        "start_sec": 10,
        "start_usec": 20,
    }
    monkeypatch.setattr(
        macos_debug_app,
        "_recorded_pid_is_absent",
        lambda _pid: True,
    )
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda _path: ())
    monkeypatch.setattr(
        macos_debug_app,
        "_recorded_debug_executable",
        lambda _record: pytest.fail("dead PID required current app/cache artifact"),
    )
    assert macos_debug_app.recorded_debug_copy_is_running(record) is False
    assert macos_debug_app.terminate_recorded_debug_copy(record) is True


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS recovery contract")
def test_live_or_reused_debug_pid_with_artifact_drift_is_not_released(
    monkeypatch,
):
    from chatlog_keeper import macos_debug_app

    record = {
        "schema": protocol.MACOS_PROCESS_SCHEMA,
        "operation_id": "7" * 64,
        "state": "running",
        "source": "wechat",
        "path_hex": (
            b"/private/debug-apps/WeChat-0123456789ab.app/Contents/MacOS/WeChat"
        ).hex(),
        "pid": 7104,
        "start_sec": 10,
        "start_usec": 20,
    }
    monkeypatch.setattr(
        macos_debug_app,
        "_recorded_pid_is_absent",
        lambda _pid: False,
    )
    monkeypatch.setattr(macos_debug_app, "_exact_process_pids", lambda _path: ())
    monkeypatch.setattr(
        macos_debug_app,
        "_recorded_debug_executable",
        lambda _record: None,
    )
    monkeypatch.setattr(
        macos_debug_app,
        "_terminate_generation",
        lambda *_args, **_kwargs: pytest.fail("reused PID was signaled"),
    )
    with pytest.raises(RuntimeError, match="artifact"):
        macos_debug_app.recorded_debug_copy_is_running(record)
    assert macos_debug_app.terminate_recorded_debug_copy(record) is False


def test_macos_memory_helper_self_terminates_on_owner_or_target_loss():
    helper_source = (
        Path(cli.active_key.__file__).parent / "scripts" / "macos_memory_scan.c"
    ).read_text(encoding="utf-8")
    assert "getppid() == expected_parent" in helper_source
    assert "owner_process_lost" in helper_source
    assert helper_source.count("identity_matches(pid, &expected)") >= 4
    assert "str(os.getpid())" in Path(
        cli.active_key.__file__
    ).with_name("macos_key.py").read_text(encoding="utf-8")


def test_macos_watchdog_arms_before_open_and_freezes_exact_generations():
    source = (
        Path(cli.active_key.__file__).parent / "scripts" / "macos_memory_scan.c"
    ).read_text(encoding="utf-8")
    sigpipe_ignored = source.index("signal(SIGPIPE, SIG_IGN)")
    armed = source.index('emit_watch_marker("WATCH_ARMED\\n")')
    launch_command = source.index("wait_for_launch_command(owner_pid)")
    spawn = source.index("posix_spawn(", launch_command)
    launched = source.index('emit_watch_marker("WATCH_LAUNCHED\\n")', spawn)
    cleanup = source.index("cleanup_watched_target(", launched)
    assert sigpipe_ignored < armed < launch_command < spawn < launched < cleanup
    marker_failure = source[launched:cleanup]
    assert "watch_interrupted = 1;" in marker_failure
    assert "return" not in marker_failure
    assert 'lstat("/usr/bin/open"' in source
    assert "info.st_uid == 0" in source
    assert "FD_CLOEXEC" in source
    assert "char *open_envp[] = {NULL};" in source
    assert "extern char **environ" not in source
    assert "strcmp(expected->path, canonical) != 0" in source
    assert "baseline_count != 0" in source
    assert source.count("frozen_launch_path_matches(&target") >= 2
    assert "frozen_launch_path_matches(&app, S_IFDIR, 0700)" in source
    assert "frozen_launch_path_matches(&capture_library, S_IFREG, 0700)" in source
    assert "frozen_launch_path_matches(&capture_fifo, S_IFIFO, 0600)" in source
    final_identity_check = source.rindex(
        "frozen_launch_path_matches(&target", launch_command, spawn
    )
    assert launch_command < final_identity_check < spawn
    assert "same_identity(&known[index].identity" in source
    assert source.index("identity_matches(known[index].pid") < source.index(
        "kill(known[index].pid"
    )
