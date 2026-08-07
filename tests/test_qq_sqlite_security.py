"""Security contracts for the isolated shifted-pending-byte QQ reader."""

from __future__ import annotations

import io
import json
import os
import sqlite3
from types import SimpleNamespace

import pytest

from chatlog_keeper import _qq_sqlite_helper as helper
from chatlog_keeper import _qq_sqlite_proxy as proxy


def test_runtime_probe_sets_and_reads_back_shifted_pending_without_connecting(
    monkeypatch,
) -> None:
    state = {"pending": helper._SQLITE_STANDARD_PENDING_BYTE, "set_calls": 0}

    class DataFreeSQLite:
        sqlite_version = "3.53.2"

        @staticmethod
        def connect(*_args, **_kwargs):
            raise AssertionError("runtime probe must not open a database")

    def set_pending(_test_control) -> None:
        state["set_calls"] += 1
        state["pending"] = helper._NTQQ_STRIPPED_PENDING_BYTE

    monkeypatch.setattr(
        helper,
        "_validated_sqlite_runtime",
        lambda: (DataFreeSQLite, object()),
    )
    monkeypatch.setattr(helper, "_set_shifted_pending_byte", set_pending)
    monkeypatch.setattr(helper, "_pending_byte", lambda _control: state["pending"])
    stdout = io.StringIO()
    monkeypatch.setattr(helper.sys, "stdout", stdout)

    assert helper.main(["--runtime-probe"]) == 0

    payload = json.loads(stdout.getvalue())
    assert state["set_calls"] == 1
    assert payload["type"] == "runtime_probe"
    assert payload["pending_byte"] == helper._NTQQ_STRIPPED_PENDING_BYTE
    assert payload["sqlite_version"] == "3.53.2"
    assert "sqlite_dll" not in payload


def test_runtime_probe_fails_when_shifted_pending_readback_does_not_match(
    monkeypatch,
) -> None:
    sqlite_runtime = SimpleNamespace(sqlite_version="3.53.2")
    monkeypatch.setattr(
        helper,
        "_validated_sqlite_runtime",
        lambda: (sqlite_runtime, object()),
    )
    monkeypatch.setattr(helper, "_set_shifted_pending_byte", lambda _control: None)
    monkeypatch.setattr(
        helper,
        "_pending_byte",
        lambda _control: helper._SQLITE_STANDARD_PENDING_BYTE,
    )
    stdout = io.StringIO()
    monkeypatch.setattr(helper.sys, "stdout", stdout)

    assert helper.main(["--runtime-probe"]) == 2
    assert json.loads(stdout.getvalue()) == {
        "ok": False,
        "error": "sqlite3_pending_byte_readback_failed",
    }


def test_open_attestation_is_exact_and_database_path_stays_on_stdin(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(helper, "_NTQQ_WRAPPED_LOCK_PAGE_NO", 2)
    database = (tmp_path / "private-qq-plaintext.db").resolve()
    database.write_bytes(b"SQLite format 3\0" + b"\0" * (8192 - 16))
    request = {
        "op": "open",
        "protocol": helper._OPEN_PROTOCOL,
        "database_path": str(database),
        "wrapper_size": helper._NTQQ_WRAPPER_SIZE,
        "lock_page_no": 2,
        "pending_byte": helper._NTQQ_STRIPPED_PENDING_BYTE,
    }
    monkeypatch.setattr(
        helper.sys,
        "stdin",
        io.StringIO(json.dumps(request, separators=(",", ":")) + "\n"),
    )

    assert helper._read_open_attestation() == database


def test_parent_never_places_database_path_in_helper_argv(monkeypatch, tmp_path) -> None:
    database = tmp_path / "private-qq-plaintext.db"
    database.write_bytes(b"SQLite format 3\0")
    ready = {
        "ok": True,
        "type": "ready",
        "pid": os.getpid() + 1000,
        "isolated": 1,
        "sqlite_version": "3.53.2",
        "pending_byte": proxy._NTQQ_STRIPPED_PENDING_BYTE,
        "quick_check": "ok",
    }

    class FakeProcess:
        def __init__(self):
            self.stdin = io.StringIO()
            self.stdout = io.StringIO(json.dumps(ready) + "\n")
            self.stderr = None

        @staticmethod
        def poll():
            return None

        @staticmethod
        def kill():
            return None

        @staticmethod
        def wait(timeout=None):
            return 0

    process = FakeProcess()
    helper_arguments = []

    def spawn(arguments):
        helper_arguments.extend(arguments)
        return process

    monkeypatch.setattr(proxy, "_spawn_helper", spawn)
    connection = proxy.IsolatedQQSQLiteConnection(database)
    try:
        assert helper_arguments == []
        attestation = json.loads(process.stdin.getvalue().splitlines()[0])
        assert attestation["database_path"] == str(database)
        assert str(database) not in proxy._helper_command()
        assert "sqlite_dll" not in connection.verification
    finally:
        # Avoid exercising the request protocol on this intentionally tiny fake.
        connection._closed = True  # noqa: SLF001
        process.stdin.close()
        process.stdout.close()


@pytest.mark.parametrize(
    ("sql", "allowed"),
    [
        ('PRAGMA table_info("c2c_msg_table")', True),
        ('PRAGMA table_info("secret")', False),
        ("SELECT name FROM sqlite_master WHERE type='table'", True),
        ("SELECT COUNT(*) FROM c2c_msg_table", True),
        ("PRAGMA query_only=OFF", False),
        ("ATTACH DATABASE ':memory:' AS evil", False),
        ("SELECT * FROM c2c_msg_table; DELETE FROM c2c_msg_table", False),
        ("SELECT load_extension('payload')", False),
        ("WITH rows AS (SELECT 1) SELECT * FROM rows", False),
    ],
)
def test_sql_text_gate_is_default_deny(sql, allowed) -> None:
    assert helper._sql_is_allowlisted_read(sql) is allowed


def test_sqlite_authorizer_allows_fixed_reader_shape_and_denies_attacks() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE c2c_msg_table(x INTEGER)")
    connection.execute("CREATE TABLE secret(value TEXT)")
    connection.execute("INSERT INTO c2c_msg_table VALUES (1)")
    connection.execute("INSERT INTO secret VALUES ('private')")
    connection.commit()
    connection.execute("PRAGMA query_only=ON")
    helper._install_read_only_authorizer(connection, sqlite3)
    try:
        assert connection.execute(
            'PRAGMA table_info("c2c_msg_table")'
        ).fetchall()
        assert connection.execute(
            "SELECT COUNT(*), MAX(x), "
            "NULLIF(TRIM(CAST(x AS TEXT)), '') FROM c2c_msg_table"
        ).fetchone() == (1, 1, "1")

        attacks = (
            "PRAGMA query_only=OFF",
            "ATTACH DATABASE ':memory:' AS evil",
            "CREATE TABLE injected(value TEXT)",
            "DELETE FROM c2c_msg_table",
            "BEGIN",
            "SELECT load_extension('payload')",
            "SELECT * FROM secret",
        )
        for statement in attacks:
            with pytest.raises(sqlite3.DatabaseError):
                connection.execute(statement).fetchall()
    finally:
        connection.close()


def test_helper_launch_oserror_is_stable_and_path_free(monkeypatch) -> None:
    private_path = r"C:\Users\private\plaintext.db"

    def fail(*_args, **_kwargs):
        raise OSError(private_path)

    monkeypatch.setattr(proxy.subprocess, "Popen", fail)
    with pytest.raises(proxy.QQShiftedSQLiteError) as exc_info:
        proxy._spawn_helper([])

    assert str(exc_info.value) == "isolated QQ SQLite helper launch failed"
    assert private_path not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
