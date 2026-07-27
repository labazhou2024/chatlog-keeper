import io

from chatlog_keeper import cli


def test_set_key_can_be_read_from_stdin_without_argv_secret(monkeypatch):
    seen = {}

    def fake_set_key(source, key):
        seen.update(source=source, key=key)
        return {"source": source, "ok": True}

    monkeypatch.setattr(cli, "_set_key", fake_set_key)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("0123456789abcdef\n"))

    assert cli.main(["set-key", "--source", "qq", "--key-stdin"]) == 0
    assert seen == {"source": "qq", "key": "0123456789abcdef\n"}
