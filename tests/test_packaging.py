from pathlib import Path


def test_pyinstaller_spec_bundles_every_platform_key_helper():
    root = Path(__file__).resolve().parents[1]
    spec = (root / "packaging" / "chatlog_keeper.spec").read_text(encoding="utf-8")
    for helper in (
        "windows_ntqq_get_key.ps1",
        "windows_wechat_get_key.ps1",
        "macos_memory_scan.c",
    ):
        assert helper in spec
