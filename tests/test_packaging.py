from pathlib import Path


def test_pyinstaller_spec_bundles_every_platform_key_helper():
    root = Path(__file__).resolve().parents[1]
    spec = (root / "packaging" / "chatlog_keeper.spec").read_text(encoding="utf-8")
    for helper in (
        "windows_ntqq_get_key.ps1",
        "windows_wechat_get_key.ps1",
        "macos_memory_scan.c",
        "macos_wechat_key_capture.c",
        "macos_wechat_key_capture.dylib",
    ):
        assert helper in spec
    assert '"-arch",\n            "arm64"' in spec
    assert "-mmacosx-version-min=11.0" in spec
    assert "-Wl,-install_name,@rpath/macos_wechat_key_capture.dylib" in spec
    assert 'for _pkg in ("Crypto", "zstandard")' in spec
    assert 'os.path.join(SPEC_DIR, "chatlog_keeper_main.py")' in spec
    assert 'name="chatlog-keeper"' in spec


def test_release_workflow_freezes_source_capabilities_and_descriptors():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("release_metadata.py verify-version") == 2
    assert workflow.count("release_metadata.py validate-capabilities") == 2
    assert "build-source-bundle" in workflow
    assert '--commit "${GITHUB_SHA}"' in workflow
    assert workflow.count("release_metadata.py build-descriptor") == 2
    assert "--platform windows" in workflow
    assert "--arch x86_64" in workflow
    assert "--platform macos" in workflow
    assert "--arch arm64" in workflow
    assert "chatlog-keeper-v${version}-source.tar.gz.sha256" in workflow
    assert "windows-x86_64.artifact.json.sha256" in workflow
    assert "macos-arm64.artifact.json.sha256" in workflow
    assert "verify-checksum" in workflow


def test_release_output_directories_are_ignored():
    root = Path(__file__).resolve().parents[1]
    ignore = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert {"dist_exe*/", "dist_macos*/", "dist_source*/", "dist_metadata*/"} <= set(ignore)


def test_readmes_document_standalone_verification_and_both_protocol_probes():
    root = Path(__file__).resolve().parents[1]
    for name in ("README.md", "README.zh.md"):
        readme = (root / name).read_text(encoding="utf-8")
        assert "chatlog-keeper.exe.sha256" in readme
        assert "chatlog-keeper-macos-arm64.sha256" in readme
        assert "shasum -a 256 -c" in readme
        assert "chmod 755 chatlog-keeper-macos-arm64" in readme
        assert "message-stream-v1 --capabilities" in readme
        assert "participant-directory-v1 --capabilities" in readme
        assert "chatlog-keeper-v*-source.tar.gz" in readme
        assert "artifact descriptor" in readme
