import re
from pathlib import Path


_RELEASE_REQUIREMENTS = (
    "numpy==2.4.6",
    "pip==26.1.2",
    "pycryptodome==3.23.0",
    "pyinstaller==6.20.0",
    "pytest==9.1.1",
    "setuptools==83.0.0",
    "wheel==0.47.0",
    "zstandard==0.25.0",
)

_COMMON_RELEASE_LOCK = {
    "altgraph": "0.17.5",
    "iniconfig": "2.3.0",
    "numpy": "2.4.6",
    "packaging": "26.3",
    "pip": "26.1.2",
    "pluggy": "1.6.0",
    "pycryptodome": "3.23.0",
    "pygments": "2.20.0",
    "pyinstaller": "6.20.0",
    "pyinstaller-hooks-contrib": "2026.6",
    "pytest": "9.1.1",
    "setuptools": "83.0.0",
    "wheel": "0.47.0",
    "zstandard": "0.25.0",
}

_MACOS_RELEASE_LOCK = {
    **_COMMON_RELEASE_LOCK,
    "macholib": "1.16.4",
}

_WINDOWS_RELEASE_LOCK = {
    **_COMMON_RELEASE_LOCK,
    "colorama": "0.4.6",
    "pefile": "2024.8.26",
    "pywin32-ctypes": "0.2.3",
}


def _parse_hashed_lock(path: Path) -> tuple[str, dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    for forbidden in (
        "http://",
        "https://",
        "git+",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "-e ",
    ):
        assert forbidden not in text

    versions: dict[str, str] = {}
    current_name: str | None = None
    hashed_names: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" "):
            assert line.endswith(" \\")
            requirement = line[:-2]
            name, separator, version = requirement.partition("==")
            assert separator == "=="
            assert re.fullmatch(r"[A-Za-z0-9_.-]+", name)
            assert re.fullmatch(r"[A-Za-z0-9.+!-]+", version)
            normalized_name = name.lower().replace("_", "-")
            assert normalized_name not in versions
            versions[normalized_name] = version
            current_name = normalized_name
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert current_name is not None
        assert re.fullmatch(r"--hash=sha256:[0-9a-f]{64}(?: \\)?", stripped)
        hashed_names.add(current_name)

    assert versions
    assert hashed_names == set(versions)
    return text, versions


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
    frozen_main = (root / "packaging" / "chatlog_keeper_main.py").read_text(
        encoding="utf-8"
    )
    assert 'sys.argv[1:2] == ["--_qq-sqlite-helper"]' in frozen_main
    assert "chatlog_keeper._qq_sqlite_helper" in frozen_main


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
    assert (
        "python -I chatlog_keeper/_qq_sqlite_helper.py --runtime-probe"
        in workflow
    )
    assert (
        ".\\dist_exe\\chatlog-keeper.exe --_qq-sqlite-helper --runtime-probe"
        in workflow
    )
    assert (
        "conda-incubator/setup-miniconda@"
        "835234971496cad1653abb28a638a281cf32541f"
    ) in workflow
    assert "packaging/windows-release-environment.yml" in workflow
    assert 'miniconda-version: "py311_26.5.3-2"' in workflow
    assert re.search(r"(?m)^permissions:\n  contents: read$", workflow)
    assert re.search(
        r"(?m)^  publish-release:\n(?:.*\n)*?    permissions:\n      contents: write$",
        workflow,
    )
    assert workflow.count("contents: write") == 1
    assert workflow.count("persist-credentials: false") == workflow.count(
        "actions/checkout@"
    )
    assert "release-ref-gate:" in workflow
    assert 'test "$GITHUB_REF_TYPE" = "tag"' in workflow
    assert '[[ "$GITHUB_REF_NAME" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+[A-Za-z0-9.+-]*$ ]]' in workflow
    assert 'git cat-file -t "$GITHUB_REF_NAME"' in workflow
    assert 'git rev-parse --verify "${GITHUB_REF_NAME}^{commit}"' in workflow
    assert 'test "$tag_commit" = "$GITHUB_SHA"' in workflow
    assert "build-windows:" in workflow
    assert "publish-release:" in workflow
    publisher = workflow.split("  publish-release:\n", maxsplit=1)[1]
    assert "actions/checkout@" not in publisher
    assert "pip install" not in publisher
    assert "python -m pytest" not in publisher
    assert "PyInstaller" not in publisher
    assert "chatlog-keeper-release-inputs" in publisher
    assert 'test "$(find release_inputs -type f | wc -l | tr -d \' \')" = "10"' in publisher
    assert publisher.count("sha256sum -c") == 5
    assert publisher.count("GH_TOKEN: ${{ github.token }}") == 1
    assert "Publish immutable GitHub Release" not in workflow
    assert workflow.count("RELEASE_TAG: ${{ github.ref_name }}") == 4
    for line in workflow.splitlines():
        if "${{ github.ref_name }}" in line:
            assert line.strip() == "RELEASE_TAG: ${{ github.ref_name }}"
    assert '--tag "$RELEASE_TAG"' in workflow
    assert '--tag "$env:RELEASE_TAG"' in workflow
    assert '$releaseTag = [string]$env:RELEASE_TAG' in workflow
    windows_runtime_line = next(
        line
        for line in workflow.splitlines()
        if "CONDA_DEFAULT_ENV') == 'chatlog-release-windows'" in line
    )
    assert (
        windows_runtime_line
        + "\n          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
        in workflow
    )
    assert workflow.count("sys.version_info[:3] == (3, 11, 15)") == 2
    assert workflow.count("sys.prefix == os.environ['CONDA_PREFIX']") == 2
    assert workflow.count("CONDA_DEFAULT_ENV") == 2
    assert workflow.count("platform.machine() == 'arm64'") == 1
    assert workflow.count("platform.machine().lower() in {'amd64', 'x86_64'}") == 1
    assert "packaging/macos-release-environment.yml" in workflow
    assert workflow.count("--require-hashes --only-binary=:all:") == 2
    assert workflow.count("packaging/release-requirements-macos.txt") == 1
    assert workflow.count("packaging/release-requirements-windows.txt") == 1
    assert workflow.count("--no-deps --no-build-isolation .") == 2
    assert workflow.count("python -m pip check") == 2
    assert ". pytest pyinstaller==" not in workflow
    assert workflow.count("shell: bash -el {0}") == 1
    assert workflow.count("set -euo pipefail") == 7
    assert (
        ".\\dist_exe\\chatlog-keeper.exe --help\n"
        "          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
    ) in workflow


def test_ci_covers_release_python_and_runs_the_runtime_probe_on_windows():
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert 'python-version: ["3.9", "3.11", "3.12"]' in workflow
    assert "windows-release-runtime:" in workflow
    assert 'python-version: "3.11"' in workflow
    assert "conda-incubator/setup-miniconda@835234971496cad1653abb28a638a281cf32541f" in workflow
    assert "packaging/windows-release-environment.yml" in workflow
    assert "_qq_sqlite_helper.py --runtime-probe" in workflow
    assert "macos-release-runtime:" in workflow
    assert workflow.count("sys.version_info[:3] == (3, 11, 15)") == 2
    assert "packaging/macos-release-environment.yml" in workflow
    assert workflow.count("persist-credentials: false") == workflow.count(
        "actions/checkout@"
    )
    assert workflow.count("--require-hashes --only-binary=:all:") == 2
    assert workflow.count("--no-deps --no-build-isolation .") == 2
    assert workflow.count("python -m pip check") == 2
    assert "packaging/release-requirements-macos.txt" in workflow
    assert "packaging/release-requirements-windows.txt" in workflow
    assert workflow.count("shell: bash -el {0}") == 1
    assert (
        "run: |\n"
        "          set -euo pipefail\n"
        "          python -m pip install --disable-pip-version-check "
        "--require-hashes --only-binary=:all: "
        "-r packaging/release-requirements-macos.txt"
    ) in workflow
    windows_runtime_line = next(
        line
        for line in workflow.splitlines()
        if "CONDA_DEFAULT_ENV') == 'chatlog-release-windows'" in line
    )
    assert (
        windows_runtime_line
        + "\n          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
        in workflow
    )
    assert workflow.count("sys.prefix == os.environ['CONDA_PREFIX']") == 2
    assert workflow.count("CONDA_DEFAULT_ENV") == 2
    assert workflow.count("platform.machine() == 'arm64'") == 1
    assert workflow.count("platform.machine().lower() in {'amd64', 'x86_64'}") == 1


def test_ci_push_runs_for_main_and_release_branches() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "  push:\n    branches:\n      - main\n      - \"release/**\"\n" in workflow


def test_windows_release_environment_pins_the_validated_python_and_sqlite_builds():
    root = Path(__file__).resolve().parents[1]
    environment = (
        root / "packaging" / "windows-release-environment.yml"
    ).read_text(encoding="utf-8")

    assert "name: chatlog-release-windows" in environment
    assert "python=3.11.15=hb00fc5c_1" in environment
    assert "sqlite=3.53.2=hee5a0db_0" in environment
    assert "pip=26.1.2=pyhc872135_0" in environment


def test_macos_release_environment_pins_the_validated_python_and_sqlite_builds():
    root = Path(__file__).resolve().parents[1]
    environment = (
        root / "packaging" / "macos-release-environment.yml"
    ).read_text(encoding="utf-8")

    assert "name: chatlog-release-macos" in environment
    assert "python=3.11.15=h478e877_1" in environment
    assert "sqlite=3.53.2=h1cce5ff_0" in environment
    assert "pip=26.1.2=pyhc872135_0" in environment


def test_release_dependency_inputs_and_platform_locks_are_complete_and_hashed():
    root = Path(__file__).resolve().parents[1]
    input_text = (
        root / "packaging" / "release-requirements.in"
    ).read_text(encoding="utf-8")
    assert "uv 0.11.30" in input_text
    inputs = input_text.splitlines()
    assert tuple(
        line for line in inputs if line and not line.startswith("#")
    ) == _RELEASE_REQUIREMENTS

    mac_text, mac_versions = _parse_hashed_lock(
        root / "packaging" / "release-requirements-macos.txt"
    )
    windows_text, windows_versions = _parse_hashed_lock(
        root / "packaging" / "release-requirements-windows.txt"
    )
    assert mac_versions == _MACOS_RELEASE_LOCK
    assert windows_versions == _WINDOWS_RELEASE_LOCK
    assert "--generate-hashes --only-binary :all:" in mac_text
    assert "--generate-hashes --only-binary :all:" in windows_text
    assert "--python-platform aarch64-apple-darwin" in mac_text
    assert "--python-platform x86_64-pc-windows-msvc" in windows_text
    assert "--python-version 3.11.15" in mac_text
    assert "--python-version 3.11.15" in windows_text


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
