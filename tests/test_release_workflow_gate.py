"""Integration coverage for the exact inline Release ref-gate script."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _git(repository: Path, *arguments: str, input_text: str | None = None) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True,
    )
    return completed.stdout.strip()


def _freeze_script(workflow: str) -> str:
    marker = "        id: freeze\n"
    step_start = workflow.index(marker)
    run_marker = "        run: |\n"
    script_start = workflow.index(run_marker, step_start) + len(run_marker)
    script_lines: list[str] = []
    for line in workflow[script_start:].splitlines():
        if line and not line.startswith("          "):
            break
        script_lines.append(line[10:] if line else "")
    script = "\n".join(script_lines).strip()
    assert script.startswith("set -euo pipefail")
    assert script.endswith('echo "release_tag_object=$tag_object" >> "$GITHUB_OUTPUT"')
    return script


def _run_gate(
    repository: Path,
    script: str,
    output: Path,
    *,
    release_tag: str,
    event_name: str,
    ref_type: str,
    ref_name: str,
    ref: str,
    sha: str,
) -> subprocess.CompletedProcess[str]:
    output.unlink(missing_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_EVENT_NAME": event_name,
            "GITHUB_OUTPUT": str(output),
            "GITHUB_REF": ref,
            "GITHUB_REF_NAME": ref_name,
            "GITHUB_REF_TYPE": ref_type,
            "GITHUB_SHA": sha,
            "RELEASE_TAG": release_tag,
        }
    )
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        cwd=repository,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )


def _output_values(output: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in output.read_text(encoding="utf-8").splitlines()
    )


def test_release_ref_gate_freezes_existing_annotated_tag_and_fails_closed(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        # The production gate is bash on Ubuntu. macOS CI executes this exact script.
        return

    project_root = Path(__file__).resolve().parents[1]
    workflow = (project_root / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    script = _freeze_script(workflow)

    remote = tmp_path / "remote.git"
    author = tmp_path / "author"
    runner = tmp_path / "runner"
    remote.mkdir()
    author.mkdir()
    _git(remote, "init", "--bare")
    _git(author, "init", "-b", "main")
    _git(author, "config", "user.name", "Release Gate Test")
    _git(author, "config", "user.email", "release-gate@example.invalid")
    (author / "marker.txt").write_text("release\n", encoding="utf-8")
    _git(author, "add", "marker.txt")
    _git(author, "commit", "-m", "release")
    release_commit = _git(author, "rev-parse", "HEAD")
    _git(author, "tag", "-a", "v1.2.3", "-m", "release v1.2.3")
    tag_object = _git(author, "rev-parse", "v1.2.3^{tag}")
    _git(author, "remote", "add", "origin", str(remote))
    _git(author, "push", "origin", "main", "refs/tags/v1.2.3")

    (author / "marker.txt").write_text("controller\n", encoding="utf-8")
    _git(author, "commit", "-am", "repair release controller")
    controller_commit = _git(author, "rev-parse", "HEAD")
    _git(author, "push", "origin", "main")
    _git(tmp_path, "clone", str(remote), str(runner))
    _git(runner, "checkout", "--detach", controller_commit)

    output = tmp_path / "gate.out"
    dispatch = _run_gate(
        runner,
        script,
        output,
        release_tag="v1.2.3",
        event_name="workflow_dispatch",
        ref_type="branch",
        ref_name="main",
        ref="refs/heads/main",
        sha=controller_commit,
    )
    assert dispatch.returncode == 0, dispatch.stderr
    assert _output_values(output) == {
        "release_commit": release_commit,
        "release_tag": "v1.2.3",
        "release_tag_object": tag_object,
    }

    _git(runner, "checkout", "--detach", release_commit)
    pushed_tag = _run_gate(
        runner,
        script,
        output,
        release_tag="v1.2.3",
        event_name="push",
        ref_type="tag",
        ref_name="v1.2.3",
        ref="refs/tags/v1.2.3",
        sha=release_commit,
    )
    assert pushed_tag.returncode == 0, pushed_tag.stderr
    _git(runner, "checkout", "--detach", controller_commit)

    _git(author, "tag", "v1.2.4", release_commit)
    _git(author, "push", "origin", "refs/tags/v1.2.4")
    _git(author, "tag", "-a", "v1.2.5", release_commit, "-m", "inner")
    _git(author, "tag", "-a", "v1.2.6", "v1.2.5", "-m", "nested")
    _git(author, "push", "origin", "refs/tags/v1.2.5", "refs/tags/v1.2.6")

    _git(author, "checkout", "-b", "side", release_commit)
    (author / "side.txt").write_text("not on main\n", encoding="utf-8")
    _git(author, "add", "side.txt")
    _git(author, "commit", "-m", "side release")
    _git(author, "tag", "-a", "v1.2.7", "-m", "side")
    _git(author, "push", "origin", "refs/tags/v1.2.7")

    mismatched_payload = (
        f"object {release_commit}\n"
        "type commit\n"
        "tag wrong-name\n"
        "tagger Release Gate Test <release-gate@example.invalid> 1700000000 +0000\n"
        "\n"
        "mismatched embedded name\n"
    )
    mismatched_object = _git(author, "mktag", input_text=mismatched_payload)
    _git(author, "update-ref", "refs/tags/v1.2.8", mismatched_object)
    _git(author, "push", "origin", "refs/tags/v1.2.8")

    for rejected_tag in (
        "invalid/tag",
        "v1.2.4",  # lightweight
        "v1.2.6",  # direct target is another tag
        "v1.2.7",  # commit is not on remote main
        "v1.2.8",  # embedded tag name differs from the remote ref
        "v1.2.9",  # missing
    ):
        rejected = _run_gate(
            runner,
            script,
            output,
            release_tag=rejected_tag,
            event_name="workflow_dispatch",
            ref_type="branch",
            ref_name="main",
            ref="refs/heads/main",
            sha=controller_commit,
        )
        assert rejected.returncode != 0, rejected_tag
        assert not output.exists(), rejected_tag
