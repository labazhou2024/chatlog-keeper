from __future__ import annotations

import re
from pathlib import Path


APPROVED_NODE24_ACTIONS = {
    "actions/checkout": (
        "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "v7.0.1",
    ),
    "actions/setup-python": (
        "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "v7.0.0",
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1",
    ),
    "actions/download-artifact": (
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "v8.0.1",
    ),
    "conda-incubator/setup-miniconda": (
        "8ee1f361103df19b6f8c8655fd3967a8ecb162d5",
        "v4.0.1",
    ),
}

_USE_LINE = re.compile(r"(?m)^\s*uses:\s+([^@\s]+)@([0-9a-f]{40})\s+#\s+(v\S+)\s*$")


def test_workflows_only_use_audited_node24_action_pins() -> None:
    root = Path(__file__).resolve().parents[1]
    observed: dict[str, set[tuple[str, str]]] = {}

    for path in sorted((root / ".github" / "workflows").glob("*.yml")):
        workflow = path.read_text(encoding="utf-8")
        use_lines = [line for line in workflow.splitlines() if "uses:" in line]
        matches = list(_USE_LINE.finditer(workflow))
        assert len(matches) == len(use_lines), f"unreviewed action pin in {path.name}"
        for match in matches:
            action, sha, version = match.groups()
            observed.setdefault(action, set()).add((sha, version))

    expected = {action: {pin} for action, pin in APPROVED_NODE24_ACTIONS.items()}
    assert observed == expected


def test_setup_miniconda_v4_uses_current_auto_activate_input() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((root / ".github" / "workflows").glob("*.yml"))
    )

    assert "auto-activate-base:" not in workflow_text
    assert workflow_text.count("auto-activate: false") == 4
