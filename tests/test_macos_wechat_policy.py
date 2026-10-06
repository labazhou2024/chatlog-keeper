"""Exercise signed-bundle entitlement decisions on every CI platform."""
import copy
import json
import plistlib
from pathlib import Path

import pytest

from chatlog_keeper import macos_debug_app


_CLIENTS = json.loads(
    (Path(__file__).parent / "fixtures/macos_wechat_shipping_clients.json")
    .read_text(encoding="utf-8")
)
_APP_ID = "5A4RE8SF68.com.tencent.xinWeChat"
_REGISTER = "com.apple.security.temporary-exception.mach-register.global-name"


@pytest.mark.parametrize("client", _CLIENTS, ids=lambda c: c["client_version"][1])
def test_shipping_bundle_has_exact_entitlement_delta(client):
    original = copy.deepcopy(client["entitlements"])
    granted = macos_debug_app._debug_copy_entitlements(
        "wechat", original, client_version=tuple(client["client_version"]),
    )
    expected = copy.deepcopy(original)
    for name in (
        "application-identifier", "com.apple.application-identifier",
        "com.apple.developer.team-identifier", "com.apple.security.application-groups",
    ):
        expected.pop(name, None)
    expected["com.apple.security.get-task-allow"] = True
    expected[_REGISTER] = [
        f"{_APP_ID}.MachPortRendezvousServer.*",
        f"{_APP_ID}.MMMojo.MachPortRendezvousServer.*",
    ]
    if client["client_version"][1] == "270102":
        expected[_REGISTER].append(f"{_APP_ID}.XPlayerMachPortRendezvousServer.*")
    assert granted == expected
    assert original == client["entitlements"]


@pytest.mark.parametrize("client", _CLIENTS, ids=lambda c: c["client_version"][1])
@pytest.mark.parametrize("change", [
    {"com.apple.developer.team-identifier": "OTHERTEAM1"},
    {"com.apple.developer.team-identifier": None},
    {"com.apple.developer.team-identifier": ""},
    {"com.apple.developer.team-identifier": 5},
    {"com.apple.application-identifier": "OTHERTEAM1.com.tencent.xinWeChat"},
    {"application-identifier": "5A4RE8SF68.com.tencent.other"},
    {"com.apple.security.app-sandbox": False},
    {"com.apple.security.app-sandbox": "true"},
    {"com.apple.security.application-groups": []},
    {"com.apple.security.application-groups": [_APP_ID, _APP_ID]},
    {"com.apple.security.application-groups": [_APP_ID, "group.other"]},
    {"com.apple.security.application-groups": _APP_ID},
    {"keychain-access-groups": [_APP_ID]},
    {"com.apple.security.keychain-access-groups": [_APP_ID]},
    {"com.apple.developer.icloud-container-identifiers": [_APP_ID]},
    {"com.apple.private.example": True},
])
def test_shipping_build_does_not_relax_identity_checks(client, change):
    assert macos_debug_app._debug_copy_entitlements(
        "wechat", {**client["entitlements"], **change},
        client_version=tuple(client["client_version"]),
    ) is None


@pytest.mark.parametrize("client", _CLIENTS, ids=lambda c: c["client_version"][1])
def test_shipping_build_accepts_correct_present_team_identifier(client):
    assert macos_debug_app._debug_copy_entitlements(
        "wechat",
        {**client["entitlements"], "com.apple.developer.team-identifier": "5A4RE8SF68"},
        client_version=tuple(client["client_version"]),
    ) is not None


@pytest.mark.parametrize("client_version", [
    None, ("4.1.12", "269339"), ("4.1.12", "269341"),
    ("4.1.15", "270101"), ("4.1.15", "270103"),
    ("4.1.15.22", "270102"), ("4.1.12.28", "269340"),
    ("4.1.13", "269340"), ("4.1.12", "270102"),
])
def test_uninspected_pairs_and_feed_versions_fail_closed(client_version):
    assert macos_debug_app._debug_copy_entitlements(
        "wechat", _CLIENTS[1]["entitlements"], client_version=client_version,
    ) is None


def test_bundle_version_is_independent_of_sparkle_marketing_version(tmp_path):
    contents = tmp_path / "WeChat.app/Contents"
    contents.mkdir(parents=True)
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleShortVersionString": "4.1.15", "CFBundleVersion": "270102",
        "SUFeedURL": "https://example.com/4.1.15.22.xml",
    }))
    assert macos_debug_app._app_client_version(contents.parent) == ("4.1.15", "270102")


@pytest.mark.parametrize("client", _CLIENTS, ids=lambda c: c["client_version"][1])
def test_wechat_policy_does_not_transform_qq_identity(client):
    original = copy.deepcopy(client["entitlements"])
    assert macos_debug_app._debug_copy_entitlements(
        "qq", original, client_version=tuple(client["client_version"]),
    ) == {**original, "com.apple.security.get-task-allow": True}


def test_qq_cache_generation_is_unchanged():
    assert macos_debug_app._DEBUG_COPY_FORMATS["qq"] == (
        b"preserve-nested-signatures-v7-wechat-compat-exact-entitlements-kernel-pid"
    )
