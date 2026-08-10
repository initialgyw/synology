from __future__ import annotations

import json
from typing import Literal, cast

import pytest

from synology_manager.config import EMPTY_ACL, EMPTY_NFS, AclConfig, AclRule, Host, Share
from synology_manager.engine import AclObservations
from synology_manager.models import ObservedAclRule, ObservedShare, desired_acl
from synology_manager.plan import Action, ActionPlan, build_plan


def observed_acl(
    effect: Literal["allow", "deny"],
    permission: Literal["read_only", "read_write", "full_control"],
    inheritance: Literal["none", "this_folder", "children", "all"],
) -> ObservedAclRule:
    return desired_acl(
        AclConfig(
            True,
            False,
            False,
            (AclRule("group", "engineering", effect, permission, inheritance),),
        )
    )[0]


def acl_host(rule: AclRule) -> Host:
    return Host(
        "test",
        ("/volume1",),
        (
            Share(
                "data",
                "/volume1",
                "",
                0,
                "present",
                EMPTY_NFS,
                AclConfig(True, False, False, (rule,)),
            ),
        ),
    )


@pytest.mark.parametrize(
    ("current", "wanted", "expected"),
    [
        (
            observed_acl("allow", "read_only", "all"),
            AclRule("group", "engineering", "deny", "read_only", "all"),
            "effect=allow permissions=read_only inheritance=all -> group:engineering effect=deny permissions=read_only inheritance=all",
        ),
        (
            observed_acl("allow", "read_only", "all"),
            AclRule("group", "engineering", "allow", "read_write", "all"),
            "effect=allow permissions=read_only inheritance=all -> group:engineering effect=allow permissions=read_write inheritance=all",
        ),
        (
            observed_acl("allow", "read_write", "none"),
            AclRule("group", "engineering", "allow", "read_write", "children"),
            "effect=allow permissions=read_write inheritance=none -> group:engineering effect=allow permissions=read_write inheritance=children",
        ),
    ],
)
def test_acl_single_principal_changes_are_replacements(
    current: ObservedAclRule, wanted: AclRule, expected: str
) -> None:
    plan = build_plan(
        acl_host(wanted),
        {"data": ObservedShare("data", "/volume1", "", 0, "v1", False)},
        {},
        {"data": (current,)},
        {"data": False},
    )
    text = plan.as_text()
    assert f"~ group:engineering {expected}" in text
    assert "\n  - group:engineering" not in text
    assert "\n  + group:engineering" not in text


def test_acl_duplicate_effect_transition_is_explicit_remove() -> None:
    allow = observed_acl("allow", "read_only", "all")
    deny = observed_acl("deny", "read_only", "all")
    wanted = AclRule("group", "engineering", "allow", "read_only", "all")
    plan = build_plan(
        acl_host(wanted),
        {"data": ObservedShare("data", "/volume1", "", 0, "v1", False)},
        {},
        {"data": (allow, deny)},
        {"data": False},
    )
    text = plan.as_text()
    assert "- group:engineering effect=deny" in text
    assert "~ group:engineering" not in text


def test_acl_add_remove_and_reordered_rules_are_deterministic() -> None:
    wanted = AclRule("group", "engineering", "allow", "read_write", "all")
    removed = observed_acl("allow", "read_only", "all")
    added = observed_acl("allow", "read_write", "all")
    other = desired_acl(
        AclConfig(True, False, False, (AclRule("group", "retired", "allow", "read_only", "all"),))
    )[0]
    host = acl_host(wanted)
    current = ObservedShare("data", "/volume1", "", 0, "v1", False)
    first = build_plan(host, {"data": current}, {}, {"data": (other,)}, {"data": False})
    second = build_plan(
        host, {"data": current}, {}, {"data": tuple(reversed((other,)))}, {"data": False}
    )
    assert first.as_dict() == second.as_dict()
    assert "- group:retired" in first.as_text()
    assert (
        "+ group:engineering effect=allow permissions=read_write inheritance=all" in first.as_text()
    )
    assert added != removed


def test_reordered_acl_replacements_are_deterministic() -> None:
    wanted = (
        AclRule("group", "engineering", "deny", "read_write", "all"),
        AclRule("user", "alice", "allow", "full_control", "children"),
    )
    host = Host(
        "test",
        ("/volume1",),
        (
            Share(
                "data",
                "/volume1",
                "",
                0,
                "present",
                EMPTY_NFS,
                AclConfig(True, False, False, wanted),
            ),
        ),
    )
    old_engineering = observed_acl("allow", "read_only", "all")
    old_alice = desired_acl(
        AclConfig(True, False, False, (AclRule("user", "alice", "allow", "read_only", "none"),))
    )[0]
    current = {"data": ObservedShare("data", "/volume1", "", 0, "v1", False)}
    first = build_plan(host, current, {}, {"data": (old_alice, old_engineering)}, {"data": False})
    second = build_plan(host, current, {}, {"data": (old_engineering, old_alice)}, {"data": False})
    assert first.as_dict() == second.as_dict()
    assert first.as_text().index("~ group:engineering") < first.as_text().index("~ user:alice")


def test_acl_inheritance_drift_is_an_update_and_matching_state_is_noop() -> None:
    rule = AclRule("group", "engineering", "allow", "read_write", "all")
    host = Host(
        "test",
        ("/volume1",),
        (
            Share(
                "data",
                "/volume1",
                "",
                0,
                "present",
                EMPTY_NFS,
                AclConfig(True, True, False, (rule,)),
            ),
        ),
    )
    observed = {"data": ObservedShare("data", "/volume1", "", 0, "v1", False)}
    mismatch_acl = AclObservations()
    mismatch_acl["data"] = desired_acl(host.shares[0].acl)
    mismatch_acl.inherited["data"] = False
    matching_acl = AclObservations()
    matching_acl["data"] = desired_acl(host.shares[0].acl)
    matching_acl.inherited["data"] = True
    mismatch = build_plan(host, observed, {}, mismatch_acl)
    matching = build_plan(host, observed, {}, matching_acl)
    missing_metadata = build_plan(host, observed, {}, {"data": desired_acl(host.shares[0].acl)})
    assert [action.kind for action in mismatch.actions] == ["noop", "noop", "update"]
    assert [action.kind for action in matching.actions] == ["noop", "noop", "noop"]
    assert [action.kind for action in missing_metadata.actions] == ["noop", "noop", "unsupported"]


def test_direct_homes_models_are_rejected() -> None:
    with pytest.raises(ValueError, match="homes"):
        Share("homes", "/volume1", "", 0, "absent", EMPTY_NFS, EMPTY_ACL)
    with pytest.raises(ValueError, match="homes"):
        Share("homes", "/volume1", "wanted", 1024, "present", EMPTY_NFS, EMPTY_ACL)


def test_json_actions_escape_control_characters_without_changing_shape() -> None:
    plan = ActionPlan((Action("unsupported", "share:bad\nname", 'unsafe "detail"\x00'),))
    action = cast(dict[str, object], cast(list[object], plan.as_dict()["actions"])[0])
    assert set(action) == {"kind", "resource", "detail", "gated"}
    assert action["resource"] == "share:bad\\nname"
    assert action["detail"] == 'unsafe \\"detail\\"\\u0000'
    encoded = json.dumps(plan.as_dict())
    assert "\nname" not in encoded and "\x00" not in encoded
    compatible = ActionPlan((Action("noop", "share:data", "shared folder matches"),))
    assert compatible.as_dict()["actions"] == [
        {
            "kind": "noop",
            "resource": "share:data",
            "detail": "shared folder matches",
            "gated": False,
        }
    ]
    assert (
        compatible.digest
        == ActionPlan((Action("noop", "share:data", "shared folder matches"),)).digest
    )


def test_reordered_configured_shares_have_stable_plan_and_deletes_last() -> None:
    create = Share("create", "/volume1", "", 0, "present", EMPTY_NFS, EMPTY_ACL)
    delete = Share("delete", "/volume1", "", 0, "absent", EMPTY_NFS, EMPTY_ACL)
    update = Share("update", "/volume2", "new", 0, "present", EMPTY_NFS, EMPTY_ACL)
    observed = {
        "delete": ObservedShare("delete", "/volume1", "", 0, "v1", False),
        "update": ObservedShare("update", "/volume2", "old", 0, "v1", False),
    }
    first = build_plan(
        Host("test", ("/volume1", "/volume2"), (update, delete, create)), observed, {}, {}
    )
    second = build_plan(
        Host("test", ("/volume1", "/volume2"), (create, update, delete)), observed, {}, {}
    )
    assert first.as_dict() == second.as_dict()
    assert [action.resource for action in first.actions] == [
        "share:create",
        "acl:create",
        "share:update",
        "nfs:update",
        "acl:update",
        "share:delete",
    ]
