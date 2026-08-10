from __future__ import annotations

import json

import pytest

from synology_manager.config import (
    EMPTY_ACL,
    EMPTY_NFS,
    AclConfig,
    AclRule,
    Host,
    NfsConfig,
    NfsRule,
    Share,
)
from synology_manager.models import (
    ObservedAclRule,
    ObservedNfsRule,
    ObservedShare,
    acl_api,
    desired_acl,
)
from synology_manager.plan import build_plan


def test_plan_models_nfs_acl_and_protected_volume_cases() -> None:
    nfs = NfsConfig(
        True,
        (NfsRule("192.0.2.0/24", "rw", "root", False, False, False, ("sys",)),),
    )
    acl = AclConfig(
        True, False, False, (AclRule("special", "Owner", "allow", "full_control", "all"),)
    )
    host = Host("x", ("/volume1",), (Share("data", "/volume1", "wanted", 1, "present", nfs, acl),))
    current = ObservedShare("data", "/volume1", "old", 0, "v1", False)
    actions = build_plan(host, {"data": current}, {"data": ()}, {"data": ()}).actions
    assert {action.resource for action in actions} == {"share:data", "nfs:data", "acl:data"}
    protected = build_plan(
        host, {"data": ObservedShare("data", "/volume1", "", 0, "v1", True)}, {}, {}
    ).actions
    assert protected[0].kind == "unsupported"
    moved = build_plan(
        host, {"data": ObservedShare("data", "/volume2", "", 0, "v1", False)}, {}, {}
    ).actions
    assert moved[0].kind == "unsupported"
    assert desired_acl(acl) and acl_api(acl)[0]["owner_name"] == "Owner"


def test_plan_authoritatively_removes_live_rule_omitted_from_desired_list() -> None:
    host = Host(
        "x",
        ("/volume1",),
        (Share("data", "/volume1", "", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    baseline = (ObservedNfsRule("192.0.2.0/24", "rw", "root", False, False, False, ("sys",)),)
    plan = build_plan(
        host,
        {"data": ObservedShare("data", "/volume1", "", 0, "v1", False)},
        {"data": baseline},
        {},
        {"data": False},
    )
    assert any(action.resource == "nfs:data" and action.kind == "delete" for action in plan.actions)


def test_new_share_text_plan_has_dependent_nfs_and_acl_children() -> None:
    nfs = NfsConfig(
        True,
        (NfsRule("192.0.2.0/24", "rw", "root", True, False, False, ("sys",)),),
    )
    acl = AclConfig(
        True, False, False, (AclRule("group", "engineering", "allow", "read_write", "all"),)
    )
    host = Host(
        "x",
        ("/volume1",),
        (Share("project-data", "/volume1", "Managed project data", 20480, "present", nfs, acl),),
    )
    plan = build_plan(host, {}, {}, {})
    assert [action.kind for action in plan.actions] == ["create", "create", "create"]
    assert plan.as_dict()["actions"] == [
        {
            "kind": "create",
            "resource": "share:project-data",
            "detail": "create shared folder",
            "gated": False,
        },
        {
            "kind": "create",
            "resource": "nfs:project-data",
            "detail": "replace authoritative NFS exports",
            "gated": False,
        },
        {
            "kind": "create",
            "resource": "acl:project-data",
            "detail": "replace ACL recursively=False",
            "gated": False,
        },
    ]
    assert plan.as_text().splitlines()[2] == "share:project-data [create]"
    assert "  nfs:project-data [create; after share verification]" in plan.as_text()
    assert "  acl:project-data [create; after share verification]" in plan.as_text()
    assert (
        "+ group:engineering effect=allow permissions=read_write inheritance=all" in plan.as_text()
    )


def test_existing_plan_displays_quota_nfs_and_acl_deltas() -> None:
    desired_nfs_rule = NfsRule("192.0.2.2/32", "rw", "root", True, False, False, ("sys",))
    removed_nfs = ObservedNfsRule("192.0.2.1/32", "ro", "guest", False, True, False, ("sys",))
    old_nfs = ObservedNfsRule("192.0.2.2/32", "ro", "root", False, False, False, ("sys",))
    desired_rule = AclRule("group", "engineering", "allow", "read_write", "all")
    old_acl = ObservedAclRule("group", "old", "allow", (True,) + (False,) * 12, (False,) * 4)
    changed_acl = ObservedAclRule(
        "group", "engineering", "allow", (True,) + (False,) * 12, (False,) * 4
    )
    host = Host(
        "x",
        ("/volume1",),
        (
            Share(
                "data",
                "/volume1",
                "same",
                20480,
                "present",
                NfsConfig(
                    True,
                    (desired_nfs_rule,),
                ),
                AclConfig(True, True, True, (desired_rule,)),
            ),
        ),
    )
    plan = build_plan(
        host,
        {"data": ObservedShare("data", "/volume1", "same", 10240, "v1", False)},
        {"data": (removed_nfs, old_nfs)},
        {"data": (old_acl, changed_acl)},
        {"data": False},
    )
    text = plan.as_text()
    assert "quota: 10240 MiB -> 20480 MiB" in text
    assert "- 192.0.2.1/32" in text and "~ 192.0.2.2/32" in text
    assert "- group:old" in text and "~ group:engineering" in text
    assert "inherit_parent=true recursive=true" in text


def test_text_plan_is_control_safe_and_noop_is_explicit() -> None:
    host = Host(
        "x",
        ("/volume1",),
        (Share("data", "/volume1", "wanted", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    plan = build_plan(
        host, {"data": ObservedShare("data", "/volume1", "old\nvalue", 0, "v1", False)}, {}, {}
    )
    assert 'description: "old\\nvalue" -> "wanted"' in plan.as_text()
    matching = build_plan(
        host, {"data": ObservedShare("data", "/volume1", "wanted", 0, "v1", False)}, {}, {}
    )
    assert "share:data [noop]" in matching.as_text()


@pytest.mark.parametrize(
    "description", ["plain", 'quote"value', "line\nbreak", "tab\tvalue", "unicode-✓", ""]
)
def test_text_plan_escapes_observed_description(description: str) -> None:
    host = Host(
        "x",
        ("/volume1",),
        (Share("data", "/volume1", "wanted", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    plan = build_plan(
        host, {"data": ObservedShare("data", "/volume1", description, 0, "v1", False)}, {}, {}
    )
    assert (
        f'description: {json.dumps(description, ensure_ascii=True)} -> "wanted"' in plan.as_text()
    )


def test_plan_order_and_hash_are_stable_for_reordered_observations() -> None:
    nfs = NfsConfig(
        True,
        (
            NfsRule("198.51.100.0/24", "rw", "root", False, False, False, ("sys",)),
            NfsRule("192.0.2.0/24", "rw", "root", False, False, False, ("sys",)),
        ),
    )
    host = Host("x", ("/volume1",), (Share("data", "/volume1", "", 0, "present", nfs, EMPTY_ACL),))
    observed = {"data": ObservedShare("data", "/volume1", "", 0, "v1", False)}
    first = build_plan(host, observed, {"data": ()}, {})
    second = build_plan(host, observed, {"data": tuple(reversed(()))}, {})
    assert first.as_dict() == second.as_dict()
