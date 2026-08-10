from __future__ import annotations

from typing import Any

import pytest

from synology_manager.config import EMPTY_NFS, AclConfig, AclRule, Host, Share
from synology_manager.engine import DriftError, _apply_acl, _preflight_acl
from synology_manager.models import ObservedShare, desired_acl
from synology_manager.plan import build_plan
from test_engine import AclClient


def item() -> Share:
    return Share(
        "data",
        "/volume1",
        "wanted",
        1024,
        "present",
        EMPTY_NFS,
        AclConfig(
            True, False, False, (AclRule("special", "Owner", "allow", "full_control", "all"),)
        ),
    )


def test_canonical_group_acl_matching_observation_is_plan_and_apply_noop() -> None:
    acl = AclConfig(
        True, False, False, (AclRule("group", "administrators", "allow", "full_control", "all"),)
    )
    share = Share("data", "/volume1", "wanted", 1024, "present", EMPTY_NFS, acl)
    current = ObservedShare("data", "/volume1", "wanted", 1024, "v1", False)
    client = AclClient(desired_acl(acl))

    plan = build_plan(
        Host("test", ("/volume1",), (share,)),
        {"data": current},
        {},
        {"data": client.rules},
        {"data": False},
    )
    assert any(action.resource == "acl:data" and action.kind == "noop" for action in plan.actions)

    _preflight_acl(client, share, current)  # type: ignore[arg-type]
    _apply_acl(client, share, current)  # type: ignore[arg-type]

    assert client.calls == []


@pytest.mark.parametrize(
    "ids",
    [
        ("/data", "/changed"),
        ("/data", "/data", "/changed"),
        ("/data", "/data", "/data", "/changed"),
    ],
)
def test_acl_identity_drift_blocks_set_or_postcondition(ids: tuple[str, ...]) -> None:
    class PostconditionClient(AclClient):
        def acl(self, path: str) -> dict[str, Any]:
            self.calls.append("get")
            return super().acl(path)

    client = PostconditionClient()
    iterator = iter(ids)
    client.resolve_share_file_id = lambda name, physical: next(iterator)  # type: ignore[method-assign]
    with pytest.raises(DriftError):
        _apply_acl(client, item(), ObservedShare("data", "/volume1", "wanted", 1024, "v1", False))  # type: ignore[arg-type]
    if len(ids) == 2:
        assert "set" not in client.calls
    else:
        assert "set" in client.calls
    if len(ids) == 4:
        assert "get" in client.calls
