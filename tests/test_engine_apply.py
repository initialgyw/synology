from __future__ import annotations

from typing import Any, Literal, cast

import pytest

from synology_manager.config import EMPTY_ACL, EMPTY_NFS, Host, Share
from synology_manager.dsm import DsmClient, DsmError, UnsupportedCapability
from synology_manager.engine import ApplyResult, PartialApplyError, _verify_share, apply, plan
from synology_manager.models import ObservedNfsRule, ObservedShare


class ShareClient:
    def __init__(
        self,
        *,
        exists: bool = True,
        description: str = "old",
        quota: object = 1024,
        quota_status: object = "v1",
        fields: dict[str, object] | None = None,
        post_set_fields: dict[str, object] | None = None,
    ) -> None:
        self.exists = exists
        self.description = description
        self.quota = quota
        self.quota_status = quota_status
        self.fields = fields or {}
        self.post_set_fields = post_set_fields or {}
        self.set_payloads: list[dict[str, Any]] = []
        self.calls: list[str] = []

    def require(self, required: dict[str, int]) -> None:
        self.calls.append("require")
        assert "SYNO.Core.Share" in required or required == {
            "SYNO.Core.FileServ.NFS.SharePrivilege": 1
        }

    def list_shares(self) -> list[dict[str, Any]]:
        self.calls.append("list")
        if not self.exists:
            return []
        observed: dict[str, Any] = {
            "name": "data",
            "vol_path": "/volume1",
            "desc": self.description,
            "quota_value": self.quota,
            "share_quota_status": self.quota_status,
        }
        observed.update(self.fields)
        if self.set_payloads:
            observed.update(self.post_set_fields)
        return [observed]

    def acl(self, path: str) -> dict[str, Any]:
        self.calls.append("acl")
        return {
            "acl_editable": True,
            "change_permission": True,
            "is_acl": True,
            "is_inherited": False,
            "acl": [],
        }

    def nfs_enabled(self) -> bool:
        self.calls.append("nfs_enabled")
        return True

    def nfs_rules(self, name: str) -> list[dict[str, Any]]:
        self.calls.append("nfs_rules")
        return []

    def call(
        self, api: str, method: str, params: dict[str, Any], *, version: int
    ) -> dict[str, Any]:
        self.calls.append(method)
        assert api == "SYNO.Core.Share" and version == 1
        if method == "create":
            self.exists = True
            self.description = "wanted"
            return {"name": "data"}
        if method == "validate_set":
            assert params["name"] == "data"
            return {}
        if method == "set":
            self.set_payloads.append(params)
            self.description = params["shareinfo"]["desc"]
            self.quota = params["shareinfo"]["share_quota"]
            return {"name": "data"}
        if method == "validate_delete":
            return {}
        if method == "delete":
            self.exists = False
            return {}
        raise AssertionError(method)


def share(state: Literal["present", "absent"] = "present") -> Share:
    return Share("data", "/volume1", "wanted", 1024, state, EMPTY_NFS, EMPTY_ACL)


def managed_quota(quota_mib: int) -> Share:
    return Share("data", "/volume1", "wanted", quota_mib, "present", EMPTY_NFS, EMPTY_ACL)


def apply_with_plan(client: DsmClient, host: Host) -> ApplyResult:
    return apply(client, host, plan(client, host))


@pytest.mark.parametrize("status", ["v1", "v2"])
@pytest.mark.parametrize(
    ("label", "desired_mib", "initial_mib", "wire_value"),
    [
        ("unlimited", 0, 1024, "0"),
        ("explicit-zero", 0, 1024, "0"),
        ("finite", 4096, 0, 4096),
    ],
)
def test_apply_uses_exact_quota_wire_payload(
    status: str, label: str, desired_mib: int, initial_mib: int, wire_value: int | str
) -> None:
    client = ShareClient(quota=initial_mib, quota_status=status)
    result = apply_with_plan(
        cast(DsmClient, client), Host("test", ("/volume1",), (managed_quota(desired_mib),))
    )
    assert result.applied is True
    assert result.final_plan is not None
    assert all(action.kind == "noop" for action in result.final_plan.actions), label
    assert client.set_payloads == [
        {
            "name": "data",
            "shareinfo": {
                "name": "data",
                "name_org": "",
                "vol_path": "/volume1",
                "desc": "wanted",
                "share_quota": wire_value,
            },
        }
    ]


def test_apply_existing_set_preflights_then_verifies_and_converges() -> None:
    client = ShareClient()
    result = apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (share(),)))
    assert result.applied is True
    assert result.final_plan is not None
    assert all(action.kind == "noop" for action in result.final_plan.actions)
    assert client.calls.index("validate_set") < client.calls.index("set")
    assert client.calls.count("list") >= 4


def test_apply_absent_share_deletes_without_legacy_confirmation_flags() -> None:
    client = ShareClient()
    host = Host("test", ("/volume1",), (share("absent"),))
    result = apply_with_plan(cast(DsmClient, client), host)
    assert result.applied is True
    assert "validate_delete" in client.calls
    assert "delete" in client.calls


def test_apply_absent_share_clears_nfs_without_acl_or_filestation_calls() -> None:
    class AbsentShareClient(ShareClient):
        def __init__(self) -> None:
            super().__init__()
            self.exports = [
                ObservedNfsRule("192.0.2.0/24", "rw", "root", False, False, False, ("sys",)).api()
            ]

        def acl(self, path: str) -> dict[str, Any]:
            raise AssertionError(f"unexpected ACL observation for {path}")

        def resolve_share_file_id(self, name: str, physical: str) -> str:
            raise AssertionError(f"unexpected FileStation lookup for {name}:{physical}")

        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            self.calls.append("nfs_rules")
            assert name == "data"
            return self.exports

        def call(
            self, api: str, method: str, params: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if api == "SYNO.Core.ACL":
                raise AssertionError(f"unexpected ACL call: {method}")
            if api == "SYNO.Core.FileServ.NFS.SharePrivilege":
                assert (method, params, version) == ("save", {"share_name": "data", "rule": []}, 1)
                self.calls.append("nfs_save")
                self.exports = []
                return {}
            return super().call(api, method, params, version=version)

    client = AbsentShareClient()
    result = apply_with_plan(
        cast(DsmClient, client), Host("test", ("/volume1",), (share("absent"),))
    )
    assert result.applied is True
    assert result.final_plan is not None
    assert all(action.kind == "noop" for action in result.final_plan.actions)
    assert client.exports == []
    final_nfs_read = max(index for index, call in enumerate(client.calls) if call == "nfs_rules")
    assert client.calls.index("validate_delete") < final_nfs_read < client.calls.index("delete")
    assert client.calls.index("nfs_save") < client.calls.index("delete")


def test_absent_delete_missing_nfs_capability_blocks_before_delete() -> None:
    class MissingNfsCapabilityClient(ShareClient):
        def require(self, required: dict[str, int]) -> None:
            self.calls.append("require")
            if required == {"SYNO.Core.FileServ.NFS.SharePrivilege": 1}:
                raise UnsupportedCapability("DSM does not support NFS share exports")

        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            raise AssertionError("NFS rules must not load before capability validation")

    client = MissingNfsCapabilityClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (share("absent"),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", "nfs_apply")
    assert "delete" not in client.calls
    assert "validate_delete" not in client.calls


@pytest.mark.parametrize(("quota", "quota_status"), [("malformed", "v1"), (1024, "unsupported")])
def test_unsafe_quota_observation_blocks_validate_set_and_set(
    quota: object, quota_status: object
) -> None:
    client = ShareClient(quota=quota, quota_status=quota_status)
    with pytest.raises(DsmError):
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (share(),)))
    assert "validate_set" not in client.calls
    assert "set" not in client.calls


def test_invalid_programmatic_quota_observation_cannot_reach_apply() -> None:
    client = ShareClient()
    with pytest.raises(DsmError):
        ObservedShare("data", "/volume1", "old", 1024, "unsupported", False)
    assert "validate_set" not in client.calls
    assert "set" not in client.calls


def test_scoped_postcondition_fails_closed_for_malformed_configured_identity() -> None:
    client = ShareClient(fields={"name": None})
    with pytest.raises(
        DsmError,
        match="^observed share name is invalid: api=SYNO.Core.Share method=list version=1$",
    ):
        _verify_share(cast(DsmClient, client), share())


@pytest.mark.parametrize("status", ["v1", "v2"])
def test_share_postcondition_accepts_each_supported_canonical_status(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    import synology_manager.engine as engine

    current = ObservedShare("data", "/volume1", "wanted", 1024, status, False)
    monkeypatch.setattr(engine, "_shares", lambda *args: {"data": current})
    assert _verify_share(cast(DsmClient, object()), share()) == current


@pytest.mark.parametrize(
    "post_set_fields",
    [
        {"quota_value": "malformed"},
        {"shareinfo": {"share_quota": 1024}},
        {"share_quota_status": "unsupported"},
    ],
    ids=["malformed", "conflicting", "unsupported-status"],
)
def test_apply_fails_closed_on_unsafe_post_mutation_quota_observation(
    post_set_fields: dict[str, object],
) -> None:
    client = ShareClient(quota=0, post_set_fields=post_set_fields)
    with pytest.raises(DsmError):
        apply_with_plan(
            cast(DsmClient, client), Host("test", ("/volume1",), (managed_quota(2048),))
        )
    assert "validate_set" in client.calls
    assert "set" in client.calls


@pytest.mark.parametrize("read_only", ["is_readonly", "is_read_only", "is_force_readonly"])
def test_protected_quota_drift_blocks_validate_set_and_set(read_only: str) -> None:
    client = ShareClient(quota=0, fields={read_only: True})
    with pytest.raises(UnsupportedCapability, match="unsupported"):
        apply_with_plan(
            cast(DsmClient, client), Host("test", ("/volume1",), (managed_quota(2048),))
        )
    assert "validate_set" not in client.calls
    assert "set" not in client.calls
