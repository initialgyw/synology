from __future__ import annotations

from dataclasses import replace
from typing import Any, Literal, cast

import pytest

from synology_manager.config import EMPTY_ACL, EMPTY_NFS, AclConfig, AclRule, Host, NfsConfig, Share
from synology_manager.dsm import DsmError, UnsupportedCapability
from synology_manager.engine import (
    AclObservations,
    ApplyResult,
    DriftError,
    SafetyError,
    _acl_payload,
    _apply_acl,
    _preflight_acl,
    _save_rules,
    _verify_share,
    apply,
)
from synology_manager.models import ObservedAclRule, ObservedNfsRule, ObservedShare, desired_acl
from synology_manager.plan import Action, ActionPlan


def managed(
    *,
    state: Literal["present", "absent"] = "present",
    nfs: NfsConfig = EMPTY_NFS,
    acl: AclConfig = EMPTY_ACL,
) -> Share:
    return Share("data", "/volume1", "wanted", 1024, state, nfs, acl)


def observed(**changes: object) -> ObservedShare:
    return replace(ObservedShare("data", "/volume1", "wanted", 1024, "v1", False), **changes)  # type: ignore[arg-type]


def rule(client: str = "192.0.2.0/24") -> ObservedNfsRule:
    return ObservedNfsRule(client, "rw", "root", False, False, False, ("sys",))


class NfsClient:
    def __init__(self, rules: tuple[ObservedNfsRule, ...]) -> None:
        self.rules = rules
        self.calls: list[str] = []

    def require(self, required: dict[str, int]) -> None:
        assert required == {"SYNO.Core.FileServ.NFS.SharePrivilege": 1}
        self.calls.append("require")

    def nfs_rules(self, name: str) -> list[dict[str, Any]]:
        assert name == "data"
        self.calls.append("load")
        return [item.api() for item in self.rules]

    def call(
        self, api: str, method: str, parameters: dict[str, Any], *, version: int
    ) -> dict[str, Any]:
        self.calls.append(method)
        assert api.endswith("SharePrivilege") and version == 1
        self.rules = tuple(
            sorted(
                ObservedNfsRule(
                    raw["client"],
                    raw["privilege"],
                    raw["root_squash"],
                    raw["async"],
                    raw["insecure"],
                    raw["crossmnt"],
                    tuple(
                        key
                        for key, wire in {
                            "sys": "sys",
                            "krb5": "kerberos",
                            "krb5i": "kerberos_integrity",
                            "krb5p": "kerberos_privacy",
                        }.items()
                        if raw["security_flavor"][wire]
                    ),
                )
                for raw in parameters["rule"]
            )
        )
        return {"unexpected": "ignored"}


def test_authoritative_nfs_desired_list_removes_omitted_live_rule() -> None:
    desired = NfsConfig(True, ())
    assert managed(nfs=desired).nfs.rules == EMPTY_NFS.rules


def test_save_nfs_checks_original_baseline_and_ignores_callback_data() -> None:
    client = NfsClient((rule(),))
    _save_rules(client, "data", (rule(),), ())  # type: ignore[arg-type]
    assert client.calls == ["require", "load", "save", "require", "load"] and client.rules == ()
    with pytest.raises(DriftError):
        _save_rules(client, "data", (rule(),), ())  # type: ignore[arg-type]


def test_absent_share_normalizes_direct_nfs_configuration() -> None:
    item = Share("data", "/volume1", "", 0, "absent", cast(NfsConfig, "ignored"), EMPTY_ACL)
    assert item.nfs == EMPTY_NFS


def test_apply_result_exposes_expected_and_current_plan_hashes() -> None:
    expected = ActionPlan((Action("noop", "share:data", "matches"),))
    current = ActionPlan((Action("update", "share:data", "changed"),))
    result = ApplyResult(expected, current, False, "stale", current)
    assert result.as_dict()["expected_plan_hash"] == expected.digest
    assert result.as_dict()["current_plan_hash"] == current.digest
    assert result.as_dict()["pre_apply_plan"] == expected.as_dict()
    assert result.as_dict()["current_plan"] == current.as_dict()


def test_stale_apply_returns_displayed_and_current_plans_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import synology_manager.engine as engine

    expected = ActionPlan((Action("noop", "share:data", "expected"),))
    current = ActionPlan((Action("update", "share:data", "current"),))
    monkeypatch.setattr(engine, "observe", lambda *args: ({}, {}, AclObservations()))
    monkeypatch.setattr(engine, "build_plan", lambda *args: current)
    calls: list[str] = []

    class Client:
        def require(self, required: dict[str, int]) -> None:
            calls.append("require")

    result = apply(Client(), Host("test", ("/volume1",), ()), expected)  # type: ignore[arg-type]
    assert result.status == "stale" and result.applied is False
    assert result.pre_apply_plan is expected and result.current_plan is current
    assert result.expected_plan_hash == expected.digest
    assert result.current_plan_hash == current.digest
    assert calls == []


def test_share_postcondition_rejects_rename_volume_protection_and_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import synology_manager.engine as engine

    monkeypatch.setattr(engine, "_shares", lambda *args: {"data": observed()})
    assert _verify_share(object(), managed()) == observed()  # type: ignore[arg-type]
    monkeypatch.setattr(engine, "_shares", lambda *args: {"renamed": observed(name="renamed")})
    with pytest.raises(DriftError):
        _verify_share(object(), managed())  # type: ignore[arg-type]
    monkeypatch.setattr(engine, "_shares", lambda *args: {"data": observed()})
    with pytest.raises(DriftError):
        _verify_share(object(), managed(), absent=True)  # type: ignore[arg-type]


class AclClient:
    def __init__(self, rules: tuple[ObservedAclRule, ...] = ()) -> None:
        self.rules = rules
        self.inherited = False
        self.calls: list[str] = []

    def acl(self, path: str) -> dict[str, Any]:
        return {
            "acl_editable": True,
            "change_permission": True,
            "is_acl": True,
            "is_inherited": self.inherited,
            "acl": [
                {
                    "level": 0,
                    "owner_type": x.owner_type,
                    "owner_name": x.owner_name,
                    "permission_type": x.permission_type,
                    "permission": dict(
                        zip(
                            (
                                "read_data",
                                "write_data",
                                "exe_file",
                                "append_data",
                                "delete",
                                "delete_sub",
                                "read_attr",
                                "write_attr",
                                "read_ext_attr",
                                "write_ext_attr",
                                "read_perm",
                                "change_perm",
                                "take_ownership",
                            ),
                            x.permissions,
                            strict=True,
                        )
                    ),
                    "inherit": dict(
                        zip(
                            ("child_files", "child_folders", "this_folder", "all_descendants"),
                            x.inheritance,
                            strict=True,
                        )
                    ),
                }
                for x in self.rules
            ],
        }

    def resolve_share_file_id(self, name: str, physical: str) -> str:
        self.calls.append("resolve")
        assert (name, physical) == ("data", "/volume1/data")
        return "/data"

    def call(
        self, api: str, method: str, params: dict[str, Any], *, version: int
    ) -> dict[str, Any]:
        self.calls.append(method)
        assert api == "SYNO.Core.ACL" and version == 1
        if method == "set":
            self.rules = (ObservedAclRule("special", "Owner", "allow", (True,) * 13, (True,) * 4),)
        return {}


def test_acl_precheck_set_and_canonical_postcondition() -> None:
    acl = AclConfig(
        True, False, True, (AclRule("special", "Owner", "allow", "full_control", "all"),)
    )
    client = AclClient()
    item = managed(acl=acl)
    _preflight_acl(client, item, observed())  # type: ignore[arg-type]
    _apply_acl(client, item, observed())  # type: ignore[arg-type]
    assert client.calls == [
        "resolve",
        "check_self_denied",
        "resolve",
        "check_self_denied",
        "resolve",
        "set",
        "resolve",
        "resolve",
    ]
    payload = _acl_payload(item, observed(), "/data")
    assert payload["acl_recur"] is True and payload["inherited"] is False


def test_acl_payload_contract_covers_explicit_empty_inherited_and_recursive_targets() -> None:
    fixture = ObservedShare("fixture-share", "/volume9", "", 0, "v1", False)
    explicit = Share(
        "fixture-share",
        "/volume9",
        "",
        0,
        "present",
        EMPTY_NFS,
        AclConfig(
            True,
            False,
            False,
            (AclRule("group", "fixture-group", "allow", "read_only", "children"),),
        ),
    )
    inherited_recursive = Share(
        "fixture-share",
        "/volume9",
        "",
        0,
        "present",
        EMPTY_NFS,
        AclConfig(
            True, True, True, (AclRule("user", "fixture-user", "deny", "full_control", "all"),)
        ),
    )

    explicit_payload = _acl_payload(explicit, fixture, "/fixture-id")
    assert explicit_payload == {
        "file_path": "/volume9/fixture-share",
        "files": "/volume9/fixture-share",
        "dirPaths": "/fixture-id",
        "change_acl": True,
        "rules": [
            {
                "owner_type": "group",
                "owner_name": "fixture-group",
                "permission_type": "allow",
                "permission": {
                    "read_data": True,
                    "write_data": False,
                    "exe_file": True,
                    "append_data": False,
                    "delete": False,
                    "delete_sub": False,
                    "read_attr": True,
                    "write_attr": False,
                    "read_ext_attr": True,
                    "write_ext_attr": False,
                    "read_perm": True,
                    "change_perm": False,
                    "take_ownership": False,
                },
                "inherit": {
                    "child_files": True,
                    "child_folders": True,
                    "this_folder": False,
                    "all_descendants": False,
                },
            }
        ],
        "inherited": False,
        "acl_recur": False,
    }
    assert {key: type(value) for key, value in explicit_payload.items()} == {
        "file_path": str,
        "files": str,
        "dirPaths": str,
        "change_acl": bool,
        "rules": list,
        "inherited": bool,
        "acl_recur": bool,
    }

    empty = Share("fixture-share", "/volume9", "", 0, "present", EMPTY_NFS, EMPTY_ACL)
    empty_payload = _acl_payload(empty, fixture, "/fixture-id")
    assert empty_payload == {
        "file_path": "/volume9/fixture-share",
        "files": "/volume9/fixture-share",
        "dirPaths": "/fixture-id",
        "change_acl": True,
        "rules": [],
        "inherited": False,
        "acl_recur": False,
    }

    inherited_recursive_payload = _acl_payload(inherited_recursive, fixture, "/fixture-id")
    assert inherited_recursive_payload["inherited"] is True
    assert inherited_recursive_payload["acl_recur"] is True
    assert inherited_recursive_payload["rules"][0]["owner_type"] == "user"
    assert inherited_recursive_payload["rules"][0]["permission_type"] == "deny"


@pytest.mark.parametrize(
    ("response", "error_type"),
    [
        ({}, None),
        ({"warning": "fixture"}, UnsupportedCapability),
        (
            DsmError(
                "DSM API error",
                code="6211",
                api="SYNO.Core.ACL",
                method="check_self_denied",
                version=1,
            ),
            DsmError,
        ),
        (None, UnsupportedCapability),
    ],
    ids=["success", "non_empty", "code_6211", "malformed"],
)
def test_acl_self_denial_failure_matrix_stops_before_set(
    response: object, error_type: type[Exception] | None
) -> None:
    item = managed(
        acl=AclConfig(
            True, False, False, (AclRule("special", "Owner", "allow", "full_control", "all"),)
        )
    )

    class ResponseClient(AclClient):
        def call(
            self, api: str, method: str, params: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            self.calls.append(method)
            assert (api, version) == ("SYNO.Core.ACL", 1)
            if method == "check_self_denied":
                if isinstance(response, Exception):
                    raise response
                return response  # type: ignore[return-value]
            assert method == "set"
            self.rules = desired_acl(item.acl)
            return {}

    client = ResponseClient()
    if error_type is None:
        _apply_acl(client, item, observed())  # type: ignore[arg-type]
        assert "set" in client.calls
        return

    with pytest.raises(error_type) as raised:
        _apply_acl(client, item, observed())  # type: ignore[arg-type]
    assert "set" not in client.calls
    assert isinstance(raised.value, DsmError)
    assert raised.value.operation() == {
        "api": "SYNO.Core.ACL",
        "method": "check_self_denied",
        "version": 1,
    }


def test_direct_acl_requires_authoritative_configuration() -> None:
    with pytest.raises(ValueError):
        AclConfig(
            False, False, False, (AclRule("special", "Owner", "allow", "full_control", "all"),)
        )


def test_inherited_acl_requires_true_observation_before_acl_calls() -> None:
    acl = AclConfig(True, True, False, ())
    item = managed(acl=acl)
    for operation in (_preflight_acl, _apply_acl):
        client = AclClient()
        with pytest.raises(SafetyError, match="inheritance must be observed as true"):
            operation(client, item, observed())  # type: ignore[arg-type]
        assert client.calls == []
    matching = AclClient()
    matching.inherited = True
    _preflight_acl(matching, item, observed())  # type: ignore[arg-type]
    _apply_acl(matching, item, observed())  # type: ignore[arg-type]
    assert matching.calls == []


def test_missing_inherited_acl_metadata_fails_before_acl_calls() -> None:
    class MissingInheritedClient(AclClient):
        def acl(self, path: str) -> dict[str, Any]:
            response = super().acl(path)
            response.pop("is_inherited")
            return response

    client = MissingInheritedClient()
    item = managed(acl=AclConfig(True, True, False, ()))
    with pytest.raises(UnsupportedCapability, match="not safely editable"):
        _preflight_acl(client, item, observed())  # type: ignore[arg-type]
    assert client.calls == []


def test_ambiguous_acl_replacement_fails_before_acl_calls() -> None:
    allow = ObservedAclRule("special", "Owner", "allow", (False,) * 13, (False,) * 4)
    deny = ObservedAclRule("special", "Owner", "deny", (False,) * 13, (False,) * 4)
    item = managed(
        acl=AclConfig(
            True, False, False, (AclRule("special", "Owner", "allow", "full_control", "all"),)
        )
    )
    current = observed()
    for operation in (_preflight_acl, _apply_acl):
        client = AclClient((allow, deny))
        with pytest.raises(SafetyError, match="multiple rules for one principal"):
            operation(client, item, current)  # type: ignore[arg-type]
        assert client.calls == []


def test_identical_ambiguous_acl_state_is_a_safe_noop() -> None:
    allow = AclRule("special", "Owner", "allow", "read_only", "none")
    deny = AclRule("special", "Owner", "deny", "read_only", "none")
    acl = AclConfig(True, False, False, (allow, deny))
    rules = desired_acl(acl)
    client = AclClient(rules)
    _preflight_acl(client, managed(acl=acl), observed())  # type: ignore[arg-type]
    _apply_acl(client, managed(acl=acl), observed())  # type: ignore[arg-type]
    assert client.calls == []


def test_apply_stops_before_mutation_when_existing_preflight_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import synology_manager.engine as engine

    host = Host("test", ("/volume1",), (managed(),))
    current = observed(description="old")
    monkeypatch.setattr(engine, "observe", lambda client, host: ({"data": current}, {}, {}))
    monkeypatch.setattr(
        engine, "build_plan", lambda *args: ActionPlan((Action("update", "share:data", "update"),))
    )
    calls: list[str] = []

    class Client:
        def require(self, required: dict[str, int]) -> None:
            calls.append("require")

        def call(
            self, api: str, method: str, parameters: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            calls.append(method)
            return {"warning": "no"}

    expected = ActionPlan((Action("update", "share:data", "update"),))
    with pytest.raises(UnsupportedCapability):
        apply(Client(), host, expected)  # type: ignore[arg-type]
    assert calls == ["require", "validate_set"]
