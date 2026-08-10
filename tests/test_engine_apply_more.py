from __future__ import annotations

from typing import Any, cast

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
from synology_manager.dsm import DsmClient, DsmError, UnsupportedCapability
from synology_manager.engine import (
    DriftError,
    PartialApplyError,
    _acl_response,
    _apply_acl,
    _contextualize,
    _normalized_nfs_rules,
    _required,
    _save_rules,
    _shares,
    _verify_share,
    apply,
    observe,
)
from synology_manager.engine import plan as engine_plan
from synology_manager.models import ObservedShare, acl_api, desired_nfs
from synology_manager.plan import Action, ActionPlan
from test_engine_apply import ShareClient, apply_with_plan, share


def test_normalization_errors_keep_fixed_operation_context() -> None:
    class InvalidSharesClient:
        def list_shares(self) -> list[dict[str, object]]:
            return [{"name": None, "vol_path": "/volume1", "desc": "raw=/private"}]

    with pytest.raises(DsmError) as share_error:
        _shares(InvalidSharesClient(), frozenset({"data"}))  # type: ignore[arg-type]
    assert share_error.value.operation() == {
        "api": "SYNO.Core.Share",
        "method": "list",
        "version": 1,
    }
    assert "private" not in str(share_error.value)

    with pytest.raises(DsmError) as nfs_error:
        _normalized_nfs_rules([{"client": "raw=/private"}])
    assert nfs_error.value.operation() == {
        "api": "SYNO.Core.FileServ.NFS.SharePrivilege",
        "method": "load",
        "version": 1,
    }
    assert "private" not in str(nfs_error.value)

    class InvalidAclClient:
        def acl(self, path: str) -> dict[str, object]:
            return {
                "acl_editable": True,
                "change_permission": True,
                "is_acl": True,
                "is_inherited": False,
                "acl": [{"owner_name": "raw=/private"}],
            }

    with pytest.raises(DsmError) as acl_error:
        _acl_response(InvalidAclClient(), ObservedShare("data", "/volume1", "", 0, "v2", False))  # type: ignore[arg-type]
    assert acl_error.value.operation() == {"api": "SYNO.Core.ACL", "method": "get", "version": 1}
    assert "private" not in str(acl_error.value)


def test_contextualize_replaces_existing_context_without_duplication() -> None:
    error = DsmError("stable message", api="SYNO.Core.Share", method="list", version=1)
    contextual = _contextualize(error, api="SYNO.Core.ACL", method="get", version=1)

    assert str(contextual) == "stable message: api=SYNO.Core.ACL method=get version=1"
    assert str(contextual).count("api=") == 1


def test_partial_apply_text_uses_stable_cause_once_without_raw_detail() -> None:
    safe = PartialApplyError(
        "share:data",
        "share_create",
        DsmError(
            "unexpected share create response", api="SYNO.Core.Share", method="create", version=1
        ),
    )
    assert str(safe).count("unexpected share create response") == 1
    assert "phase=share_create" in str(safe)
    assert "recovery=rerun_apply_after_resolving_failure" in str(safe)

    raw = PartialApplyError(
        "share:data",
        "share_create",
        DsmError(
            "detail=/volume1/private password=secret",
            api="SYNO.Core.Share",
            method="create",
            version=1,
        ),
    )
    arbitrary = PartialApplyError(
        "share:data",
        "share_create",
        DsmError("arbitrary DSM text from NAS", api="SYNO.Core.Share", method="create", version=1),
    )
    assert "private" not in str(raw) and "secret" not in str(raw)
    assert "arbitrary DSM text from NAS" not in str(arbitrary)


def test_share_and_nfs_postconditions_have_fixed_context(monkeypatch: pytest.MonkeyPatch) -> None:
    import synology_manager.engine as engine

    monkeypatch.setattr(engine, "_shares", lambda *args: {})
    with pytest.raises(DriftError) as share_error:
        _verify_share(object(), share())  # type: ignore[arg-type]
    assert share_error.value.operation() == {
        "api": "SYNO.Core.Share",
        "method": "list",
        "version": 1,
    }

    class NfsClient:
        def require(self, required: dict[str, int]) -> None:
            assert required == {"SYNO.Core.FileServ.NFS.SharePrivilege": 1}

        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            return []

    monkeypatch.setattr(engine, "_normalized_nfs_rules", lambda raw: ("changed",))
    with pytest.raises(DriftError) as nfs_error:
        _save_rules(NfsClient(), "private-share", (), ())  # type: ignore[arg-type]
    assert nfs_error.value.operation() == {
        "api": "SYNO.Core.FileServ.NFS.SharePrivilege",
        "method": "load",
        "version": 1,
    }
    assert "private" not in str(nfs_error.value)


def test_nfs_service_disabled_has_nfs_status_context() -> None:
    nfs = NfsConfig(True, (NfsRule("192.0.2.0/24", "rw", "root", False, False, False, ("sys",)),))
    item = Share("data", "/volume1", "wanted", 1024, "present", nfs, EMPTY_ACL)

    class DisabledNfsClient(ShareClient):
        def nfs_enabled(self) -> bool:
            return False

    with pytest.raises(UnsupportedCapability) as raised:
        observe(DisabledNfsClient(), Host("test", ("/volume1",), (item,)))  # type: ignore[arg-type]
    assert raised.value.operation() == {
        "api": "SYNO.Core.FileServ.NFS",
        "method": "get",
        "version": 3,
    }


def test_empty_or_absent_nfs_never_requires_or_queries_global_service() -> None:
    empty = Share("empty", "/volume1", "", 0, "present", EMPTY_NFS, EMPTY_ACL)
    absent = Share("absent", "/volume1", "", 0, "absent", EMPTY_NFS, EMPTY_ACL)
    host = Host("test", ("/volume1",), (empty, absent))
    assert _required(host) == {
        "SYNO.Core.Share": 1,
        "SYNO.Core.FileServ.NFS.SharePrivilege": 1,
        "SYNO.Core.ACL": 1,
        "SYNO.FileStation.List": 2,
    }

    class GlobalUnavailableClient(ShareClient):
        def nfs_enabled(self) -> bool:
            raise AssertionError("empty or absent NFS must not query global service")

        def list_shares(self) -> list[dict[str, Any]]:
            return [
                {
                    "name": name,
                    "vol_path": "/volume1",
                    "desc": "",
                    "quota_value": 0,
                    "share_quota_status": "v1",
                }
                for name in ("empty", "absent")
            ]

    observed, nfs, _ = observe(GlobalUnavailableClient(), host)  # type: ignore[arg-type]
    assert set(observed) == {"empty", "absent"}
    assert nfs == {"empty": ()}


def test_absent_only_observation_and_plan_skip_nfs_capability_and_actions() -> None:
    absent = Share("data", "/volume1", "", 0, "absent", EMPTY_NFS, EMPTY_ACL)
    host = Host("test", ("/volume1",), (absent,))

    class AbsentOnlyClient(ShareClient):
        def __init__(self) -> None:
            super().__init__()
            self.required: list[dict[str, int]] = []

        def require(self, required: dict[str, int]) -> None:
            self.required.append(required)
            assert required == {"SYNO.Core.Share": 1}

        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            raise AssertionError(f"unexpected NFS observation for {name}")

        def acl(self, path: str) -> dict[str, Any]:
            raise AssertionError(f"unexpected ACL observation for {path}")

    client = AbsentOnlyClient()
    observed, nfs, acl = observe(cast(DsmClient, client), host)
    assert set(observed) == {"data"}
    assert nfs == {} and not acl
    assert client.required == [{"SYNO.Core.Share": 1}]
    actions = engine_plan(cast(DsmClient, client), host).actions
    assert [(action.resource, action.kind) for action in actions] == [("share:data", "delete")]
    assert client.required == [{"SYNO.Core.Share": 1}, {"SYNO.Core.Share": 1}]


def test_final_existing_share_disappearance_has_list_context() -> None:
    class DisappearingClient(ShareClient):
        def __init__(self) -> None:
            super().__init__()
            self.list_calls = 0

        def list_shares(self) -> list[dict[str, Any]]:
            self.list_calls += 1
            if self.list_calls == 3:
                return []
            return super().list_shares()

    with pytest.raises(DriftError) as raised:
        apply_with_plan(DisappearingClient(), Host("test", ("/volume1",), (share(),)))  # type: ignore[arg-type]
    assert raised.value.operation() == {
        "api": "SYNO.Core.Share",
        "method": "list",
        "version": 1,
    }


def test_acl_identity_postcondition_has_filestation_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import synology_manager.engine as engine

    acl = AclConfig(
        True, False, False, (AclRule("group", "engineering", "allow", "read_only", "all"),)
    )
    item = Share("data", "/volume1", "wanted", 0, "present", EMPTY_NFS, acl)
    current = ObservedShare("data", "/volume1", "", 0, "v2", False)
    monkeypatch.setattr(engine, "_acl_response", lambda *args: ((), False))

    class ChangedIdentityClient:
        def __init__(self) -> None:
            self.calls = 0

        def resolve_share_file_id(self, name: str, physical: str) -> str:
            self.calls += 1
            return "/id" if self.calls == 1 else "/changed"

        def call(
            self, api: str, method: str, params: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            assert (api, method, version) == ("SYNO.Core.ACL", "check_self_denied", 1)
            return {}

    with pytest.raises(DriftError) as raised:
        _apply_acl(ChangedIdentityClient(), item, current)  # type: ignore[arg-type]
    assert raised.value.operation() == {
        "api": "SYNO.FileStation.List",
        "method": "getinfo",
        "version": 2,
    }


def test_final_acl_convergence_error_has_acl_observation_context() -> None:
    class FinalAclMismatchClient(ShareClient):
        def __init__(self) -> None:
            super().__init__()
            self.acl_reads = 0

        def acl(self, path: str) -> dict[str, Any]:
            self.acl_reads += 1
            response = super().acl(path)
            response["is_inherited"] = self.acl_reads < 5
            return response

    item = Share(
        "data",
        "/volume1",
        "wanted",
        1024,
        "present",
        EMPTY_NFS,
        AclConfig(True, True, False, ()),
    )
    with pytest.raises(DriftError) as raised:
        apply_with_plan(FinalAclMismatchClient(), Host("test", ("/volume1",), (item,)))  # type: ignore[arg-type]

    assert raised.value.operation() == {"api": "SYNO.Core.ACL", "method": "get", "version": 1}


def test_final_residual_plan_error_has_safe_list_context(monkeypatch: pytest.MonkeyPatch) -> None:
    import synology_manager.engine as engine

    plans = [
        ActionPlan(()),
        ActionPlan((Action("update", "share:raw=/private", "sid=secret path=/volume1/private"),)),
    ]
    monkeypatch.setattr(engine, "observe", lambda *args: ({}, {}, engine.AclObservations()))
    monkeypatch.setattr(engine, "build_plan", lambda *args: plans.pop(0))

    class Client:
        def require(self, required: dict[str, int]) -> None:
            assert required == {"SYNO.Core.Share": 1}

    with pytest.raises(DriftError) as raised:
        apply(Client(), Host("test", ("/volume1",), ()), ActionPlan(()))  # type: ignore[arg-type]

    assert raised.value.operation() == {"api": "SYNO.Core.Share", "method": "list", "version": 1}
    assert (
        str(raised.value)
        == "final state did not converge: api=SYNO.Core.Share method=list version=1"
    )
    assert "private" not in str(raised.value) and "secret" not in str(raised.value)


def test_apply_create_has_exact_response_and_immediate_readback() -> None:
    client = ShareClient(exists=False)
    result = apply_with_plan(client, Host("test", ("/volume1",), (share(),)))  # type: ignore[arg-type]
    assert result.applied is True
    assert result.final_plan is not None
    assert result.final_plan.actions[0].kind == "noop"
    assert client.calls.index("create") < client.calls.index(
        "list", client.calls.index("create") + 1
    )


def test_new_share_appearance_before_create_aborts_without_create() -> None:
    class AppearingClient(ShareClient):
        def __init__(self) -> None:
            super().__init__(exists=False)
            self.list_calls = 0

        def list_shares(self) -> list[dict[str, Any]]:
            self.list_calls += 1
            if self.list_calls == 3:
                self.exists = True
            return super().list_shares()

    client = AppearingClient()
    with pytest.raises(DriftError, match="appeared before creation") as raised:
        apply_with_plan(client, Host("test", ("/volume1",), (share(),)))  # type: ignore[arg-type]
    assert raised.value.operation() == {"api": "SYNO.Core.Share", "method": "list", "version": 1}
    assert "create" not in client.calls


def test_apply_owned_delete_preflights_and_deletes_last() -> None:
    client = ShareClient()
    absent = Share("data", "/volume1", "wanted", 1024, "absent", EMPTY_NFS, EMPTY_ACL)
    result = apply_with_plan(client, Host("test", ("/volume1",), (absent,)))  # type: ignore[arg-type]
    assert result.applied is True
    assert result.final_plan is not None
    assert result.final_plan.actions[0].kind == "noop"
    assert client.calls.index("validate_delete") < client.calls.index("delete")


def test_new_share_partial_phase_preserves_safe_operation_context() -> None:
    class FailingCreateClient(ShareClient):
        def __init__(self) -> None:
            super().__init__(exists=False)

        def call(
            self, api: str, method: str, params: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if method == "create":
                raise DsmError(
                    "DSM API error",
                    code="6211",
                    api=api,
                    method=method,
                    version=version,
                )
            return super().call(api, method, params, version=version)

    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(FailingCreateClient(), Host("test", ("/volume1",), (share(),)))  # type: ignore[arg-type]

    error = raised.value
    assert (error.resource, error.phase, error.recovery) == (
        "share:data",
        "share_create",
        "rerun_apply_after_resolving_failure",
    )
    assert error.operation() == {"api": "SYNO.Core.Share", "method": "create", "version": 1}
    assert str(error).endswith("code=6211 api=SYNO.Core.Share method=create version=1")


def test_new_share_unexpected_create_response_keeps_phase_context() -> None:
    class BadCreateClient(ShareClient):
        def __init__(self) -> None:
            super().__init__(exists=False)

        def call(
            self, api: str, method: str, params: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if method == "create":
                return {"name": "raw=/private"}
            return super().call(api, method, params, version=version)

    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(BadCreateClient(), Host("test", ("/volume1",), (share(),)))  # type: ignore[arg-type]

    assert raised.value.phase == "share_create"
    assert raised.value.operation() == {
        "api": "SYNO.Core.Share",
        "method": "create",
        "version": 1,
    }
    assert "private" not in str(raised.value)


def test_existing_share_unexpected_set_response_is_a_contextual_partial_phase() -> None:
    class BadSetClient(ShareClient):
        def call(
            self, api: str, method: str, params: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if method == "set":
                return {"name": "raw=/private"}
            return super().call(api, method, params, version=version)

    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(BadSetClient(), Host("test", ("/volume1",), (share(),)))  # type: ignore[arg-type]

    assert raised.value.phase == "share_set"
    assert raised.value.operation() == {"api": "SYNO.Core.Share", "method": "set", "version": 1}
    assert "private" not in str(raised.value)


class NewShareChildrenClient(ShareClient):
    def __init__(self, nfs: NfsConfig, acl: AclConfig) -> None:
        super().__init__(exists=False)
        self.nfs = nfs
        self.acl_config = acl
        self.nfs_saved = False
        self.acl_saved = False
        self.inherited = acl.inherit_parent

    def nfs_rules(self, name: str) -> list[dict[str, Any]]:
        self.calls.append("nfs_rules")
        assert name == "data"
        if not self.nfs_saved:
            return []
        return [desired_nfs(rule).api() for rule in self.nfs.rules]

    def acl(self, path: str) -> dict[str, Any]:
        assert path == "/volume1/data"
        rules = acl_api(self.acl_config) if self.acl_saved else []
        return {
            "acl_editable": True,
            "change_permission": True,
            "is_acl": True,
            "is_inherited": self.inherited,
            "acl": [{"level": 0, **rule} for rule in rules],
        }

    def resolve_share_file_id(self, name: str, physical: str) -> str:
        self.calls.append("resolve")
        assert (name, physical) == ("data", "/volume1/data")
        return "/data"

    def call(
        self, api: str, method: str, params: dict[str, Any], *, version: int
    ) -> dict[str, Any]:
        if api == "SYNO.Core.FileServ.NFS.SharePrivilege":
            assert method == "save" and version == 1
            self.calls.append("nfs_save")
            self.nfs_saved = True
            return {}
        if api == "SYNO.Core.ACL":
            assert version == 1
            if method == "check_self_denied":
                self.calls.append("acl_check")
                return {}
            assert method == "set"
            self.calls.append("acl_set")
            self.acl_saved = True
            self.inherited = self.acl_config.inherit_parent
            return {}
        return super().call(api, method, params, version=version)


def test_apply_new_share_children_are_postconditioned_and_converge() -> None:
    nfs = NfsConfig(
        True,
        (NfsRule("192.0.2.0/24", "rw", "root", True, False, False, ("sys",)),),
    )
    acl = AclConfig(
        True, True, False, (AclRule("group", "engineering", "allow", "read_write", "all"),)
    )
    item = Share("data", "/volume1", "wanted", 1024, "present", nfs, acl)
    client = NewShareChildrenClient(nfs, acl)
    result = apply_with_plan(client, Host("test", ("/volume1",), (item,)))  # type: ignore[arg-type]
    assert result.applied is True
    assert result.final_plan is not None
    assert [action.kind for action in result.final_plan.actions] == ["noop", "noop", "noop"]
    assert (
        client.calls.index("create")
        < client.calls.index("nfs_save")
        < client.calls.index("acl_set")
    )
    assert client.nfs_saved and client.acl_saved and client.inherited


def test_apply_new_share_fails_before_convergence_when_nfs_postcondition_fails() -> None:
    nfs = NfsConfig(
        True,
        (NfsRule("192.0.2.0/24", "rw", "root", True, False, False, ("sys",)),),
    )
    item = Share("data", "/volume1", "wanted", 1024, "present", nfs, EMPTY_ACL)

    class StaleNfsClient(NewShareChildrenClient):
        def call(
            self, api: str, method: str, params: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if api == "SYNO.Core.FileServ.NFS.SharePrivilege":
                self.calls.append("nfs_save")
                return {}
            return super().call(api, method, params, version=version)

    client = StaleNfsClient(nfs, AclConfig(True, False, False, ()))
    with pytest.raises(DriftError, match="share:data was created but reconciliation is incomplete"):
        apply_with_plan(client, Host("test", ("/volume1",), (item,)))  # type: ignore[arg-type]
    assert "nfs_save" in client.calls
