from __future__ import annotations

from typing import Any, cast

import pytest

from synology_manager.config import EMPTY_ACL, EMPTY_NFS, Host, Share
from synology_manager.dsm import DsmClient, DsmError, UnsupportedCapability
from synology_manager.engine import ApplyResult, DriftError, PartialApplyError, apply, plan
from synology_manager.models import ObservedShare
from synology_manager.plan import build_plan


def nfs_raw() -> dict[str, object]:
    return {
        "client": "192.0.2.0/24",
        "privilege": "rw",
        "root_squash": "root",
        "async": False,
        "insecure": False,
        "crossmnt": False,
        "security_flavor": {
            "sys": True,
            "kerberos": False,
            "kerberos_integrity": False,
            "kerberos_privacy": False,
        },
    }


class ExportDeleteClient:
    def __init__(
        self, *, second_validation: dict[str, Any] | None = None, save_clears: bool = True
    ) -> None:
        self.exists = True
        self.rules: list[dict[str, object]] = [nfs_raw()]
        self.second_validation = second_validation
        self.save_clears = save_clears
        self.calls: list[str] = []
        self.requirements: list[dict[str, int]] = []
        self.validations = 0

    def require(self, required: dict[str, int]) -> None:
        self.calls.append("require")
        self.requirements.append(required)

    def list_shares(self) -> list[dict[str, Any]]:
        self.calls.append("list")
        return (
            []
            if not self.exists
            else [
                {
                    "name": "data",
                    "vol_path": "/volume1",
                    "desc": "",
                    "quota_value": 0,
                    "share_quota_status": "v1",
                }
            ]
        )

    def nfs_enabled(self) -> bool:
        self.calls.append("nfs_enabled")
        return True

    def nfs_rules(self, name: str) -> list[dict[str, Any]]:
        assert name == "data"
        self.calls.append("nfs_load")
        return self.rules

    def call(
        self, api: str, method: str, parameters: dict[str, Any], *, version: int
    ) -> dict[str, Any]:
        self.calls.append(method)
        if method == "save":
            assert api == "SYNO.Core.FileServ.NFS.SharePrivilege"
            if self.save_clears:
                self.rules = []
            return {"callback": "intentionally ignored"}
        assert api == "SYNO.Core.Share"
        if method == "validate_delete":
            self.validations += 1
            if self.validations == 1 and self.second_validation is not None:
                return self.second_validation
            return {}
        if method == "delete":
            self.exists = False
            return {}
        raise AssertionError(method)


def deleted_share() -> Share:
    return Share("data", "/volume1", "", 0, "absent", EMPTY_NFS, EMPTY_ACL)


def apply_with_plan(client: DsmClient, host: Host) -> ApplyResult:
    return apply(client, host, plan(client, host))


def test_absent_deletion_defers_nfs_and_executes_exact_best_effort_order() -> None:
    client = ExportDeleteClient()
    result = apply_with_plan(
        cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),))
    )
    assert result.applied is True
    assert client.calls == [
        "require",
        "list",
        "require",
        "list",
        "require",
        "require",
        "nfs_load",
        "require",
        "nfs_load",
        "save",
        "require",
        "nfs_load",
        "list",
        "require",
        "nfs_load",
        "validate_delete",
        "require",
        "nfs_load",
        "delete",
        "list",
        "require",
        "list",
    ]
    assert client.requirements == [
        {"SYNO.Core.Share": 1},
        {"SYNO.Core.Share": 1},
        {"SYNO.Core.Share": 1},
        {"SYNO.Core.FileServ.NFS.SharePrivilege": 1},
        {"SYNO.Core.FileServ.NFS.SharePrivilege": 1},
        {"SYNO.Core.FileServ.NFS.SharePrivilege": 1},
        {"SYNO.Core.FileServ.NFS.SharePrivilege": 1},
        {"SYNO.Core.FileServ.NFS.SharePrivilege": 1},
        {"SYNO.Core.Share": 1},
    ]
    assert "nfs_enabled" not in client.calls


def test_export_delete_revalidates_after_empty_export_readback() -> None:
    client = ExportDeleteClient()
    result = apply_with_plan(
        cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),))
    )
    assert result.applied is True
    assert result.final_plan is not None
    assert result.final_plan.actions[0].kind == "noop"
    save = client.calls.index("save")
    assert client.calls[save + 1 : save + 6] == [
        "require",
        "nfs_load",
        "list",
        "require",
        "nfs_load",
    ]
    assert client.calls[save + 6] == "validate_delete"
    assert client.calls[save + 7 : save + 9] == ["require", "nfs_load"]
    assert client.calls[save + 9] == "delete"
    assert client.calls[save + 10 : save + 12] == ["list", "require"]
    assert client.calls.count("validate_delete") == 1


def test_export_reintroduced_after_final_read_is_an_unobservable_no_cas_race() -> None:
    class PostReadRaceClient(ExportDeleteClient):
        def __init__(self) -> None:
            super().__init__()
            self.export_added_after_final_read = False

        def call(
            self, api: str, method: str, parameters: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if method == "delete":
                # The final read already returned empty. DSM has no conditional delete API
                # binding this mutation to that read, so the engine cannot observe this race.
                self.rules = [nfs_raw()]
                self.export_added_after_final_read = True
            return super().call(api, method, parameters, version=version)

    client = PostReadRaceClient()
    result = apply_with_plan(
        cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),))
    )
    assert result.applied is True
    assert client.export_added_after_final_read is True
    assert client.rules == [nfs_raw()]
    assert "delete" in client.calls


def test_final_export_read_detects_reintroduced_export_after_delete_validation() -> None:
    class ReintroducedExportClient(ExportDeleteClient):
        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            if "validate_delete" in self.calls:
                self.calls.append("nfs_load")
                return [nfs_raw()]
            return super().nfs_rules(name)

    client = ReintroducedExportClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", "share_delete")
    assert raised.value.operation() == {
        "api": "SYNO.Core.FileServ.NFS.SharePrivilege",
        "method": "load",
        "version": 1,
    }
    assert client.calls.index("validate_delete") < client.calls.index(
        "nfs_load", client.calls.index("validate_delete")
    )
    assert "delete" not in client.calls


def test_final_export_read_failure_is_share_delete_partial_and_blocks_delete() -> None:
    class FinalReadFailureClient(ExportDeleteClient):
        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            if "validate_delete" in self.calls:
                raise DsmError(
                    "DSM API error",
                    api="SYNO.Core.FileServ.NFS.SharePrivilege",
                    method="load",
                    version=1,
                )
            return super().nfs_rules(name)

    client = FinalReadFailureClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", "share_delete")
    assert raised.value.operation() == {
        "api": "SYNO.Core.FileServ.NFS.SharePrivilege",
        "method": "load",
        "version": 1,
    }
    assert "delete" not in client.calls


def test_post_clear_capability_failure_is_share_partial_state_and_blocks_delete() -> None:
    from synology_manager.engine import PartialApplyError

    class PostClearCapabilityFailureClient(ExportDeleteClient):
        def require(self, required: dict[str, int]) -> None:
            super().require(required)
            if required == {"SYNO.Core.FileServ.NFS.SharePrivilege": 1} and "save" in self.calls:
                raise UnsupportedCapability(
                    "NFS privilege unavailable",
                    api="SYNO.Core.FileServ.NFS.SharePrivilege",
                    method="load",
                    version=1,
                )

    client = PostClearCapabilityFailureClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", "nfs_apply")
    assert raised.value.operation() == {
        "api": "SYNO.Core.FileServ.NFS.SharePrivilege",
        "method": "load",
        "version": 1,
    }
    assert "save" in client.calls
    assert "delete" not in client.calls


def test_post_clear_nfs_read_failure_is_partial_and_blocks_delete() -> None:
    from synology_manager.engine import PartialApplyError

    class PostClearReadFailureClient(ExportDeleteClient):
        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            if "save" in self.calls:
                raise DsmError(
                    "DSM API error",
                    api="SYNO.Core.FileServ.NFS.SharePrivilege",
                    method="load",
                    version=1,
                )
            return super().nfs_rules(name)

    client = PostClearReadFailureClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", "nfs_apply")
    assert raised.value.operation() == {
        "api": "SYNO.Core.FileServ.NFS.SharePrivilege",
        "method": "load",
        "version": 1,
    }
    assert "validate_delete" not in client.calls
    assert "delete" not in client.calls


@pytest.mark.parametrize(
    ("failure", "phase"),
    [
        ("baseline", "nfs_apply"),
        ("clear", "nfs_apply"),
        ("post_clear", "nfs_apply"),
        ("identity", "share_delete"),
    ],
)
def test_absent_deletion_safety_failures_are_partial_and_never_validate_or_delete(
    failure: str, phase: str
) -> None:
    class FailingDeletionClient(ExportDeleteClient):
        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            if failure == "baseline" and "save" not in self.calls:
                raise DsmError(
                    "DSM API error",
                    api="SYNO.Core.FileServ.NFS.SharePrivilege",
                    method="load",
                    version=1,
                )
            if failure == "post_clear" and "save" in self.calls:
                raise DsmError(
                    "DSM API error",
                    api="SYNO.Core.FileServ.NFS.SharePrivilege",
                    method="load",
                    version=1,
                )
            return super().nfs_rules(name)

        def list_shares(self) -> list[dict[str, Any]]:
            if failure == "identity" and "save" in self.calls:
                return [
                    {
                        "name": "data",
                        "vol_path": "/volume2",
                        "desc": "",
                        "quota_value": 0,
                        "share_quota_status": "v1",
                    }
                ]
            return super().list_shares()

        def call(
            self, api: str, method: str, parameters: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if failure == "clear" and method == "save":
                raise DsmError(
                    "DSM API error",
                    api="SYNO.Core.FileServ.NFS.SharePrivilege",
                    method="save",
                    version=1,
                )
            return super().call(api, method, parameters, version=version)

    client = FailingDeletionClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", phase)
    assert raised.value.operation() is not None
    assert "validate_delete" not in client.calls
    assert "delete" not in client.calls


def test_empty_deletion_baseline_skips_save_and_detects_new_export() -> None:
    class LateExportClient(ExportDeleteClient):
        def __init__(self) -> None:
            super().__init__()
            self.rules = []
            self.loads = 0

        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            self.loads += 1
            if self.loads == 2:
                self.rules = [nfs_raw()]
            return super().nfs_rules(name)

    client = LateExportClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", "share_delete")
    assert "save" not in client.calls
    assert "validate_delete" not in client.calls
    assert "delete" not in client.calls


@pytest.mark.parametrize("failure", ["transport", "non_empty"])
def test_validate_delete_failure_is_partial_and_blocks_delete(failure: str) -> None:
    class ValidationFailureClient(ExportDeleteClient):
        def call(
            self, api: str, method: str, parameters: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if method == "validate_delete":
                if failure == "transport":
                    raise DsmError(
                        "DSM API error", api="SYNO.Core.Share", method="validate_delete", version=1
                    )
                return {"warning": "blocked"}
            return super().call(api, method, parameters, version=version)

    client = ValidationFailureClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", "share_delete")
    assert raised.value.operation() == {
        "api": "SYNO.Core.Share",
        "method": "validate_delete",
        "version": 1,
    }
    assert "delete" not in client.calls


def test_delete_progress_callback_failure_is_share_delete_partial_and_skips_call() -> None:
    client = ExportDeleteClient()
    host = Host("test", ("/volume1",), (deleted_share(),))

    def fail_progress(event: object) -> None:
        if getattr(event, "resource", None) == "share:data":
            raise RuntimeError("progress callback failed")

    with pytest.raises(PartialApplyError) as raised:
        apply(
            cast(DsmClient, client),
            host,
            plan(cast(DsmClient, client), host),
            progress=fail_progress,
        )
    assert (raised.value.resource, raised.value.phase) == ("share:data", "share_delete")
    assert "delete" not in client.calls


@pytest.mark.parametrize("failure", ["call", "response", "postcondition"])
def test_delete_failures_are_share_delete_partial(failure: str) -> None:
    class DeleteFailureClient(ExportDeleteClient):
        def call(
            self, api: str, method: str, parameters: dict[str, Any], *, version: int
        ) -> dict[str, Any]:
            if method == "delete":
                self.calls.append("delete")
                if failure == "call":
                    raise DsmError("DSM API error", api=api, method=method, version=version)
                if failure == "response":
                    return {"warning": "blocked"}
                return {}
            return super().call(api, method, parameters, version=version)

    client = DeleteFailureClient()
    with pytest.raises(PartialApplyError) as raised:
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert (raised.value.resource, raised.value.phase) == ("share:data", "share_delete")
    assert "delete" in client.calls


@pytest.mark.parametrize(
    "second_validation,save_clears", [({"warning": "blocked"}, True), (None, False)]
)
def test_export_delete_revalidation_or_remainder_blocks_delete(
    second_validation: dict[str, Any] | None, save_clears: bool
) -> None:
    client = ExportDeleteClient(second_validation=second_validation, save_clears=save_clears)
    with pytest.raises((UnsupportedCapability, DriftError)):
        apply_with_plan(cast(DsmClient, client), Host("test", ("/volume1",), (deleted_share(),)))
    assert "delete" not in client.calls


@pytest.mark.parametrize(
    ("responses", "changed_share", "expected"),
    [
        (
            ([nfs_raw()], [nfs_raw()], [], [nfs_raw()]),
            False,
            ("SYNO.Core.FileServ.NFS.SharePrivilege", "load", 1),
        ),
        (
            ([nfs_raw()], [nfs_raw()], [], [nfs_raw()]),
            False,
            ("SYNO.Core.FileServ.NFS.SharePrivilege", "load", 1),
        ),
        (
            ([nfs_raw()], [nfs_raw()], [], []),
            True,
            ("SYNO.Core.Share", "list", 1),
        ),
    ],
)
def test_deletion_readback_failures_have_exact_safe_context(
    responses: tuple[list[dict[str, object]], ...] | list[list[dict[str, object]]],
    changed_share: bool,
    expected: tuple[str, str, int],
) -> None:
    class ReadbackFailureClient(ExportDeleteClient):
        def __init__(self) -> None:
            super().__init__()
            self.replies = list(responses)
            self.list_count = 0

        def nfs_rules(self, name: str) -> list[dict[str, Any]]:
            self.calls.append("nfs_load")
            return self.replies.pop(0)

        def list_shares(self) -> list[dict[str, Any]]:
            self.list_count += 1
            if changed_share and self.list_count == 3:
                return [
                    {
                        "name": "data",
                        "vol_path": "/volume2",
                        "desc": "raw=/private",
                        "quota_value": 0,
                        "share_quota_status": "v1",
                    }
                ]
            return super().list_shares()

    with pytest.raises(DriftError) as raised:
        apply_with_plan(
            cast(DsmClient, ReadbackFailureClient()),
            Host("test", ("/volume1",), (deleted_share(),)),
        )

    assert raised.value.operation() == dict(
        zip(("api", "method", "version"), expected, strict=True)
    )
    assert "private" not in str(raised.value)


def test_direct_invalid_homes_and_host_volume_are_rejected() -> None:
    with pytest.raises(ValueError):
        Share("homes", "/volume1", "", 0, "absent", EMPTY_NFS, EMPTY_ACL)
    with pytest.raises(ValueError):
        Host(
            "x",
            ("/volume1",),
            (Share("data", "/volume2", "", 0, "absent", EMPTY_NFS, EMPTY_ACL),),
        )


def test_absent_share_plan_clears_live_exports_then_deletes() -> None:
    current = ObservedShare("data", "/volume1", "", 0, "v1", False)
    actions = build_plan(
        Host("x", ("/volume1",), (deleted_share(),)),
        {"data": current},
        {},
        {},
    ).actions
    assert [(action.resource, action.kind) for action in actions] == [("share:data", "delete")]
