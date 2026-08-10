from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from synology_manager.config import Host, Share
from synology_manager.dsm import DsmClient, DsmError, UnsupportedCapability, operation_error
from synology_manager.models import (
    ObservedAclRule,
    ObservedNfsRule,
    ObservedShare,
    acl_api,
    acl_rules,
    desired_acl,
    desired_nfs,
    nfs_rules,
    observed_share_name,
    quota_wire_value,
    share,
)
from synology_manager.plan import ActionPlan, build_plan


class SafetyError(DsmError):
    pass


class DriftError(DsmError):
    pass


PartialPhase = Literal[
    "share_create",
    "share_readback",
    "nfs_baseline",
    "nfs_apply",
    "acl_preflight",
    "acl_apply",
    "share_set",
    "share_delete",
    "final_verify",
]


class PartialApplyError(DriftError):
    """A created resource needs a safe, deterministic rerun-based recovery."""

    def __init__(self, resource: str, phase: PartialPhase, cause: DsmError | None = None) -> None:
        self.resource = resource
        self.phase = phase
        self.recovery = "rerun_apply_after_resolving_failure"
        cause_message = _partial_cause_message(cause)
        message = (
            f"{resource} was created but reconciliation is incomplete; "
            f"phase={phase} recovery={self.recovery}; rerun after resolving the failure"
        )
        if cause_message is not None:
            message = f"{message}: {cause_message}"
        super().__init__(
            message,
            code=cause.code if cause is not None else None,
            api=cause.api if cause is not None else None,
            method=cause.method if cause is not None else None,
            version=cause.version if cause is not None else None,
        )


_PARTIAL_CAUSE_MESSAGES = frozenset(
    {
        "DSM API error",
        "DSM response was not JSON",
        "DSM response JSON was invalid",
        "DSM success response has invalid data",
        "unexpected share create response",
        "unexpected share set response",
        "share postcondition verification failed",
        "share postcondition quota observation is unsafe",
        "share postcondition is unsafe or does not match configuration",
        "NFS rules changed concurrently; refusing replacement",
        "NFS postcondition verification failed",
        "ACL file identity changed after self-denial check",
        "ACL file identity changed before postcondition",
        "ACL file identity changed after postcondition",
        "ACL postcondition verification failed",
    }
)


def _partial_cause_message(cause: DsmError | None) -> str | None:
    """Retain only fixed application-generated base messages, never arbitrary DSM text."""
    if cause is None or not cause.args or not isinstance(cause.args[0], str):
        return None
    message = cause.args[0]
    return message if message in _PARTIAL_CAUSE_MESSAGES else None


class AclObservations(dict[str, tuple[ObservedAclRule, ...]]):
    def __init__(self) -> None:
        super().__init__()
        self.inherited: dict[str, bool] = {}


@dataclass(frozen=True)
class ProgressEvent:
    """A safe, deterministic notification that an actionable plan item is beginning.

    Events deliberately contain only public plan metadata: no DSM request data, response data,
    physical paths, FileStation identifiers, credentials, or session information.
    """

    sequence: int
    kind: str
    resource: str
    phase: Literal["starting"] = "starting"

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "phase": self.phase,
            "resource": self.resource,
            "sequence": self.sequence,
        }


@dataclass
class MutationTracker:
    """State-changing operation lifecycle after the stale-plan barrier."""

    started: bool = False
    resource: str = "configuration"
    phase: PartialPhase = "share_create"

    def begin(self, kind: str, resource: str) -> None:
        self.started = True
        self.resource = resource
        if resource.startswith("nfs:"):
            self.phase = "nfs_apply"
        elif resource.startswith("acl:"):
            self.phase = "acl_apply"
        elif kind == "create":
            self.phase = "share_create"
        elif kind == "delete":
            self.phase = "share_delete"
        else:
            self.phase = "share_set"

    def begin_final_verification(self) -> None:
        if self.started:
            self.resource = "configuration"
            self.phase = "final_verify"


@dataclass(frozen=True)
class ApplyResult:
    """Outcome of applying a displayed plan against a freshly observed current plan."""

    pre_apply_plan: ActionPlan
    current_plan: ActionPlan
    applied: bool
    status: Literal["applied", "stale"]
    final_plan: ActionPlan | None = None

    @property
    def expected_plan_hash(self) -> str:
        return self.pre_apply_plan.digest

    @property
    def current_plan_hash(self) -> str:
        return self.current_plan.digest

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "pre_apply_plan": self.pre_apply_plan.as_dict(),
            "expected_plan_hash": self.expected_plan_hash,
            "current_plan": self.current_plan.as_dict(),
            "current_plan_hash": self.current_plan_hash,
            "applied": self.applied,
            "status": self.status,
        }
        if self.final_plan is not None:
            result["final_plan"] = self.final_plan.as_dict()
        return result


def _contextualize(error: DsmError, *, api: str, method: str, version: int) -> DsmError:
    """Preserve one stable message while replacing context with a fixed operation."""
    message = (
        error.args[0]
        if error.args and isinstance(error.args[0], str)
        else "DSM response is invalid"
    )
    return operation_error(type(error), message, api=api, method=method, version=version)


def _required(host: Host) -> dict[str, int]:
    required = {"SYNO.Core.Share": 1}
    if any(item.state == "present" for item in host.shares):
        required["SYNO.Core.FileServ.NFS.SharePrivilege"] = 1
    if any(item.state == "present" and item.nfs.rules for item in host.shares):
        required["SYNO.Core.FileServ.NFS"] = 3
    if any(item.state == "present" and item.name != "homes" for item in host.shares):
        required |= {"SYNO.Core.ACL": 1, "SYNO.FileStation.List": 2}
    return required


def _shares(client: DsmClient, configured_names: frozenset[str]) -> dict[str, ObservedShare]:
    """Select configured shares before normalizing mutable share metadata."""
    raw_shares = client.list_shares()
    if not isinstance(raw_shares, list) or not all(isinstance(raw, dict) for raw in raw_shares):
        raise operation_error(
            DsmError,
            "share list response is invalid",
            api="SYNO.Core.Share",
            method="list",
            version=1,
        )
    try:
        selected: list[dict[str, Any]] = []
        for raw in raw_shares:
            name = observed_share_name(raw)
            if name in configured_names:
                selected.append(raw)
        result = {current.name: current for current in (share(raw) for raw in selected)}
        if len(result) != len(selected):
            raise DsmError("observed share names are duplicated")
        return result
    except DsmError as error:
        raise _contextualize(error, api="SYNO.Core.Share", method="list", version=1) from error


def _configured_names(host: Host) -> frozenset[str]:
    return frozenset(item.name for item in host.shares)


def _acl_response(
    client: DsmClient, current: ObservedShare
) -> tuple[tuple[ObservedAclRule, ...], bool]:
    response = client.acl(f"{current.volume}/{current.name}")
    if (
        not isinstance(response.get("acl_editable"), bool)
        or not isinstance(response.get("change_permission"), bool)
        or not isinstance(response.get("is_acl"), bool)
        or not isinstance(response.get("is_inherited"), bool)
        or not response["acl_editable"]
        or not response["change_permission"]
        or not response["is_acl"]
    ):
        raise UnsupportedCapability(
            "ACL response is not safely editable",
            api="SYNO.Core.ACL",
            method="get",
            version=1,
        )
    try:
        return acl_rules(response.get("acl")), response["is_inherited"]
    except DsmError as error:
        raise _contextualize(error, api="SYNO.Core.ACL", method="get", version=1) from error


def _normalized_nfs_rules(raw_rules: list[dict[str, Any]]) -> tuple[ObservedNfsRule, ...]:
    try:
        return nfs_rules(raw_rules)
    except DsmError as error:
        raise _contextualize(
            error,
            api="SYNO.Core.FileServ.NFS.SharePrivilege",
            method="load",
            version=1,
        ) from error


def _load_nfs_rules(client: DsmClient, name: str) -> tuple[ObservedNfsRule, ...]:
    """Require the per-share capability immediately before every authoritative NFS read."""
    client.require({"SYNO.Core.FileServ.NFS.SharePrivilege": 1})
    return _normalized_nfs_rules(client.nfs_rules(name))


def observe(
    client: DsmClient, host: Host
) -> tuple[
    dict[str, ObservedShare],
    dict[str, tuple[ObservedNfsRule, ...]],
    AclObservations,
]:
    client.require(_required(host))
    all_shares = _shares(client, _configured_names(host))
    relevant = {item.name: item for item in host.shares if item.name in all_shares}
    nfs: dict[str, tuple[ObservedNfsRule, ...]] = {}
    # Observe only configured existing shares.  Global NFS service is unmanaged: it is
    # required only when this configuration needs a non-empty desired export list.
    nfs_needed = [item for item in relevant.values() if item.state == "present"]
    needs_service = any(item.state == "present" and item.nfs.rules for item in host.shares)
    if needs_service and not client.nfs_enabled():
        raise operation_error(
            UnsupportedCapability,
            "NFS service is disabled; refusing non-empty NFS export operations",
            api="SYNO.Core.FileServ.NFS",
            method="get",
            version=3,
        )
    for item in nfs_needed:
        nfs[item.name] = _load_nfs_rules(client, item.name)
    acl = AclObservations()
    for item in relevant.values():
        current = all_shares[item.name]
        if (
            item.state == "present"
            and item.name != "homes"
            and not current.protected
            and current.volume == item.volume
        ):
            acl[item.name], acl.inherited[item.name] = _acl_response(client, current)
    return all_shares, nfs, acl


def plan(client: DsmClient, host: Host) -> ActionPlan:
    observed, nfs, acl = observe(client, host)
    return build_plan(host, observed, nfs, acl)


def _info(item: Share) -> dict[str, Any]:
    return {
        "name": item.name,
        "name_org": "",
        "vol_path": item.volume,
        "desc": item.description,
        "share_quota": quota_wire_value(item.quota_mib),
    }


def _response_value_type(value: object) -> str:
    """Classify a response value without serializing or otherwise exposing it."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _acl_self_denied_metadata(data: object) -> str:
    """Return diagnostic metadata for the undocumented self-denial response only."""
    if not isinstance(data, dict):
        return f"response type={_response_value_type(data)}"
    entries = [
        f"{key if isinstance(key, str) and key.isidentifier() else '<nonstandard-key>'}:"
        f"{_response_value_type(value)}"
        for key, value in data.items()
    ]
    return f"response keys/types: {', '.join(sorted(entries))}"


def _validate_acl_self_denied_data(data: object) -> None:
    """Validate the strictly allow-listed ACL self-denial response contract.

    The legacy empty object and the verified ``{"is_denied": false}`` response are safe.
    A verified denial is a safety failure. All other responses fail closed without rendering
    response values, which may contain filesystem, principal, or session information.
    """
    if type(data) is dict and not data:
        return
    if type(data) is dict and set(data) == {"is_denied"} and type(data["is_denied"]) is bool:
        if not data["is_denied"]:
            return
        raise operation_error(
            SafetyError,
            "ACL self-denial check denied ACL replacement",
            api="SYNO.Core.ACL",
            method="check_self_denied",
            version=1,
        )
    kind = "unverified non-empty data" if type(data) is dict else "malformed data"
    raise operation_error(
        UnsupportedCapability,
        f"ACL check_self_denied returned {kind} ({_acl_self_denied_metadata(data)})",
        api="SYNO.Core.ACL",
        method="check_self_denied",
        version=1,
    )


def _require_empty_validation(
    data: dict[str, Any], operation: str, *, api: str, method: str, version: int
) -> None:
    if data != {}:
        raise operation_error(
            UnsupportedCapability,
            f"{operation} returned warnings or an unknown response",
            api=api,
            method=method,
            version=version,
        )


def _require_empty_delete_result(data: dict[str, Any]) -> None:
    if data != {}:
        raise operation_error(
            UnsupportedCapability,
            "share delete returned an unknown response",
            api="SYNO.Core.Share",
            method="delete",
            version=1,
        )


def _share_matches(current: ObservedShare, item: Share) -> bool:
    return (current.description, current.quota.mib) == (item.description, item.quota_mib)


def _verify_share(client: DsmClient, item: Share, *, absent: bool = False) -> ObservedShare | None:
    current = _shares(client, frozenset({item.name})).get(item.name)
    if absent:
        if current is not None:
            raise operation_error(
                DriftError,
                "share delete postcondition verification failed",
                api="SYNO.Core.Share",
                method="list",
                version=1,
            )
        return None
    if current is None:
        raise operation_error(
            DriftError,
            "share postcondition verification failed",
            api="SYNO.Core.Share",
            method="list",
            version=1,
        )
    try:
        quota = current.quota
    except DsmError as error:
        raise operation_error(
            DriftError,
            "share postcondition quota observation is unsafe",
            api="SYNO.Core.Share",
            method="list",
            version=1,
        ) from error
    if (
        current.name != item.name
        or current.volume != item.volume
        or current.description != item.description
        or quota.mib != item.quota_mib
        or current.protected
    ):
        raise operation_error(
            DriftError,
            "share postcondition is unsafe or does not match configuration",
            api="SYNO.Core.Share",
            method="list",
            version=1,
        )
    return current


def _desired_nfs_rules(item: Share) -> tuple[ObservedNfsRule, ...]:
    """Return the complete export list; never carry forward unconfigured live rules."""
    return tuple(sorted(desired_nfs(rule) for rule in item.nfs.rules))


def _save_rules(
    client: DsmClient,
    name: str,
    baseline: tuple[ObservedNfsRule, ...],
    desired: tuple[ObservedNfsRule, ...],
    *,
    starting: Callable[[], None] | None = None,
) -> None:
    # The save callback data is undocumented; only a canonical full reload is authoritative.
    current = _load_nfs_rules(client, name)
    if current != baseline:
        raise operation_error(
            DriftError,
            "NFS rules changed concurrently; refusing replacement",
            api="SYNO.Core.FileServ.NFS.SharePrivilege",
            method="load",
            version=1,
        )
    if current == desired:
        return
    if starting is not None:
        starting()
    try:
        client.call(
            "SYNO.Core.FileServ.NFS.SharePrivilege",
            "save",
            {"share_name": name, "rule": [rule.api() for rule in desired]},
            version=1,
        )
        if _load_nfs_rules(client, name) != desired:
            raise operation_error(
                DriftError,
                "NFS postcondition verification failed",
                api="SYNO.Core.FileServ.NFS.SharePrivilege",
                method="save",
                version=1,
            )
    except DsmError as error:
        raise PartialApplyError(f"nfs:{name}", "nfs_apply", error) from error


def _acl_payload(item: Share, current: ObservedShare, file_id: str) -> dict[str, Any]:
    """Build the shared, private-DSM contract for ACL self-denial checks and writes.

    `file_path` and `files` use the physical share path; `dirPaths` uses the separately
    resolved FileStation path. Keeping this contract in one helper makes its exact logical
    fields testable without probing a NAS.
    """
    physical = f"{current.volume}/{item.name}"
    return {
        "file_path": physical,
        "files": physical,
        "dirPaths": file_id,
        "change_acl": True,
        "rules": acl_api(item.acl),
        "inherited": item.acl.inherit_parent,
        "acl_recur": item.acl.recursive,
    }


def _ambiguous_acl_principals(rules: tuple[ObservedAclRule, ...]) -> bool:
    principals = [(rule.owner_type, rule.owner_name) for rule in rules]
    return len(principals) != len(set(principals))


def _require_inherited_acl_state(item: Share, inherited: bool) -> None:
    if item.acl.inherit_parent and not inherited:
        raise SafetyError("ACL inheritance must be observed as true before replacement")


def _preflight_acl(client: DsmClient, item: Share, current: ObservedShare) -> None:
    rules, inherited = _acl_response(client, current)
    _require_inherited_acl_state(item, inherited)
    if rules == desired_acl(item.acl) and inherited == item.acl.inherit_parent:
        return
    if _ambiguous_acl_principals(rules):
        raise SafetyError("ACL replacement with multiple rules for one principal is unsupported")
    if not item.acl.authoritative:
        raise SafetyError("authoritative: false ACLs are unsupported")
    file_id = client.resolve_share_file_id(item.name, f"{current.volume}/{item.name}")
    _validate_acl_self_denied_data(
        client.call(
            "SYNO.Core.ACL", "check_self_denied", _acl_payload(item, current, file_id), version=1
        )
    )


def _apply_acl(
    client: DsmClient,
    item: Share,
    current: ObservedShare,
    *,
    starting: Callable[[], None] | None = None,
) -> None:
    rules, inherited = _acl_response(client, current)
    _require_inherited_acl_state(item, inherited)
    if rules == desired_acl(item.acl) and inherited == item.acl.inherit_parent:
        return
    if _ambiguous_acl_principals(rules):
        raise SafetyError("ACL replacement with multiple rules for one principal is unsupported")
    # Bind the safety check and both postcondition reads to one freshly proven file identity.
    physical = f"{current.volume}/{item.name}"
    file_id = client.resolve_share_file_id(item.name, physical)
    payload = _acl_payload(item, current, file_id)
    _validate_acl_self_denied_data(
        client.call("SYNO.Core.ACL", "check_self_denied", payload, version=1)
    )
    if client.resolve_share_file_id(item.name, physical) != file_id:
        raise operation_error(
            DriftError,
            "ACL file identity changed after self-denial check",
            api="SYNO.FileStation.List",
            method="getinfo",
            version=2,
        )
    if starting is not None:
        starting()
    client.call("SYNO.Core.ACL", "set", payload, version=1)
    if client.resolve_share_file_id(item.name, physical) != file_id:
        raise operation_error(
            DriftError,
            "ACL file identity changed before postcondition",
            api="SYNO.FileStation.List",
            method="getinfo",
            version=2,
        )
    actual, inherited = _acl_response(client, current)
    if client.resolve_share_file_id(item.name, physical) != file_id:
        raise operation_error(
            DriftError,
            "ACL file identity changed after postcondition",
            api="SYNO.FileStation.List",
            method="getinfo",
            version=2,
        )
    if actual != desired_acl(item.acl) or inherited != item.acl.inherit_parent:
        raise operation_error(
            DriftError,
            "ACL postcondition verification failed",
            api="SYNO.Core.ACL",
            method="get",
            version=1,
        )


def _apply(
    client: DsmClient,
    host: Host,
    pre_apply_plan: ActionPlan,
    tracker: MutationTracker,
    *,
    progress: Callable[[ProgressEvent], None] | None = None,
) -> ApplyResult:
    """Apply only if a freshly re-observed plan matches the displayed pre-apply plan.

    DSM has neither an NFS CAS token nor a transactional conditional share delete.
    Baseline and final reads narrow concurrent-writer windows but cannot close the interval
    after the final read; authoritative NFS/share deletion requires exclusive maintenance.
    An applied result proves the delete API and share-absence postcondition, not that an export
    was absent at deletion if a concurrent writer added it after the final read.
    """
    if not isinstance(pre_apply_plan, ActionPlan):
        raise SafetyError("pre-apply plan is required")
    # Complete every safe probe for existing resources before the first mutation.
    observed, baselines, acl = observe(client, host)
    current_plan = build_plan(host, observed, baselines, acl)
    if current_plan.digest != pre_apply_plan.digest:
        return ApplyResult(pre_apply_plan, current_plan, False, "stale", current_plan)
    initial = current_plan
    if any(action.kind == "unsupported" for action in initial.actions):
        raise UnsupportedCapability("plan contains unsupported operations")
    event_sequence = 0

    def starting(kind: str, resource: str) -> None:
        nonlocal event_sequence
        tracker.begin(kind, resource)
        if progress is not None:
            event_sequence += 1
            progress(ProgressEvent(event_sequence, kind, resource))

    def event_starter(kind: str, resource: str) -> Callable[[], None]:
        return lambda: starting(kind, resource)

    client.require(_required(host))
    for item in host.shares:
        current = observed.get(item.name)
        if item.name == "homes" and item.state == "absent":
            raise SafetyError("homes can never be deleted")
        if item.state == "absent" and current is not None:
            if current.protected or current.volume != item.volume or item.name == "homes":
                raise SafetyError("share deletion protection or volume requirement failed")
        elif item.state == "present" and current is not None:
            try:
                _ = current.quota
            except DsmError as error:
                raise SafetyError(
                    "share protection, volume, or quota observation is unsafe"
                ) from error
            if current.protected or current.volume != item.volume:
                raise SafetyError("share protection, volume, or quota observation is unsafe")
            if not _share_matches(current, item):
                _require_empty_validation(
                    client.call(
                        "SYNO.Core.Share",
                        "validate_set",
                        {"name": item.name, "shareinfo": _info(item)},
                        version=1,
                    ),
                    "share validate_set",
                    api="SYNO.Core.Share",
                    method="validate_set",
                    version=1,
                )
            _preflight_acl(client, item, current)
            _desired_nfs_rules(item)

    # A new share is a terminal lifecycle barrier: finish its children before another create.
    created: set[str] = set()
    for item in host.shares:
        if item.state == "present" and item.name not in observed:
            resource = f"share:{item.name}"
            if _shares(client, frozenset({item.name})).get(item.name) is not None:
                raise operation_error(
                    DriftError,
                    "configured share appeared before creation; refusing create",
                    api="SYNO.Core.Share",
                    method="list",
                    version=1,
                )
            try:
                starting("create", resource)
                response = client.call(
                    "SYNO.Core.Share",
                    "create",
                    {"name": item.name, "shareinfo": _info(item)},
                    version=1,
                )
                if response.get("name") != item.name or set(response) != {"name"}:
                    raise operation_error(
                        UnsupportedCapability,
                        "unexpected share create response",
                        api="SYNO.Core.Share",
                        method="create",
                        version=1,
                    )
            except DsmError as error:
                raise PartialApplyError(resource, "share_create", error) from error
            try:
                verified = _verify_share(client, item)
                assert verified is not None
            except DsmError as error:
                raise PartialApplyError(resource, "share_readback", error) from error
            try:
                baseline = _load_nfs_rules(client, item.name)
                if baseline:
                    raise DriftError("new share has unexpected NFS exports")
                baselines[item.name] = baseline
            except DsmError as error:
                raise PartialApplyError(resource, "nfs_baseline", error) from error
            try:
                _preflight_acl(client, item, verified)
            except DsmError as error:
                raise PartialApplyError(resource, "acl_preflight", error) from error
            try:
                _save_rules(
                    client,
                    item.name,
                    baselines[item.name],
                    _desired_nfs_rules(item),
                    starting=event_starter("create", f"nfs:{item.name}"),
                )
            except DsmError as error:
                raise PartialApplyError(resource, "nfs_apply", error) from error
            try:
                _apply_acl(
                    client,
                    item,
                    verified,
                    starting=event_starter("create", f"acl:{item.name}"),
                )
            except DsmError as error:
                raise PartialApplyError(resource, "acl_apply", error) from error
            try:
                _verify_share(client, item)
            except DsmError as error:
                raise PartialApplyError(resource, "share_readback", error) from error
            created.add(item.name)

    for item in host.shares:
        if item.state != "present" or item.name in created:
            continue
        current = _shares(client, frozenset({item.name})).get(item.name)
        if current is None:
            raise operation_error(
                DriftError,
                "configured share disappeared",
                api="SYNO.Core.Share",
                method="list",
                version=1,
            )
        if not _share_matches(current, item):
            payload = {"name": item.name, "shareinfo": _info(item)}
            starting("update", f"share:{item.name}")
            try:
                response = client.call("SYNO.Core.Share", "set", payload, version=1)
                if response.get("name") != item.name or set(response) != {"name"}:
                    cause = operation_error(
                        UnsupportedCapability,
                        "unexpected share set response",
                        api="SYNO.Core.Share",
                        method="set",
                        version=1,
                    )
                    raise PartialApplyError(f"share:{item.name}", "share_set", cause)
                _verify_share(client, item)
            except PartialApplyError:
                raise
            except DsmError as error:
                raise PartialApplyError(f"share:{item.name}", "share_set", error) from error

    for item in host.shares:
        if item.state == "present" and item.name not in created:
            _save_rules(
                client,
                item.name,
                baselines[item.name],
                _desired_nfs_rules(item),
                starting=event_starter("update", f"nfs:{item.name}"),
            )

    for item in host.shares:
        if item.state == "present" and item.name not in created:
            current = _shares(client, frozenset({item.name})).get(item.name)
            if current is None:
                raise operation_error(
                    DriftError,
                    "configured share disappeared",
                    api="SYNO.Core.Share",
                    method="list",
                    version=1,
                )
            _apply_acl(
                client,
                item,
                current,
                starting=event_starter("update", f"acl:{item.name}"),
            )

    for item in host.shares:
        if item.state == "absent" and item.name in observed:
            # NFS baseline/clear failures are partial export reconciliation. Once that completes,
            # remaining identity and deletion checks are share-deletion partial state.
            try:
                # Absent shares intentionally avoid NFS observation until deletion. The read
                # helper requires the per-share capability immediately before the baseline load.
                baseline = _load_nfs_rules(client, item.name)
                if baseline:
                    _save_rules(
                        client,
                        item.name,
                        baseline,
                        (),
                        starting=event_starter("delete", f"nfs:{item.name}"),
                    )
            except PartialApplyError as error:
                raise PartialApplyError(f"share:{item.name}", "nfs_apply", error) from error
            except DsmError as error:
                raise PartialApplyError(f"share:{item.name}", "nfs_apply", error) from error
            try:
                # Deletion is intentionally not atomic: prove the target identity again after export clear.
                current = _shares(client, frozenset({item.name})).get(item.name)
                if (
                    current is None
                    or current.protected
                    or current.volume != item.volume
                    or item.name == "homes"
                ):
                    raise operation_error(
                        DriftError,
                        "share changed before deletion; refusing delete",
                        api="SYNO.Core.Share",
                        method="list",
                        version=1,
                    )
                if _load_nfs_rules(client, item.name) != ():
                    raise operation_error(
                        DriftError,
                        "share exports changed before deletion; refusing delete",
                        api="SYNO.Core.FileServ.NFS.SharePrivilege",
                        method="load",
                        version=1,
                    )
                _require_empty_validation(
                    client.call(
                        "SYNO.Core.Share", "validate_delete", {"name": [item.name]}, version=1
                    ),
                    "share validate_delete",
                    api="SYNO.Core.Share",
                    method="validate_delete",
                    version=1,
                )
                # DSM has no CAS token for export replacement. Re-read immediately after
                # validation to narrow the interval in which a concurrent export can appear.
                if _load_nfs_rules(client, item.name) != ():
                    raise operation_error(
                        DriftError,
                        "share exports changed after deletion validation; refusing delete",
                        api="SYNO.Core.FileServ.NFS.SharePrivilege",
                        method="load",
                        version=1,
                    )
            except PartialApplyError as error:
                raise PartialApplyError(f"share:{item.name}", "share_delete", error) from error
            except DsmError as error:
                raise PartialApplyError(f"share:{item.name}", "share_delete", error) from error
            try:
                starting("delete", f"share:{item.name}")
                response = client.call(
                    "SYNO.Core.Share", "delete", {"name": [item.name]}, version=1
                )
                _require_empty_delete_result(response)
                _verify_share(client, item, absent=True)
            except DsmError as error:
                raise PartialApplyError(f"share:{item.name}", "share_delete", error) from error
            except Exception as error:
                raise PartialApplyError(f"share:{item.name}", "share_delete") from error

    tracker.begin_final_verification()
    final_observed, final_nfs, final_acl = observe(client, host)
    for item in host.shares:
        if (
            item.state == "present"
            and item.acl.inherit_parent
            and (
                not isinstance(final_acl, AclObservations)
                or final_acl.inherited.get(item.name) is not True
            )
        ):
            raise operation_error(
                DriftError,
                "final ACL inheritance observation did not converge",
                api="SYNO.Core.ACL",
                method="get",
                version=1,
            )
    final = build_plan(host, final_observed, final_nfs, final_acl)
    if any(action.kind != "noop" for action in final.actions):
        raise operation_error(
            DriftError,
            "final state did not converge",
            api="SYNO.Core.Share",
            method="list",
            version=1,
        )
    return ApplyResult(pre_apply_plan, current_plan, True, "applied", final)


def apply(
    client: DsmClient,
    host: Host,
    pre_apply_plan: ActionPlan,
    *,
    progress: Callable[[ProgressEvent], None] | None = None,
) -> ApplyResult:
    """Apply while classifying every DSM failure after mutation as partial state."""
    tracker = MutationTracker()
    try:
        return _apply(client, host, pre_apply_plan, tracker, progress=progress)
    except PartialApplyError:
        raise
    except DsmError as error:
        if tracker.started:
            raise PartialApplyError(tracker.resource, tracker.phase, error) from error
        raise
