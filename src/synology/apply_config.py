from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import yaml

from synology.config import (
    MAX_QUOTA_GIB,
    normalize_nfs_client,
    validate_share_create_request,
)
from synology.exceptions import (
    ApiError,
    ConfigurationError,
    PartialOperationError,
    ScalarUpdatePreflightError,
)
from synology.models import (
    AclPermissionRecord,
    NfsAccessMode,
    NfsClientPermission,
    NfsRootSquash,
    NfsSecurityFlavor,
    OperationStatus,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    PrincipalIdentity,
    ShareCreateOptions,
    ShareCreateRequest,
    ShareDeleteRequest,
    ShareDetails,
    ShareRecord,
    ShareScalarUpdateRequest,
)

_MISSING = object()


@dataclass(frozen=True, slots=True)
class ApplyShare:
    name: str
    volume: str
    state: str
    description: str | object
    quota_mib: int | None
    acl: tuple[PermissionSpec, ...]
    nfs: tuple[NfsClientPermission, ...]


@dataclass(frozen=True, slots=True)
class ApplyConfig:
    host: str | None
    principal_lookup_share: str | None
    shares: tuple[ApplyShare, ...]


@dataclass(frozen=True, slots=True)
class ApplyOperation:
    share: str
    family: str
    before: str
    after: str
    status: OperationStatus = OperationStatus.PLANNED


@dataclass(frozen=True, slots=True)
class ApplyPlan:
    config: ApplyConfig
    operations: tuple[ApplyOperation, ...]
    effective_descriptions: tuple[tuple[str, str], ...] = ()


class ApplyClient(Protocol):
    def list_shares(self) -> tuple[ShareRecord, ...]: ...

    def read_apply_details(self, name: str) -> ShareDetails: ...

    def validate_apply_principals_globally(
        self, lookup_share: str, permissions: tuple[PermissionSpec, ...]
    ) -> None: ...

    def preflight_apply_create(self) -> None: ...

    def create_share(self, request: ShareCreateRequest) -> object: ...

    def delete_share(self, request: ShareDeleteRequest) -> object: ...

    def update_share_scalars(self, request: ShareScalarUpdateRequest) -> object: ...

    def replace_apply_acl(
        self, name: str, permissions: tuple[PermissionSpec, ...]
    ) -> object: ...

    def replace_apply_nfs(
        self, name: str, permissions: tuple[NfsClientPermission, ...]
    ) -> object: ...


def load_apply_config(path: str) -> ApplyConfig:
    """Load and strictly validate a V1 apply-config document."""
    try:
        source = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError("unable to load apply configuration") from exc
    return parse_apply_config(source)


def parse_apply_config(source: str) -> ApplyConfig:
    """Parse and strictly validate V1 configuration source text."""
    try:
        loaded = yaml.load(source, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ConfigurationError("unable to load apply configuration") from exc
    root = _mapping(loaded, "configuration root")
    _keys(
        root,
        {"version", "host", "principal_lookup_share", "volumes"},
        "configuration root",
    )
    if isinstance(root.get("version"), bool) or root.get("version") != 1:
        raise ConfigurationError("configuration version must be 1")
    host = _optional_text(root.get("host", _MISSING), "host", nonblank=True)
    lookup_share = _optional_text(
        root.get("principal_lookup_share", _MISSING),
        "principal_lookup_share",
        nonblank=True,
    )
    if lookup_share is not _MISSING:
        validate_share_create_request(
            ShareCreateRequest(cast(str, lookup_share), "/volume1")
        )
    volumes = _mapping(root.get("volumes"), "volumes")
    shares: list[ApplyShare] = []
    names: set[str] = set()
    for volume, entry in volumes.items():
        if not isinstance(volume, str):
            raise ConfigurationError("volume path must be a string")
        _valid_volume(volume)
        volume_data = _mapping(entry, "volume")
        _keys(volume_data, {"shares"}, "volume")
        values = _sequence(volume_data.get("shares"), "volume shares")
        for value in values:
            share = _share(_mapping(value, "share"), volume)
            if share.name in names:
                raise ConfigurationError(
                    "duplicate share names across volumes are not allowed"
                )
            names.add(share.name)
            shares.append(share)
    principal_lookup_share = (
        None if lookup_share is _MISSING else cast(str | None, lookup_share)
    )
    if principal_lookup_share is not None and any(
        share.name == principal_lookup_share and share.state == "absent"
        for share in shares
    ):
        raise ConfigurationError("principal_lookup_share cannot be state: absent")
    return ApplyConfig(
        host=None if host is _MISSING else cast(str | None, host),
        principal_lookup_share=principal_lookup_share,
        shares=tuple(sorted(shares, key=lambda item: item.name)),
    )


def build_apply_plan(config: ApplyConfig, client: ApplyClient) -> ApplyPlan:
    """Complete global remote preflight before constructing a mutation plan."""
    inventory: dict[str, ShareRecord] = {}
    for share in client.list_shares():
        if share.name in inventory:
            raise ApiError("duplicate live share name in inventory")
        inventory[share.name] = share
    existing: dict[str, ShareDetails] = {}
    new_shares: list[ApplyShare] = []
    effective_descriptions: dict[str, str] = {}

    for desired in config.shares:
        listed = inventory.get(desired.name)
        if desired.state == "absent":
            continue
        if listed is None:
            _validate_desired_quota_capability(desired, None)
            new_shares.append(desired)
            effective_descriptions[desired.name] = (
                ""
                if desired.description is _MISSING
                else cast(str, desired.description)
            )
            continue
        if listed.volume != desired.volume:
            raise ApiError(f"share {desired.name} exists on a different volume")
        details = client.read_apply_details(desired.name)
        _validate_details(details, desired.name)
        _validate_desired_quota_capability(desired, details.share)
        existing[desired.name] = details
        effective_descriptions[desired.name] = (
            cast(str, details.share.description)
            if desired.description is _MISSING
            else cast(str, desired.description)
        )

    if new_shares:
        client.preflight_apply_create()

    requested_principals = _requested_principal_permissions(config.shares)
    if requested_principals or config.principal_lookup_share is not None:
        lookup_share = _select_principal_lookup_share(config, inventory, existing)
        client.validate_apply_principals_globally(lookup_share, requested_principals)

    operations: list[ApplyOperation] = []
    for desired in config.shares:
        listed = inventory.get(desired.name)
        if desired.state == "absent":
            if listed is not None:
                operations.append(
                    ApplyOperation(desired.name, "delete", "present", "absent")
                )
        elif listed is None:
            operations.extend(_create_operations(desired))
        else:
            operations.extend(
                _existing_operations(
                    desired,
                    existing[desired.name],
                    effective_descriptions[desired.name],
                )
            )
    return ApplyPlan(
        config=config,
        operations=tuple(operations),
        effective_descriptions=tuple(sorted(effective_descriptions.items())),
    )


def _requested_principal_permissions(
    shares: tuple[ApplyShare, ...],
) -> tuple[PermissionSpec, ...]:
    """Return unique requested ACL identities from present shares."""
    seen: set[PrincipalIdentity] = set()
    requested: list[PermissionSpec] = []
    for share in shares:
        if share.state != "present":
            continue
        for permission in share.acl:
            identity = PrincipalIdentity(
                permission.principal_type, permission.principal_name
            )
            if identity not in seen:
                seen.add(identity)
                requested.append(permission)
    return tuple(
        sorted(
            requested,
            key=lambda item: (item.principal_type.value, item.principal_name),
        )
    )


def _select_principal_lookup_share(
    config: ApplyConfig,
    inventory: Mapping[str, ShareRecord],
    existing: Mapping[str, ShareDetails],
) -> str:
    """Select an explicitly approved existing share for read-only ACL lookup."""
    if config.principal_lookup_share is not None:
        if config.principal_lookup_share not in inventory:
            raise ApiError("principal_lookup_share is not an existing live share")
        return config.principal_lookup_share
    if existing:
        return min(existing)
    raise ApiError(
        "principal_lookup_share is required for ACL preflight of a new share"
    )


def execute_apply_plan(plan: ApplyPlan, client: ApplyClient) -> ApplyPlan:
    """Execute a fully preflighted plan serially and retain terminal statuses."""
    completed: list[ApplyOperation] = []
    for operation in plan.operations:
        try:
            _execute_operation(operation, plan, client)
        except ScalarUpdatePreflightError:
            raise
        except Exception as exc:
            failed = ApplyOperation(
                operation.share,
                operation.family,
                operation.before,
                operation.after,
                OperationStatus.UNKNOWN
                if isinstance(exc, PartialOperationError)
                else OperationStatus.FAILED,
            )
            remaining = [
                ApplyOperation(
                    item.share,
                    item.family,
                    item.before,
                    item.after,
                    OperationStatus.SKIPPED,
                )
                for item in plan.operations[len(completed) + 1 :]
            ]
            result = ApplyPlan(
                plan.config,
                tuple([*completed, failed, *remaining]),
                plan.effective_descriptions,
            )
            raise PartialOperationError(
                "apply-config stopped after a mutation failure", result
            ) from exc
        completed.append(
            ApplyOperation(
                operation.share,
                operation.family,
                operation.before,
                operation.after,
                OperationStatus.SUCCEEDED,
            )
        )
    return ApplyPlan(plan.config, tuple(completed))


def _execute_operation(
    operation: ApplyOperation, plan: ApplyPlan, client: ApplyClient
) -> None:
    desired = next(item for item in plan.config.shares if item.name == operation.share)
    effective_descriptions = dict(plan.effective_descriptions)
    effective_description = effective_descriptions.get(desired.name, "")
    if operation.family == "create":
        description = effective_description
        client.create_share(
            validate_share_create_request(
                ShareCreateRequest(
                    desired.name,
                    desired.volume,
                    description,
                    ShareCreateOptions(
                        quota_api_value=(
                            desired.quota_mib
                            if desired.quota_mib is not None
                            else (0 if _canonical_volume(desired.volume) else None)
                        ),
                        scalar_options_available=_canonical_volume(desired.volume),
                    ),
                )
            )
        )
        observed = client.read_apply_details(desired.name).share
        if observed.name != desired.name or observed.volume != desired.volume:
            raise PartialOperationError(
                "created share identity verification failed", None
            )
        expected_quota = (
            desired.quota_mib
            if desired.quota_mib is not None
            else (0 if _canonical_volume(desired.volume) else None)
        )
        if (
            observed.description != description
            or (
                expected_quota is not None
                and observed.quota_api_value != expected_quota
            )
        ):
            client.update_share_scalars(
                ShareScalarUpdateRequest(
                    desired.name, description, expected_quota
                )
            )
            verified = client.read_apply_details(desired.name).share
            if (
                verified.name != desired.name
                or verified.volume != desired.volume
                or verified.description != description
                or (
                    expected_quota is not None
                    and verified.quota_api_value != expected_quota
                )
            ):
                raise PartialOperationError("created share verification failed", None)

    elif operation.family == "scalars":
        quota_mib = (
            desired.quota_mib
            if desired.quota_mib is not None
            else (0 if _canonical_volume(desired.volume) else None)
        )
        client.update_share_scalars(
            ShareScalarUpdateRequest(desired.name, effective_description, quota_mib)
        )
        verified = client.read_apply_details(desired.name).share
        if (
            verified.name != desired.name
            or verified.volume != desired.volume
            or verified.description != effective_description
            or (
                desired.quota_mib is not None
                and verified.quota_api_value != desired.quota_mib
            )
        ):
            raise PartialOperationError("share scalar read-back did not match", None)
    elif operation.family == "acl":
        client.replace_apply_acl(desired.name, desired.acl)
        acl_observed = client.read_apply_details(desired.name)
        _validate_details(acl_observed, desired.name)
        _assert_protected_administrator_grant(acl_observed.acl_permissions)
        actual = _mutable_live_acl(acl_observed.acl_permissions)
        if _acl_set(actual) != _acl_set(desired.acl):
            raise PartialOperationError("ACL read-back did not match", None)
    elif operation.family == "nfs":
        client.replace_apply_nfs(desired.name, desired.nfs)
        nfs_observed = client.read_apply_details(desired.name)
        _validate_details(nfs_observed, desired.name)
        if _nfs_set(nfs_observed.nfs_permissions) != _nfs_set(desired.nfs):
            raise PartialOperationError("NFS read-back did not match", None)
    elif operation.family == "delete":
        client.delete_share(ShareDeleteRequest(desired.name))


def _create_operations(desired: ApplyShare) -> list[ApplyOperation]:
    return [
        ApplyOperation(desired.name, "create", "absent", "present"),
        ApplyOperation(
            desired.name, "acl", "unknown mutable entries", _acl_text(desired.acl)
        ),
        ApplyOperation(desired.name, "nfs", "unknown rules", _nfs_text(desired.nfs)),
    ]


def _existing_operations(
    desired: ApplyShare, details: ShareDetails, effective_description: str
) -> list[ApplyOperation]:
    share = details.share
    operations: list[ApplyOperation] = []
    description = share.description or ""
    raw_quota = share.quota_api_value
    desired_quota = (
        0 if desired.quota_mib is None and raw_quota is not None else desired.quota_mib
    )
    wanted_description = effective_description
    if description != wanted_description or (
        desired_quota is not None and raw_quota != desired_quota
    ):
        operations.append(
            ApplyOperation(
                desired.name,
                "scalars",
                f"{description} | {_quota_text(raw_quota)}",
                f"{wanted_description} | {_quota_text(desired_quota)}",
            )
        )
    actual_acl = _mutable_live_acl(details.acl_permissions)
    if _acl_set(actual_acl) != _acl_set(desired.acl):
        operations.append(
            ApplyOperation(
                desired.name, "acl", _acl_text(actual_acl), _acl_text(desired.acl)
            )
        )
    if _nfs_set(details.nfs_permissions) != _nfs_set(desired.nfs):
        operations.append(
            ApplyOperation(
                desired.name,
                "nfs",
                _nfs_text(details.nfs_permissions),
                _nfs_text(desired.nfs),
            )
        )
    return operations


def _validate_details(details: ShareDetails, name: str) -> None:
    if (
        details.share.name != name
        or details.acl_status.value == "unavailable"
        or details.nfs_status.value == "unavailable"
    ):
        raise ApiError("incomplete share preflight response")
    identities = Counter((item.category, item.name) for item in details.acl_permissions)
    if any(count != 1 for count in identities.values()):
        raise ApiError("duplicate active ACL permission response item")
    for item in details.acl_permissions:
        _normalize_live_acl(item)
    if details.nfs_display_permissions and any(
        not isinstance(permission, NfsClientPermission)
        for permission in details.nfs_display_permissions
    ):
        raise ApiError("invalid NFS client in live share response")
    if any(
        not isinstance(permission.root_squash, NfsRootSquash)
        for permission in details.nfs_permissions
    ):
        raise ApiError("invalid NFS root_squash in live share response")
    if any(
        permission.security_flavor != NfsSecurityFlavor()
        for permission in details.nfs_permissions
    ):
        raise ApiError("unsupported NFS security flavor in live share response")
    try:
        clients = [
            normalize_nfs_client(permission.client)[1]
            for permission in details.nfs_permissions
        ]
    except ConfigurationError as exc:
        raise ApiError("invalid NFS client in live share response") from exc
    if len(set(clients)) != len(clients):
        raise ApiError("duplicate live NFS clients")


def _share(data: Mapping[str, object], volume: str) -> ApplyShare:
    _keys(data, {"name", "state", "description", "quota", "acl", "nfs"}, "share")
    name = data.get("name")
    if not isinstance(name, str):
        raise ConfigurationError("share name must be a string")
    validate_share_create_request(ShareCreateRequest(name, volume))
    state = data.get("state", "present")
    if state not in {"present", "absent"}:
        raise ConfigurationError("share state must be present or absent")
    if state == "absent":
        if set(data) != {"name", "state"}:
            raise ConfigurationError("absent shares allow only name and state")
        return ApplyShare(name.strip(), volume, state, _MISSING, 0, (), ())
    description = _optional_text(data.get("description", _MISSING), "description")
    quota = data.get("quota", _MISSING)
    if quota is _MISSING:
        quota_mib = None
    elif (
        isinstance(quota, bool)
        or not isinstance(quota, int)
        or not 0 <= quota <= MAX_QUOTA_GIB
    ):
        raise ConfigurationError(f"quota must be between 0 and {MAX_QUOTA_GIB} GiB")
    else:
        quota_mib = quota * 1024
    return ApplyShare(
        name.strip(),
        volume,
        state,
        description,
        quota_mib,
        _acl(data.get("acl", _MISSING)),
        _nfs(data.get("nfs", _MISSING)),
    )


def _acl(value: object) -> tuple[PermissionSpec, ...]:
    if value is _MISSING:
        return ()
    data = _mapping(value, "acl")
    _keys(data, {"entries"}, "acl")
    entries = _sequence(data.get("entries"), "acl entries")
    result: list[PermissionSpec] = []
    identities: set[tuple[str, str]] = set()
    for entry in entries:
        item = _mapping(entry, "acl entry")
        _keys(item, {"principal", "principal_type", "permissions"}, "acl entry")
        principal = _required_text(item.get("principal"), "ACL principal")
        try:
            principal_type = PermissionPrincipalType(
                _required_text(item.get("principal_type"), "ACL principal_type")
            )
            access = PermissionAccessMode(
                _required_text(item.get("permissions"), "ACL permissions")
            )
        except ValueError as exc:
            raise ConfigurationError(
                "unsupported ACL principal type or permissions"
            ) from exc
        if (
            principal_type is PermissionPrincipalType.LOCAL_GROUP
            and principal == "administrators"
        ):
            raise ConfigurationError(
                "administrators ACL grant is managed implicitly by apply-config"
            )
        identity = (principal_type.value, principal)
        if identity in identities:
            raise ConfigurationError("duplicate ACL principal identity")
        identities.add(identity)
        result.append(PermissionSpec(principal_type, principal, access))
    return tuple(result)


def _nfs(value: object) -> tuple[NfsClientPermission, ...]:
    if value is _MISSING:
        return ()
    data = _mapping(value, "nfs")
    _keys(data, {"rules"}, "nfs")
    rules = _sequence(data.get("rules"), "nfs rules")
    result: list[NfsClientPermission] = []
    clients: set[tuple[int, int, int]] = set()
    for rule in rules:
        item = _mapping(rule, "nfs rule")
        _keys(
            item,
            {
                "client_cidr",
                "access",
                "root_squash",
                "security_flavors",
                "async",
                "insecure",
                "crossmnt",
            },
            "nfs rule",
        )
        client, normalized = normalize_nfs_client(
            _required_text(item.get("client_cidr"), "NFS client")
        )
        if normalized in clients:
            raise ConfigurationError("duplicate normalized NFS clients")
        clients.add(normalized)
        try:
            access = NfsAccessMode(_required_text(item.get("access"), "NFS access"))
        except ValueError as exc:
            raise ConfigurationError(
                "NFS access must be read-only or read-write"
            ) from exc
        try:
            root_squash = NfsRootSquash(
                _required_text(item.get("root_squash"), "NFS root_squash")
            )
        except ValueError as exc:
            raise ConfigurationError(
                "NFS root_squash must be one of root, admin, guest, all_admin, or "
                "all_guest; Linux no_root_squash and none are not accepted by this "
                "DSM API"
            ) from exc
        if item.get("security_flavors") != ["sys"]:
            raise ConfigurationError("NFS security_flavors must be [sys]")
        flags = [
            _strict_bool(item.get(key), f"NFS {key}")
            for key in ("async", "insecure", "crossmnt")
        ]
        result.append(
            NfsClientPermission(
                client,
                access,
                flags[0],
                flags[1],
                flags[2],
                root_squash,
                NfsSecurityFlavor(),
            )
        )
    return tuple(result)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ConfigurationError(f"{label} must be a mapping")
    return value


def _sequence(value: object, label: str) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ConfigurationError(f"{label} must be a list")
    return value


def _keys(data: Mapping[str, object], allowed: set[str], label: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise ConfigurationError(
            f"unknown {label} fields: {', '.join(sorted(unknown))}"
        )


def _required_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or _control(value):
        raise ConfigurationError(
            f"{label} must be nonblank text without control characters"
        )
    return value.strip()


def _optional_text(
    value: object, label: str, *, nonblank: bool = False
) -> str | None | object:
    if value is _MISSING:
        return _MISSING
    if (
        not isinstance(value, str)
        or _control(value)
        or (nonblank and not value.strip())
    ):
        raise ConfigurationError(f"{label} must be valid text")
    return value.strip() if nonblank else value


def _valid_volume(volume: str) -> None:
    validate_share_create_request(ShareCreateRequest("validation", volume))


def _strict_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{label} must be boolean")
    return value


def _control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


_ACL_CATEGORY_TYPES = {
    "local_user": PermissionPrincipalType.LOCAL_USER,
    "local_group": PermissionPrincipalType.LOCAL_GROUP,
    "ldap_user": PermissionPrincipalType.LDAP_USER,
    "ldap_group": PermissionPrincipalType.LDAP_GROUP,
}


def _normalize_live_acl(item: AclPermissionRecord) -> PermissionSpec:
    try:
        principal_type = _ACL_CATEGORY_TYPES[item.category]
    except KeyError as exc:
        raise ApiError("invalid ACL permission category") from exc
    if not item.name:
        raise ApiError("invalid ACL permission principal")
    return PermissionSpec(principal_type, item.name, _acl_access(item))


def _mutable_live_acl(
    permissions: tuple[AclPermissionRecord, ...],
) -> tuple[PermissionSpec, ...]:
    """Return mutable ACL entries after verifying the protected grant."""
    protected = [
        item
        for item in permissions
        if item.category == "local_group" and item.name == "administrators"
    ]
    if (
        len(protected) == 1
        and _acl_access(protected[0]) is PermissionAccessMode.READ_WRITE
    ):
        return tuple(
            _normalize_live_acl(item)
            for item in permissions
            if item is not protected[0]
        )
    return tuple(_normalize_live_acl(item) for item in permissions)


def _assert_protected_administrator_grant(
    permissions: tuple[AclPermissionRecord, ...],
) -> None:
    """Require exactly one read-write local administrators ACL grant."""
    protected = [
        item
        for item in permissions
        if item.category == "local_group" and item.name == "administrators"
    ]
    if (
        len(protected) != 1
        or _acl_access(protected[0]) is not PermissionAccessMode.READ_WRITE
    ):
        raise PartialOperationError(
            "protected administrators ACL grant is missing", None
        )


def _acl_access(item: AclPermissionRecord) -> PermissionAccessMode:
    active_bits = sum((item.is_deny, item.is_readonly, item.is_writable))
    if active_bits != 1:
        raise ApiError("ambiguous ACL permission flags")
    if item.is_deny:
        return PermissionAccessMode.DENY
    if item.is_readonly:
        return PermissionAccessMode.READ_ONLY
    return PermissionAccessMode.READ_WRITE


def _acl_set(values: tuple[PermissionSpec, ...]) -> Counter[tuple[str, str, str]]:
    return Counter(
        (item.principal_type.value, item.principal_name, item.access_mode.value)
        for item in values
    )


def _nfs_set(values: tuple[NfsClientPermission, ...]) -> set[tuple[object, ...]]:
    return {
        (
            item.client,
            item.access_mode.value,
            item.async_enabled,
            item.insecure,
            item.crossmnt,
            item.root_squash.value,
            item.security_flavor.sys,
            item.security_flavor.kerberos,
            item.security_flavor.kerberos_integrity,
            item.security_flavor.kerberos_privacy,
        )
        for item in values
    }


def _validate_desired_quota_capability(
    desired: ApplyShare, observed: ShareRecord | None
) -> None:
    unavailable = (
        not _canonical_volume(desired.volume)
        if observed is None
        else observed.quota_api_value is None
    )
    if unavailable and desired.quota_mib is not None:
        raise ApiError(
            f"share {desired.name} on {desired.volume} "
            "does not support quota management"
        )


def _canonical_volume(volume: str) -> bool:
    return volume.startswith("/volume") and volume[7:].isdigit() and int(volume[7:]) > 0


def _quota_text(value: int | None) -> str:
    if value is None:
        return "unavailable"
    return "unlimited (0 MiB)" if value == 0 else f"{value} MiB"


def _acl_text(values: tuple[PermissionSpec, ...]) -> str:
    return (
        "clear mutable entries"
        if not values
        else ", ".join(
            f"{item.principal_type.value}:{item.principal_name}:{item.access_mode.value}"
            for item in values
        )
    )


def _nfs_text(values: tuple[NfsClientPermission, ...]) -> str:
    return (
        "clear rules"
        if not values
        else ", ".join(
            f"{item.client}:{item.access_mode.value}:root_squash={item.root_squash.value}"
            for item in values
        )
    )


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConfigurationError("duplicate YAML key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)
