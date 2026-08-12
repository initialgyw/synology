import ipaddress
import os
from collections.abc import Mapping
from dataclasses import replace

from synology.exceptions import ConfigurationError
from synology.models import (
    CliArguments,
    ConnectionConfig,
    NfsAccessMode,
    NfsClientPermission,
    NfsRootSquash,
    NfsSecurityFlavor,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    RecycleBinOptions,
    ShareCreateOptions,
    ShareCreateRequest,
    ShareDeleteRequest,
    ShareModifyRequest,
)

QUOTA_MIB_PER_GIB = 1024
MAX_QUOTA_API_MIB = 2_147_483_647
MAX_QUOTA_GIB = MAX_QUOTA_API_MIB // QUOTA_MIB_PER_GIB


def parse_permission_spec(specification: str) -> PermissionSpec:
    if ":" not in specification:
        raise ConfigurationError("permission must be TYPE:NAME:ACCESS")
    principal_type_text, remainder = specification.split(":", 1)
    if ":" not in remainder:
        raise ConfigurationError("permission must be TYPE:NAME:ACCESS")
    principal_name, access_mode_text = remainder.rsplit(":", 1)
    if not principal_type_text or not principal_name or not access_mode_text:
        raise ConfigurationError("permission type, name, and access are required")
    try:
        principal_type = PermissionPrincipalType(principal_type_text)
        access_mode = PermissionAccessMode(access_mode_text)
    except ValueError as exc:
        raise ConfigurationError("unsupported permission type or access mode") from exc
    return PermissionSpec(principal_type, principal_name, access_mode)


def parse_nfs_permission_spec(specification: str) -> NfsClientPermission:
    parts = specification.split(",")
    values: dict[str, str] = {}
    allowed = {"client", "access", "async", "insecure", "crossmnt", "root_squash"}
    for part in parts:
        if "=" not in part:
            raise ConfigurationError(
                "nfs permission must use comma-separated key=value pairs"
            )
        key, value = (item.strip() for item in part.split("=", 1))
        if key not in allowed:
            raise ConfigurationError(f"unknown nfs permission key: {key}")
        if key in values:
            raise ConfigurationError(f"duplicate nfs permission key: {key}")
        if not value:
            raise ConfigurationError("nfs permission values must not be empty")
        values[key] = value
    if set(values) & {"client", "access"} != {"client", "access"}:
        raise ConfigurationError("nfs permission requires client and access")
    client = _normalize_nfs_client(values["client"])
    try:
        access_mode = NfsAccessMode(values["access"])
    except ValueError as exc:
        raise ConfigurationError("nfs access must be read-only or read-write") from exc
    booleans: dict[str, bool] = {}
    for key in ("async", "insecure", "crossmnt"):
        value = values.get(key, "false")
        if value not in {"true", "false"}:
            raise ConfigurationError(f"nfs {key} must be true or false")
        booleans[key] = value == "true"
    try:
        root_squash = NfsRootSquash(values.get("root_squash", "root"))
    except ValueError as exc:
        raise ConfigurationError(
            "nfs root_squash must be one of root, admin, guest, all_admin, or "
            "all_guest; Linux no_root_squash and none are not accepted by this DSM API"
        ) from exc
    return NfsClientPermission(
        client=client,
        access_mode=access_mode,
        async_enabled=booleans["async"],
        insecure=booleans["insecure"],
        crossmnt=booleans["crossmnt"],
        root_squash=root_squash,
        security_flavor=NfsSecurityFlavor(),
    )


def normalize_nfs_client(value: str) -> tuple[str, tuple[int, int, int]]:
    if value == "*":
        return value, (0, 0, 0)
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=True)
            return str(network), (
                network.version,
                int(network.network_address),
                network.prefixlen,
            )
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigurationError(
            "nfs client must be a valid IP address, CIDR, or wildcard"
        ) from exc
    return str(address), (address.version, int(address), address.max_prefixlen)


def _normalize_nfs_client(value: str) -> str:
    return normalize_nfs_client(value)[0]


def validate_nfs_permission_specs(
    specifications: tuple[str, ...],
) -> tuple[NfsClientPermission, ...]:
    permissions = tuple(parse_nfs_permission_spec(item) for item in specifications)
    clients = [normalize_nfs_client(item.client)[1] for item in permissions]
    if len(set(clients)) != len(clients):
        raise ConfigurationError("duplicate nfs clients are not allowed")
    return permissions


def validate_permission_specs(
    specifications: tuple[str, ...],
) -> tuple[PermissionSpec, ...]:
    permissions = tuple(parse_permission_spec(item) for item in specifications)
    if len(set(permissions)) != len(permissions):
        raise ConfigurationError("duplicate permission specifications are not allowed")
    identities = {(item.principal_type, item.principal_name) for item in permissions}
    if len(identities) != len(permissions):
        raise ConfigurationError(
            "conflicting permission specifications are not allowed"
        )
    return permissions


def validate_share_modify_request(request: ShareModifyRequest) -> ShareModifyRequest:
    name = request.name.strip()
    if not name:
        raise ConfigurationError("share name must not be empty")
    if name in {".", ".."} or any(character in {"/", "\\"} for character in name):
        raise ConfigurationError("share name contains invalid characters")
    if _contains_control_characters(name):
        raise ConfigurationError("share name contains invalid characters")
    families = sum(
        item is not None
        for item in (
            request.quota_gib,
            request.permissions,
            request.nfs_permissions,
        )
    )
    if families != 1:
        raise ConfigurationError(
            "exactly one of quota, permissions, or NFS permissions must be selected"
        )
    if request.quota_gib is not None:
        if isinstance(request.quota_gib, bool) or not isinstance(
            request.quota_gib, int
        ):
            raise ConfigurationError("quota must be an integer GiB value")
        if request.quota_gib < 0 or request.quota_gib > MAX_QUOTA_GIB:
            raise ConfigurationError(f"quota must be between 0 and {MAX_QUOTA_GIB} GiB")
    nfs_permissions = (
        None
        if request.nfs_permissions is None
        else _validate_nfs_permissions(request.nfs_permissions)
    )
    return replace(request, name=name, nfs_permissions=nfs_permissions)


def validate_share_delete_request(request: ShareDeleteRequest) -> ShareDeleteRequest:
    name = request.name.strip()
    if not name:
        raise ConfigurationError("share name must not be empty")
    if name in {".", ".."} or any(character in {"/", "\\"} for character in name):
        raise ConfigurationError("share name contains invalid characters")
    if _contains_control_characters(name):
        raise ConfigurationError("share name contains invalid characters")
    return ShareDeleteRequest(name=name)


def validate_share_create_request(request: ShareCreateRequest) -> ShareCreateRequest:
    name = request.name.strip()
    volume_path = request.volume_path.strip()
    description = request.description
    if not name:
        raise ConfigurationError("share name must not be empty")
    if name in {".", ".."} or any(character in {"/", "\\"} for character in name):
        raise ConfigurationError("share name contains invalid characters")
    if _contains_control_characters(name):
        raise ConfigurationError("share name contains invalid characters")
    if not volume_path or not volume_path.startswith("/"):
        raise ConfigurationError("share volume path must be an absolute NAS path")
    if _contains_control_characters(volume_path):
        raise ConfigurationError("share volume path contains invalid characters")
    if _contains_control_characters(description):
        raise ConfigurationError("share description contains invalid characters")
    options = _validate_options(request.options)
    return ShareCreateRequest(
        name=name,
        volume_path=volume_path,
        description=description,
        options=options,
        permissions=request.permissions,
        nfs_permissions=_validate_nfs_permissions(request.nfs_permissions),
    )


def _validate_nfs_permissions(
    permissions: tuple[NfsClientPermission, ...],
) -> tuple[NfsClientPermission, ...]:
    normalized: list[NfsClientPermission] = []
    clients: set[tuple[int, int, int]] = set()
    for permission in permissions:
        if not isinstance(permission, NfsClientPermission):
            raise ConfigurationError("invalid NFS permission")
        if not isinstance(permission.client, str):
            raise ConfigurationError(
                "nfs client must be a valid IP address, CIDR, or wildcard"
            )
        client, identity = normalize_nfs_client(permission.client)
        if identity in clients:
            raise ConfigurationError("duplicate nfs clients are not allowed")
        clients.add(identity)
        if not isinstance(permission.access_mode, NfsAccessMode):
            raise ConfigurationError("nfs access must be read-only or read-write")
        if not all(
            isinstance(value, bool)
            for value in (
                permission.async_enabled,
                permission.insecure,
                permission.crossmnt,
            )
        ):
            raise ConfigurationError("nfs flags must be boolean")
        if not isinstance(permission.root_squash, NfsRootSquash):
            raise ConfigurationError("invalid nfs root_squash")
        if permission.security_flavor != NfsSecurityFlavor():
            raise ConfigurationError("NFS security_flavor must be [sys]")
        normalized.append(replace(permission, client=client))
    return tuple(normalized)


def _validate_options(options: ShareCreateOptions) -> ShareCreateOptions:
    if not isinstance(options, ShareCreateOptions):
        raise ConfigurationError("invalid share creation options")
    if not isinstance(options.recycle_bin, RecycleBinOptions):
        raise ConfigurationError("invalid recycle bin options")
    if not isinstance(options.recycle_bin.enabled, bool) or not isinstance(
        options.recycle_bin.admin_only, bool
    ):
        raise ConfigurationError("recycle bin options must be boolean")
    if not isinstance(options.compression_enabled, bool):
        raise ConfigurationError("compression option must be boolean")
    if not options.recycle_bin.enabled and not options.recycle_bin.admin_only:
        raise ConfigurationError("recycle bin user access requires recycle bin enabled")
    if options.quota_gib is not None:
        if isinstance(options.quota_gib, bool) or not isinstance(
            options.quota_gib, int
        ):
            raise ConfigurationError("quota must be a positive integer GiB value")
        if options.quota_gib <= 0 or options.quota_gib > MAX_QUOTA_GIB:
            raise ConfigurationError(f"quota must be between 1 and {MAX_QUOTA_GIB} GiB")
        quota_api_value = options.quota_gib * QUOTA_MIB_PER_GIB
        if quota_api_value > MAX_QUOTA_API_MIB:
            raise ConfigurationError("quota exceeds the supported API range")
        return replace(options, quota_api_value=quota_api_value)
    return options


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def resolve_connection_config(
    arguments: CliArguments,
    *,
    environ: Mapping[str, str] | None = None,
) -> ConnectionConfig:
    environment = os.environ if environ is None else environ
    username = _resolve_required_value(
        cli_value=arguments.username,
        environment_name="SYN_USERNAME",
        environment=environment,
        strip_value=True,
    )
    password = _resolve_required_value(
        cli_value=arguments.password,
        environment_name="SYN_PASSWORD",
        environment=environment,
        strip_value=False,
    )
    host = _resolve_required_value(
        cli_value=arguments.host,
        environment_name="SYN_HOST",
        environment=environment,
        strip_value=True,
    )
    _validate_port(arguments.port)
    return ConnectionConfig(
        username=username,
        password=password,
        host=host,
        port=arguments.port,
        insecure=arguments.insecure,
    )


def _resolve_required_value(
    *,
    cli_value: str | None,
    environment_name: str,
    environment: Mapping[str, str],
    strip_value: bool,
) -> str:
    value = cli_value if cli_value is not None else environment.get(environment_name)
    if value is None or not value.strip():
        raise ConfigurationError(f"missing required configuration: {environment_name}")
    return value.strip() if strip_value else value


def _validate_port(port: int) -> None:
    if isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigurationError("port must be between 1 and 65535")
