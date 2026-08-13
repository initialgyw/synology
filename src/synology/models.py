from dataclasses import dataclass, field
from enum import StrEnum


@dataclass(frozen=True, slots=True)
class ConnectionConfig:
    username: str
    password: str = field(repr=False)
    host: str
    port: int = 5001
    insecure: bool = False


class Command(StrEnum):
    LIST_SHARES = "list-shares"
    CREATE_SHARE = "create-share"
    DELETE_SHARE = "delete-share"
    MODIFY_SHARE = "modify-share"
    APPLY_CONFIG = "apply-config"
    CONFIG_IMPORT = "config-import"


class OperationStatus(StrEnum):
    PLANNED = "planned"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


class PermissionPrincipalType(StrEnum):
    LOCAL_USER = "local-user"
    LOCAL_GROUP = "local-group"
    LDAP_USER = "ldap-user"
    LDAP_GROUP = "ldap-group"


class PermissionAccessMode(StrEnum):
    READ_ONLY = "read-only"
    READ_WRITE = "read-write"
    DENY = "deny"


class PermissionStatus(StrEnum):
    PLANNED = "planned"
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    FAILED = "failed"


class EnrichmentStatus(StrEnum):
    NOT_REQUESTED = "not-requested"
    EMPTY = "empty"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class NfsAccessMode(StrEnum):
    READ_ONLY = "read-only"
    READ_WRITE = "read-write"


class NfsRootSquash(StrEnum):
    ROOT = "root"
    ADMIN = "admin"
    GUEST = "guest"
    ALL_ADMIN = "all_admin"
    ALL_GUEST = "all_guest"


@dataclass(frozen=True, slots=True)
class NfsSecurityFlavor:
    sys: bool = True
    kerberos: bool = False
    kerberos_integrity: bool = False
    kerberos_privacy: bool = False


@dataclass(frozen=True, slots=True)
class NfsClientPermission:
    client: str
    access_mode: NfsAccessMode
    async_enabled: bool = False
    insecure: bool = False
    crossmnt: bool = False
    root_squash: NfsRootSquash = NfsRootSquash.ROOT
    security_flavor: NfsSecurityFlavor = field(default_factory=NfsSecurityFlavor)


@dataclass(frozen=True, slots=True)
class NfsDisplayPermission:
    client: str
    access_mode: NfsAccessMode
    async_enabled: bool = False
    insecure: bool = False
    crossmnt: bool = False
    root_squash: NfsRootSquash = NfsRootSquash.ROOT
    security_flavor: NfsSecurityFlavor = field(default_factory=NfsSecurityFlavor)


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    principal_type: PermissionPrincipalType
    principal_name: str
    access_mode: PermissionAccessMode


@dataclass(frozen=True, slots=True)
class PrincipalIdentity:
    principal_type: PermissionPrincipalType
    name: str


@dataclass(frozen=True, slots=True)
class PrincipalLookupRequest:
    lookup_share: str
    identities: tuple[PrincipalIdentity, ...]


@dataclass(frozen=True, slots=True)
class PrincipalLookupResult:
    lookup_share: str
    identities: tuple[PrincipalIdentity, ...]


@dataclass(frozen=True, slots=True)
class RecycleBinOptions:
    enabled: bool = True
    admin_only: bool = True


@dataclass(frozen=True, slots=True)
class ShareCreateOptions:
    recycle_bin: RecycleBinOptions = field(default_factory=RecycleBinOptions)
    compression_enabled: bool = False
    quota_gib: int | None = None
    quota_api_value: int | None = None
    scalar_options_available: bool = True


@dataclass(frozen=True, slots=True)
class ShareOperationStep:
    name: str
    status: OperationStatus
    message: str | None = None
    permission_status: PermissionStatus | None = None


@dataclass(frozen=True, slots=True)
class CliArguments:
    username: str | None
    password: str | None
    host: str | None
    port: int
    insecure: bool
    verbose: bool
    output: "OutputFormat"
    command: Command = Command.LIST_SHARES
    name: str = ""
    volume_path: str = ""
    description: str = ""
    confirm: bool = False
    disable_recycle_bin: bool = False
    recycle_bin_user_access: bool = False
    compress: bool = False
    quota_gib: int | None = None
    quota_values: tuple[int, ...] = ()
    permission_specs: tuple[str, ...] = ()
    nfs_permission_specs: tuple[str, ...] = ()
    permissions: bool = False
    config_path: str = ""


@dataclass(frozen=True, slots=True)
class ShareListRequest:
    share_type: str = "all"
    additional: tuple[str, ...] = ("share_quota",)


@dataclass(frozen=True, slots=True)
class ShareCreateRequest:
    name: str
    volume_path: str
    description: str = ""
    options: ShareCreateOptions = field(default_factory=ShareCreateOptions)
    permissions: tuple[PermissionSpec, ...] = ()
    nfs_permissions: tuple[NfsClientPermission, ...] = ()


@dataclass(frozen=True, slots=True)
class ShareCreateResult:
    name: str
    volume: str
    description: str
    created: bool
    options: ShareCreateOptions = field(default_factory=ShareCreateOptions)
    permissions: tuple[PermissionSpec, ...] = ()
    nfs_permissions: tuple[NfsClientPermission, ...] = ()
    steps: tuple[ShareOperationStep, ...] = ()


@dataclass(frozen=True, slots=True)
class ShareDeleteRequest:
    name: str


@dataclass(frozen=True, slots=True)
class ShareModifyRequest:
    name: str
    quota_gib: int | None = None
    permissions: tuple[PermissionSpec, ...] | None = None
    nfs_permissions: tuple[NfsClientPermission, ...] | None = None
    _acl_clear_mode: bool = field(default=False, repr=False, compare=False)
    _acl_authoritative_mode: bool = field(default=False, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ShareQuotaState:
    api_value: int
    api_unit: str = "MiB"

    @property
    def unlimited(self) -> bool:
        return self.api_value == 0

    @property
    def gib(self) -> float | None:
        return None if self.unlimited else self.api_value / 1024


@dataclass(frozen=True, slots=True)
class ShareCapabilities:
    quota_available: bool
    compression_available: bool
    cow_available: bool


@dataclass(frozen=True, slots=True)
class MutableShareState:
    name: str
    volume_path: str
    description: str
    hidden: bool
    recycle_bin_enabled: bool
    recycle_bin_admin_only: bool
    compression_enabled: bool | None
    cow_enabled: bool | None
    quota: ShareQuotaState | None
    capabilities: ShareCapabilities


@dataclass(frozen=True, slots=True)
class ShareScalarUpdateRequest:
    """Requested managed share scalar changes after apply-config preflight."""

    name: str
    description: str
    quota_api_value: int | None = None


@dataclass(frozen=True, slots=True)
class ShareScalarUpdatePayload:
    name: str
    version: int
    shareinfo: str


@dataclass(frozen=True, slots=True)
class ShareModifyResult:
    name: str
    changed: bool
    quota_gib: int | None = None
    observed_quota: ShareQuotaState | None = None
    permissions: tuple[PermissionSpec, ...] | None = None
    nfs_permissions: tuple[NfsClientPermission, ...] | None = None
    steps: tuple[ShareOperationStep, ...] = ()


@dataclass(frozen=True, slots=True)
class ShareDeleteResult:
    name: str
    deleted: bool
    steps: tuple[ShareOperationStep, ...] = ()


@dataclass(frozen=True, slots=True)
class ShareRecord:
    name: str
    volume: str | None = None
    description: str | None = None
    uuid: str | None = None
    is_usb: bool | None = None
    quota_gib: float | None = None
    quota_api_value: int | None = None
    quota_api_unit: str = "MiB"


@dataclass(frozen=True, slots=True)
class AclPermissionRecord:
    name: str
    category: str
    is_deny: bool
    is_readonly: bool
    is_writable: bool
    is_custom: bool
    is_admin: bool


@dataclass(frozen=True, slots=True)
class AclPrincipal:
    name: str
    category: str


@dataclass(frozen=True, slots=True)
class AclPermissionState:
    name: str
    category: str
    access_mode: PermissionAccessMode
    is_custom: bool
    is_admin: bool


@dataclass(frozen=True, slots=True)
class AclPermissionInventory:
    category: str
    principals: tuple[AclPrincipal, ...]
    active_permissions: tuple[AclPermissionState, ...]


@dataclass(frozen=True, slots=True)
class EnrichmentDiagnostic:
    share_name: str
    detail: str
    category: str | None = None
    status: EnrichmentStatus = EnrichmentStatus.UNAVAILABLE


@dataclass(frozen=True, slots=True)
class ShareDetails:
    share: ShareRecord
    acl_permissions: tuple[AclPermissionRecord, ...] = ()
    nfs_permissions: tuple[NfsClientPermission, ...] = ()
    acl_status: EnrichmentStatus = EnrichmentStatus.NOT_REQUESTED
    nfs_status: EnrichmentStatus = EnrichmentStatus.NOT_REQUESTED
    diagnostics: tuple[EnrichmentDiagnostic, ...] = ()
    nfs_display_permissions: tuple[NfsClientPermission | NfsDisplayPermission, ...] = (
        field(default=(), repr=False, compare=False)
    )


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    YAML = "yaml"
