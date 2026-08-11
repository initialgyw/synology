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
    root_squash: str = "root"
    security_flavor: NfsSecurityFlavor = field(default_factory=NfsSecurityFlavor)


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    principal_type: PermissionPrincipalType
    principal_name: str
    access_mode: PermissionAccessMode


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
    permission_specs: tuple[str, ...] = ()
    nfs_permission_specs: tuple[str, ...] = ()
    permissions: bool = False


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


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    YAML = "yaml"
