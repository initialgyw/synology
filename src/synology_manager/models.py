from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from re import fullmatch
from typing import Any

from synology_manager.config import AclConfig, NfsRule
from synology_manager.dsm import DsmError

_SHARE_NAME = r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}"
_INTERNAL_VOLUME = r"/volume[1-9][0-9]*"
_EXTERNAL_VOLUME_ROOT = r"/volumeUSB[1-9][0-9]*"


def _external_component(value: str) -> bool:
    return value not in {".", ".."} and bool(fullmatch(_SHARE_NAME, value))


def _external_volume(value: str) -> bool:
    if not value.startswith("/"):
        return False
    root, *components = value.removeprefix("/").split("/")
    return bool(fullmatch(_EXTERNAL_VOLUME_ROOT.removeprefix("/"), root)) and all(
        _external_component(component) for component in components
    )


@dataclass(frozen=True)
class ObservedShare:
    name: str
    volume: str
    description: str
    quota_mib: int
    quota_status: str
    protected: bool

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not fullmatch(_SHARE_NAME, self.name):
            raise DsmError("observed share name is invalid")
        if not isinstance(self.volume, str) or not (
            fullmatch(_INTERNAL_VOLUME, self.volume) or _external_volume(self.volume)
        ):
            raise DsmError("observed share volume path is invalid")
        if not isinstance(self.description, str):
            raise DsmError("observed share description is invalid")
        if not isinstance(self.protected, bool):
            raise DsmError("observed share protection metadata is invalid")
        if _external_volume(self.volume):
            object.__setattr__(self, "protected", True)
        if isinstance(self.quota_mib, bool) or not isinstance(self.quota_mib, int):
            raise DsmError("observed quota is invalid")
        quota = canonical_quota(self.quota_mib, self.quota_status)
        object.__setattr__(self, "quota_mib", quota.mib)
        object.__setattr__(self, "quota_status", quota.status)

    @property
    def quota(self) -> ObservedQuota:
        return canonical_quota(self.quota_mib, self.quota_status)


@dataclass(frozen=True, order=True)
class ObservedNfsRule:
    client: str
    privilege: str
    root_squash: str
    asynchronous: bool
    insecure: bool
    crossmnt: bool
    flavors: tuple[str, ...]

    def api(self) -> dict[str, Any]:
        keys = {
            "sys": "sys",
            "krb5": "kerberos",
            "krb5i": "kerberos_integrity",
            "krb5p": "kerberos_privacy",
        }
        return {
            "client": self.client,
            "privilege": self.privilege,
            "root_squash": self.root_squash,
            "async": self.asynchronous,
            "insecure": self.insecure,
            "crossmnt": self.crossmnt,
            "security_flavor": {wire: key in self.flavors for key, wire in keys.items()},
        }


@dataclass(frozen=True, order=True)
class ObservedAclRule:
    owner_type: str
    owner_name: str
    permission_type: str
    permissions: tuple[bool, ...]
    inheritance: tuple[bool, ...]


PERMISSIONS = (
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
)
INHERITANCE = ("child_files", "child_folders", "this_folder", "all_descendants")


def _int(value: Any) -> int:
    if isinstance(value, bool):
        raise DsmError("observed quota is invalid")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isdecimal():
        result = int(value)
    else:
        raise DsmError("observed quota is invalid")
    if result < 0:
        raise DsmError("observed quota is invalid")
    return result


@dataclass(frozen=True)
class ObservedQuota:
    """Canonical share-capacity observation for the supported DSM quota contracts."""

    mib: int
    status: str


SUPPORTED_QUOTA_STATUSES = frozenset({"v1", "v2"})
UNLIMITED_QUOTA_MIB = 0


def canonical_quota(value: Any, status: Any) -> ObservedQuota:
    """Validate a normalized quota value and its DSM representation status."""
    if not isinstance(status, str) or status not in SUPPORTED_QUOTA_STATUSES:
        raise DsmError("observed share quota status is unsafe")
    return ObservedQuota(_int(value), status)


def quota_wire_value(mib: int) -> int | str:
    """Encode a canonical integer MiB quota for DSM's share mutation contract."""
    if isinstance(mib, bool) or not isinstance(mib, int) or mib < 0:
        raise DsmError("desired quota wire value is invalid")
    return "0" if mib == UNLIMITED_QUOTA_MIB else mib


def observed_quota(raw: dict[str, Any]) -> ObservedQuota:
    """Normalize DSM quota fields; omitted metadata is DSM's unlimited representation."""
    values = [raw[key] for key in ("quota_value", "share_quota") if key in raw]
    if "shareinfo" in raw:
        nested = raw["shareinfo"]
        if not isinstance(nested, dict):
            raise DsmError("observed share quota metadata is invalid")
        if "share_quota" in nested:
            values.append(nested["share_quota"])
    quotas = {_int(value) for value in values} if values else {UNLIMITED_QUOTA_MIB}
    if len(quotas) != 1:
        raise DsmError("observed share quota is conflicting")
    return canonical_quota(quotas.pop(), raw.get("share_quota_status", "v1"))


_PROTECTION_FLAGS = (
    "is_usb_share",
    "is_system_share",
    "is_package_share",
    "is_service_share",
    "is_external",
    "is_force_readonly",
    "is_readonly",
    "is_read_only",
)
_EXTERNAL_MARKERS = ("external_dev_type", "external_vol", "external_device")


def _protected(raw: dict[str, Any]) -> bool:
    flags: list[bool] = []
    for key in _PROTECTION_FLAGS:
        if key in raw:
            value = raw[key]
            if not isinstance(value, bool):
                raise DsmError("observed share protection metadata is invalid")
            flags.append(value)
    for key in _EXTERNAL_MARKERS:
        if key in raw:
            marker = raw[key]
            if not isinstance(marker, str):
                raise DsmError("observed share external marker is invalid")
            # Non-empty marker values are not assumed to be understood; protect them.
            flags.append(marker != "")
    return any(flags)


def observed_share_name(raw: Any) -> str:
    """Read only the stable list identity needed to select configured shares."""
    if not isinstance(raw, dict):
        raise DsmError("observed share entry is invalid")
    name = raw.get("name")
    if not isinstance(name, str) or not fullmatch(_SHARE_NAME, name):
        raise DsmError("observed share name is invalid")
    return name


def share(raw: Any) -> ObservedShare:
    """Normalize only DSM fields needed for safe reconciliation.

    UUID and display metadata are intentionally ignored: they are not stable identity or
    mutation inputs.  The observed DSM contract establishes descriptions as strings,
    so null or omitted descriptions are rejected rather than silently normalized.
    """
    name = observed_share_name(raw)
    assert isinstance(raw, dict)
    volume, description = raw.get("vol_path"), raw.get("desc")
    if not isinstance(volume, str):
        raise DsmError("observed share volume path is invalid")
    if not isinstance(description, str):
        raise DsmError("observed share description is invalid")
    protected = _protected(raw)
    quota = observed_quota(raw)
    return ObservedShare(name, volume, description, quota.mib, quota.status, protected)


def _client(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise DsmError("observed NFS client is invalid")
    try:
        return str(ip_network(value, strict=False))
    except ValueError:
        if value.replace("-", "").replace(".", "").isalnum() and ".." not in value:
            return value.lower()
    raise DsmError("observed NFS client is invalid")


def nfs_rule(raw: Any) -> ObservedNfsRule:
    if not isinstance(raw, dict):
        raise DsmError("observed NFS rule is invalid")
    privilege, squash = raw.get("privilege"), raw.get("root_squash")
    if privilege not in {"ro", "rw"} or squash not in {
        "root",
        "admin",
        "guest",
        "all_admin",
        "all_guest",
    }:
        raise DsmError("observed NFS rule is invalid")
    asynchronous, insecure, crossmnt = raw.get("async"), raw.get("insecure"), raw.get("crossmnt")
    flavor = raw.get("security_flavor")
    if (
        not isinstance(asynchronous, bool)
        or not isinstance(insecure, bool)
        or not isinstance(crossmnt, bool)
        or not isinstance(flavor, dict)
    ):
        raise DsmError("observed NFS rule is invalid")
    mapping = {
        "sys": "sys",
        "kerberos": "krb5",
        "kerberos_integrity": "krb5i",
        "kerberos_privacy": "krb5p",
    }
    if set(flavor) != set(mapping) or not all(isinstance(flavor[key], bool) for key in mapping):
        raise DsmError("observed NFS security flavor is invalid")
    return ObservedNfsRule(
        _client(raw.get("client")),
        privilege,
        squash,
        asynchronous,
        insecure,
        crossmnt,
        tuple(key for wire, key in mapping.items() if flavor[wire]),
    )


def nfs_rules(raw: Any) -> tuple[ObservedNfsRule, ...]:
    if not isinstance(raw, list):
        raise DsmError("NFS rule list is invalid")
    rules = tuple(sorted(nfs_rule(item) for item in raw))
    if len({rule.client for rule in rules}) != len(rules):
        raise DsmError("observed NFS client identities are duplicated")
    return rules


def desired_nfs(rule: NfsRule) -> ObservedNfsRule:
    return ObservedNfsRule(
        rule.client,
        rule.privilege,
        rule.root_squash,
        rule.asynchronous,
        rule.insecure,
        rule.crossmnt,
        rule.flavors,
    )


def acl_rules(raw: Any) -> tuple[ObservedAclRule, ...]:
    if not isinstance(raw, list):
        raise DsmError("ACL list is invalid")
    result: list[ObservedAclRule] = []
    for item in raw:
        if (
            not isinstance(item, dict)
            or item.get("level") != 0
            or item.get("owner_type") not in {"user", "group", "special"}
            or not isinstance(item.get("owner_name"), str)
            or not item["owner_name"]
            or item.get("permission_type") not in {"allow", "deny"}
        ):
            raise DsmError("ACL entry is unsupported")
        permission, inherit = item.get("permission"), item.get("inherit")
        if (
            not isinstance(permission, dict)
            or not isinstance(inherit, dict)
            or set(permission) != set(PERMISSIONS)
            or set(inherit) != set(INHERITANCE)
            or not all(isinstance(permission[key], bool) for key in PERMISSIONS)
            or not all(isinstance(inherit[key], bool) for key in INHERITANCE)
        ):
            raise DsmError("ACL entry is invalid")
        result.append(
            ObservedAclRule(
                item["owner_type"],
                item["owner_name"],
                item["permission_type"],
                tuple(permission[key] for key in PERMISSIONS),
                tuple(inherit[key] for key in INHERITANCE),
            )
        )
    if len(set(result)) != len(result):
        raise DsmError("observed ACL entries are duplicated")
    return tuple(sorted(result))


def desired_acl(config: AclConfig) -> tuple[ObservedAclRule, ...]:
    presets = {
        "read_only": {"read_data", "exe_file", "read_attr", "read_ext_attr", "read_perm"},
        "read_write": {
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
        },
        "full_control": set(PERMISSIONS),
    }
    inherit = {
        "none": set(),
        "this_folder": {"this_folder"},
        "children": {"child_files", "child_folders"},
        "all": set(INHERITANCE),
    }
    return tuple(
        sorted(
            ObservedAclRule(
                rule.owner_type,
                rule.owner_name,
                rule.permission_type,
                tuple(key in presets[rule.preset] for key in PERMISSIONS),
                tuple(key in inherit[rule.inheritance] for key in INHERITANCE),
            )
            for rule in config.rules
        )
    )


def acl_api(config: AclConfig) -> list[dict[str, Any]]:
    return [
        {
            "owner_type": rule.owner_type,
            "owner_name": rule.owner_name,
            "permission_type": rule.permission_type,
            "permission": dict(zip(PERMISSIONS, rule.permissions, strict=True)),
            "inherit": dict(zip(INHERITANCE, rule.inheritance, strict=True)),
        }
        for rule in desired_acl(config)
    ]
