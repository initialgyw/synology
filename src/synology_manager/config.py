from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from re import fullmatch
from typing import Any, Literal

import yaml


class ConfigError(ValueError):
    pass


State = Literal["present", "absent"]


def _direct_text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{where} must be a non-empty, trimmed string")
    return value


def _direct_client(value: object) -> str:
    text = _direct_text(value, "NFS client")
    try:
        return str(ip_network(text, strict=False))
    except ValueError:
        if fullmatch(
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
            text,
        ):
            return text.lower()
    raise ValueError("NFS client must be a canonical IP/CIDR or conservative hostname")


@dataclass(frozen=True)
class NfsRule:
    client: str
    privilege: Literal["ro", "rw"]
    root_squash: Literal["root", "admin", "guest", "all_admin", "all_guest"]
    asynchronous: bool
    insecure: bool
    crossmnt: bool
    flavors: tuple[Literal["sys", "krb5", "krb5i", "krb5p"], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "client", _direct_client(self.client))
        if self.privilege not in {"ro", "rw"} or self.root_squash not in {
            "root",
            "admin",
            "guest",
            "all_admin",
            "all_guest",
        }:
            raise ValueError("NFS rule has invalid access semantics")
        if not all(
            isinstance(value, bool) for value in (self.asynchronous, self.insecure, self.crossmnt)
        ):
            raise ValueError("NFS rule booleans are invalid")
        if (
            not self.flavors
            or len(self.flavors) != len(set(self.flavors))
            or any(value not in {"sys", "krb5", "krb5i", "krb5p"} for value in self.flavors)
        ):
            raise ValueError("NFS security flavors are invalid")


@dataclass(frozen=True)
class NfsConfig:
    enabled: bool
    rules: tuple[NfsRule, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.enabled, bool)
            or not isinstance(self.rules, tuple)
            or not all(isinstance(rule, NfsRule) for rule in self.rules)
        ):
            raise ValueError("NFS configuration is invalid")
        if len({rule.client for rule in self.rules}) != len(self.rules):
            raise ValueError("NFS client identities are duplicated")
        if not self.enabled and self.rules:
            raise ValueError("disabled NFS requires an empty rule list")


EMPTY_NFS = NfsConfig(False, ())


@dataclass(frozen=True)
class AclRule:
    owner_type: Literal["user", "group", "special"]
    owner_name: str
    permission_type: Literal["allow", "deny"]
    preset: Literal["read_only", "read_write", "full_control"]
    inheritance: Literal["none", "this_folder", "children", "all"]

    def __post_init__(self) -> None:
        _direct_text(self.owner_name, "ACL principal")
        if self.owner_type == "group" and self.owner_name.startswith("@"):
            raise ValueError(
                "ACL group principals must use the canonical DSM group name without '@'"
            )
        if (
            not isinstance(self.owner_type, str)
            or not isinstance(self.permission_type, str)
            or not isinstance(self.preset, str)
            or not isinstance(self.inheritance, str)
            or self.owner_type not in {"user", "group", "special"}
            or self.permission_type not in {"allow", "deny"}
            or self.preset not in {"read_only", "read_write", "full_control"}
            or self.inheritance not in {"none", "this_folder", "children", "all"}
        ):
            raise ValueError("ACL rule is invalid")


@dataclass(frozen=True)
class AclConfig:
    authoritative: bool
    inherit_parent: bool
    recursive: bool
    rules: tuple[AclRule, ...]

    def __post_init__(self) -> None:
        if (
            not self.authoritative
            or not isinstance(self.inherit_parent, bool)
            or not isinstance(self.recursive, bool)
            or not isinstance(self.rules, tuple)
            or not all(isinstance(rule, AclRule) for rule in self.rules)
        ):
            raise ValueError("ACL configuration is invalid")
        identities = {
            (rule.owner_type, rule.owner_name, rule.permission_type) for rule in self.rules
        }
        if len(identities) != len(self.rules):
            raise ValueError("ACL rule identities are duplicated")


EMPTY_ACL = AclConfig(True, False, False, ())


@dataclass(frozen=True)
class Share:
    name: str
    volume: str
    description: str
    quota_mib: int
    state: State
    nfs: NfsConfig
    acl: AclConfig

    def __post_init__(self) -> None:
        name = _direct_text(self.name, "share name")
        if not fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}", name):
            raise ValueError("share name is invalid")
        if not isinstance(self.volume, str) or not fullmatch(r"/volume[1-9][0-9]*", self.volume):
            raise ValueError("share volume is invalid")
        if (
            not isinstance(self.description, str)
            or isinstance(self.quota_mib, bool)
            or not isinstance(self.quota_mib, int)
            or self.quota_mib < 0
        ):
            raise ValueError("share semantics are invalid")
        if self.state not in {"present", "absent"} or not isinstance(self.acl, AclConfig):
            raise ValueError("share state is invalid")
        if self.name == "homes":
            raise ValueError("homes is unsupported")
        if self.state == "absent":
            if self.acl != EMPTY_ACL:
                raise ValueError("absent shares cannot define ACL state")
            object.__setattr__(self, "nfs", EMPTY_NFS)
        elif not isinstance(self.nfs, NfsConfig):
            raise ValueError("share state is invalid")


@dataclass(frozen=True)
class Host:
    alias: str
    volumes: tuple[str, ...]
    shares: tuple[Share, ...]

    def __post_init__(self) -> None:
        _direct_text(self.alias, "host logical identifier")
        if (
            not fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.alias)
            or not isinstance(self.volumes, tuple)
            or not self.volumes
            or not all(
                isinstance(volume, str) and fullmatch(r"/volume[1-9][0-9]*", volume)
                for volume in self.volumes
            )
            or len(set(self.volumes)) != len(self.volumes)
            or not isinstance(self.shares, tuple)
            or not all(isinstance(share, Share) for share in self.shares)
        ):
            raise ValueError("host configuration is invalid")
        if any(share.volume not in self.volumes for share in self.shares) or len(
            {share.name for share in self.shares}
        ) != len(self.shares):
            raise ValueError("host share identities are invalid")


@dataclass(frozen=True)
class Config:
    host: Host

    def __post_init__(self) -> None:
        if not isinstance(self.host, Host):
            raise ValueError("configuration requires one Host")


def _mapping(value: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{where} must be a mapping")
    unknown = set(value) - allowed
    if unknown:
        raise ConfigError(f"{where} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def _text(value: Any, where: str) -> str:
    try:
        return _direct_text(value, where)
    except ValueError as error:
        raise ConfigError(str(error)) from error


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} must be a boolean")
    return value


def _quota(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        raise ConfigError("quota must be an integer GiB or {value, unit}")
    if isinstance(value, int):
        amount, unit = value, "GiB"
    elif isinstance(value, dict):
        data = _mapping(value, "quota", {"value", "unit"})
        if set(data) != {"value", "unit"} or isinstance(data["value"], bool):
            raise ConfigError("quota requires integer value and unit")
        amount, unit = data["value"], data["unit"]
    else:
        raise ConfigError("quota must be an integer GiB or {value, unit}")
    if not isinstance(amount, int) or amount < 0 or unit not in {"GiB", "MiB"}:
        raise ConfigError("quota must be non-negative with unit GiB or MiB")
    mib = amount * 1024 if unit == "GiB" else amount
    if mib > 2**63 - 1:
        raise ConfigError("quota is too large")
    return mib


def _client(value: str, cidr: bool) -> str:
    if cidr:
        try:
            return str(ip_network(value, strict=False))
        except ValueError as error:
            raise ConfigError("NFS client_cidr must be an IP address or CIDR") from error
    try:
        result = _direct_client(value)
    except ValueError as error:
        raise ConfigError(str(error)) from error
    if "/" in result:
        raise ConfigError("NFS client must be a conservative hostname literal")
    return result


def _nfs(value: Any) -> NfsConfig:
    data = _mapping(value, "nfs", {"enabled", "rules"})
    if "enabled" not in data:
        raise ConfigError("nfs.enabled is required")
    enabled = _bool(data["enabled"], "nfs.enabled")
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ConfigError("nfs.rules must be a list")
    if len(raw_rules) > 200:
        raise ConfigError("nfs.rules must contain 0 to 200 rules")
    rules: list[NfsRule] = []
    for index, raw in enumerate(raw_rules):
        if isinstance(raw, dict) and "state" in raw:
            raise ConfigError(
                "NFS rule state is obsolete; remove it and declare the complete rule list"
            )
        item = _mapping(
            raw,
            f"nfs.rules[{index}]",
            {
                "client_cidr",
                "client",
                "access",
                "root_squash",
                "security_flavors",
                "async",
                "insecure",
                "crossmnt",
            },
        )
        cidr, client = "client_cidr" in item, "client" in item
        if cidr == client:
            raise ConfigError("each NFS rule requires exactly one of client_cidr or client")
        if cidr:
            raw_cidr = item["client_cidr"]
            if isinstance(raw_cidr, str):
                raw_clients = [raw_cidr]
            elif isinstance(raw_cidr, list):
                if not raw_cidr:
                    raise ConfigError(
                        "NFS client_cidr must be a string or non-empty list of strings"
                    )
                if len(rules) + len(raw_cidr) > 200:
                    raise ConfigError("nfs.rules must contain 0 to 200 rules")
                if not all(isinstance(client_value, str) for client_value in raw_cidr):
                    raise ConfigError(
                        "NFS client_cidr must be a string or non-empty list of strings"
                    )
                raw_clients = raw_cidr
            else:
                raise ConfigError("NFS client_cidr must be a string or non-empty list of strings")
        else:
            raw_client = item["client"]
            if not isinstance(raw_client, str):
                raise ConfigError("NFS client must be a string")
            raw_clients = [raw_client]
        if len(rules) + len(raw_clients) > 200:
            raise ConfigError("nfs.rules must contain 0 to 200 rules")
        required = {
            "access",
            "root_squash",
            "security_flavors",
            "async",
            "insecure",
            "crossmnt",
        }
        if not required <= set(item):
            raise ConfigError("NFS rules require all semantics explicitly")
        access, squash, flavors = item["access"], item["root_squash"], item["security_flavors"]
        if (
            access not in {"read_only", "read_write"}
            or squash not in {"root", "admin", "guest", "all_admin", "all_guest"}
            or not isinstance(flavors, list)
            or not flavors
            or len(flavors) != len(set(flavors))
            or any(x not in {"sys", "krb5", "krb5i", "krb5p"} for x in flavors)
        ):
            raise ConfigError("invalid NFS rule")
        semantics: tuple[Any, ...] = (
            "ro" if access == "read_only" else "rw",
            squash,
            _bool(item["async"], "nfs.async"),
            _bool(item["insecure"], "nfs.insecure"),
            _bool(item["crossmnt"], "nfs.crossmnt"),
            tuple(sorted(flavors)),
        )
        for raw_client in raw_clients:
            try:
                rules.append(NfsRule(_client(_text(raw_client, "NFS client"), cidr), *semantics))
            except ValueError as error:
                raise ConfigError(str(error)) from error
    if not enabled and rules:
        raise ConfigError("disabled NFS requires an empty rule list")
    if len({rule.client for rule in rules}) != len(rules):
        raise ConfigError("NFS client identities are duplicated")
    try:
        return NfsConfig(enabled, tuple(sorted(rules, key=lambda rule: rule.client)))
    except ValueError as error:
        raise ConfigError(str(error)) from error


def _acl(value: Any) -> AclConfig:
    data = _mapping(value, "acl", {"authoritative", "inherit_parent", "recursive", "rules"})
    if set(data) != {"authoritative", "inherit_parent", "recursive", "rules"}:
        raise ConfigError("ACL requires authoritative, inherit_parent, recursive, and rules")
    if not _bool(data["authoritative"], "acl.authoritative"):
        raise ConfigError("authoritative: false ACLs are unsupported")
    raw_rules = data["rules"]
    if not isinstance(raw_rules, list) or len(raw_rules) > 200:
        raise ConfigError("acl.rules must contain 0 to 200 rules")
    rules: list[AclRule] = []
    for index, raw in enumerate(raw_rules):
        item = _mapping(
            raw,
            f"acl.rules[{index}]",
            {"principal", "principal_type", "permissions", "inheritance", "effect"},
        )
        if set(item) != {"principal", "principal_type", "permissions", "inheritance", "effect"}:
            raise ConfigError("ACL rules require all semantics explicitly")
        try:
            rules.append(
                AclRule(
                    item["principal_type"],
                    _text(item["principal"], "ACL principal"),
                    item["effect"],
                    item["permissions"],
                    item["inheritance"],
                )
            )
        except ValueError as error:
            raise ConfigError(str(error)) from error
    try:
        return AclConfig(
            True,
            _bool(data["inherit_parent"], "acl.inherit_parent"),
            _bool(data["recursive"], "acl.recursive"),
            tuple(
                sorted(
                    rules, key=lambda rule: (rule.owner_type, rule.owner_name, rule.permission_type)
                )
            ),
        )
    except ValueError as error:
        raise ConfigError(str(error)) from error


def load_config(path: Path) -> Config:
    class Loader(yaml.SafeLoader):
        pass

    def construct_mapping(
        loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
    ) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key, value in loader.construct_pairs(node, deep=deep):
            try:
                if key in result:
                    raise ConfigError("YAML contains duplicate mapping keys")
                result[key] = value
            except TypeError as error:
                raise ConfigError("YAML mapping keys must be hashable") from error
        return result

    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=Loader)
    except (OSError, yaml.YAMLError) as error:
        raise ConfigError("cannot load configuration") from error
    if isinstance(raw, dict) and "hosts" in raw:
        raise ConfigError("root hosts is obsolete; migrate to root host and nested volumes/shares")
    root = _mapping(raw, "root", {"version", "host", "volumes"})
    if root.get("version") != 1:
        raise ConfigError("only version: 1 is supported; migrate obsolete configuration")
    alias = _text(root.get("host"), "host logical identifier")
    if not fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", alias):
        raise ConfigError("host must be a safe logical identifier, not a DSM endpoint")
    raw_volumes = root.get("volumes")
    if not isinstance(raw_volumes, list) or not raw_volumes:
        raise ConfigError("volumes must be a non-empty list")
    volumes: list[str] = []
    shares: list[Share] = []
    for index, raw_volume in enumerate(raw_volumes):
        volume_data = _mapping(raw_volume, f"volumes[{index}]", {"name", "shares"})
        name = _text(volume_data.get("name"), "volume name")
        if not fullmatch(r"volume[1-9][0-9]*", name) or f"/{name}" in volumes:
            raise ConfigError("volumes must have unique volumeN names")
        volume = f"/{name}"
        volumes.append(volume)
        raw_shares = volume_data.get("shares", [])
        if not isinstance(raw_shares, list):
            raise ConfigError("volume shares must be a list")
        for raw_share in raw_shares:
            item = _mapping(
                raw_share, "share", {"name", "description", "quota", "state", "nfs", "acl"}
            )
            state = item.get("state", "present")
            if state not in {"present", "absent"}:
                raise ConfigError("share state must be present or absent")
            nfs = (
                EMPTY_NFS
                if state == "absent"
                else _nfs(item["nfs"])
                if "nfs" in item
                else EMPTY_NFS
            )
            acl = (
                EMPTY_ACL
                if state == "absent"
                else _acl(item["acl"])
                if "acl" in item
                else EMPTY_ACL
            )
            try:
                shares.append(
                    Share(
                        _text(item.get("name"), "share name"),
                        volume,
                        item.get("description", ""),
                        _quota(item.get("quota")),
                        state,
                        nfs,
                        acl,
                    )
                )
            except ValueError as error:
                raise ConfigError(str(error)) from error
    try:
        return Config(
            Host(
                alias,
                tuple(volumes),
                tuple(sorted(shares, key=lambda share: (share.volume, share.name))),
            )
        )
    except ValueError as error:
        raise ConfigError(str(error)) from error
