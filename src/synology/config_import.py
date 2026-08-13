from __future__ import annotations

import difflib
import os
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from synology.apply_config import (
    ApplyConfig,
    ApplyShare,
    load_apply_config,
    parse_apply_config,
)
from synology.config import (
    MAX_QUOTA_API_MIB,
    MAX_QUOTA_GIB,
    QUOTA_MIB_PER_GIB,
    normalize_nfs_client,
    validate_share_delete_request,
)
from synology.exceptions import ApiError, ConfigurationError, LocalPersistenceError
from synology.models import (
    AclPermissionRecord,
    EnrichmentStatus,
    NfsClientPermission,
    NfsSecurityFlavor,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    ShareDeleteRequest,
    ShareDetails,
    ShareRecord,
)


@dataclass(frozen=True, slots=True)
class ConfigImportDocument:
    path: Path
    source: str
    config: ApplyConfig
    document: Any


@dataclass(frozen=True, slots=True)
class ConfigImportResult:
    share: str
    host: str
    action: str
    diff: str
    written: bool


class ConfigImportClient(Protocol):
    def list_shares(self) -> tuple[ShareRecord, ...]: ...

    def read_apply_details(self, name: str) -> ShareDetails: ...


def load_config_import_document(path: str) -> ConfigImportDocument:
    """Load a strict V1 document while retaining its round-trip YAML tree."""
    source_path = Path(path)
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError("unable to load import configuration") from exc
    yaml = _round_trip_yaml()
    try:
        document = yaml.load(source)
    except Exception as exc:
        raise ConfigurationError("unable to load import configuration") from exc
    if not isinstance(document, Mapping):
        raise ConfigurationError("configuration root must be a mapping")
    if "volumes" in document:
        config = load_apply_config(path)
    else:
        config = _empty_config(document)
    return ConfigImportDocument(source_path, source, config, document)


def _empty_config(document: Mapping[object, object]) -> ApplyConfig:
    allowed = {"version", "host", "principal_lookup_share"}
    if any(not isinstance(key, str) for key in document) or set(document) - allowed:
        raise ConfigurationError("unknown configuration root fields")
    if document.get("version") != 1 or isinstance(document.get("version"), bool):
        raise ConfigurationError("configuration version must be 1")
    host = document.get("host")
    if host is not None and (not isinstance(host, str) or not host.strip()):
        raise ConfigurationError("host must be valid text")
    lookup_share = document.get("principal_lookup_share")
    if lookup_share is not None and (
        not isinstance(lookup_share, str) or not lookup_share.strip()
    ):
        raise ConfigurationError("principal_lookup_share must be valid text")
    return ApplyConfig(host, lookup_share, ())


def import_share_config(
    document: ConfigImportDocument,
    *,
    share_name: str,
    host: str,
    client: ConfigImportClient,
    write: bool,
) -> ConfigImportResult:
    """Read one live share and merge its complete mutable state into a V1 document."""
    target = validate_share_delete_request(ShareDeleteRequest(share_name)).name
    inventory: dict[str, ShareRecord] = {}
    for listed in client.list_shares():
        if listed.name in inventory:
            raise ApiError("duplicate live share name in inventory")
        inventory[listed.name] = listed
    if target not in inventory:
        raise ApiError("target share was not found in live inventory")
    details = client.read_apply_details(target)
    imported = _imported_share(details, target)
    proposed = _merge(document.document, imported, host)
    rendered = _dump(proposed)
    # Validate the exact text that would be persisted, not merely its typed equivalent.
    parse_apply_config(rendered)
    if rendered == document.source:
        return ConfigImportResult(target, host, "no-change", "", False)
    diff = "".join(
        difflib.unified_diff(
            document.source.splitlines(keepends=True),
            rendered.splitlines(keepends=True),
            fromfile="current-config.yaml",
            tofile="proposed-config.yaml",
        )
    )
    if write:
        atomic_write(document.path, rendered.encode("utf-8"))
    return ConfigImportResult(target, host, "imported", diff, write)


def atomic_write(path: Path, content: bytes) -> None:
    """Atomically replace a regular configuration file without weakening its mode."""
    try:
        target = path.lstat()
    except OSError as exc:
        raise LocalPersistenceError("unable to inspect configuration file") from exc
    if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
        raise LocalPersistenceError("configuration file must be a regular non-symlink")
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".syn-cli-", dir=path.parent)
        os.fchmod(descriptor, stat.S_IMODE(target.st_mode))
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = ""
        _fsync_directory(path.parent)
    except OSError as exc:
        raise LocalPersistenceError(
            "unable to atomically write configuration file"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _imported_share(details: ShareDetails, target: str) -> ApplyShare:
    if details.share.name != target or not details.share.volume:
        raise ApiError("incomplete target share response")
    if details.acl_status is EnrichmentStatus.UNAVAILABLE:
        raise ApiError("incomplete target ACL response")
    if details.nfs_status is EnrichmentStatus.UNAVAILABLE:
        raise ApiError("incomplete target NFS response")
    quota = details.share.quota_api_value
    if quota is not None:
        if isinstance(quota, bool) or not isinstance(quota, int) or quota < 0:
            raise ApiError("invalid target share quota")
        if quota > MAX_QUOTA_API_MIB:
            raise ApiError("target share quota exceeds the supported API range")
        if quota % QUOTA_MIB_PER_GIB:
            raise ApiError("target share quota is not representable as integer GiB")
        if quota // QUOTA_MIB_PER_GIB > MAX_QUOTA_GIB:
            raise ApiError("target share quota exceeds the supported GiB range")
    acl = tuple(sorted(_mutable_acl(details.acl_permissions), key=_acl_key))
    nfs_items = tuple(_import_nfs(item) for item in details.nfs_permissions)
    identities = [normalize_nfs_client(item.client)[1] for item in nfs_items]
    if len(set(identities)) != len(identities):
        raise ApiError("duplicate target NFS clients")
    nfs = tuple(sorted(nfs_items, key=_nfs_key))
    return ApplyShare(
        target,
        details.share.volume,
        "present",
        details.share.description or "",
        quota,
        acl,
        nfs,
    )


def _mutable_acl(values: tuple[AclPermissionRecord, ...]) -> tuple[PermissionSpec, ...]:
    result: list[PermissionSpec] = []
    identities: set[tuple[str, str]] = set()
    categories = {
        "local_user": PermissionPrincipalType.LOCAL_USER,
        "local_group": PermissionPrincipalType.LOCAL_GROUP,
        "ldap_user": PermissionPrincipalType.LDAP_USER,
        "ldap_group": PermissionPrincipalType.LDAP_GROUP,
    }
    for value in values:
        active = sum((value.is_deny, value.is_readonly, value.is_writable))
        if active != 1 or not value.name:
            raise ApiError("invalid target ACL response")
        try:
            principal_type = categories[value.category]
        except KeyError as exc:
            raise ApiError("invalid target ACL category") from exc
        access = (
            PermissionAccessMode.DENY
            if value.is_deny
            else PermissionAccessMode.READ_ONLY
            if value.is_readonly
            else PermissionAccessMode.READ_WRITE
        )
        if (
            principal_type is PermissionPrincipalType.LOCAL_GROUP
            and value.name == "administrators"
            and access is PermissionAccessMode.READ_WRITE
        ):
            continue
        identity = (principal_type.value, value.name)
        if identity in identities:
            raise ApiError("duplicate target ACL identity")
        identities.add(identity)
        result.append(PermissionSpec(principal_type, value.name, access))
    return tuple(result)


def _import_nfs(value: NfsClientPermission) -> NfsClientPermission:
    if value.security_flavor != NfsSecurityFlavor():
        raise ApiError("target NFS security flavor is not representable")
    try:
        client, _ = normalize_nfs_client(value.client)
    except ConfigurationError as exc:
        raise ApiError("target NFS client is not importable") from exc
    return NfsClientPermission(
        client,
        value.access_mode,
        value.async_enabled,
        value.insecure,
        value.crossmnt,
        value.root_squash,
        value.security_flavor,
    )


def _merge(document: object, imported: ApplyShare, host: str) -> object:
    root = cast(Any, document)
    assert isinstance(root, Mapping)
    root = cast(Any, root)
    if "host" not in root:
        root["host"] = host
    volumes = root.get("volumes")
    if volumes is None:
        volumes = _commented_map()
        root["volumes"] = volumes
    if not isinstance(volumes, Mapping):
        raise ConfigurationError("volumes must be a mapping")
    volumes = cast(Any, volumes)
    for _volume, value in volumes.items():
        if not isinstance(value, Mapping):
            continue
        value = cast(Any, value)
        shares = value.get("shares")
        if not isinstance(shares, list):
            continue
        for index in range(len(shares) - 1, -1, -1):
            item = shares[index]
            if isinstance(item, Mapping) and item.get("name") == imported.name:
                del shares[index]
    volume = volumes.get(imported.volume)
    if volume is None:
        volume = _commented_map()
        volumes[imported.volume] = volume
    if not isinstance(volume, Mapping):
        raise ConfigurationError("volume must be a mapping")
    volume = cast(Any, volume)
    shares = volume.get("shares")
    if shares is None:
        shares = _commented_seq()
        volume["shares"] = shares
    if not isinstance(shares, list):
        raise ConfigurationError("volume shares must be a list")
    shares.append(_share_node(imported))
    return root


def _share_node(share: ApplyShare) -> object:
    node = _commented_map()
    node["name"] = share.name
    node["state"] = "present"
    node["description"] = share.description
    if share.quota_mib is not None:
        node["quota"] = share.quota_mib // QUOTA_MIB_PER_GIB
    acl = _commented_map()
    entries = _commented_seq()
    for item in share.acl:
        entries.append(
            _mapping_node(
                principal=item.principal_name,
                principal_type=item.principal_type.value,
                permissions=item.access_mode.value,
            )
        )
    acl["entries"] = entries
    node["acl"] = acl
    nfs = _commented_map()
    rules = _commented_seq()
    for rule in share.nfs:
        rules.append(
            _mapping_node(
                client_cidr=rule.client,
                access=rule.access_mode.value,
                root_squash=rule.root_squash.value,
                security_flavors=["sys"],
                **{
                    "async": rule.async_enabled,
                    "insecure": rule.insecure,
                    "crossmnt": rule.crossmnt,
                },
            )
        )
    nfs["rules"] = rules
    node["nfs"] = nfs
    return node


def _mapping_node(**values: object) -> object:
    node = _commented_map()
    node.update(values)
    return node


def _acl_key(value: PermissionSpec) -> tuple[str, str, str]:
    return value.principal_type.value, value.principal_name, value.access_mode.value


def _nfs_key(value: NfsClientPermission) -> tuple[str, str, str, bool, bool, bool]:
    return (
        value.client,
        value.access_mode.value,
        value.root_squash.value,
        value.async_enabled,
        value.insecure,
        value.crossmnt,
    )


def _round_trip_yaml() -> Any:
    try:
        from ruamel.yaml import YAML
    except ImportError as exc:
        raise ConfigurationError(
            "config-import requires the installed ruamel.yaml round-trip dependency"
        ) from exc
    yaml = YAML(typ="rt")
    yaml.allow_duplicate_keys = False
    yaml.preserve_quotes = True
    return yaml


def _commented_map() -> Any:
    from ruamel.yaml.comments import CommentedMap

    return CommentedMap()


def _commented_seq() -> Any:
    from ruamel.yaml.comments import CommentedSeq

    return CommentedSeq()


def _dump(document: object) -> str:
    from io import StringIO

    stream = StringIO()
    _round_trip_yaml().dump(document, stream)
    return stream.getvalue()


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)
