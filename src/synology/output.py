import json
from collections.abc import Sequence

import yaml

from synology.apply_config import ApplyPlan
from synology.config_import import ConfigImportResult
from synology.exceptions import OutputError
from synology.models import (
    AclPermissionRecord,
    EnrichmentStatus,
    ListDirsResult,
    NfsClientPermission,
    NfsDisplayPermission,
    NfsRootSquash,
    OperationStatus,
    OutputFormat,
    PermissionSpec,
    ShareCreateResult,
    ShareDeleteResult,
    ShareDetails,
    ShareModifyResult,
    ShareOperationStep,
    ShareRecord,
    SubshareCreateResult,
    SubshareDeleteResult,
)


def render_subshare_delete(
    result: SubshareDeleteResult, output_format: OutputFormat
) -> str:
    try:
        record = {
            "share": result.share,
            "directory": result.directory,
            "path": result.path,
            "virtual_path": result.virtual_path,
            "deleted": result.deleted,
            "status": result.status,
            "mode": "empty-only",
            "steps": [_step_record(step) for step in result.steps],
        }
        if output_format is OutputFormat.JSON:
            return json.dumps(record, ensure_ascii=False)
        if output_format is OutputFormat.YAML:
            return yaml.safe_dump(record, allow_unicode=True, sort_keys=False).rstrip()
        return "\n".join(
            (
                "SHARE  DIRECTORY  PATH  MODE  STATUS",
                "-----  ---------  ----  ----  ------",
                f"{result.share}  {result.directory}  {result.path or '-'}  "
                f"empty-only  {result.status}",
            )
        )
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def render_list_dirs(result: ListDirsResult, output_format: OutputFormat) -> str:
    try:
        record = {
            "share": result.share,
            "directories": [
                {"name": item.name, "path": item.path} for item in result.directories
            ],
        }
        if output_format is OutputFormat.JSON:
            return json.dumps(record, ensure_ascii=False)
        if output_format is OutputFormat.YAML:
            return yaml.safe_dump(record, allow_unicode=True, sort_keys=False).rstrip()
        if not result.directories:
            return f"SHARE: {result.share}\nNo directories found."
        headers = ["NAME", "PATH"]
        rows = [[item.name, item.path] for item in result.directories]
        widths = [
            max(len(headers[index]), *(len(row[index]) for row in rows))
            for index in range(len(headers))
        ]
        return "\n".join(
            [
                "  ".join(
                    header.ljust(widths[index]) for index, header in enumerate(headers)
                ),
                "  ".join("-" * width for width in widths),
                *[
                    "  ".join(
                        value.ljust(widths[index]) for index, value in enumerate(row)
                    )
                    for row in rows
                ],
            ]
        )
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def render_config_import(
    result: ConfigImportResult, output_format: OutputFormat
) -> str:
    """Render config-import metadata and its reviewed unified diff."""
    try:
        record = {
            "share": result.share,
            "host": result.host,
            "action": result.action,
            "written": result.written,
            "diff": result.diff,
        }
        if output_format is OutputFormat.JSON:
            return json.dumps(record, ensure_ascii=False)
        if output_format is OutputFormat.YAML:
            return yaml.safe_dump(record, allow_unicode=True, sort_keys=False).rstrip()
        if not result.diff:
            return "\n".join(
                [
                    f"SHARE: {result.share}",
                    f"HOST: {result.host}",
                    "ACTION: no-change",
                    "No changes.",
                ]
            )
        return "\n".join(
            [
                f"SHARE: {result.share}",
                f"HOST: {result.host}",
                f"ACTION: {result.action}",
                result.diff.rstrip("\n"),
            ]
        )
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def render_apply_plan(
    plan: ApplyPlan, output_format: OutputFormat, *, mode: str, host: str
) -> str:
    """Render an apply-config plan without connection secrets."""
    try:
        warnings = apply_plan_warnings(plan)
        record = {
            "mode": mode,
            "host": host,
            "no_op": not plan.operations,
            "warnings": warnings,
            "operations": [
                {
                    "share": item.share,
                    "family": item.family,
                    "before": item.before,
                    "after": item.after,
                    "status": item.status.value,
                    **(
                        {
                            "directory": {
                                "name": item.directory.name,
                                "state": item.directory.state,
                            }
                        }
                        if item.directory is not None
                        else {}
                    ),
                }
                for item in plan.operations
            ],
        }
        if output_format is OutputFormat.JSON:
            return json.dumps(record, ensure_ascii=False)
        if output_format is OutputFormat.YAML:
            return yaml.safe_dump(record, allow_unicode=True, sort_keys=False).rstrip()
        if not plan.operations:
            return f"MODE: {mode}\nHOST: {host}\nNo changes."
        headers = ["SHARE", "DIRECTORY", "FAMILY", "BEFORE", "AFTER", "STATUS"]
        rows = [
            [
                item.share,
                item.directory.name if item.directory is not None else "-",
                item.family,
                item.before,
                item.after,
                item.status.value,
            ]
            for item in plan.operations
        ]
        widths = [
            max(len(headers[index]), *(len(row[index]) for row in rows))
            for index in range(len(headers))
        ]
        return "\n".join(
            [
                f"MODE: {mode}",
                f"HOST: {host}",
                *(f"WARNING: {warning}" for warning in warnings),
                "  ".join(
                    header.ljust(widths[index]) for index, header in enumerate(headers)
                ),
                "  ".join("-" * width for width in widths),
                *[
                    "  ".join(
                        value.ljust(widths[index]) for index, value in enumerate(row)
                    )
                    for row in rows
                ],
            ]
        )
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


_ROOT_SQUASH_WARNINGS = {
    NfsRootSquash.ADMIN: (
        "root_squash=admin (Map root to admin) is a privileged identity mapping; "
        "review before applying"
    ),
    NfsRootSquash.GUEST: (
        "root_squash=guest (Map root to guest) changes root-originated identity "
        "mapping; review before applying"
    ),
    NfsRootSquash.ALL_ADMIN: (
        "root_squash=all_admin (Map all users to admin) is a privileged identity "
        "mapping; review before applying"
    ),
    NfsRootSquash.ALL_GUEST: (
        "root_squash=all_guest (Map all users to guest) changes all-user identity "
        "mapping; review before applying"
    ),
}


def apply_plan_warnings(plan: ApplyPlan) -> list[str]:
    """Return safety warnings for non-default NFS mapping operations."""
    nfs_operation_shares = {
        operation.share for operation in plan.operations if operation.family == "nfs"
    }
    root_squash_modes = {
        rule.root_squash
        for share in plan.config.shares
        if share.name in nfs_operation_shares
        for rule in share.nfs
    }
    return [
        warning
        for root_squash, warning in _ROOT_SQUASH_WARNINGS.items()
        if root_squash in root_squash_modes
    ]


def render_share_create(result: ShareCreateResult, output_format: OutputFormat) -> str:
    try:
        record = {
            "name": result.name,
            "volume": result.volume,
            "description": result.description,
            "created": result.created,
            "options": {
                "recycle_bin": {
                    "enabled": result.options.recycle_bin.enabled,
                    "admin_only": result.options.recycle_bin.admin_only,
                },
                "compression_enabled": result.options.compression_enabled,
                "quota_gib": result.options.quota_gib,
                "quota_api_value": result.options.quota_api_value,
                "quota_api_unit": "MiB",
            },
            "permissions": _permission_records(result),
            **(
                {
                    "nfs_permissions": [
                        {
                            "client": item.client,
                            "access": item.access_mode.value,
                            "async": item.async_enabled,
                            "insecure": item.insecure,
                            "crossmnt": item.crossmnt,
                            "root_squash": item.root_squash.value,
                            "security_flavor": {
                                "sys": item.security_flavor.sys,
                                "kerberos": item.security_flavor.kerberos,
                                "kerberos_integrity": (
                                    item.security_flavor.kerberos_integrity
                                ),
                                "kerberos_privacy": (
                                    item.security_flavor.kerberos_privacy
                                ),
                            },
                        }
                        for item in result.nfs_permissions
                    ]
                }
                if result.nfs_permissions
                else {}
            ),
            "steps": [
                {
                    "name": step.name,
                    "status": step.status.value,
                    **({"message": step.message} if step.message is not None else {}),
                    **(
                        {"permission_status": step.permission_status.value}
                        if step.permission_status is not None
                        else {}
                    ),
                }
                for step in result.steps
            ],
        }
        if output_format is OutputFormat.TABLE:
            headers = [
                "NAME",
                "VOLUME",
                "DESCRIPTION",
                "RECYCLE",
                "RECYCLE ACCESS",
                "COMPRESSION",
                "NFS_RULES",
                "STATUS",
            ]
            values = [
                result.name,
                result.volume,
                result.description or "-",
                "enabled" if result.options.recycle_bin.enabled else "disabled",
                _recycle_access(
                    result.options.recycle_bin.enabled,
                    result.options.recycle_bin.admin_only,
                ),
                "enabled" if result.options.compression_enabled else "disabled",
                str(len(result.nfs_permissions)) if result.nfs_permissions else "-",
                "created" if result.created else "planned",
            ]
            widths = [
                max(len(header), len(value))
                for header, value in zip(headers, values, strict=True)
            ]
            return "\n".join(
                [
                    "  ".join(
                        header.ljust(width)
                        for header, width in zip(headers, widths, strict=True)
                    ),
                    "  ".join("-" * width for width in widths),
                    "  ".join(
                        value.ljust(width)
                        for value, width in zip(values, widths, strict=True)
                    ),
                ]
            )
        if output_format is OutputFormat.JSON:
            return json.dumps(record, ensure_ascii=False)
        return yaml.safe_dump(record, allow_unicode=True, sort_keys=False).rstrip()
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def render_subshare_create(
    result: SubshareCreateResult, output_format: OutputFormat
) -> str:
    try:
        record = {
            "share": result.share,
            "directory": result.directory,
            "path": result.path,
            "created": result.created,
            "steps": [_step_record(step) for step in result.steps],
        }
        if output_format is OutputFormat.JSON:
            return json.dumps(record, ensure_ascii=False)
        if output_format is OutputFormat.YAML:
            return yaml.safe_dump(record, allow_unicode=True, sort_keys=False).rstrip()
        status = _subshare_status(result)
        return "\n".join(
            (
                "SHARE  DIRECTORY  PATH  STATUS",
                "-----  ---------  ----  ------",
                f"{result.share}  {result.directory}  {result.path or '-'}  {status}",
            )
        )
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def _subshare_status(result: SubshareCreateResult) -> str:
    if result.created:
        return "created"
    statuses = {step.status for step in result.steps}
    if OperationStatus.UNKNOWN in statuses:
        return "unknown"
    if OperationStatus.FAILED in statuses:
        return "failed"
    return "planned"


def render_share_delete(result: ShareDeleteResult, output_format: OutputFormat) -> str:
    try:
        record = {
            "name": result.name,
            "deleted": result.deleted,
            "steps": [
                {
                    "name": step.name,
                    "status": step.status.value,
                    **({"message": step.message} if step.message is not None else {}),
                }
                for step in result.steps
            ],
        }
        if output_format is OutputFormat.TABLE:
            headers = ["NAME", "STATUS"]
            values = [result.name, "deleted" if result.deleted else "planned"]
            widths = [
                max(len(header), len(value))
                for header, value in zip(headers, values, strict=True)
            ]
            return "\n".join(
                [
                    "  ".join(
                        header.ljust(width)
                        for header, width in zip(headers, widths, strict=True)
                    ),
                    "  ".join("-" * width for width in widths),
                    "  ".join(
                        value.ljust(width)
                        for value, width in zip(values, widths, strict=True)
                    ),
                ]
            )
        if output_format is OutputFormat.JSON:
            return json.dumps(record, ensure_ascii=False)
        return yaml.safe_dump(record, allow_unicode=True, sort_keys=False).rstrip()
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def render_share_modify(result: ShareModifyResult, output_format: OutputFormat) -> str:
    try:
        record: dict[str, object] = {
            "name": result.name,
            "changed": result.changed,
            "steps": [_step_record(step) for step in result.steps],
        }
        if result.quota_gib is not None:
            record["quota_gib"] = result.quota_gib
        if result.observed_quota is not None:
            record["observed_quota"] = {
                "api_value": result.observed_quota.api_value,
                "api_unit": result.observed_quota.api_unit,
                "unlimited": result.observed_quota.unlimited,
                "gib": result.observed_quota.gib,
            }
        if result.permissions is not None:
            record["permissions"] = _modify_permissions(result.permissions)
        if result.nfs_permissions is not None:
            record["nfs_permissions"] = [
                _nfs_record(item) for item in result.nfs_permissions
            ]
        if output_format is OutputFormat.TABLE:
            family, rules = _modify_summary(result)
            status = (
                "changed"
                if result.changed
                else "planned"
                if any(step.status.value == "planned" for step in result.steps)
                else "no-op"
            )
            headers = ["NAME", "FAMILY", "REPLACEMENT", "STATUS"]
            values = [result.name, family, rules, status]
            widths = [
                max(len(header), len(value))
                for header, value in zip(headers, values, strict=True)
            ]
            return "\n".join(
                [
                    "  ".join(
                        header.ljust(width)
                        for header, width in zip(headers, widths, strict=True)
                    ),
                    "  ".join("-" * width for width in widths),
                    "  ".join(
                        value.ljust(width)
                        for value, width in zip(values, widths, strict=True)
                    ),
                ]
            )
        if output_format is OutputFormat.JSON:
            return json.dumps(record, ensure_ascii=False)
        return yaml.safe_dump(record, allow_unicode=True, sort_keys=False).rstrip()
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def _modify_permissions(
    permissions: tuple[PermissionSpec, ...],
) -> list[dict[str, str]]:
    return [
        {
            "principal_type": item.principal_type.value,
            "principal_name": item.principal_name,
            "access_mode": item.access_mode.value,
        }
        for item in permissions
    ]


def _step_record(step: ShareOperationStep) -> dict[str, str]:
    return {
        "name": step.name,
        "status": step.status.value,
        **({"message": step.message} if step.message is not None else {}),
        **(
            {"permission_status": step.permission_status.value}
            if step.permission_status is not None
            else {}
        ),
    }


def _modify_summary(result: ShareModifyResult) -> tuple[str, str]:
    if result.quota_gib is not None:
        if result.observed_quota is not None:
            return (
                "quota",
                "unlimited"
                if result.observed_quota.unlimited
                else f"{result.observed_quota.gib:g} GiB",
            )
        return (
            "quota",
            "unlimited" if result.quota_gib == 0 else f"{result.quota_gib} GiB",
        )
    if result.permissions is not None:
        return "acl", "; ".join(
            f"{item.principal_type.value}:{item.principal_name}:{item.access_mode.value}"
            for item in result.permissions
        ) or "clear"
    if result.nfs_permissions is not None:
        return "nfs", "; ".join(
            f"{item.client}:{item.access_mode.value}" for item in result.nfs_permissions
        ) or "clear"
    return "-", "-"


def _permission_records(result: ShareCreateResult) -> list[dict[str, str]]:
    return [
        {
            "principal_type": permission.principal_type.value,
            "principal_name": permission.principal_name,
            "access_mode": permission.access_mode.value,
        }
        for permission in result.permissions
    ]


def _recycle_access(enabled: bool, admin_only: bool) -> str:
    if not enabled:
        return "-"
    return "admin-only" if admin_only else "users"


def render_share_details(
    details: Sequence[ShareDetails], output_format: OutputFormat
) -> str:
    try:
        if output_format is OutputFormat.TABLE:
            return _render_detail_table(details)
        records = [_detail_record(item) for item in details]
        if output_format is OutputFormat.JSON:
            return json.dumps(records, ensure_ascii=False)
        return yaml.safe_dump(records, allow_unicode=True, sort_keys=False).rstrip()
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def render_shares(shares: Sequence[ShareRecord], output_format: OutputFormat) -> str:
    try:
        if output_format is OutputFormat.TABLE:
            return _render_table(shares)
        records = [_record(share) for share in shares]
        if output_format is OutputFormat.JSON:
            return json.dumps(records, ensure_ascii=False)
        return yaml.safe_dump(records, allow_unicode=True, sort_keys=False).rstrip()
    except (TypeError, ValueError, yaml.YAMLError) as exc:
        raise OutputError("unable to render output") from exc


def _record(share: ShareRecord) -> dict[str, object]:
    return {
        "name": share.name,
        "volume": share.volume,
        "description": share.description,
        "uuid": share.uuid,
        "is_usb": share.is_usb,
        "quota_gib": share.quota_gib,
        "quota_api_value": share.quota_api_value,
        "quota_api_unit": share.quota_api_unit,
    }


def _detail_record(detail: ShareDetails) -> dict[str, object]:
    share: dict[str, object] = _record(detail.share)
    share["permissions"] = [
        {
            "name": item.name,
            "category": item.category,
            "is_deny": item.is_deny,
            "is_readonly": item.is_readonly,
            "is_writable": item.is_writable,
            "is_custom": item.is_custom,
            "is_admin": item.is_admin,
        }
        for item in _display_acl_permissions(detail.acl_permissions)
    ]
    share["nfs_permissions"] = _detail_nfs_records(detail)
    share["permission_status"] = detail.acl_status.value
    share["nfs_status"] = detail.nfs_status.value
    share["diagnostics"] = [
        {
            "share_name": item.share_name,
            "category": item.category,
            "detail": item.detail,
            "status": item.status.value,
        }
        for item in detail.diagnostics
    ]
    return share


def _detail_nfs_records(detail: ShareDetails) -> list[dict[str, object]] | None:
    """Return display NFS records or null when the NFS read was unavailable."""
    if detail.nfs_status is EnrichmentStatus.UNAVAILABLE:
        return None
    return [_nfs_record(item) for item in _display_nfs_permissions(detail)]


def _nfs_record(
    permission: NfsClientPermission | NfsDisplayPermission,
) -> dict[str, object]:
    return {
        "client": permission.client,
        "access": permission.access_mode.value,
        "async": permission.async_enabled,
        "insecure": permission.insecure,
        "crossmnt": permission.crossmnt,
        "root_squash": permission.root_squash.value,
        "security_flavor": {
            "sys": permission.security_flavor.sys,
            "kerberos": permission.security_flavor.kerberos,
            "kerberos_integrity": permission.security_flavor.kerberos_integrity,
            "kerberos_privacy": permission.security_flavor.kerberos_privacy,
        },
    }


def _display_acl_permissions(
    permissions: Sequence[AclPermissionRecord],
) -> list[AclPermissionRecord]:
    return sorted(
        (
            permission
            for permission in permissions
            if not _is_protected_administrator_permission(permission)
        ),
        key=lambda permission: (
            permission.category,
            permission.name,
            _access(permission),
        ),
    )


def _is_protected_administrator_permission(permission: AclPermissionRecord) -> bool:
    return (
        permission.category == "local_group"
        and permission.name == "administrators"
        and not permission.is_deny
        and _access(permission) == "read-write"
    )


def _display_nfs_permissions(
    detail: ShareDetails,
) -> list[NfsClientPermission | NfsDisplayPermission]:
    permissions = (
        detail.nfs_display_permissions
        if detail.nfs_display_permissions
        else detail.nfs_permissions
    )
    return sorted(permissions, key=_nfs_display_sort_key)


def _nfs_display_sort_key(
    permission: NfsClientPermission | NfsDisplayPermission,
) -> tuple[str, str, str, str]:
    """Sort display-only NFS rules by identity before stable rule details."""
    formatted = _nfs_display_text(permission)
    return (
        permission.client,
        permission.access_mode.value,
        permission.root_squash.value,
        formatted,
    )


def _nfs_display_text(permission: NfsClientPermission | NfsDisplayPermission) -> str:
    return (
        f"{permission.client}:{permission.access_mode.value},"
        f"squash={permission.root_squash.value},"
        f"security_flavors=[{_enabled_security_flavors(permission)}],"
        f"async={str(permission.async_enabled).lower()},"
        f"insecure={str(permission.insecure).lower()},"
        f"crossmnt={str(permission.crossmnt).lower()}"
    )


def _enabled_security_flavors(
    permission: NfsClientPermission | NfsDisplayPermission,
) -> str:
    """Return enabled DSM NFS security flavors in canonical display order."""
    flavor = permission.security_flavor
    return ",".join(
        name
        for name, enabled in (
            ("sys", flavor.sys),
            ("kerberos", flavor.kerberos),
            ("kerberos_integrity", flavor.kerberos_integrity),
            ("kerberos_privacy", flavor.kerberos_privacy),
        )
        if enabled
    )


def _render_table(shares: Sequence[ShareRecord]) -> str:
    if not shares:
        return "No shares found."
    headers = ["NAME", "VOLUME", "DESCRIPTION", "USB", "QUOTA_GIB"]
    rows = [
        [
            _display(share.name),
            _display(share.volume),
            _display(share.description),
            _display_boolean(share.is_usb),
            _display_integer(share.quota_gib),
        ]
        for share in shares
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]
    return "\n".join(
        [
            "  ".join(
                title.ljust(widths[index]) for index, title in enumerate(headers)
            ),
            "  ".join("-" * width for width in widths),
            *[
                "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
                for row in rows
            ],
        ]
    )


def _render_detail_table(details: Sequence[ShareDetails]) -> str:
    if not details:
        return "No shares found."
    headers = [
        "NAME",
        "VOLUME",
        "DESCRIPTION",
        "USB",
        "QUOTA_GIB",
        "PERMISSION",
        "NFS-PERMISSIONS",
    ]
    rows: list[list[str]] = []
    for detail in details:
        acl = (
            "?"
            if detail.acl_status is EnrichmentStatus.UNAVAILABLE
            else "; ".join(
                f"{item.category}:{item.name}:{_access(item)}"
                for item in _display_acl_permissions(detail.acl_permissions)
            )
            or "-"
        )
        nfs = (
            "?"
            if detail.nfs_status is EnrichmentStatus.UNAVAILABLE
            else "; ".join(
                _nfs_display_text(item) for item in _display_nfs_permissions(detail)
            )
            or "-"
        )
        base = [
            _display(detail.share.name),
            _display(detail.share.volume),
            _display(detail.share.description),
            _display_boolean(detail.share.is_usb),
            _display_integer(detail.share.quota_gib),
            _clean(acl),
            _clean(nfs),
        ]
        lines = max(base[5].count("; ") + 1, base[6].count("; ") + 1)
        for index in range(lines):
            rows.append(
                base
                if index == 0
                else [
                    "",
                    "",
                    "",
                    "",
                    "",
                    base[5].split("; ")[index]
                    if index < base[5].count("; ") + 1
                    else "",
                    base[6].split("; ")[index]
                    if index < base[6].count("; ") + 1
                    else "",
                ]
            )
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]
    return "\n".join(
        [
            "  ".join(
                title.ljust(widths[index]) for index, title in enumerate(headers)
            ),
            "  ".join("-" * width for width in widths),
            *[
                "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
                for row in rows
            ],
        ]
    )


def _access(item: AclPermissionRecord) -> str:
    if item.is_deny:
        return "deny"
    if item.is_writable:
        return "read-write"
    if item.is_readonly:
        return "read-only"
    return "unknown"


def _clean(value: str) -> str:
    return "".join(character for character in value if character.isprintable())


def _display(value: str | None) -> str:
    return "-" if value is None or value == "" else value


def _display_integer(value: int | float | None) -> str:
    if value is None:
        return "-"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")


def _display_boolean(value: bool | None) -> str:
    if value is None:
        return "-"
    return "true" if value else "false"
