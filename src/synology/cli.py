import argparse
import logging as stdlib_logging
import sys
from collections.abc import Mapping, Sequence
from typing import NoReturn, Protocol, TextIO, cast

from synology.config import (
    resolve_connection_config,
    validate_nfs_permission_specs,
    validate_permission_specs,
    validate_share_create_request,
    validate_share_delete_request,
    validate_share_modify_request,
)
from synology.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    OutputError,
    PartialOperationError,
    PrincipalNotFoundError,
    TransportError,
    UnexpectedApplicationError,
)
from synology.logging import configure_logging
from synology.models import (
    CliArguments,
    Command,
    ConnectionConfig,
    NfsClientPermission,
    OperationStatus,
    OutputFormat,
    PermissionSpec,
    RecycleBinOptions,
    ShareCreateOptions,
    ShareCreateRequest,
    ShareCreateResult,
    ShareDeleteRequest,
    ShareDeleteResult,
    ShareDetails,
    ShareModifyRequest,
    ShareModifyResult,
    ShareOperationStep,
    ShareRecord,
)
from synology.output import (
    render_share_create,
    render_share_delete,
    render_share_details,
    render_share_modify,
    render_shares,
)
from synology.shares import SynShareClient


class ShareClient(Protocol):
    def list_shares(self) -> tuple[ShareRecord, ...]: ...

    def list_share_details(self) -> tuple[ShareDetails, ...]: ...

    def create_share(self, request: ShareCreateRequest) -> ShareCreateResult: ...

    def delete_share(self, request: ShareDeleteRequest) -> ShareDeleteResult: ...

    def modify_share(self, request: ShareModifyRequest) -> ShareModifyResult: ...


class ShareClientFactory(Protocol):
    def __call__(
        self,
        config: ConnectionConfig,
        logger: stdlib_logging.Logger,
    ) -> ShareClient: ...


class _UsageError(Exception):
    pass


class _CliArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(message)


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv, stdout=sys.stdout, stderr=sys.stderr)


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO,
    stderr: TextIO,
    environ: Mapping[str, str] | None = None,
    client_factory: ShareClientFactory | None = None,
) -> int:
    parser = _build_parser()
    try:
        arguments = _parse_arguments(parser, argv)
    except _UsageError as exc:
        stderr.write(parser.format_usage())
        stderr.write(f"{parser.prog}: error: {exc}\n")
        return 2
    except SystemExit as exc:
        return 0 if exc.code is None else int(exc.code)

    logger = configure_logging(arguments.verbose, stream=stderr)
    try:
        if arguments.command is Command.DELETE_SHARE:
            delete_request = validate_share_delete_request(
                ShareDeleteRequest(name=arguments.name)
            )
            if not arguments.confirm:
                _write_output(
                    render_share_delete(
                        ShareDeleteResult(
                            name=delete_request.name,
                            deleted=False,
                            steps=(
                                ShareOperationStep(
                                    name="delete", status=OperationStatus.PLANNED
                                ),
                            ),
                        ),
                        arguments.output,
                    ),
                    stdout,
                )
                return 11
        if arguments.command is Command.MODIFY_SHARE:
            if len(arguments.quota_values) > 1:
                raise ConfigurationError("--quota may be specified only once")
            permissions, acl_clear_mode = _modify_permissions(
                arguments.permission_specs
            )
            nfs_permissions = _modify_nfs_permissions(arguments.nfs_permission_specs)
            modify_request = validate_share_modify_request(
                ShareModifyRequest(
                    name=arguments.name,
                    quota_gib=(
                        arguments.quota_values[0] if arguments.quota_values else None
                    ),
                    permissions=permissions,
                    nfs_permissions=nfs_permissions,
                    _acl_clear_mode=acl_clear_mode,
                )
            )
            if not arguments.confirm:
                _write_output(
                    render_share_modify(
                        ShareModifyResult(
                            name=modify_request.name,
                            changed=False,
                            quota_gib=modify_request.quota_gib,
                            permissions=modify_request.permissions,
                            nfs_permissions=modify_request.nfs_permissions,
                            steps=(
                                ShareOperationStep(
                                    name="modify",
                                    status=OperationStatus.PLANNED,
                                    message=(
                                        "principal existence unverified"
                                        if modify_request.permissions
                                        else None
                                    ),
                                ),
                            ),
                        ),
                        arguments.output,
                    ),
                    stdout,
                )
                return 11
        if arguments.command is Command.CREATE_SHARE:
            if arguments.disable_recycle_bin and arguments.recycle_bin_user_access:
                raise ConfigurationError(
                    "--disable-recycle-bin cannot be combined with "
                    "--recycle-bin-user-access"
                )

            permissions = validate_permission_specs(arguments.permission_specs)
            nfs_permissions = validate_nfs_permission_specs(
                arguments.nfs_permission_specs
            )
            create_request = validate_share_create_request(
                ShareCreateRequest(
                    name=arguments.name,
                    volume_path=arguments.volume_path,
                    description=arguments.description,
                    options=ShareCreateOptions(
                        recycle_bin=RecycleBinOptions(
                            enabled=not arguments.disable_recycle_bin,
                            admin_only=not arguments.recycle_bin_user_access,
                        ),
                        compression_enabled=arguments.compress,
                        quota_gib=arguments.quota_gib,
                    ),
                    permissions=permissions,
                    nfs_permissions=nfs_permissions,
                )
            )
            if not arguments.confirm:
                _write_output(
                    render_share_create(
                        ShareCreateResult(
                            name=create_request.name,
                            volume=create_request.volume_path,
                            description=create_request.description,
                            created=False,
                            options=create_request.options,
                            permissions=permissions,
                            nfs_permissions=nfs_permissions,
                            steps=(
                                ShareOperationStep(
                                    name="create", status=OperationStatus.PLANNED
                                ),
                            ),
                        ),
                        arguments.output,
                    ),
                    stdout,
                )
                return 11
        factory = _default_client_factory if client_factory is None else client_factory
        config = resolve_connection_config(arguments, environ=environ)
        if config.insecure:
            logger.warning("TLS certificate verification is disabled")
        client = factory(config, logger)
        if arguments.command is Command.MODIFY_SHARE:
            rendered = render_share_modify(
                client.modify_share(modify_request), arguments.output
            )
        elif arguments.command is Command.CREATE_SHARE:
            rendered = render_share_create(
                client.create_share(create_request), arguments.output
            )
        elif arguments.command is Command.DELETE_SHARE:
            rendered = render_share_delete(
                client.delete_share(delete_request), arguments.output
            )
        else:
            if arguments.permissions:
                details = client.list_share_details()
                rendered = render_share_details(details, arguments.output)
                if any(item.diagnostics for item in details):
                    _write_output(rendered, stdout)
                    for item in details:
                        for diagnostic in item.diagnostics:
                            _write_error(
                                f"{item.share.name}: {diagnostic.detail}", stderr
                            )
                    return 60
            else:
                rendered = render_shares(client.list_shares(), arguments.output)

        _write_output(rendered, stdout)
        return 0
    except ConfigurationError as exc:
        _write_error(str(exc), stderr)
        return 10
    except AuthenticationError as exc:
        _write_error(str(exc), stderr)
        return 20
    except TransportError as exc:
        _write_error(str(exc), stderr)
        return 30
    except PrincipalNotFoundError as exc:
        _write_error(str(exc), stderr)
        return 41
    except ApiError as exc:
        _write_error(str(exc), stderr)
        return 40
    except PartialOperationError as exc:
        result = exc.result
        try:
            if isinstance(result, ShareModifyResult):
                rendered = render_share_modify(result, arguments.output)
            elif isinstance(result, ShareCreateResult):
                rendered = render_share_create(result, arguments.output)
            else:
                raise OutputError("unable to render partial operation output")
            _write_output(rendered, stdout)
        except OutputError as output_exc:
            _write_error(str(output_exc), stderr)
            return 50
        _write_error(str(exc), stderr)
        return 60
    except OutputError as exc:
        _write_error(str(exc), stderr)
        return 50
    except BrokenPipeError:
        return 50
    except UnexpectedApplicationError as exc:
        _write_error(str(exc), stderr)
        return 70
    except Exception as exc:
        logger.debug("Unexpected application failure error_type=%s", type(exc).__name__)
        _write_error("unexpected application failure", stderr)
        return 70


def _default_client_factory(
    config: ConnectionConfig,
    logger: stdlib_logging.Logger,
) -> ShareClient:
    return SynShareClient(config, logger)


def _build_parser() -> _CliArgumentParser:
    parser = _CliArgumentParser(
        prog="syn-cli",
        description="Manage Synology NAS shared folders through the Synology Web API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  syn-cli list-shares --output json\n"
            "  syn-cli create-share projects --path /volume1\n"
            "  syn-cli create-share projects --path /volume1 --yes\n"
            "  syn-cli delete-share projects --yes\n"
            "  syn-cli create-share projects --path /volume1 "
            "--permission 'local-user:alice:read-write' --yes\n"
            "  syn-cli create-share nfs-data --path /volume1 "
            "--nfs-permission 'client=10.192.10.0/24,access=read-write' --yes\n"
            "  syn-cli modify-share projects --permission ''\n\n"
            "Create, delete, and modify operations require --yes to contact the NAS; "
            "without it, a local plan is printed and exit code 11 is returned."
        ),
    )
    _add_global_options(parser)
    parser.set_defaults(
        username=None,
        password=None,
        host=None,
        port=5001,
        insecure=False,
        verbose=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    list_shares = subparsers.add_parser(
        "list-shares",
        help="List configured NAS shared folders.",
        description="List configured shared folders from the Synology NAS.",
    )
    _add_global_options(list_shares)
    list_shares.add_argument(
        "--permissions",
        action="store_true",
        help="Include ACL and per-share NFS permissions.",
    )
    list_shares.add_argument(
        "-o",
        "--output",
        choices=tuple(item.value for item in OutputFormat),
        default=OutputFormat.TABLE.value,
        help="Output format: table, json, or yaml. Defaults to table.",
    )
    create_share = subparsers.add_parser(
        "create-share",
        help="Create a shared folder and optional ACL/NFS rules.",
        description=(
            "Create a shared folder. Without --yes, validate and print a local "
            "plan without contacting the NAS."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Permission format: TYPE:NAME:ACCESS\n"
            "  --permission 'local-user:alice:read-write'\n"
            "  --permission 'ldap-user:uid=alice:ou=People:read-only'\n\n"
            "NFS format: comma-separated key=value pairs\n"
            "  --nfs-permission 'client=10.192.10.0/24,access=read-write'\n\n"
            "ACL and NFS entries replace the complete rule set. Global NFS must "
            "already be enabled."
        ),
    )
    _add_global_options(create_share)
    create_share.add_argument("name", help="Shared-folder name to create.")
    create_share.add_argument(
        "-p",
        "--path",
        dest="volume_path",
        required=True,
        help="NAS volume path, not a local or final share path.",
    )
    create_share.add_argument(
        "--description",
        default="",
        help="Optional shared-folder description.",
    )
    create_share.add_argument(
        "--disable-recycle-bin",
        action="store_true",
        help="Disable the default-enabled recycle bin.",
    )
    create_share.add_argument(
        "--recycle-bin-user-access",
        action="store_true",
        help="Allow non-administrators to access the recycle bin.",
    )
    create_share.add_argument(
        "--compress",
        action="store_true",
        help="Request file compression when supported by DSM/storage.",
    )
    create_share.add_argument(
        "--quota",
        dest="quota_gib",
        type=int,
        help="Positive shared-folder quota in GiB; converted to the DSM API unit.",
    )
    create_share.add_argument(
        "--permission",
        dest="permission_specs",
        action="append",
        default=[],
        metavar="TYPE:NAME:ACCESS",
        help=(
            "Repeatable complete ACL rule, e.g. "
            "local-user:alice:read-write; LDAP names may contain colons."
        ),
    )
    create_share.add_argument(
        "--nfs-permission",
        dest="nfs_permission_specs",
        action="append",
        default=[],
        metavar="SPEC",
        help=(
            "Repeatable complete NFS rule, e.g. "
            "client=10.192.10.0/24,access=read-write; global NFS must be enabled."
        ),
    )
    create_share.add_argument(
        "--yes",
        dest="confirm",
        action="store_true",
        help="Confirm NAS mutation; without it, print a local plan and exit 11.",
    )
    create_share.add_argument(
        "-o",
        "--output",
        choices=tuple(item.value for item in OutputFormat),
        default=OutputFormat.TABLE.value,
        help="Output format: table, json, or yaml. Defaults to table.",
    )
    modify_share = subparsers.add_parser(
        "modify-share",
        help="Replace share quota, ACL, or NFS rules.",
        description=(
            "Replace exactly one share setting family. Without --yes, validate and "
            "print a local plan without contacting the NAS."
        ),
    )
    _add_global_options(modify_share)
    modify_share.add_argument("name", help="Shared-folder name to modify.")
    modify_share.add_argument(
        "--quota",
        dest="quota_values",
        action="append",
        type=int,
        metavar="INTEGER",
        help="Quota in GiB; zero clears the quota (unlimited).",
    )
    modify_share.add_argument(
        "--permission",
        dest="permission_specs",
        action="append",
        default=[],
        metavar="TYPE:NAME:ACCESS",
        help="Repeatable replacement ACL rule; an empty value clears the ACL.",
    )
    modify_share.add_argument(
        "--nfs-permission",
        dest="nfs_permission_specs",
        action="append",
        default=[],
        metavar="SPEC",
        help="Repeatable replacement NFS rule; an empty value clears all NFS rules.",
    )
    modify_share.add_argument(
        "--yes",
        dest="confirm",
        action="store_true",
        help="Confirm NAS mutation; without it, print a local plan and exit 11.",
    )
    modify_share.add_argument(
        "-o",
        "--output",
        choices=tuple(item.value for item in OutputFormat),
        default=OutputFormat.TABLE.value,
        help="Output format: table, json, or yaml. Defaults to table.",
    )
    delete_share = subparsers.add_parser(
        "delete-share",
        help="Delete a shared folder.",
        description=(
            "Delete a shared folder by exact name. Without --yes, validate and "
            "print a local plan without contacting the NAS."
        ),
    )
    _add_global_options(delete_share)
    delete_share.add_argument("name", help="Shared-folder name to delete.")
    delete_share.add_argument(
        "--yes",
        dest="confirm",
        action="store_true",
        help="Confirm NAS mutation; without it, print a local plan and exit 11.",
    )
    delete_share.add_argument(
        "-o",
        "--output",
        choices=tuple(item.value for item in OutputFormat),
        default=OutputFormat.TABLE.value,
        help="Output format: table, json, or yaml. Defaults to table.",
    )
    return parser


def _add_global_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--username",
        default=argparse.SUPPRESS,
        help="NAS username; overrides SYN_USERNAME.",
    )
    parser.add_argument(
        "--password",
        default=argparse.SUPPRESS,
        help="NAS password; overrides SYN_PASSWORD. Avoid shell history exposure.",
    )
    parser.add_argument(
        "--host",
        default=argparse.SUPPRESS,
        help="NAS hostname or address; overrides SYN_HOST.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=argparse.SUPPRESS,
        help="NAS API port. Defaults to 5001.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable TLS certificate verification.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Emit sanitized DEBUG diagnostics to stderr.",
    )


def _parse_arguments(
    parser: argparse.ArgumentParser,
    argv: Sequence[str] | None,
) -> CliArguments:
    namespace = parser.parse_args(argv)
    values = cast(Mapping[str, object], vars(namespace))
    try:
        return CliArguments(
            username=_optional_string(values.get("username"), "username"),
            password=_optional_string(values.get("password"), "password"),
            host=_optional_string(values.get("host"), "host"),
            port=_integer(values.get("port"), "port"),
            insecure=_boolean(values.get("insecure"), "insecure"),
            verbose=_boolean(values.get("verbose"), "verbose"),
            output=OutputFormat(_string(values.get("output"), "output")),
            command=Command(_string(values.get("command"), "command")),
            name=_optional_string(values.get("name"), "name") or "",
            volume_path=_optional_string(values.get("volume_path"), "volume_path")
            or "",
            description=_optional_string(values.get("description"), "description")
            or "",
            confirm=_boolean(values.get("confirm", False), "confirm"),
            disable_recycle_bin=_boolean(
                values.get("disable_recycle_bin", False), "disable_recycle_bin"
            ),
            recycle_bin_user_access=_boolean(
                values.get("recycle_bin_user_access", False),
                "recycle_bin_user_access",
            ),
            compress=_boolean(values.get("compress", False), "compress"),
            quota_gib=_optional_integer(values.get("quota_gib"), "quota"),
            quota_values=_integer_tuple(values.get("quota_values", []), "quota"),
            permission_specs=_string_tuple(
                values.get("permission_specs", []), "permission"
            ),
            nfs_permission_specs=_string_tuple(
                values.get("nfs_permission_specs", []), "nfs-permission"
            ),
            permissions=_boolean(values.get("permissions", False), "permissions"),
        )
    except ValueError as exc:
        raise _UsageError("invalid command-line value") from exc


def _modify_permissions(
    specifications: tuple[str, ...],
) -> tuple[tuple[PermissionSpec, ...] | None, bool]:
    if not specifications:
        return None, False
    if "" in specifications:
        if len(specifications) != 1:
            raise ConfigurationError(
                "--permission may contain exactly one empty value and no other values"
            )
        return (), True
    return validate_permission_specs(specifications), False


def _modify_nfs_permissions(
    specifications: tuple[str, ...],
) -> tuple[NfsClientPermission, ...] | None:
    if not specifications:
        return None
    if "" in specifications:
        if len(specifications) != 1:
            raise ConfigurationError(
                "--nfs-permission may contain exactly one empty value "
                "and no other values"
            )
        return ()
    return validate_nfs_permission_specs(specifications)


def _optional_string(value: object, name: str) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise _UsageError(f"invalid {name}")


def _string(value: object, name: str) -> str:
    if isinstance(value, str):
        return value
    raise _UsageError(f"invalid {name}")


def _integer(value: object, name: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise _UsageError(f"invalid {name}")


def _boolean(value: object, name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise _UsageError(f"invalid {name}")


def _string_tuple(value: object, name: str) -> tuple[str, ...]:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise _UsageError(f"invalid {name}")


def _optional_integer(value: object, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise _UsageError(f"invalid {name}")


def _integer_tuple(value: object, name: str) -> tuple[int, ...]:
    if value is None:
        return ()
    if isinstance(value, list) and all(
        isinstance(item, int) and not isinstance(item, bool) for item in value
    ):
        return tuple(value)
    raise _UsageError(f"invalid {name}")


def _write_output(output: str, stream: TextIO) -> None:
    stream.write(output)
    stream.write("\n")
    stream.flush()


def _write_error(message: str, stream: TextIO) -> None:
    stream.write(f"error: {message}\n")
    stream.flush()


if __name__ == "__main__":
    raise SystemExit(main())
