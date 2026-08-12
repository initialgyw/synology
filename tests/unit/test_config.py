from dataclasses import replace

import pytest

from synology.config import (
    parse_nfs_permission_spec,
    parse_permission_spec,
    resolve_connection_config,
    validate_nfs_permission_specs,
    validate_permission_specs,
    validate_share_create_request,
    validate_share_modify_request,
)
from synology.exceptions import ConfigurationError
from synology.models import (
    CliArguments,
    NfsAccessMode,
    NfsRootSquash,
    OutputFormat,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    RecycleBinOptions,
    ShareCreateOptions,
    ShareCreateRequest,
    ShareModifyRequest,
)


def _arguments(**changes: object) -> CliArguments:
    values: dict[str, object] = {
        "username": None,
        "password": None,
        "host": None,
        "port": 5001,
        "insecure": False,
        "verbose": False,
        "output": OutputFormat.TABLE,
    }
    values.update(changes)
    return CliArguments(**values)


def test_cli_values_override_environment_values() -> None:
    config = resolve_connection_config(
        _arguments(username="cli-user", password="cli-password", host=" cli-host "),
        environ={
            "SYN_USERNAME": "environment-user",
            "SYN_PASSWORD": "environment-password",
            "SYN_HOST": "environment-host",
        },
    )

    assert config.username == "cli-user"
    assert config.password == "cli-password"
    assert config.host == "cli-host"


def test_explicit_port_overrides_new_default() -> None:
    config = resolve_connection_config(
        _arguments(port=5000),
        environ={
            "SYN_USERNAME": "user",
            "SYN_PASSWORD": "password",
            "SYN_HOST": "host",
        },
    )

    assert config.port == 5000


def test_environment_values_fill_omitted_cli_options() -> None:
    config = resolve_connection_config(
        _arguments(),
        environ={
            "SYN_USERNAME": "environment-user",
            "SYN_PASSWORD": "environment-password",
            "SYN_HOST": " environment-host ",
        },
    )

    assert config.username == "environment-user"
    assert config.password == "environment-password"
    assert config.host == "environment-host"
    assert config.port == 5001
    assert config.insecure is False


@pytest.mark.parametrize("field", ["username", "password", "host"])
def test_missing_required_configuration_fails(field: str) -> None:
    values = {
        "SYN_USERNAME": "user",
        "SYN_PASSWORD": "password",
        "SYN_HOST": "host",
    }
    values.pop(f"SYN_{field.upper()}")

    with pytest.raises(ConfigurationError):
        resolve_connection_config(_arguments(), environ=values)


@pytest.mark.parametrize("port", [0, 65536])
def test_invalid_port_fails_before_client_construction(port: int) -> None:
    with pytest.raises(ConfigurationError, match="port must be between"):
        resolve_connection_config(
            _arguments(port=port),
            environ={
                "SYN_USERNAME": "user",
                "SYN_PASSWORD": "password",
                "SYN_HOST": "host",
            },
        )


def test_blank_password_is_rejected_without_trimming_valid_password() -> None:
    environment = {
        "SYN_USERNAME": "user",
        "SYN_PASSWORD": "  preserved-password  ",
        "SYN_HOST": "host",
    }

    config = resolve_connection_config(_arguments(), environ=environment)

    assert config.password == "  preserved-password  "
    with pytest.raises(ConfigurationError):
        resolve_connection_config(
            replace(_arguments(), password="   "),
            environ=environment,
        )


@pytest.mark.parametrize(
    ("specification", "principal_type", "principal_name", "access_mode"),
    [
        (
            "local-user:alice:read-write",
            PermissionPrincipalType.LOCAL_USER,
            "alice",
            PermissionAccessMode.READ_WRITE,
        ),
        (
            "ldap-user:uid=alice:ou=People:read-only",
            PermissionPrincipalType.LDAP_USER,
            "uid=alice:ou=People",
            PermissionAccessMode.READ_ONLY,
        ),
    ],
)
def test_permission_spec_parses_colon_separated_values(
    specification: str,
    principal_type: PermissionPrincipalType,
    principal_name: str,
    access_mode: PermissionAccessMode,
) -> None:
    permission = parse_permission_spec(specification)

    assert permission.principal_type is principal_type
    assert permission.principal_name == principal_name
    assert permission.access_mode is access_mode


@pytest.mark.parametrize(
    "specification",
    [
        "alice:read-write",
        "local-user::read-write",
        "local-user:alice:",
        ":alice:read-write",
        "system:admin:read-write",
        "local-user:alice:unknown",
    ],
)
def test_invalid_permission_specifications_fail(specification: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_permission_spec(specification)


def test_duplicate_permission_specifications_fail() -> None:
    with pytest.raises(ConfigurationError, match="duplicate"):
        validate_permission_specs(
            ("local-user:alice:read-write", "local-user:alice:read-write")
        )


def test_nfs_permission_spec_parses_safe_defaults() -> None:
    permission = parse_nfs_permission_spec("client=10.192.10.20,access=read-write")

    assert permission.client == "10.192.10.20"
    assert permission.access_mode is NfsAccessMode.READ_WRITE
    assert permission.async_enabled is False
    assert permission.insecure is False
    assert permission.crossmnt is False
    assert permission.root_squash is NfsRootSquash.ROOT
    assert permission.security_flavor.sys is True


@pytest.mark.parametrize("root_squash", list(NfsRootSquash))
def test_nfs_permission_spec_parses_exact_dsm_root_squash_tokens(
    root_squash: NfsRootSquash,
) -> None:
    permission = parse_nfs_permission_spec(
        "client=10.192.10.20,access=read-write,root_squash=" + root_squash.value
    )

    assert permission.root_squash is root_squash


@pytest.mark.parametrize(
    "root_squash",
    ["no_root_squash", "none", "all_squash", "map_root", "ROOT", "Admin", "unknown"],
)
def test_nfs_permission_spec_rejects_non_dsm_root_squash_tokens(
    root_squash: str,
) -> None:
    with pytest.raises(ConfigurationError, match="root_squash"):
        parse_nfs_permission_spec(
            "client=10.192.10.20,access=read-write,root_squash=" + root_squash
        )


@pytest.mark.parametrize(
    "specification",
    [
        "client=10.192.10.20",
        "access=read-write",
        "client=10.192.10.20,access=unknown",
        "client=hostname,access=read-write",
        "client=10.192.10.20,access=read-write,async=yes",
        "client=10.192.10.20,access=read-write,root_squash=",
        "client=10.192.10.20,access=read-write,root_squash",
        "client=10.192.10.20,access=read-write,unknown=value",
        "client=10.192.10.20,client=10.192.10.21,access=read-write",
    ],
)
def test_invalid_nfs_permission_specifications_fail(specification: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_nfs_permission_spec(specification)


def test_duplicate_nfs_clients_fail() -> None:
    with pytest.raises(ConfigurationError, match="duplicate nfs clients"):
        validate_nfs_permission_specs(
            (
                "client=10.192.10.20,access=read-only",
                "client=10.192.10.20,access=read-write",
            )
        )


def test_create_request_preserves_permissions() -> None:
    permission = PermissionSpec(
        PermissionPrincipalType.LOCAL_USER,
        "alice",
        PermissionAccessMode.READ_WRITE,
    )

    request = validate_share_create_request(
        ShareCreateRequest(
            name="projects",
            volume_path="/volume1",
            permissions=(permission,),
        )
    )

    assert request.permissions == (permission,)


def test_create_request_trims_name_and_volume_path() -> None:
    request = validate_share_create_request(
        ShareCreateRequest(
            name=" media ",
            volume_path=" /volume1 ",
            description="Media files",
        )
    )

    assert request == ShareCreateRequest(
        name="media",
        volume_path="/volume1",
        description="Media files",
    )


@pytest.mark.parametrize(
    "create_request",
    [
        ShareCreateRequest(name="", volume_path="/volume1"),
        ShareCreateRequest(name=".", volume_path="/volume1"),
        ShareCreateRequest(name="..", volume_path="/volume1"),
        ShareCreateRequest(name="nested/share", volume_path="/volume1"),
        ShareCreateRequest(name="nested\\share", volume_path="/volume1"),
        ShareCreateRequest(name="line\nbreak", volume_path="/volume1"),
        ShareCreateRequest(name="share", volume_path="relative"),
        ShareCreateRequest(name="share", volume_path="/volume1\x00bad"),
        ShareCreateRequest(
            name="share", volume_path="/volume1", description="bad\ntext"
        ),
    ],
)
def test_invalid_create_request_fails_locally(
    create_request: ShareCreateRequest,
) -> None:
    with pytest.raises(ConfigurationError):
        validate_share_create_request(create_request)


def test_create_request_preserves_phase_one_options() -> None:
    options = ShareCreateOptions(
        recycle_bin=RecycleBinOptions(enabled=False, admin_only=True),
        compression_enabled=True,
    )

    request = validate_share_create_request(
        ShareCreateRequest(
            name="media",
            volume_path="/volume1",
            options=options,
        )
    )

    assert request.options == options


@pytest.mark.parametrize("quota", [0, -1, True])
def test_invalid_quota_fails_locally(quota: object) -> None:
    with pytest.raises(ConfigurationError, match="quota must be"):
        validate_share_create_request(
            ShareCreateRequest(
                name="media",
                volume_path="/volume1",
                options=ShareCreateOptions(quota_gib=quota),
            )
        )


def test_positive_quota_is_accepted_as_gib() -> None:
    request = validate_share_create_request(
        ShareCreateRequest(
            name="media",
            volume_path="/volume1",
            options=ShareCreateOptions(quota_gib=100),
        )
    )

    assert request.options.quota_gib == 100
    assert request.options.quota_api_value == 102400


def test_recycle_bin_user_access_requires_recycle_bin() -> None:
    with pytest.raises(ConfigurationError, match="requires recycle bin enabled"):
        validate_share_create_request(
            ShareCreateRequest(
                name="media",
                volume_path="/volume1",
                options=ShareCreateOptions(
                    recycle_bin=RecycleBinOptions(enabled=False, admin_only=False)
                ),
            )
        )


def test_modify_request_preserves_zero_quota_and_trims_name() -> None:
    request = validate_share_modify_request(
        ShareModifyRequest(name=" media ", quota_gib=0)
    )

    assert request == ShareModifyRequest(name="media", quota_gib=0)


@pytest.mark.parametrize(
    "modify_request",
    [
        ShareModifyRequest(name="media"),
        ShareModifyRequest(name="media", quota_gib=-1),
        ShareModifyRequest(name="media", quota_gib=1, permissions=()),
        ShareModifyRequest(name="media", permissions=(), nfs_permissions=()),
    ],
)
def test_modify_request_requires_exactly_one_valid_family(
    modify_request: ShareModifyRequest,
) -> None:
    with pytest.raises(ConfigurationError):
        validate_share_modify_request(modify_request)
