import contextlib
import json
import logging as stdlib_logging
import tomllib
from io import StringIO
from pathlib import Path

import pytest

from synology.cli import run
from synology.exceptions import (
    ApiError,
    AuthenticationError,
    OutputError,
    PartialOperationError,
    TransportError,
)
from synology.models import (
    ConnectionConfig,
    NfsAccessMode,
    NfsClientPermission,
    OperationStatus,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    RecycleBinOptions,
    ShareCreateOptions,
    ShareCreateRequest,
    ShareCreateResult,
    ShareDeleteRequest,
    ShareDeleteResult,
    ShareOperationStep,
    ShareRecord,
)


class FakeClient:
    def __init__(
        self,
        shares: tuple[ShareRecord, ...] = (),
        error: Exception | None = None,
        create_result: ShareCreateResult | None = None,
        create_error: Exception | None = None,
        delete_result: ShareDeleteResult | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.shares = shares
        self.error = error
        self.create_result = create_result
        self.create_error = create_error
        self.delete_result = delete_result
        self.delete_error = delete_error
        self.create_requests: list[ShareCreateRequest] = []
        self.delete_requests: list[ShareDeleteRequest] = []

    def list_shares(self) -> tuple[ShareRecord, ...]:
        if self.error is not None:
            raise self.error
        return self.shares

    def create_share(self, request: ShareCreateRequest) -> ShareCreateResult:
        self.create_requests.append(request)
        if self.create_error is not None:
            raise self.create_error
        if self.create_result is None:
            raise AssertionError("unexpected create-share invocation")
        return self.create_result

    def delete_share(self, request: ShareDeleteRequest) -> ShareDeleteResult:
        self.delete_requests.append(request)
        if self.delete_error is not None:
            raise self.delete_error
        if self.delete_result is None:
            raise AssertionError("unexpected delete-share invocation")
        return self.delete_result


class CapturingFactory:
    def __init__(self, client: FakeClient) -> None:
        self.client = client
        self.config: ConnectionConfig | None = None

    def __call__(
        self,
        config: ConnectionConfig,
        logger: stdlib_logging.Logger,
    ) -> FakeClient:
        self.config = config
        return self.client


class DebugFactory(CapturingFactory):
    def __call__(
        self,
        config: ConnectionConfig,
        logger: stdlib_logging.Logger,
    ) -> FakeClient:
        logger.debug("factory debug diagnostic")
        return super().__call__(config, logger)


class BrokenOutput(StringIO):
    def write(self, value: str) -> int:
        raise BrokenPipeError


class FailingEnvironment(dict[str, str]):
    def get(self, key: str, default: str | None = None) -> str | None:
        raise AssertionError(f"environment access is not allowed: {key}")


def _environment() -> dict[str, str]:
    return {
        "SYN_USERNAME": "environment-user",
        "SYN_PASSWORD": "environment-password",
        "SYN_HOST": "environment-host",
    }


def _run(
    arguments: list[str],
    factory: CapturingFactory,
    *,
    environment: dict[str, str] | None = None,
) -> tuple[int, StringIO, StringIO]:
    stdout = StringIO()
    stderr = StringIO()
    result = run(
        arguments,
        stdout=stdout,
        stderr=stderr,
        environ=_environment() if environment is None else environment,
        client_factory=factory,
    )
    return result, stdout, stderr


@pytest.mark.parametrize(
    "arguments",
    [
        [
            "--username",
            "cli-user",
            "--password",
            "cli-password",
            "--host",
            "cli-host",
            "--port",
            "8443",
            "list-shares",
        ],
        [
            "list-shares",
            "--username",
            "cli-user",
            "--password",
            "cli-password",
            "--host",
            "cli-host",
            "--port",
            "8443",
        ],
    ],
)
def test_global_options_work_before_and_after_subcommand(arguments: list[str]) -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(arguments, factory)

    assert result == 0
    assert stdout.getvalue() == "No shares found.\n"
    assert stderr.getvalue() == ""
    assert factory.config == ConnectionConfig(
        username="cli-user",
        password="cli-password",
        host="cli-host",
        port=8443,
    )


def test_pre_subcommand_boolean_options_are_preserved() -> None:
    factory = DebugFactory(FakeClient())

    result, stdout, stderr = _run(
        [
            "--username",
            "cli-user",
            "--password",
            "cli-password",
            "--host",
            "cli-host",
            "--insecure",
            "--verbose",
            "list-shares",
        ],
        factory,
    )

    assert result == 0
    assert stdout.getvalue() == "No shares found.\n"
    assert "TLS certificate verification is disabled" in stderr.getvalue()
    assert "DEBUG: factory debug diagnostic" in stderr.getvalue()
    assert factory.config == ConnectionConfig(
        username="cli-user",
        password="cli-password",
        host="cli-host",
        insecure=True,
    )


def test_omitted_port_uses_5001() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(["list-shares"], factory)

    assert result == 0
    assert stdout.getvalue() == "No shares found.\n"
    assert stderr.getvalue() == ""
    assert factory.config is not None
    assert factory.config.port == 5001


def test_delete_share_without_yes_returns_local_plan_without_client() -> None:
    client = FakeClient()
    factory = CapturingFactory(client)

    result, stdout, stderr = _run(
        ["delete-share", "media", "--output", "json"],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue()) == {
        "name": "media",
        "deleted": False,
        "steps": [{"name": "delete", "status": "planned"}],
    }
    assert stderr.getvalue() == ""
    assert factory.config is None
    assert client.delete_requests == []


def test_delete_share_with_yes_invokes_client() -> None:
    client = FakeClient(
        delete_result=ShareDeleteResult(
            name="media",
            deleted=True,
            steps=(
                ShareOperationStep(name="delete", status=OperationStatus.SUCCEEDED),
            ),
        )
    )
    factory = CapturingFactory(client)

    result, stdout, stderr = _run(
        ["delete-share", "media", "--yes", "--output", "json"],
        factory,
    )

    assert result == 0
    assert json.loads(stdout.getvalue()) == {
        "name": "media",
        "deleted": True,
        "steps": [{"name": "delete", "status": "succeeded"}],
    }
    assert stderr.getvalue() == ""
    assert client.delete_requests == [ShareDeleteRequest(name="media")]


@pytest.mark.parametrize("name", ["", "bad/name", ".", "..", "bad\nname"])
def test_delete_share_invalid_name_returns_validation_error(name: str) -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(
        ["delete-share", name],
        factory,
        environment={},
    )

    assert result == 10
    assert stdout.getvalue() == ""
    assert "share name" in stderr.getvalue()
    assert factory.config is None


@pytest.mark.parametrize(
    ("error", "expected_exit"),
    [
        (AuthenticationError("authentication failed"), 20),
        (TransportError("transport failed"), 30),
        (ApiError("api failed"), 40),
        (OutputError("output failed"), 50),
        (RuntimeError("unexpected"), 70),
    ],
)
def test_delete_share_maps_client_failures_to_exit_codes(
    error: Exception,
    expected_exit: int,
) -> None:
    factory = CapturingFactory(FakeClient(delete_error=error))

    result, stdout, stderr = _run(
        ["delete-share", "media", "--yes"],
        factory,
    )

    assert result == expected_exit
    assert stdout.getvalue() == ""
    assert "error:" in stderr.getvalue()


def test_create_share_permission_plan_requires_no_credentials() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(
        [
            "create-share",
            "projects",
            "--path",
            "/volume1",
            "--permission",
            "local-user:alice:read-write",
            "--permission",
            "ldap-user:uid=alice:ou=People:read-only",
            "--output",
            "json",
        ],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue())["permissions"] == [
        {
            "principal_type": "local-user",
            "principal_name": "alice",
            "access_mode": "read-write",
        },
        {
            "principal_type": "ldap-user",
            "principal_name": "uid=alice:ou=People",
            "access_mode": "read-only",
        },
    ]
    assert stderr.getvalue() == ""
    assert factory.config is None


def test_create_share_nfs_plan_requires_no_credentials() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(
        [
            "create-share",
            "projects",
            "--path",
            "/volume1",
            "--nfs-permission",
            "client=10.192.10.20,access=read-write",
            "--output",
            "json",
        ],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue())["nfs_permissions"] == [
        {
            "client": "10.192.10.20",
            "access": "read-write",
            "async": False,
            "insecure": False,
            "crossmnt": False,
            "root_squash": "root",
            "security_flavor": {
                "sys": True,
                "kerberos": False,
                "kerberos_integrity": False,
                "kerberos_privacy": False,
            },
        }
    ]
    assert stderr.getvalue() == ""
    assert factory.config is None


def test_create_share_with_yes_preserves_nfs_permissions_for_client() -> None:
    nfs_permission = NfsClientPermission(
        client="10.192.10.20",
        access_mode=NfsAccessMode.READ_ONLY,
    )
    client = FakeClient(
        create_result=ShareCreateResult(
            name="projects",
            volume="/volume1",
            description="",
            created=True,
            nfs_permissions=(nfs_permission,),
            steps=(
                ShareOperationStep(name="create", status=OperationStatus.SUCCEEDED),
            ),
        )
    )
    factory = CapturingFactory(client)

    result, stdout, stderr = _run(
        [
            "create-share",
            "projects",
            "--path",
            "/volume1",
            "--nfs-permission",
            "client=10.192.10.20,access=read-only",
            "--yes",
            "--output",
            "json",
        ],
        factory,
    )

    assert result == 0
    assert client.create_requests[0].nfs_permissions == (nfs_permission,)
    assert json.loads(stdout.getvalue())["nfs_permissions"][0]["access"] == "read-only"
    assert stderr.getvalue() == ""


def test_create_share_with_yes_preserves_permissions_for_client() -> None:
    permissions = (
        PermissionSpec(
            PermissionPrincipalType.LOCAL_USER,
            "synadmin",
            PermissionAccessMode.READ_WRITE,
        ),
        PermissionSpec(
            PermissionPrincipalType.LDAP_USER,
            "konri@jumpcloud.com",
            PermissionAccessMode.READ_ONLY,
        ),
    )
    client = FakeClient(
        create_result=ShareCreateResult(
            name="projects",
            volume="/volume1",
            description="",
            created=True,
            permissions=permissions,
            steps=(
                ShareOperationStep(
                    name="create",
                    status=OperationStatus.SUCCEEDED,
                ),
            ),
        )
    )
    factory = CapturingFactory(client)

    result, stdout, stderr = _run(
        [
            "create-share",
            "projects",
            "--path",
            "/volume1",
            "--permission",
            "local-user:synadmin:read-write",
            "--permission",
            "ldap-user:konri@jumpcloud.com:read-only",
            "--yes",
            "--output",
            "json",
        ],
        factory,
    )

    assert result == 0
    assert stderr.getvalue() == ""
    assert client.create_requests[0].permissions == permissions
    assert json.loads(stdout.getvalue())["permissions"] == [
        {
            "principal_type": "local-user",
            "principal_name": "synadmin",
            "access_mode": "read-write",
        },
        {
            "principal_type": "ldap-user",
            "principal_name": "konri@jumpcloud.com",
            "access_mode": "read-only",
        },
    ]


def test_create_share_without_yes_returns_local_plan_without_client() -> None:
    client = FakeClient()
    factory = CapturingFactory(client)

    result, stdout, stderr = _run(
        [
            "create-share",
            "media",
            "--path",
            "/volume1",
            "--description",
            "Media files",
            "--output",
            "json",
        ],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue()) == {
        "name": "media",
        "volume": "/volume1",
        "description": "Media files",
        "created": False,
        "options": {
            "recycle_bin": {"enabled": True, "admin_only": True},
            "compression_enabled": False,
            "quota_gib": None,
            "quota_api_value": None,
            "quota_api_unit": "MiB",
        },
        "permissions": [],
        "steps": [{"name": "create", "status": "planned"}],
    }
    assert stderr.getvalue() == ""
    assert factory.config is None
    assert client.create_requests == []


@pytest.mark.parametrize(
    "arguments",
    [
        [
            "--username",
            "cli-user",
            "--password",
            "cli-password",
            "--host",
            "cli-host",
            "create-share",
            "media",
            "--path",
            "/volume1",
            "--description",
            "Media files",
            "--yes",
            "--output",
            "json",
        ],
        [
            "create-share",
            "media",
            "--path",
            "/volume1",
            "--description",
            "Media files",
            "--yes",
            "--output",
            "json",
            "--username",
            "cli-user",
            "--password",
            "cli-password",
            "--host",
            "cli-host",
        ],
    ],
)
def test_create_share_with_yes_invokes_client(arguments: list[str]) -> None:
    client = FakeClient(
        create_result=ShareCreateResult(
            name="media",
            volume="/volume1",
            description="Media files",
            created=True,
            options=ShareCreateOptions(),
            steps=(
                ShareOperationStep(
                    name="create",
                    status=OperationStatus.SUCCEEDED,
                ),
            ),
        )
    )
    factory = CapturingFactory(client)

    result, stdout, stderr = _run(arguments, factory)

    assert result == 0
    assert json.loads(stdout.getvalue()) == {
        "name": "media",
        "volume": "/volume1",
        "description": "Media files",
        "created": True,
        "options": {
            "recycle_bin": {"enabled": True, "admin_only": True},
            "compression_enabled": False,
            "quota_gib": None,
            "quota_api_value": None,
            "quota_api_unit": "MiB",
        },
        "permissions": [],
        "steps": [{"name": "create", "status": "succeeded"}],
    }
    assert stderr.getvalue() == ""
    assert factory.config == ConnectionConfig(
        username="cli-user",
        password="cli-password",
        host="cli-host",
    )
    assert client.create_requests == [
        ShareCreateRequest(
            name="media",
            volume_path="/volume1",
            description="Media files",
        )
    ]


def test_create_share_quota_appears_in_plan() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(
        [
            "create-share",
            "media",
            "--path",
            "/volume1",
            "--quota",
            "100",
            "--output",
            "json",
        ],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue())["options"] == {
        "recycle_bin": {"enabled": True, "admin_only": True},
        "compression_enabled": False,
        "quota_gib": 100,
        "quota_api_value": 102400,
        "quota_api_unit": "MiB",
    }
    assert stderr.getvalue() == ""
    assert factory.config is None


def test_create_share_invalid_quota_returns_validation_error() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(
        ["create-share", "media", "--path", "/volume1", "--quota", "0"],
        factory,
        environment={},
    )

    assert result == 10
    assert stdout.getvalue() == ""
    assert "quota must be" in stderr.getvalue()
    assert factory.config is None


@pytest.mark.parametrize(
    ("flags", "expected_options"),
    [
        (
            ["--disable-recycle-bin"],
            ShareCreateOptions(
                recycle_bin=RecycleBinOptions(enabled=False, admin_only=True)
            ),
        ),
        (
            ["--recycle-bin-user-access"],
            ShareCreateOptions(
                recycle_bin=RecycleBinOptions(enabled=True, admin_only=False)
            ),
        ),
        (["--compress"], ShareCreateOptions(compression_enabled=True)),
    ],
)
def test_create_share_phase_one_plan_overrides(
    flags: list[str],
    expected_options: ShareCreateOptions,
) -> None:
    client = FakeClient()
    factory = CapturingFactory(client)

    result, stdout, stderr = _run(
        ["create-share", "media", "--path", "/volume1", *flags, "--output", "json"],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue())["options"] == {
        "recycle_bin": {
            "enabled": expected_options.recycle_bin.enabled,
            "admin_only": expected_options.recycle_bin.admin_only,
        },
        "compression_enabled": expected_options.compression_enabled,
        "quota_gib": expected_options.quota_gib,
        "quota_api_value": expected_options.quota_api_value,
        "quota_api_unit": "MiB",
    }

    assert stderr.getvalue() == ""
    assert factory.config is None
    assert client.create_requests == []


def test_create_share_rejects_contradictory_recycle_flags() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(
        [
            "create-share",
            "media",
            "--path",
            "/volume1",
            "--disable-recycle-bin",
            "--recycle-bin-user-access",
        ],
        factory,
        environment=FailingEnvironment(),
    )

    assert result == 10
    assert stdout.getvalue() == ""
    assert "cannot be combined" in stderr.getvalue()
    assert factory.config is None


def test_confirmed_create_share_forwards_phase_one_options() -> None:
    options = ShareCreateOptions(
        recycle_bin=RecycleBinOptions(enabled=True, admin_only=False),
        compression_enabled=True,
    )
    client = FakeClient(
        create_result=ShareCreateResult(
            name="media",
            volume="/volume1",
            description="",
            created=True,
            options=options,
            steps=(
                ShareOperationStep(
                    name="create",
                    status=OperationStatus.SUCCEEDED,
                ),
            ),
        )
    )
    factory = CapturingFactory(client)

    result, stdout, stderr = _run(
        [
            "create-share",
            "media",
            "--path",
            "/volume1",
            "--recycle-bin-user-access",
            "--compress",
            "--yes",
            "--output",
            "json",
        ],
        factory,
    )

    assert result == 0
    assert json.loads(stdout.getvalue())["options"] == {
        "recycle_bin": {"enabled": True, "admin_only": False},
        "compression_enabled": True,
        "quota_gib": None,
        "quota_api_value": None,
        "quota_api_unit": "MiB",
    }

    assert stderr.getvalue() == ""
    assert client.create_requests == [
        ShareCreateRequest(
            name="media",
            volume_path="/volume1",
            options=options,
        )
    ]


def test_create_share_requires_path_argument() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(["create-share", "media", "--yes"], factory)

    assert result == 2
    assert stdout.getvalue() == ""
    assert "the following arguments are required: -p/--path" in stderr.getvalue()
    assert factory.config is None


@pytest.mark.parametrize(
    "arguments",
    [
        ["create-share", "bad/name", "--path", "/volume1"],
        ["create-share", "media", "--path", "relative"],
        ["create-share", "media", "-p", "/volume1", "--description", "bad\ntext"],
    ],
)
def test_create_share_invalid_request_returns_validation_error(
    arguments: list[str],
) -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(arguments, factory, environment={})

    assert result == 10
    assert stdout.getvalue() == ""
    assert "error:" in stderr.getvalue()
    assert factory.config is None


def test_create_share_api_failure_uses_api_exit_code() -> None:
    factory = CapturingFactory(FakeClient(create_error=ApiError("create failed")))

    result, stdout, stderr = _run(
        ["create-share", "media", "--path", "/volume1", "--yes"],
        factory,
    )

    assert result == 40
    assert stdout.getvalue() == ""
    assert "error: create failed" in stderr.getvalue()


@pytest.mark.parametrize(
    ("error", "expected_exit"),
    [
        (AuthenticationError("authentication failed"), 20),
        (TransportError("transport failed"), 30),
        (ApiError("api failed"), 40),
        (OutputError("output failed"), 50),
        (RuntimeError("unexpected"), 70),
    ],
)
def test_confirmed_create_share_maps_client_failures_to_exit_codes(
    error: Exception,
    expected_exit: int,
) -> None:
    factory = CapturingFactory(FakeClient(create_error=error))

    result, stdout, stderr = _run(
        ["create-share", "media", "--path", "/volume1", "--yes"],
        factory,
    )

    assert result == expected_exit
    assert stdout.getvalue() == ""
    assert "error:" in stderr.getvalue()


def test_partial_permission_failure_returns_exit_60_with_created_result() -> None:
    permission = PermissionSpec(
        PermissionPrincipalType.LOCAL_USER,
        "alice",
        PermissionAccessMode.READ_WRITE,
    )
    result_data = ShareCreateResult(
        name="projects",
        volume="/volume1",
        description="",
        created=True,
        permissions=(permission,),
        steps=(
            ShareOperationStep(name="create", status=OperationStatus.SUCCEEDED),
            ShareOperationStep(name="permissions", status=OperationStatus.FAILED),
        ),
    )
    factory = CapturingFactory(
        FakeClient(
            create_error=PartialOperationError(
                "share created but permission configuration failed",
                result_data,
            )
        )
    )

    result, stdout, stderr = _run(
        [
            "create-share",
            "projects",
            "--path",
            "/volume1",
            "--permission",
            "local-user:alice:read-write",
            "--yes",
            "--output",
            "json",
        ],
        factory,
    )

    assert result == 60
    assert json.loads(stdout.getvalue())["created"] is True
    assert json.loads(stdout.getvalue())["permissions"] == [
        {
            "principal_type": "local-user",
            "principal_name": "alice",
            "access_mode": "read-write",
        }
    ]
    assert "permission configuration failed" in stderr.getvalue()


def test_environment_fallback_and_structured_stdout_are_clean() -> None:
    factory = CapturingFactory(
        FakeClient((ShareRecord(name="media", volume="/volume1"),))
    )

    result, stdout, stderr = _run(
        ["list-shares", "--verbose", "--output", "json"],
        factory,
    )

    assert result == 0
    assert json.loads(stdout.getvalue()) == [
        {
            "name": "media",
            "volume": "/volume1",
            "description": None,
            "uuid": None,
            "is_usb": None,
            "quota_gib": None,
            "quota_api_value": None,
            "quota_api_unit": "MiB",
        }
    ]
    assert stderr.getvalue() == ""
    assert factory.config == ConnectionConfig(
        username="environment-user",
        password="environment-password",
        host="environment-host",
    )


def test_missing_configuration_fails_before_client_construction() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(["list-shares"], factory, environment={})

    assert result == 10
    assert stdout.getvalue() == ""
    assert "missing required configuration" in stderr.getvalue()
    assert factory.config is None


def test_parser_error_uses_standard_exit_code() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(["list-shares", "--output", "csv"], factory)

    assert result == 2
    assert stdout.getvalue() == ""
    assert "usage: syn-cli" in stderr.getvalue()
    assert "invalid choice" in stderr.getvalue()


def test_insecure_mode_emits_stderr_warning() -> None:
    factory = CapturingFactory(FakeClient())

    result, stdout, stderr = _run(["list-shares", "--insecure"], factory)

    assert result == 0
    assert stdout.getvalue() == "No shares found.\n"
    assert "TLS certificate verification is disabled" in stderr.getvalue()
    assert factory.config is not None
    assert factory.config.insecure is True


@pytest.mark.parametrize(
    ("error", "expected_exit"),
    [
        (AuthenticationError("authentication failed"), 20),
        (TransportError("transport failed"), 30),
        (ApiError("api failed"), 40),
        (OutputError("output failed"), 50),
        (RuntimeError("unexpected"), 70),
    ],
)
def test_client_failures_map_to_stable_exit_codes(
    error: Exception,
    expected_exit: int,
) -> None:
    factory = CapturingFactory(FakeClient(error=error))

    result, stdout, stderr = _run(["list-shares"], factory)

    assert result == expected_exit
    assert stdout.getvalue() == ""
    assert "error:" in stderr.getvalue()
    assert "unexpected" not in stderr.getvalue() or expected_exit == 70


def test_broken_output_returns_output_exit_code() -> None:
    factory = CapturingFactory(FakeClient())
    stderr = StringIO()

    result = run(
        ["list-shares"],
        stdout=BrokenOutput(),
        stderr=stderr,
        environ=_environment(),
        client_factory=factory,
    )

    assert result == 50


@pytest.mark.parametrize(
    ("arguments", "expected_text"),
    [
        (["--help"], "Manage Synology NAS shared folders"),
        (["list-shares", "--help"], "List configured shared folders"),
        (["create-share", "--help"], "--permission"),
        (["create-share", "--help"], "--nfs-permission"),
        (["create-share", "--help"], "local-user:alice:read-write"),
        (["create-share", "--help"], "client=10.192.10.0/24,access=read-write"),
        (["create-share", "--help"], "--yes"),
        (["delete-share", "--help"], "--yes"),
    ],
)
def test_help_contains_descriptions_and_examples(
    arguments: list[str],
    expected_text: str,
) -> None:
    stdout = StringIO()
    stderr = StringIO()
    with contextlib.redirect_stdout(stdout):
        result = run(
            arguments,
            stdout=stdout,
            stderr=stderr,
            environ={},
            client_factory=CapturingFactory(FakeClient()),
        )

    assert result == 0
    assert expected_text in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_package_declares_console_script() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text())

    assert project["project"]["scripts"]["syn-cli"] == "synology.cli:main"
