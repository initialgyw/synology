import contextlib
import json
import logging as stdlib_logging
from io import StringIO

import pytest
import yaml

from synology.cli import run
from synology.config import validate_share_modify_request
from synology.exceptions import (
    ApiError,
    ConfigurationError,
    PartialOperationError,
    PrincipalNotFoundError,
)
from synology.logging import configure_logging
from synology.models import (
    AclPrincipal,
    ConnectionConfig,
    NfsAccessMode,
    NfsClientPermission,
    OperationStatus,
    OutputFormat,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    ShareModifyRequest,
    ShareModifyResult,
    ShareOperationStep,
    ShareQuotaState,
    ShareRecord,
)
from synology.output import render_share_modify
from synology.shares import SynShareClient

PERMISSION_CATEGORIES = (
    "local_user",
    "local_group",
    "ldap_user",
    "ldap_group",
)


class FakeShare:
    def list_folders(self, *, share_type: str, additional: list[str]) -> object:
        raise AssertionError("unexpected share request")

    def create_folder(self, **kwargs: object) -> object:
        raise AssertionError("unexpected share request")

    def delete_folders(self, name: list[str]) -> object:
        raise AssertionError("unexpected share request")


class MutableQuotaShare(FakeShare):
    def __init__(
        self,
        state: dict[str, object],
        *,
        metadata: dict[str, object] | None = None,
        set_response: object = None,
        readback_state: dict[str, object] | None = None,
        readback_response: object | None = None,
    ) -> None:
        self.core_list = {
            "SYNO.Core.Share": (
                {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1}
                if metadata is None
                else metadata
            )
        }
        self.state = state
        self.readback_state = readback_state
        self.readback_response = readback_response
        self.set_response = {"success": True} if set_response is None else set_response
        self.calls: list[tuple[str, str, dict[str, object], str]] = []
        self.reads = 0

    def get_folder(self, name: str, additional: list[str]) -> object:
        self.reads += 1
        if self.reads > 1 and self.readback_response is not None:
            return self.readback_response
        state = (
            self.state
            if self.reads == 1 or self.readback_state is None
            else self.readback_state
        )
        return {"success": True, "data": state}

    def list_folders(self, *, share_type: str, additional: list[str]) -> object:
        state = (
            self.state
            if self.reads <= 1 or self.readback_state is None
            else self.readback_state
        )
        return {"success": True, "data": {"shares": [state]}}

    def request_data(
        self, api_name: str, api_path: str, request: dict[str, object], method: str
    ) -> object:
        self.calls.append((api_name, api_path, request, method))
        if self.set_response == "transport":
            from requests.exceptions import ConnectionError

            raise ConnectionError()
        return self.set_response


class MutablePermissionApi:
    def __init__(
        self,
        entries: dict[str, list[dict[str, object]]],
        *,
        fail_category: str | None = None,
    ) -> None:
        self.entries = {
            category: [dict(item) for item in entries.get(category, [])]
            for category in PERMISSION_CATEGORIES
        }
        self.fail_category = fail_category
        self.set_calls: list[tuple[str, str, list[dict[str, object]]]] = []
        self.get_calls: list[tuple[str, int, int, str]] = []

    def set_folder_permissions(
        self,
        name: str,
        user_group_type: str,
        permissions: list[dict[str, object]],
    ) -> object:
        self.set_calls.append((name, user_group_type, permissions))
        if user_group_type == self.fail_category:
            return {"success": False}
        for permission in permissions:
            principal_name = permission["name"]
            if not isinstance(principal_name, str):
                raise AssertionError("permission name must be a string")
            for index, entry in enumerate(self.entries[user_group_type]):
                if entry.get("name") == principal_name:
                    self.entries[user_group_type][index] = {**entry, **permission}
                    break
            else:
                self.entries[user_group_type].append(
                    {**permission, "is_custom": True, "is_admin": False}
                )
        return {"success": True}

    def get_folder_permissions(
        self,
        name: str,
        offset: int = 0,
        limit: int = 50,
        is_unite_permission: bool = False,
        with_inherit: bool = False,
        user_group_type: str = "local_user",
    ) -> object:
        self.get_calls.append((name, offset, limit, user_group_type))
        entries = self.entries[user_group_type]
        return {
            "success": True,
            "data": {
                "items": entries[offset : offset + limit],
                "total": len(entries),
            },
        }


class UnsuccessfulPermissionApi(MutablePermissionApi):
    def get_folder_permissions(
        self,
        name: str,
        offset: int = 0,
        limit: int = 50,
        is_unite_permission: bool = False,
        with_inherit: bool = False,
        user_group_type: str = "local_user",
    ) -> object:
        return {"success": False}


class MismatchedReadbackPermissionApi(MutablePermissionApi):
    def __init__(
        self,
        entries: dict[str, list[dict[str, object]]],
        readback_entries: dict[str, list[dict[str, object]]],
    ) -> None:
        super().__init__(entries)
        self.readback_entries = readback_entries

    def set_folder_permissions(
        self,
        name: str,
        user_group_type: str,
        permissions: list[dict[str, object]],
    ) -> object:
        response = super().set_folder_permissions(name, user_group_type, permissions)
        if not getattr(self, "writes_completed", False):
            self.entries = {
                category: [
                    dict(item) for item in self.readback_entries.get(category, [])
                ]
                for category in PERMISSION_CATEGORIES
            }
            self.writes_completed = True
        return response


class MutableNfsApi:
    def __init__(
        self,
        rules: list[dict[str, object]],
        *,
        global_enabled: bool = True,
        save_success: bool = True,
        load_success: bool = True,
    ) -> None:
        self.core_list = {
            "SYNO.Core.FileServ.NFS": {"path": "entry.cgi", "maxVersion": 2},
            "SYNO.Core.FileServ.NFS.SharePrivilege": {
                "path": "entry.cgi",
                "maxVersion": 1,
            },
        }
        self.rules = [dict(item) for item in rules]
        self.global_enabled = global_enabled
        self.save_success = save_success
        self.load_success = load_success
        self.calls: list[tuple[str, str, dict[str, object], str]] = []

    def request_data(
        self,
        api_name: str,
        api_path: str,
        request: dict[str, object],
        method: str,
    ) -> object:
        self.calls.append((api_name, api_path, request, method))
        if api_name == "SYNO.Core.FileServ.NFS":
            return {"success": True, "data": {"enable_nfs": self.global_enabled}}
        if request["method"] == "load":
            if not self.load_success:
                return {"success": False}
            return {"success": True, "data": {"rule": self.rules}}
        if not self.save_success:
            return {"success": False}
        encoded_rules = request["rule"]
        if not isinstance(encoded_rules, str):
            raise AssertionError("NFS rules must be serialized")
        parsed_rules = json.loads(encoded_rules)
        if not isinstance(parsed_rules, list):
            raise AssertionError("NFS rules must be a list")
        self.rules = parsed_rules
        return {"success": True}


class CliClient:
    def __init__(
        self,
        *,
        modify_result: ShareModifyResult | None = None,
        modify_error: Exception | None = None,
    ) -> None:
        self.modify_result = modify_result
        self.modify_error = modify_error
        self.modify_requests: list[ShareModifyRequest] = []

    def list_shares(self) -> tuple[ShareRecord, ...]:
        raise AssertionError("unexpected list request")

    def list_share_details(self) -> tuple[object, ...]:
        raise AssertionError("unexpected list request")

    def create_share(self, request: object) -> object:
        raise AssertionError("unexpected create request")

    def delete_share(self, request: object) -> object:
        raise AssertionError("unexpected delete request")

    def modify_share(self, request: ShareModifyRequest) -> ShareModifyResult:
        self.modify_requests.append(request)
        if self.modify_error is not None:
            raise self.modify_error
        if self.modify_result is None:
            raise AssertionError("unexpected modify request")
        return self.modify_result


class CliFactory:
    def __init__(self, client: CliClient) -> None:
        self.client = client
        self.config: ConnectionConfig | None = None

    def __call__(
        self,
        config: ConnectionConfig,
        logger: stdlib_logging.Logger,
    ) -> CliClient:
        self.config = config
        return self.client


class FailingEnvironment(dict[str, str]):
    def get(self, key: str, default: str | None = None) -> str | None:
        raise AssertionError(f"environment access is not allowed: {key}")


def _config() -> ConnectionConfig:
    return ConnectionConfig(
        username="user",
        password="password",
        host="nas.example.test",
    )


def _logger() -> stdlib_logging.Logger:
    return configure_logging(False, stream=StringIO())


def _client(
    *,
    share: FakeShare | None = None,
    permission_api: MutablePermissionApi | None = None,
    nfs_api: MutableNfsApi | None = None,
) -> SynShareClient:
    return SynShareClient(
        _config(),
        _logger(),
        factory=lambda **_: share or FakeShare(),
        permission_factory=(lambda _: permission_api)
        if permission_api is not None
        else None,
        nfs_factory=(lambda _: nfs_api) if nfs_api is not None else None,
    )


def _permission(
    principal_type: PermissionPrincipalType,
    name: str,
    access_mode: PermissionAccessMode,
) -> PermissionSpec:
    return PermissionSpec(principal_type, name, access_mode)


def _permission_entry(
    name: str,
    *,
    deny: bool = False,
    readonly: bool = False,
    writable: bool = False,
) -> dict[str, object]:
    return {
        "name": name,
        "is_deny": deny,
        "is_readonly": readonly,
        "is_writable": writable,
        "is_custom": True,
        "is_admin": False,
    }


def _nfs_rule(permission: NfsClientPermission) -> dict[str, object]:
    return {
        "async": permission.async_enabled,
        "client": permission.client,
        "crossmnt": permission.crossmnt,
        "insecure": permission.insecure,
        "privilege": "rw"
        if permission.access_mode is NfsAccessMode.READ_WRITE
        else "ro",
        "root_squash": permission.root_squash,
        "security_flavor": {
            "sys": permission.security_flavor.sys,
            "kerberos": permission.security_flavor.kerberos,
            "kerberos_integrity": permission.security_flavor.kerberos_integrity,
            "kerberos_privacy": permission.security_flavor.kerberos_privacy,
        },
    }


def _run_cli(
    arguments: list[str],
    factory: CliFactory,
    *,
    environment: dict[str, str] | None = None,
) -> tuple[int, StringIO, StringIO]:
    stdout = StringIO()
    stderr = StringIO()
    result = run(
        arguments,
        stdout=stdout,
        stderr=stderr,
        environ=(
            {
                "SYN_USERNAME": "user",
                "SYN_PASSWORD": "password",
                "SYN_HOST": "nas.example.test",
            }
            if environment is None
            else environment
        ),
        client_factory=factory,
    )
    return result, stdout, stderr


def test_modify_plan_does_not_require_credentials_and_preserves_clear_acl() -> None:
    factory = CliFactory(CliClient())

    result, stdout, stderr = _run_cli(
        ["modify-share", "projects", "--permission", "", "--output", "json"],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue()) == {
        "name": "projects",
        "changed": False,
        "steps": [{"name": "modify", "status": "planned"}],
        "permissions": [],
    }
    assert stderr.getvalue() == ""
    assert factory.config is None


def test_modify_nfs_empty_value_plan_clears_rules_without_credentials() -> None:
    factory = CliFactory(CliClient())

    result, stdout, stderr = _run_cli(
        ["modify-share", "projects", "--nfs-permission", "", "--output", "json"],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue())["nfs_permissions"] == []
    assert stderr.getvalue() == ""
    assert factory.config is None


def test_modify_quota_zero_plan_does_not_require_credentials() -> None:
    factory = CliFactory(CliClient())

    result, stdout, stderr = _run_cli(
        ["modify-share", "projects", "--quota", "0", "--output", "json"],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue())["quota_gib"] == 0
    assert stderr.getvalue() == ""
    assert factory.config is None


def test_confirmed_modify_quota_dispatches_request() -> None:
    client = CliClient(
        modify_result=ShareModifyResult(
            name="projects",
            changed=True,
            quota_gib=5,
            steps=(
                ShareOperationStep(name="quota:set", status=OperationStatus.SUCCEEDED),
            ),
        )
    )
    factory = CliFactory(client)

    result, _, stderr = _run_cli(
        ["modify-share", "projects", "--quota", "5", "--yes"], factory
    )

    assert result == 0
    assert client.modify_requests == [ShareModifyRequest(name="projects", quota_gib=5)]
    assert stderr.getvalue() == ""


def test_modify_acl_plan_reports_unverified_principal_existence() -> None:
    factory = CliFactory(CliClient())

    result, stdout, stderr = _run_cli(
        [
            "modify-share",
            "projects",
            "--permission",
            "ldap-user:Case.Sensitive@example.com:read-only",
            "--output",
            "json",
        ],
        factory,
        environment={},
    )

    assert result == 11
    assert json.loads(stdout.getvalue())["steps"] == [
        {
            "name": "modify",
            "status": "planned",
            "message": "principal existence unverified",
        }
    ]
    assert stderr.getvalue() == ""
    assert factory.config is None


def test_confirmed_modify_acl_returns_principal_not_found_exit_code() -> None:
    error = PrincipalNotFoundError((AclPrincipal("missing@example.com", "ldap_user"),))
    client = CliClient(modify_error=error)
    factory = CliFactory(client)

    result, stdout, stderr = _run_cli(
        [
            "modify-share",
            "projects",
            "--permission",
            "ldap-user:missing@example.com:read-only",
            "--yes",
        ],
        factory,
    )

    assert result == 41
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "error: requested permission principals were not found: "
        "ldap_user:missing@example.com\n"
    )
    assert len(client.modify_requests) == 1


def test_confirmed_modify_acl_forwards_full_replacement_request() -> None:
    permission = _permission(
        PermissionPrincipalType.LOCAL_USER,
        "alice",
        PermissionAccessMode.READ_WRITE,
    )
    client = CliClient(
        modify_result=ShareModifyResult(
            name="projects",
            changed=True,
            permissions=(permission,),
            steps=(
                ShareOperationStep(
                    name="permissions", status=OperationStatus.SUCCEEDED
                ),
            ),
        )
    )
    factory = CliFactory(client)

    result, stdout, stderr = _run_cli(
        [
            "modify-share",
            "projects",
            "--permission",
            "local-user:alice:read-write",
            "--yes",
            "--output",
            "json",
        ],
        factory,
    )

    assert result == 0
    assert client.modify_requests == [
        ShareModifyRequest(name="projects", permissions=(permission,))
    ]
    assert json.loads(stdout.getvalue())["changed"] is True
    assert stderr.getvalue() == ""


def test_confirmed_modify_partial_result_renders_and_returns_exit_60() -> None:
    partial_result = ShareModifyResult(
        name="projects",
        changed=True,
        permissions=(),
        steps=(
            ShareOperationStep(
                name="permissions:local_user",
                status=OperationStatus.SUCCEEDED,
            ),
            ShareOperationStep(
                name="permissions:local_group",
                status=OperationStatus.FAILED,
            ),
        ),
    )
    factory = CliFactory(
        CliClient(
            modify_error=PartialOperationError(
                "share permission modification is uncertain",
                partial_result,
            )
        )
    )

    result, stdout, stderr = _run_cli(
        [
            "modify-share",
            "projects",
            "--permission",
            "",
            "--yes",
            "--output",
            "json",
        ],
        factory,
    )

    assert result == 60
    assert json.loads(stdout.getvalue())["steps"] == [
        {"name": "permissions:local_user", "status": "succeeded"},
        {"name": "permissions:local_group", "status": "failed"},
    ]
    assert "uncertain" in stderr.getvalue()


@pytest.mark.parametrize(
    "arguments",
    [
        ["modify-share", "projects"],
        [
            "modify-share",
            "projects",
            "--permission",
            "",
            "--permission",
            "local-user:alice:read-only",
        ],
        [
            "modify-share",
            "projects",
            "--permission",
            "",
            "--nfs-permission",
            "",
        ],
        ["modify-share", "projects", "--quota", "1", "--quota", "2"],
    ],
)
def test_modify_cli_rejects_invalid_or_mixed_selection(arguments: list[str]) -> None:
    factory = CliFactory(CliClient())

    result, stdout, stderr = _run_cli(arguments, factory, environment={})

    assert result == 10
    assert stdout.getvalue() == ""
    assert "error:" in stderr.getvalue()
    assert factory.config is None


@pytest.mark.parametrize(
    "arguments",
    [
        [
            "modify-share",
            "projects",
            "--permission",
            "",
            "--permission",
            "",
        ],
        [
            "modify-share",
            "projects",
            "--nfs-permission",
            "",
            "--nfs-permission",
            "",
        ],
        [
            "modify-share",
            "projects",
            "--nfs-permission",
            "",
            "--nfs-permission",
            "client=10.0.0.1,access=read-only",
        ],
        ["modify-share", "projects", "--quota", "1", "--permission", ""],
    ],
)
def test_modify_cli_rejects_invalid_empty_value_selection(
    arguments: list[str],
) -> None:
    factory = CliFactory(CliClient())

    result, stdout, stderr = _run_cli(arguments, factory, environment={})

    assert result == 10
    assert stdout.getvalue() == ""
    assert "error:" in stderr.getvalue()
    assert factory.config is None


@pytest.mark.parametrize("option", ["--clear-permissions", "--clear-nfs-permissions"])
def test_modify_cli_rejects_removed_clear_options(option: str) -> None:
    factory = CliFactory(CliClient())

    result, stdout, stderr = _run_cli(
        ["modify-share", "projects", option], factory, environment={}
    )

    assert result == 2
    assert stdout.getvalue() == ""
    assert "unrecognized arguments" in stderr.getvalue()
    assert factory.config is None


def test_modify_help_documents_empty_nfs_permission_clear() -> None:
    stdout = StringIO()
    stderr = StringIO()

    with contextlib.redirect_stdout(stdout):
        result = run(
            ["modify-share", "--help"],
            stdout=stdout,
            stderr=stderr,
            environ={},
            client_factory=CliFactory(CliClient()),
        )

    assert result == 0
    assert "empty value clears" in stdout.getvalue()
    assert "NFS rules" in stdout.getvalue()
    assert stderr.getvalue() == ""


def test_modify_acl_reconciles_all_categories_with_explicit_revocations() -> None:
    permissions = (
        _permission(
            PermissionPrincipalType.LOCAL_USER,
            "alice",
            PermissionAccessMode.READ_WRITE,
        ),
        _permission(
            PermissionPrincipalType.LDAP_GROUP,
            "domain-users",
            PermissionAccessMode.READ_ONLY,
        ),
    )
    api = MutablePermissionApi(
        {
            "local_user": [
                _permission_entry("stale", writable=True),
                _permission_entry("alice"),
            ],
            "local_group": [_permission_entry("developers", readonly=True)],
            "ldap_user": [_permission_entry("uid=stale", readonly=True)],
            "ldap_group": [
                _permission_entry("stale-group", readonly=True),
                _permission_entry("domain-users"),
            ],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=permissions)
    )

    assert result.changed is True
    assert api.set_calls == [
        (
            "projects",
            "local_user",
            [
                {
                    "name": "alice",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": True,
                },
                {
                    "name": "stale",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                },
            ],
        ),
        (
            "projects",
            "local_group",
            [
                {
                    "name": "developers",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                }
            ],
        ),
        (
            "projects",
            "ldap_user",
            [
                {
                    "name": "uid=stale",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                }
            ],
        ),
        (
            "projects",
            "ldap_group",
            [
                {
                    "name": "domain-users",
                    "is_deny": False,
                    "is_readonly": True,
                    "is_writable": False,
                },
                {
                    "name": "stale-group",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                },
            ],
        ),
    ]
    assert [step.name for step in result.steps] == [
        "permissions:local_user",
        "permissions:local_group",
        "permissions:ldap_user",
        "permissions:ldap_group",
        "permissions:verify",
    ]


def test_modify_acl_patch_reconciles_desired_and_stale_ldap_entries() -> None:
    api = MutablePermissionApi(
        {
            "local_user": [
                {
                    **_permission_entry("synadmin", writable=True),
                    "is_custom": False,
                    "is_admin": True,
                }
            ],
            "local_group": [
                {
                    **_permission_entry("administrators", writable=True),
                    "is_custom": False,
                    "is_admin": True,
                }
            ],
            "ldap_user": [
                _permission_entry("konri@jumpcloud.com", writable=True),
                _permission_entry("srvacc"),
            ],
            "ldap_group": [],
        }
    )
    requested = _permission(
        PermissionPrincipalType.LDAP_USER,
        "srvacc",
        PermissionAccessMode.READ_WRITE,
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=(requested,))
    )

    assert result.changed is True
    assert api.set_calls == [
        (
            "projects",
            "ldap_user",
            [
                {
                    "name": "srvacc",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": True,
                },
                {
                    "name": "konri@jumpcloud.com",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                },
            ],
        )
    ]
    assert all(
        entry["is_writable"]
        for category in ("local_user", "local_group")
        for entry in api.entries[category]
    )
    assert result.steps[-1].status is OperationStatus.SUCCEEDED


def test_modify_clear_acl_revokes_admin_users_preserves_admin_groups() -> None:
    api = MutablePermissionApi(
        {
            "local_user": [
                _permission_entry("synadmin", writable=True),
                {**_permission_entry("other-admin", writable=True), "is_admin": True},
            ],
            "local_group": [
                {
                    **_permission_entry("administrators", writable=True),
                    "is_admin": True,
                },
                {**_permission_entry("other-admins", writable=True), "is_admin": True},
            ],
            "ldap_user": [],
            "ldap_group": [],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=(), _acl_clear_mode=True)
    )

    assert result.changed is True
    assert api.set_calls == [
        (
            "projects",
            "local_user",
            [
                {
                    "name": "other-admin",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                },
                {
                    "name": "synadmin",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                },
            ],
        ),
    ]
    assert api.entries["local_group"][0]["is_writable"] is True
    assert api.entries["local_group"][1]["is_writable"] is True


def test_modify_clear_acl_revokes_non_admins_without_empty_payloads() -> None:
    api = MutablePermissionApi(
        {
            "local_user": [
                _permission_entry("alice", writable=True),
                {
                    **_permission_entry("synadmin", writable=True),
                    "is_admin": True,
                },
            ],
            "local_group": [_permission_entry("developers", readonly=True)],
            "ldap_user": [_permission_entry("konri@jumpcloud.com", writable=True)],
            "ldap_group": [_permission_entry("domain-users", deny=True)],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=())
    )

    assert result.changed is True
    assert {category for _, category, _ in api.set_calls} == set(PERMISSION_CATEGORIES)
    assert all(payload for _, _, payload in api.set_calls)
    assert api.entries["local_user"][1]["is_writable"] is True
    assert all(
        not (entry["is_deny"] or entry["is_readonly"] or entry["is_writable"])
        for category in PERMISSION_CATEGORIES
        for entry in api.entries[category]
        if not entry["is_admin"]
    )


def test_modify_acl_cross_category_revocations_skip_no_delta_categories() -> None:
    api = MutablePermissionApi(
        {
            "local_user": [_permission_entry("alice", writable=True)],
            "local_group": [
                {**_permission_entry("administrators", writable=True), "is_admin": True}
            ],
            "ldap_user": [_permission_entry("inventory")],
            "ldap_group": [_permission_entry("domain-users", readonly=True)],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=())
    )

    assert [category for _, category, _ in api.set_calls] == [
        "local_user",
        "ldap_group",
    ]
    assert [(step.name, step.status) for step in result.steps[:4]] == [
        ("permissions:local_user", OperationStatus.SUCCEEDED),
        ("permissions:local_group", OperationStatus.SKIPPED),
        ("permissions:ldap_user", OperationStatus.SKIPPED),
        ("permissions:ldap_group", OperationStatus.SUCCEEDED),
    ]


def test_modify_acl_access_update_does_not_revoke_same_principal() -> None:
    api = MutablePermissionApi(
        {"local_user": [_permission_entry("alice", readonly=True)]}
    )
    requested = _permission(
        PermissionPrincipalType.LOCAL_USER, "alice", PermissionAccessMode.READ_WRITE
    )

    _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=(requested,))
    )

    assert api.set_calls[0][2] == [
        {"name": "alice", "is_deny": False, "is_readonly": False, "is_writable": True}
    ]


def test_modify_acl_all_false_api_error_is_partial() -> None:
    api = MutablePermissionApi(
        {"local_user": [_permission_entry("alice", writable=True)]},
        fail_category="local_user",
    )

    with pytest.raises(PartialOperationError) as error:
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=())
        )

    result = error.value.result
    assert isinstance(result, ShareModifyResult)
    assert result.steps[0].name == "permissions:local_user"
    assert result.steps[0].status is OperationStatus.FAILED
    assert result.steps[0].message == "ACL delta did not complete (desired=0 revoked=1)"


def test_modify_acl_noop_skips_category_writes() -> None:
    permission = _permission(
        PermissionPrincipalType.LOCAL_USER,
        "alice",
        PermissionAccessMode.READ_ONLY,
    )
    api = MutablePermissionApi(
        {
            "local_user": [_permission_entry("alice", readonly=True)],
            "local_group": [],
            "ldap_user": [],
            "ldap_group": [],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=(permission,))
    )

    assert result.changed is False
    assert api.set_calls == []
    assert result.steps[0].status is OperationStatus.SKIPPED


def test_modify_acl_noop_reads_every_permission_page() -> None:
    permissions = tuple(
        _permission(
            PermissionPrincipalType.LOCAL_USER,
            f"user-{index}",
            PermissionAccessMode.READ_ONLY,
        )
        for index in range(51)
    )
    api = MutablePermissionApi(
        {
            "local_user": [
                _permission_entry(f"user-{index}", readonly=True) for index in range(51)
            ],
            "local_group": [],
            "ldap_user": [],
            "ldap_group": [],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=permissions)
    )

    assert result.changed is False
    assert api.set_calls == []
    assert [call[1] for call in api.get_calls if call[3] == "local_user"] == [0, 50]


def test_modify_acl_partial_failure_retains_completed_category_steps() -> None:
    permissions = (
        _permission(
            PermissionPrincipalType.LOCAL_USER,
            "alice",
            PermissionAccessMode.READ_ONLY,
        ),
        _permission(
            PermissionPrincipalType.LDAP_USER,
            "konri@jumpcloud.com",
            PermissionAccessMode.READ_WRITE,
        ),
    )
    api = MutablePermissionApi(
        {
            "local_user": [_permission_entry("alice")],
            "local_group": [],
            "ldap_user": [_permission_entry("konri@jumpcloud.com")],
            "ldap_group": [],
        },
        fail_category="ldap_user",
    )

    with pytest.raises(PartialOperationError) as error:
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=permissions)
        )

    result = error.value.result
    assert isinstance(result, ShareModifyResult)
    assert result.changed is True
    assert [(step.name, step.status) for step in result.steps] == [
        ("permissions:local_user", OperationStatus.SUCCEEDED),
        ("permissions:local_group", OperationStatus.SKIPPED),
        ("permissions:ldap_user", OperationStatus.FAILED),
    ]
    assert result.steps[0].message == "desired=1 revoked=0"
    assert (
        result.steps[-1].message == "ACL delta did not complete (desired=1 revoked=0)"
    )


def test_modify_acl_noncustom_active_ldap_grant_and_protected_admins_are_noop() -> None:
    permission = _permission(
        PermissionPrincipalType.LDAP_USER,
        "konri@jumpcloud.com",
        PermissionAccessMode.READ_WRITE,
    )
    api = MutablePermissionApi(
        {
            "local_user": [
                {
                    **_permission_entry("synadmin", writable=True),
                    "is_custom": False,
                    "is_admin": True,
                }
            ],
            "local_group": [
                {
                    **_permission_entry("administrators", writable=True),
                    "is_custom": False,
                    "is_admin": True,
                }
            ],
            "ldap_user": [
                {
                    **_permission_entry("konri@jumpcloud.com", writable=True),
                    "is_custom": False,
                }
            ],
            "ldap_group": [],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=(permission,))
    )

    assert result.changed is False
    assert api.set_calls == []


def test_modify_acl_ignores_inactive_inventory_rows() -> None:
    permission = _permission(
        PermissionPrincipalType.LDAP_USER,
        "konri@jumpcloud.com",
        PermissionAccessMode.READ_WRITE,
    )
    inventory = {
        "local_user": [{**_permission_entry("guest"), "is_custom": False}],
        "local_group": [{**_permission_entry("users"), "is_custom": False}],
        "ldap_user": [
            {**_permission_entry("unused"), "is_custom": False},
            {
                **_permission_entry("konri@jumpcloud.com", writable=True),
                "is_custom": False,
            },
        ],
        "ldap_group": [{**_permission_entry("all"), "is_custom": False}],
    }
    api = MutablePermissionApi(inventory)

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=(permission,))
    )

    assert result.changed is False
    assert api.set_calls == []


def test_modify_acl_reports_all_missing_principals_before_writes() -> None:
    permissions = (
        _permission(
            PermissionPrincipalType.LOCAL_USER,
            "present",
            PermissionAccessMode.READ_WRITE,
        ),
        _permission(
            PermissionPrincipalType.LDAP_USER,
            "missing@example.com",
            PermissionAccessMode.READ_ONLY,
        ),
        _permission(
            PermissionPrincipalType.LOCAL_GROUP,
            "missing-group",
            PermissionAccessMode.READ_ONLY,
        ),
    )
    api = MutablePermissionApi(
        {
            "local_user": [_permission_entry("present")],
            "local_group": [],
            "ldap_user": [],
            "ldap_group": [],
        }
    )

    with pytest.raises(PrincipalNotFoundError) as error:
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=permissions)
        )

    assert len(error.value.missing) == 2
    assert str(error.value) == (
        "requested permission principals were not found: "
        "ldap_user:missing@example.com, local_group:missing-group"
    )
    assert api.set_calls == []


@pytest.mark.parametrize(
    ("principal_type", "category"),
    [
        (PermissionPrincipalType.LOCAL_USER, "local_group"),
        (PermissionPrincipalType.LOCAL_GROUP, "local_user"),
        (PermissionPrincipalType.LDAP_USER, "ldap_group"),
        (PermissionPrincipalType.LDAP_GROUP, "ldap_user"),
    ],
)
def test_modify_acl_requires_principal_in_exact_category(
    principal_type: PermissionPrincipalType, category: str
) -> None:
    permission = _permission(
        principal_type, "same-name", PermissionAccessMode.READ_ONLY
    )
    api = MutablePermissionApi(
        {
            permission_category: (
                [_permission_entry("same-name")]
                if permission_category == category
                else []
            )
            for permission_category in PERMISSION_CATEGORIES
        }
    )

    with pytest.raises(PrincipalNotFoundError, match="same-name"):
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=(permission,))
        )

    assert api.set_calls == []


def test_modify_acl_inactive_requested_principal_allows_delta() -> None:
    permission = _permission(
        PermissionPrincipalType.LDAP_USER,
        "Case.Sensitive+user@example.com",
        PermissionAccessMode.READ_WRITE,
    )
    api = MutablePermissionApi(
        {
            "local_user": [],
            "local_group": [],
            "ldap_user": [_permission_entry("Case.Sensitive+user@example.com")],
            "ldap_group": [],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=(permission,))
    )

    assert result.changed is True
    assert api.set_calls[0][2][0]["name"] == "Case.Sensitive+user@example.com"


def test_modify_acl_does_not_normalize_ldap_identity() -> None:
    permission = _permission(
        PermissionPrincipalType.LDAP_USER,
        "Case.Sensitive+user@example.com",
        PermissionAccessMode.READ_ONLY,
    )
    api = MutablePermissionApi(
        {
            "local_user": [],
            "local_group": [],
            "ldap_user": [_permission_entry("case.sensitive+user@example.com")],
            "ldap_group": [],
        }
    )

    with pytest.raises(PrincipalNotFoundError, match="Case.Sensitive\\+user"):
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=(permission,))
        )

    assert api.set_calls == []


def test_modify_acl_empty_ldap_inventory_is_principal_not_found() -> None:
    permission = _permission(
        PermissionPrincipalType.LDAP_GROUP,
        "missing-group",
        PermissionAccessMode.READ_ONLY,
    )
    api = MutablePermissionApi({category: [] for category in PERMISSION_CATEGORIES})

    with pytest.raises(PrincipalNotFoundError, match="ldap_group:missing-group"):
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=(permission,))
        )

    assert api.set_calls == []


def test_modify_acl_unsuccessful_inventory_is_api_error_before_writes() -> None:
    api = UnsuccessfulPermissionApi(
        {category: [] for category in PERMISSION_CATEGORIES}
    )

    with pytest.raises(ApiError, match="unsuccessful permission"):
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=())
        )

    assert api.set_calls == []


def test_modify_acl_malformed_inventory_is_api_error_before_writes() -> None:
    api = MutablePermissionApi(
        {
            "local_user": [{"name": "malformed"}],
            "local_group": [],
            "ldap_user": [],
            "ldap_group": [],
        }
    )

    with pytest.raises(ApiError, match="invalid permission response item"):
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=())
        )

    assert api.set_calls == []


def test_modify_acl_duplicate_inactive_inventory_is_api_error_before_writes() -> None:
    api = MutablePermissionApi(
        {
            "local_user": [
                _permission_entry("duplicate"),
                _permission_entry("duplicate"),
            ],
            "local_group": [],
            "ldap_user": [],
            "ldap_group": [],
        }
    )

    with pytest.raises(ApiError, match="duplicate permission inventory principal"):
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=())
        )

    assert api.set_calls == []


def test_modify_acl_unrequested_noncustom_active_entry_is_not_a_noop() -> None:
    permission = _permission(
        PermissionPrincipalType.LDAP_USER,
        "konri@jumpcloud.com",
        PermissionAccessMode.READ_WRITE,
    )
    api = MutablePermissionApi(
        {
            "local_user": [
                {**_permission_entry("stale", readonly=True), "is_custom": False}
            ],
            "local_group": [],
            "ldap_user": [
                {
                    **_permission_entry("konri@jumpcloud.com", writable=True),
                    "is_custom": False,
                }
            ],
            "ldap_group": [],
        }
    )

    result = _client(permission_api=api).modify_share(
        ShareModifyRequest(name="projects", permissions=(permission,))
    )

    assert result.changed is True
    assert api.set_calls == [
        (
            "projects",
            "local_user",
            [
                {
                    "name": "stale",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                }
            ],
        )
    ]


@pytest.mark.parametrize(
    "readback_entries",
    [
        {
            "local_user": [
                {**_permission_entry("stale", readonly=True), "is_custom": False}
            ],
            "local_group": [],
            "ldap_user": [
                {
                    **_permission_entry("konri@jumpcloud.com", writable=True),
                    "is_custom": False,
                }
            ],
            "ldap_group": [],
        },
        {
            "local_user": [],
            "local_group": [],
            "ldap_user": [
                _permission_entry("konri@jumpcloud.com", writable=True),
                _permission_entry("konri@jumpcloud.com", writable=True),
            ],
            "ldap_group": [],
        },
    ],
)
def test_modify_acl_stale_or_duplicate_readback_is_partial(
    readback_entries: dict[str, list[dict[str, object]]],
) -> None:
    permission = _permission(
        PermissionPrincipalType.LDAP_USER,
        "konri@jumpcloud.com",
        PermissionAccessMode.READ_WRITE,
    )
    api = MismatchedReadbackPermissionApi(
        {
            "local_user": [],
            "local_group": [],
            "ldap_user": [_permission_entry("konri@jumpcloud.com")],
            "ldap_group": [],
        },
        readback_entries,
    )

    with pytest.raises(PartialOperationError) as error:
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=(permission,))
        )

    result = error.value.result
    assert isinstance(result, ShareModifyResult)
    assert result.steps[-1].name == "permissions:verify"
    assert result.steps[-1].status is OperationStatus.FAILED
    assert result.steps[-1].message in {
        "ACL replacement verification did not complete",
        "ACL replacement mismatch: local_user has an unrequested active entry",
    }


def test_modify_acl_requested_protected_admin_requires_exact_access() -> None:
    permission = _permission(
        PermissionPrincipalType.LOCAL_USER,
        "synadmin",
        PermissionAccessMode.READ_ONLY,
    )
    readback_entries = {
        "local_user": [
            {
                **_permission_entry("synadmin", writable=True),
                "is_custom": False,
                "is_admin": True,
            }
        ],
        "local_group": [],
        "ldap_user": [],
        "ldap_group": [],
    }
    api = MismatchedReadbackPermissionApi(
        {
            "local_user": [_permission_entry("synadmin")],
            "local_group": [],
            "ldap_user": [],
            "ldap_group": [],
        },
        readback_entries,
    )

    with pytest.raises(PartialOperationError) as error:
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=(permission,))
        )

    result = error.value.result
    assert isinstance(result, ShareModifyResult)
    assert result.steps[-1].message == (
        "ACL replacement mismatch: local_user expected entry has a different "
        "access mode"
    )


def test_modify_acl_contradictory_access_bits_fail_before_write() -> None:
    api = MutablePermissionApi(
        {
            "local_user": [_permission_entry("alice", readonly=True, writable=True)],
            "local_group": [],
            "ldap_user": [],
            "ldap_group": [],
        }
    )

    with pytest.raises(ApiError, match="ambiguous active permission"):
        _client(permission_api=api).modify_share(
            ShareModifyRequest(name="projects", permissions=())
        )

    assert api.set_calls == []


def _quota_state(quota_value: int) -> dict[str, object]:
    return {
        "name": "projects",
        "vol_path": "/volume1",
        "desc": "Project files",
        "hidden": False,
        "enable_share_compress": True,
        "enable_share_cow": False,
        "quota_value": quota_value,
    }


def test_modify_quota_uses_verified_raw_set_payload_and_readback() -> None:
    share = MutableQuotaShare(_quota_state(1024), readback_state=_quota_state(5120))

    result = _client(share=share).modify_share(
        ShareModifyRequest(name="projects", quota_gib=5)
    )

    assert result.changed is True
    assert result.observed_quota is not None
    assert result.observed_quota.api_value == 5120
    assert share.calls == [
        (
            "SYNO.Core.Share",
            "entry.cgi",
            {
                "version": 1,
                "method": "set",
                "name": "projects",
                "shareinfo": json.dumps(
                    {
                        "name": "projects",
                        "vol_path": "/volume1",
                        "desc": "Project files",
                        "hidden": False,
                        "enable_recycle_bin": False,
                        "recycle_bin_admin_only": True,
                        "enable_share_compress": True,
                        "enable_share_cow": False,
                        "share_quota": 5120,
                    },
                    separators=(",", ":"),
                ),
            },
            "post",
        )
    ]
    assert "name_org" not in share.calls[0][2]


def test_modify_quota_zero_sends_unlimited_value() -> None:
    share = MutableQuotaShare(_quota_state(1024), readback_state=_quota_state(0))

    result = _client(share=share).modify_share(
        ShareModifyRequest(name="projects", quota_gib=0)
    )

    assert result.changed is True
    assert result.observed_quota is not None
    assert result.observed_quota.unlimited is True
    assert json.loads(str(share.calls[0][2]["shareinfo"]))["share_quota"] == 0


def test_modify_quota_noop_skips_set() -> None:
    share = MutableQuotaShare(_quota_state(0))

    result = _client(share=share).modify_share(
        ShareModifyRequest(name="projects", quota_gib=0)
    )

    assert result.changed is False
    assert result.observed_quota is not None
    assert result.observed_quota.unlimited is True
    assert share.calls == []


@pytest.mark.parametrize(
    "metadata",
    [{}, {"path": "entry.cgi", "maxVersion": 0}],
)
def test_modify_quota_rejects_incompatible_metadata_before_set(
    metadata: dict[str, object],
) -> None:
    share = MutableQuotaShare(_quota_state(1024), metadata=metadata)

    with pytest.raises(ConfigurationError):
        _client(share=share).modify_share(
            ShareModifyRequest(name="projects", quota_gib=5)
        )

    assert share.calls == []


def test_modify_quota_readback_mismatch_is_partial() -> None:
    share = MutableQuotaShare(_quota_state(1024), readback_state=_quota_state(1024))

    with pytest.raises(PartialOperationError) as error:
        _client(share=share).modify_share(
            ShareModifyRequest(name="projects", quota_gib=5)
        )

    result = error.value.result
    assert isinstance(result, ShareModifyResult)
    assert [(step.name, step.status) for step in result.steps] == [
        ("quota:set", OperationStatus.SUCCEEDED),
        ("quota:verify", OperationStatus.FAILED),
    ]


def test_modify_quota_readback_failure_is_partial() -> None:
    share = MutableQuotaShare(_quota_state(1024), readback_response={"success": False})

    with pytest.raises(PartialOperationError) as error:
        _client(share=share).modify_share(
            ShareModifyRequest(name="projects", quota_gib=5)
        )

    result = error.value.result
    assert isinstance(result, ShareModifyResult)
    assert [(step.name, step.status) for step in result.steps] == [
        ("quota:set", OperationStatus.SUCCEEDED),
        ("quota:verify", OperationStatus.FAILED),
    ]


def test_modify_quota_api_rejection_and_transport_are_distinct() -> None:
    rejected = MutableQuotaShare(_quota_state(1024), set_response={"success": False})
    uncertain = MutableQuotaShare(_quota_state(1024), set_response="transport")

    with pytest.raises(ApiError):
        _client(share=rejected).modify_share(
            ShareModifyRequest(name="projects", quota_gib=5)
        )
    with pytest.raises(PartialOperationError) as partial:
        _client(share=uncertain).modify_share(
            ShareModifyRequest(name="projects", quota_gib=5)
        )

    assert isinstance(partial.value.result, ShareModifyResult)
    assert partial.value.result.steps[0].status is OperationStatus.UNKNOWN


def test_modify_nfs_replaces_complete_rule_list() -> None:
    requested = NfsClientPermission(
        client="10.0.0.10",
        access_mode=NfsAccessMode.READ_ONLY,
    )
    current = NfsClientPermission(
        client="10.0.0.20",
        access_mode=NfsAccessMode.READ_WRITE,
    )
    api = MutableNfsApi([_nfs_rule(current)])

    result = _client(nfs_api=api).modify_share(
        ShareModifyRequest(name="projects", nfs_permissions=(requested,))
    )

    assert result.changed is True
    assert [call[2]["method"] for call in api.calls] == [
        "get",
        "load",
        "save",
        "load",
    ]
    assert api.rules == [_nfs_rule(requested)]
    assert [step.name for step in result.steps] == ["nfs:save", "nfs:verify"]


def test_modify_clear_nfs_replaces_rules_with_empty_list() -> None:
    current = NfsClientPermission(
        client="10.0.0.20",
        access_mode=NfsAccessMode.READ_WRITE,
    )
    api = MutableNfsApi([_nfs_rule(current)])

    result = _client(nfs_api=api).modify_share(
        ShareModifyRequest(name="projects", nfs_permissions=())
    )

    assert result.changed is True
    assert api.rules == []
    save_call = next(call for call in api.calls if call[2]["method"] == "save")
    assert json.loads(str(save_call[2]["rule"])) == []


def test_modify_nfs_noop_skips_save_and_duplicate_readback_is_not_a_noop() -> None:
    requested = NfsClientPermission(
        client="10.0.0.10",
        access_mode=NfsAccessMode.READ_ONLY,
    )
    noop_api = MutableNfsApi([_nfs_rule(requested)])
    duplicate_api = MutableNfsApi([_nfs_rule(requested), _nfs_rule(requested)])

    noop_result = _client(nfs_api=noop_api).modify_share(
        ShareModifyRequest(name="projects", nfs_permissions=(requested,))
    )
    duplicate_result = _client(nfs_api=duplicate_api).modify_share(
        ShareModifyRequest(name="projects", nfs_permissions=(requested,))
    )

    assert noop_result.changed is False
    assert all(call[2]["method"] != "save" for call in noop_api.calls)
    assert duplicate_result.changed is True
    assert sum(call[2]["method"] == "save" for call in duplicate_api.calls) == 1


def test_modify_nfs_requires_global_nfs_and_reports_save_failure_as_partial() -> None:
    requested = NfsClientPermission(
        client="10.0.0.10",
        access_mode=NfsAccessMode.READ_ONLY,
    )
    disabled_api = MutableNfsApi([], global_enabled=False)
    failing_api = MutableNfsApi([], save_success=False)

    with pytest.raises(ConfigurationError, match="global NFS"):
        _client(nfs_api=disabled_api).modify_share(
            ShareModifyRequest(name="projects", nfs_permissions=(requested,))
        )
    with pytest.raises(PartialOperationError) as error:
        _client(nfs_api=failing_api).modify_share(
            ShareModifyRequest(name="projects", nfs_permissions=(requested,))
        )

    result = error.value.result
    assert isinstance(result, ShareModifyResult)
    assert result.steps[0].name == "nfs:save"
    assert result.steps[0].status is OperationStatus.FAILED


def test_modify_output_distinguishes_plans_noops_and_changes() -> None:
    permission = _permission(
        PermissionPrincipalType.LOCAL_USER,
        "alice",
        PermissionAccessMode.READ_ONLY,
    )
    planned = ShareModifyResult(
        name="projects",
        changed=False,
        quota_gib=0,
        steps=(ShareOperationStep(name="modify", status=OperationStatus.PLANNED),),
    )
    noop = ShareModifyResult(
        name="projects",
        changed=False,
        permissions=(),
        steps=(ShareOperationStep(name="permissions", status=OperationStatus.SKIPPED),),
    )
    changed = ShareModifyResult(
        name="projects",
        changed=True,
        permissions=(permission,),
        steps=(
            ShareOperationStep(name="permissions", status=OperationStatus.SUCCEEDED),
        ),
    )

    assert json.loads(render_share_modify(planned, OutputFormat.JSON))["quota_gib"] == 0
    observed = ShareModifyResult(
        name="projects",
        changed=True,
        quota_gib=5,
        observed_quota=ShareQuotaState(5120),
    )
    assert json.loads(render_share_modify(observed, OutputFormat.JSON))[
        "observed_quota"
    ] == {
        "api_value": 5120,
        "api_unit": "MiB",
        "unlimited": False,
        "gib": 5.0,
    }
    assert (
        yaml.safe_load(render_share_modify(observed, OutputFormat.YAML))[
            "observed_quota"
        ]["api_value"]
        == 5120
    )
    assert (
        yaml.safe_load(render_share_modify(noop, OutputFormat.YAML))["permissions"]
        == []
    )
    assert "planned" in render_share_modify(planned, OutputFormat.TABLE)
    assert "no-op" in render_share_modify(noop, OutputFormat.TABLE)
    assert "changed" in render_share_modify(changed, OutputFormat.TABLE)


@pytest.mark.parametrize(
    "modify_request",
    [
        ShareModifyRequest(name="projects"),
        ShareModifyRequest(name="projects", quota_gib=-1),
        ShareModifyRequest(name="projects", quota_gib=1, permissions=()),
        ShareModifyRequest(name="projects", permissions=(), nfs_permissions=()),
    ],
)
def test_modify_request_validation_rejects_invalid_family_selection(
    modify_request: ShareModifyRequest,
) -> None:
    with pytest.raises(ConfigurationError):
        validate_share_modify_request(modify_request)
