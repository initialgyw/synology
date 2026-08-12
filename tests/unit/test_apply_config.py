from io import StringIO
from typing import cast

import pytest

from synology.apply_config import (
    build_apply_plan,
    execute_apply_plan,
    load_apply_config,
)
from synology.cli import run
from synology.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    OutputError,
    PartialOperationError,
    TransportError,
)
from synology.models import (
    AclPermissionRecord,
    EnrichmentStatus,
    NfsAccessMode,
    NfsClientPermission,
    NfsDisplayPermission,
    NfsRootSquash,
    NfsSecurityFlavor,
    OperationStatus,
    ShareDetails,
    ShareRecord,
)


def _config(tmp_path, text: str):
    path = tmp_path / "apply.yaml"
    path.write_text(text)
    return load_apply_config(str(path))


class RecordingClient:
    def __init__(self, shares=(), details=None):
        self.shares = tuple(shares)
        self.details = {} if details is None else details
        self.calls = []

    def list_shares(self):
        self.calls.append("list")
        return self.shares

    def read_apply_details(self, name):
        self.calls.append(f"read:{name}")
        return self.details[name]

    def validate_apply_principals_globally(self, lookup_share, permissions):
        self.calls.append(f"principals:{lookup_share}")

    def preflight_apply_create(self):
        self.calls.append("create-preflight")

    def create_share(self, request):
        self.calls.append(f"create:{request.name}")

    def delete_share(self, request):
        self.calls.append(f"delete:{request.name}")

    def update_complete_share(self, name, description, quota_mib):
        self.calls.append(f"scalar:{name}")

    def replace_apply_acl(self, name, permissions):
        self.calls.append(f"acl:{name}")

    def replace_apply_nfs(self, name, permissions):
        self.calls.append(f"nfs:{name}")


def _details(
    name="projects", *, acl=(), nfs=(), volume="/volume1", quota=0, description=""
):
    return ShareDetails(
        ShareRecord(name, volume, description, quota_api_value=quota),
        acl_permissions=acl,
        nfs_permissions=nfs,
        acl_status=EnrichmentStatus.EMPTY if not acl else EnrichmentStatus.AVAILABLE,
        nfs_status=EnrichmentStatus.EMPTY if not nfs else EnrichmentStatus.AVAILABLE,
    )


def test_strict_schema_duplicate_nested_key_and_nfs_rejection(tmp_path):
    with pytest.raises(ConfigurationError):
        _config(
            tmp_path,
            "version: 1\nvolumes:\n  /volume1:\n    shares: []\n    shares: []\n",
        )
    with pytest.raises(ConfigurationError):
        _config(tmp_path, "version: 1\nvolumes: {}\nunknown: true\n")
    with pytest.raises(ConfigurationError):
        _config(
            tmp_path,
            "version: 1\n"
            "volumes:\n  /volume1:\n    shares:\n      - name: x\n"
            "        nfs:\n          rules:\n            - client_cidr: 10.0.0.0/24\n"
            "              access: read-write\n              root_squash: unsupported\n"
            "              security_flavors: [sys]\n              async: false\n"
            "              insecure: false\n              crossmnt: false\n",
        )


@pytest.mark.parametrize("flavors", ["[kerberos]", "[sys, kerberos]"])
def test_apply_config_rejects_desired_non_sys_security_flavors(tmp_path, flavors):
    with pytest.raises(ConfigurationError, match="security_flavors must be \\[sys\\]"):
        _config(
            tmp_path,
            "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n"
            "        nfs:\n          rules:\n"
            "            - client_cidr: 10.0.0.0/24\n              access: read-write\n"
            "              root_squash: root\n"
            f"              security_flavors: {flavors}\n"
            "              async: false\n              insecure: false\n"
            "              crossmnt: false\n",
        )


def test_apply_config_rejects_noncanonical_desired_nfs_cidr_before_client(tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text(
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n"
        "        nfs:\n          rules:\n"
        "            - client_cidr: 10.192.10.0/2\n              access: read-write\n"
        "              root_squash: root\n              security_flavors: [sys]\n"
        "              async: false\n              insecure: false\n"
        "              crossmnt: false\n"
    )
    called = False

    def factory(config, logger):
        nonlocal called
        called = True
        raise AssertionError("must not construct client")

    assert (
        run(
            ["apply-config", str(path)],
            stdout=StringIO(),
            stderr=StringIO(),
            environ={},
            client_factory=factory,
        )
        == 10
    )
    assert not called


def test_new_share_always_plans_authoritative_empty_acl_and_nfs(tmp_path):
    config = _config(
        tmp_path, "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: new\n"
    )
    client = RecordingClient()
    plan = build_apply_plan(config, client)
    assert [(item.family, item.after) for item in plan.operations] == [
        ("create", "present"),
        ("acl", "clear mutable entries"),
        ("nfs", "clear rules"),
    ]
    assert client.calls == ["list", "create-preflight"]


def test_new_share_acl_principal_lookup_fails_closed_before_writes(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: new\n"
        "        acl:\n          entries:\n            - principal: alice\n"
        "              principal_type: local-user\n"
        "              permissions: read-write\n",
    )
    client = RecordingClient()
    with pytest.raises(ApiError):
        build_apply_plan(config, client)
    assert client.calls == ["list", "create-preflight"]


def test_new_share_acl_uses_explicit_read_only_lookup_before_writes(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nprincipal_lookup_share: lookup\nvolumes:\n  /volume1:\n"
        "    shares:\n      - name: new\n        acl:\n          entries:\n"
        "            - principal: alice\n              principal_type: local-user\n"
        "              permissions: read-write\n",
    )
    client = RecordingClient((ShareRecord("lookup", "/volume1"),))

    plan = build_apply_plan(config, client)

    assert [operation.family for operation in plan.operations] == [
        "create",
        "acl",
        "nfs",
    ]
    assert client.calls == ["list", "create-preflight", "principals:lookup"]


def test_lookup_source_schema_rejects_invalid_and_absent_conflicts(tmp_path):
    with pytest.raises(ConfigurationError):
        _config(tmp_path, "version: 1\nprincipal_lookup_share: '  '\nvolumes: {}\n")
    with pytest.raises(ConfigurationError):
        _config(
            tmp_path,
            "version: 1\nprincipal_lookup_share: retired\nvolumes:\n  /volume1:\n"
            "    shares:\n      - name: retired\n        state: absent\n",
        )
    with pytest.raises(ConfigurationError):
        _config(tmp_path, "version: 1\nlookup: x\nvolumes: {}\n")


def test_acl_category_mapping_and_protected_administrator(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n",
    )
    admin = AclPermissionRecord(
        "administrators", "local_group", False, False, True, False, True
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),), {"projects": _details(acl=(admin,))}
    )
    assert build_apply_plan(config, client).operations == ()
    bad = AclPermissionRecord("x", "unknown", False, True, False, False, False)
    client.details["projects"] = _details(acl=(bad,))
    with pytest.raises(ApiError):
        build_apply_plan(config, client)


def test_all_remote_preflight_precedes_first_write(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n"
        "      - name: a\n      - name: b\n",
    )
    client = RecordingClient()
    plan = build_apply_plan(config, client)
    assert client.calls == ["list", "create-preflight"]
    with pytest.raises(PartialOperationError):
        execute_apply_plan(plan, client)
    assert client.calls[:2] == ["list", "create-preflight"]


def test_apply_readback_mismatch_is_partial(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n",
    )
    mutable = AclPermissionRecord(
        "alice", "local_user", False, True, False, False, False
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),), {"projects": _details(acl=(mutable,))}
    )
    plan = build_apply_plan(config, client)
    with pytest.raises(PartialOperationError) as error:
        execute_apply_plan(plan, client)
    result = error.value.result
    assert result.operations[0].status is OperationStatus.UNKNOWN
    assert "acl:projects" in client.calls


def test_later_remote_preflight_failure_prevents_all_writes(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n"
        "      - name: a\n      - name: z\n",
    )

    class FailingClient(RecordingClient):
        def read_apply_details(self, name):
            super().read_apply_details(name)
            if name == "z":
                raise ApiError("later target response is malformed")
            return self.details[name]

    client = FailingClient(
        (ShareRecord("a", "/volume1"), ShareRecord("z", "/volume1")),
        {"a": _details("a"), "z": _details("z")},
    )
    with pytest.raises(ApiError):
        build_apply_plan(config, client)
    assert not any(
        call.split(":")[0] in {"create", "scalar", "acl", "nfs", "delete"}
        for call in client.calls
    )


def test_live_kerberos_nfs_state_fails_closed_before_apply_writes(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n",
    )
    live_rule = NfsClientPermission(
        "10.0.0.0/24",
        NfsAccessMode.READ_WRITE,
        security_flavor=NfsSecurityFlavor(sys=False, kerberos=True),
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),),
        {"projects": _details(nfs=(live_rule,))},
    )

    with pytest.raises(ApiError, match="unsupported NFS security flavor"):
        build_apply_plan(config, client)

    assert client.calls == ["list", "read:projects"]


def test_cli_dry_run_reads_without_writes_and_redacts_secret(tmp_path):
    path = tmp_path / "apply.yaml"
    path.write_text("version: 1\nhost: selected.example\nvolumes: {}\n")
    client = RecordingClient()
    stdout, stderr = StringIO(), StringIO()
    assert (
        run(
            ["apply-config", str(path)],
            stdout=stdout,
            stderr=stderr,
            environ={"SYN_USERNAME": "user", "SYN_PASSWORD": "secret"},
            client_factory=lambda config, logger: client,
        )
        == 0
    )
    assert client.calls == ["list"]
    assert "selected.example" in stdout.getvalue()
    assert "secret" not in stdout.getvalue()


def test_cli_partial_output_uses_resolved_host(tmp_path):
    path = tmp_path / "apply.yaml"
    path.write_text(
        "version: 1\nhost: selected.example\nvolumes:\n  /volume1:\n"
        "    shares:\n      - name: projects\n"
    )
    mutable = AclPermissionRecord(
        "alice", "local_user", False, True, False, False, False
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),),
        {"projects": _details(acl=(mutable,))},
    )
    stdout, stderr = StringIO(), StringIO()
    assert (
        run(
            ["apply-config", str(path), "--yes"],
            stdout=stdout,
            stderr=stderr,
            environ={"SYN_USERNAME": "user", "SYN_PASSWORD": "secret"},
            client_factory=lambda config, logger: client,
        )
        == 60
    )
    assert "selected.example" in stdout.getvalue()
    assert "secret" not in stdout.getvalue()


def test_duplicate_live_acl_grant_never_compares_equal(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n"
        "      - name: projects\n        acl:\n          entries:\n"
        "            - principal: alice\n              principal_type: local-user\n"
        "              permissions: read-only\n",
    )
    duplicate = AclPermissionRecord(
        "alice", "local_user", False, True, False, False, False
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),),
        {"projects": _details(acl=(duplicate, duplicate))},
    )
    with pytest.raises(ApiError):
        build_apply_plan(config, client)
    assert not any(
        call.split(":")[0] in {"create", "scalar", "acl", "nfs", "delete"}
        for call in client.calls
    )


def test_duplicate_protected_administrator_inventory_fails_before_writes(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n",
    )
    administrator = AclPermissionRecord(
        "administrators", "local_group", False, False, True, False, True
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),),
        {"projects": _details(acl=(administrator, administrator))},
    )
    with pytest.raises(ApiError):
        build_apply_plan(config, client)
    assert not any(
        call.split(":")[0] in {"create", "scalar", "acl", "nfs", "delete"}
        for call in client.calls
    )


def test_new_share_acl_readback_requires_protected_administrators_grant(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: new\n",
    )
    mutable = AclPermissionRecord(
        "alice", "local_user", False, True, False, False, False
    )
    client = RecordingClient(details={"new": _details("new", acl=(mutable,))})

    with pytest.raises(PartialOperationError):
        execute_apply_plan(build_apply_plan(config, client), client)


def test_duplicate_live_share_names_fail_before_reads_or_writes(tmp_path):
    config = _config(tmp_path, "version: 1\nvolumes: {}\n")
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"), ShareRecord("projects", "/volume1"))
    )

    with pytest.raises(ApiError, match="duplicate live share"):
        build_apply_plan(config, client)
    assert client.calls == ["list"]


@pytest.mark.parametrize(
    ("is_deny", "is_readonly", "is_writable"),
    [(False, False, False), (True, True, False), (True, False, True)],
)
def test_ambiguous_live_acl_flags_fail_closed(
    tmp_path, is_deny, is_readonly, is_writable
):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n",
    )
    ambiguous = AclPermissionRecord(
        "alice", "local_user", is_deny, is_readonly, is_writable, False, False
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),),
        {"projects": _details(acl=(ambiguous,))},
    )

    with pytest.raises(ApiError, match="ambiguous ACL permission flags"):
        build_apply_plan(config, client)


def test_cli_dry_run_mixed_plan_never_calls_mutations(tmp_path):
    path = tmp_path / "apply.yaml"
    path.write_text(
        "version: 1\nhost: selected.example\nvolumes:\n  /volume1:\n    shares:\n"
        "      - name: existing\n        description: desired\n        quota: 2\n"
        "      - name: new\n      - name: retired\n        state: absent\n"
    )
    live_nfs = NfsClientPermission("10.0.0.0/24", NfsAccessMode.READ_WRITE)
    client = RecordingClient(
        (ShareRecord("existing", "/volume1"), ShareRecord("retired", "/volume1")),
        {
            "existing": _details(
                "existing", description="old", quota=1024, nfs=(live_nfs,)
            )
        },
    )
    stdout, stderr = StringIO(), StringIO()
    assert (
        run(
            ["apply-config", str(path)],
            stdout=stdout,
            stderr=stderr,
            environ={"SYN_USERNAME": "user", "SYN_PASSWORD": "secret"},
            client_factory=lambda config, logger: client,
        )
        == 0
    )
    assert "read:existing" in client.calls
    assert "create-preflight" in client.calls
    assert not any(
        call.split(":")[0] in {"create", "scalar", "acl", "nfs", "delete"}
        for call in client.calls
    )


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (AuthenticationError("x"), 20),
        (TransportError("x"), 30),
        (ApiError("x"), 40),
        (OutputError("x"), 50),
        (RuntimeError("x"), 70),
    ],
)
def test_cli_apply_preflight_error_mappings(tmp_path, error, code):
    path = tmp_path / "apply.yaml"
    path.write_text("version: 1\nhost: selected.example\nvolumes: {}\n")

    class FailingClient(RecordingClient):
        def list_shares(self):
            raise error

    stdout, stderr = StringIO(), StringIO()
    assert (
        run(
            ["apply-config", str(path)],
            stdout=stdout,
            stderr=stderr,
            environ={"SYN_USERNAME": "user", "SYN_PASSWORD": "secret"},
            client_factory=lambda config, logger: FailingClient(),
        )
        == code
    )


def test_cli_static_validation_precedes_environment_and_client(tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text("version: 2\nvolumes: {}\n")
    called = False

    def factory(config, logger):
        nonlocal called
        called = True
        raise AssertionError("must not construct client")

    stdout, stderr = StringIO(), StringIO()
    assert (
        run(
            ["apply-config", str(path)],
            stdout=stdout,
            stderr=stderr,
            environ={},
            client_factory=factory,
        )
        == 10
    )
    assert not called


@pytest.mark.parametrize("root_squash", list(NfsRootSquash))
def test_apply_nfs_parser_accepts_exact_dsm_root_squash_tokens(tmp_path, root_squash):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n"
        "        nfs:\n          rules:\n"
        "            - client_cidr: 10.0.0.0/24\n              access: read-write\n"
        f"              root_squash: {root_squash.value}\n"
        "              security_flavors: [sys]\n              async: false\n"
        "              insecure: false\n              crossmnt: false\n",
    )

    assert config.shares[0].nfs[0].root_squash is root_squash


@pytest.mark.parametrize(
    "root_squash",
    ["no_root_squash", "none", "all_squash", "map_root", "ROOT", "Admin", "unknown"],
)
def test_apply_nfs_parser_rejects_unverified_root_squash_before_client(
    tmp_path, root_squash
):
    path = tmp_path / "invalid.yaml"
    path.write_text(
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n"
        "        nfs:\n          rules:\n"
        "            - client_cidr: 10.0.0.0/24\n              access: read-write\n"
        f"              root_squash: {root_squash}\n"
        "              security_flavors: [sys]\n"
        "              async: false\n              insecure: false\n"
        "              crossmnt: false\n"
    )
    called = False

    def factory(config, logger):
        nonlocal called
        called = True
        raise AssertionError("must not construct client")

    assert (
        run(
            ["apply-config", str(path)],
            stdout=StringIO(),
            stderr=StringIO(),
            environ={},
            client_factory=factory,
        )
        == 10
    )
    assert not called


def test_apply_config_unknown_live_root_squash_returns_40_before_writes(tmp_path):
    path = tmp_path / "apply.yaml"
    path.write_text(
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n"
    )
    malformed_rule = NfsClientPermission(
        "10.0.0.0/24",
        NfsAccessMode.READ_WRITE,
        root_squash=cast(NfsRootSquash, "no_root_squash"),
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),),
        {"projects": _details(nfs=(malformed_rule,))},
    )
    stdout, stderr = StringIO(), StringIO()

    result = run(
        ["apply-config", str(path), "--yes"],
        stdout=stdout,
        stderr=stderr,
        environ={
            "SYN_USERNAME": "user",
            "SYN_PASSWORD": "secret",
            "SYN_HOST": "nas.example.test",
        },
        client_factory=lambda config, logger: client,
    )

    assert result == 40
    assert stdout.getvalue() == ""
    assert "invalid NFS root_squash" in stderr.getvalue()
    assert client.calls == ["list", "read:projects"]


@pytest.mark.parametrize("nfs", ["", "        nfs:\n          rules: []\n"])
def test_apply_config_invalid_live_nfs_client_fails_closed_before_writes(tmp_path, nfs):
    path = tmp_path / "apply.yaml"
    path.write_text(
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n" + nfs
    )
    malformed = NfsDisplayPermission("10.192.10.0/2", NfsAccessMode.READ_WRITE)
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),),
        {
            "projects": ShareDetails(
                ShareRecord("projects", "/volume1"),
                nfs_status=EnrichmentStatus.AVAILABLE,
                nfs_display_permissions=(malformed,),
            )
        },
    )

    result = run(
        ["apply-config", str(path), "--yes"],
        stdout=StringIO(),
        stderr=StringIO(),
        environ={
            "SYN_USERNAME": "user",
            "SYN_PASSWORD": "secret",
            "SYN_HOST": "nas.example.test",
        },
        client_factory=lambda config, logger: client,
    )

    assert result == 40
    assert client.calls == ["list", "read:projects"]
    assert not any(
        call.split(":")[0] in {"create", "scalar", "acl", "nfs", "delete"}
        for call in client.calls
    )


def test_root_squash_only_drift_plans_replacement_and_readback_is_partial(tmp_path):
    config = _config(
        tmp_path,
        "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n"
        "        nfs:\n          rules:\n"
        "            - client_cidr: 10.0.0.0/24\n              access: read-write\n"
        "              root_squash: guest\n              security_flavors: [sys]\n"
        "              async: false\n              insecure: false\n"
        "              crossmnt: false\n",
    )
    live_rule = NfsClientPermission("10.0.0.0/24", NfsAccessMode.READ_WRITE)
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),), {"projects": _details(nfs=(live_rule,))}
    )

    plan = build_apply_plan(config, client)
    assert [(item.family, item.after) for item in plan.operations] == [
        ("nfs", "10.0.0.0/24:read-write:root_squash=guest")
    ]
    with pytest.raises(PartialOperationError) as error:
        execute_apply_plan(plan, client)
    assert error.value.result.operations[0].status is OperationStatus.UNKNOWN


@pytest.mark.parametrize(("confirm", "expected_code"), [(False, 0), (True, 60)])
@pytest.mark.parametrize(
    ("root_squash", "warning"),
    [
        ("guest", "root_squash=guest (Map root to guest)"),
        ("admin", "root_squash=admin (Map root to admin) is a privileged"),
        ("all_admin", "root_squash=all_admin (Map all users to admin) is a privileged"),
        ("all_guest", "root_squash=all_guest (Map all users to guest)"),
    ],
)
def test_apply_root_squash_warning_is_rendered_and_secret_safe(
    tmp_path, confirm, expected_code, root_squash, warning
):
    path = tmp_path / "apply.yaml"
    path.write_text(
        "version: 1\nhost: selected.example\nvolumes:\n  /volume1:\n    shares:\n"
        "      - name: projects\n        nfs:\n          rules:\n"
        "            - client_cidr: 10.0.0.0/24\n              access: read-write\n"
        f"              root_squash: {root_squash}\n"
        "              security_flavors: [sys]\n              async: false\n"
        "              insecure: false\n              crossmnt: false\n"
    )
    client = RecordingClient(
        (ShareRecord("projects", "/volume1"),), {"projects": _details()}
    )
    stdout, stderr = StringIO(), StringIO()

    assert (
        run(
            ["apply-config", str(path), *(["--yes"] if confirm else [])],
            stdout=stdout,
            stderr=stderr,
            environ={"SYN_USERNAME": "user", "SYN_PASSWORD": "secret"},
            client_factory=lambda config, logger: client,
        )
        == expected_code
    )
    assert f"WARNING: {warning}" in stdout.getvalue()
    assert warning in stderr.getvalue()
    assert "secret" not in stdout.getvalue()
    assert "secret" not in stderr.getvalue()


@pytest.mark.parametrize(
    "root_squash_line",
    ["root_squash: no_root_squash", "root_squash: none", "root_squash: 1", ""],
)
def test_apply_nfs_parser_rejects_missing_or_invalid_root_squash(
    tmp_path, root_squash_line
):
    with pytest.raises(ConfigurationError):
        _config(
            tmp_path,
            "version: 1\nvolumes:\n  /volume1:\n    shares:\n      - name: projects\n"
            "        nfs:\n          rules:\n"
            "            - client_cidr: 10.0.0.0/24\n              access: read-write\n"
            f"              {root_squash_line}\n"
            "              security_flavors: [sys]\n              async: false\n"
            "              insecure: false\n              crossmnt: false\n",
        )
