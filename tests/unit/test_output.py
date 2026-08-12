import json

import pytest
import yaml

from synology.apply_config import ApplyConfig, ApplyOperation, ApplyPlan, ApplyShare
from synology.models import (
    AclPermissionRecord,
    EnrichmentStatus,
    NfsAccessMode,
    NfsClientPermission,
    NfsDisplayPermission,
    NfsRootSquash,
    NfsSecurityFlavor,
    OperationStatus,
    OutputFormat,
    RecycleBinOptions,
    ShareCreateOptions,
    ShareCreateResult,
    ShareDetails,
    ShareOperationStep,
    ShareRecord,
)
from synology.output import (
    apply_plan_warnings,
    render_share_create,
    render_share_details,
    render_shares,
)


def test_apply_plan_warnings_use_desired_nfs_models_not_operation_text() -> None:
    guest_rule = NfsClientPermission(
        "10.192.10.0/24", NfsAccessMode.READ_WRITE, root_squash=NfsRootSquash.GUEST
    )
    admin_rule = NfsClientPermission(
        "10.192.10.1", NfsAccessMode.READ_WRITE, root_squash=NfsRootSquash.ADMIN
    )
    plan = ApplyPlan(
        ApplyConfig(
            host=None,
            principal_lookup_share=None,
            shares=(
                ApplyShare("projects", "/volume1", "present", "", 0, (), (guest_rule,)),
                ApplyShare(
                    "unmanaged", "/volume1", "present", "", 0, (), (admin_rule,)
                ),
            ),
        ),
        (ApplyOperation("projects", "nfs", "before", "formatted differently"),),
    )

    assert apply_plan_warnings(plan) == [
        "root_squash=guest (Map root to guest) changes root-originated identity "
        "mapping; review before applying"
    ]


def test_table_uses_approved_identity_columns() -> None:
    rendered = render_shares(
        (
            ShareRecord(
                name="media",
                volume="/volume1",
                description="Media files",
                uuid="share-uuid",
                is_usb=False,
                quota_gib=5,
                quota_api_value=5120,
            ),
        ),
        OutputFormat.TABLE,
    )

    header, divider, row = rendered.splitlines()

    assert header.split() == [
        "NAME",
        "VOLUME",
        "DESCRIPTION",
        "USB",
        "QUOTA_GIB",
    ]
    assert set(divider.replace(" ", "")) == {"-"}
    assert "media" in row
    assert "/volume1" in row
    assert "Media files" in row
    assert "share-uuid" not in row
    assert "false" in row
    assert "5" in row


def test_detail_table_renders_multiline_custom_permissions_and_nfs() -> None:
    details = (
        ShareDetails(
            share=ShareRecord(name="projects", volume="/volume1"),
            acl_permissions=(
                AclPermissionRecord(
                    name="alice",
                    category="local_user",
                    is_deny=False,
                    is_readonly=False,
                    is_writable=True,
                    is_custom=True,
                    is_admin=False,
                ),
                AclPermissionRecord(
                    name="developers",
                    category="local_group",
                    is_deny=False,
                    is_readonly=True,
                    is_writable=False,
                    is_custom=True,
                    is_admin=False,
                ),
            ),
            nfs_permissions=(
                NfsClientPermission(
                    client="10.192.10.0/24",
                    access_mode=NfsAccessMode.READ_WRITE,
                ),
            ),
            acl_status=EnrichmentStatus.AVAILABLE,
            nfs_status=EnrichmentStatus.AVAILABLE,
        ),
    )

    rendered = render_share_details(details, OutputFormat.TABLE)

    assert "PERMISSION" in rendered
    assert "NFS-PERMISSIONS" in rendered
    assert "local_user:alice:read-write" in rendered
    assert "local_group:developers:read-only" in rendered
    assert "10.192.10.0/24:read-write" in rendered
    assert rendered.count("projects") == 1


def test_detail_json_includes_complete_nfs_security_flavor() -> None:
    details = (
        ShareDetails(
            share=ShareRecord(name="projects", volume="/volume1"),
            nfs_permissions=(
                NfsClientPermission(
                    client="10.192.10.0/24",
                    access_mode=NfsAccessMode.READ_WRITE,
                    security_flavor=NfsSecurityFlavor(
                        sys=False,
                        kerberos=True,
                        kerberos_integrity=True,
                        kerberos_privacy=False,
                    ),
                ),
            ),
            nfs_status=EnrichmentStatus.AVAILABLE,
        ),
    )
    rendered = json.loads(render_share_details(details, OutputFormat.JSON))
    assert rendered[0]["nfs_permissions"][0]["security_flavor"] == {
        "sys": False,
        "kerberos": True,
        "kerberos_integrity": True,
        "kerberos_privacy": False,
    }


def test_detail_table_renders_enabled_security_flavors_or_empty_list() -> None:
    detail = ShareDetails(
        share=ShareRecord(name="projects"),
        nfs_permissions=(
            NfsClientPermission(
                "10.192.10.1",
                NfsAccessMode.READ_WRITE,
                security_flavor=NfsSecurityFlavor(
                    sys=True,
                    kerberos=True,
                    kerberos_integrity=True,
                    kerberos_privacy=True,
                ),
            ),
            NfsClientPermission(
                "10.192.10.2",
                NfsAccessMode.READ_WRITE,
                security_flavor=NfsSecurityFlavor(
                    sys=False,
                    kerberos=False,
                    kerberos_integrity=False,
                    kerberos_privacy=False,
                ),
            ),
        ),
        nfs_status=EnrichmentStatus.AVAILABLE,
    )

    rendered = render_share_details((detail,), OutputFormat.TABLE)

    assert (
        "security_flavors=[sys,kerberos,kerberos_integrity,kerberos_privacy]"
        in rendered
    )
    assert "security_flavors=[]" in rendered


def test_detail_output_preserves_malformed_nfs_clients_without_internal_field() -> None:
    details = (
        ShareDetails(
            share=ShareRecord(name="projects", volume="/volume1"),
            nfs_permissions=(
                NfsClientPermission("10.192.10.0/24", NfsAccessMode.READ_ONLY),
            ),
            nfs_display_permissions=(
                NfsClientPermission("10.192.10.0/24", NfsAccessMode.READ_ONLY),
                NfsDisplayPermission("10.192.10.0/2", NfsAccessMode.READ_WRITE),
            ),
            nfs_status=EnrichmentStatus.AVAILABLE,
        ),
    )

    table = render_share_details(details, OutputFormat.TABLE)
    structured = json.loads(render_share_details(details, OutputFormat.JSON))

    assert "10.192.10.0/24:read-only" in table
    assert "10.192.10.0/2:read-write" in table
    assert "INVALID CIDR" not in table
    assert structured[0]["nfs_permissions"] == [
        {
            "client": "10.192.10.0/2",
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
        },
        {
            "client": "10.192.10.0/24",
            "access": "read-only",
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
        },
    ]
    assert "nfs_rule_observations" not in structured[0]


def test_detail_output_hides_only_protected_administrator_acl() -> None:
    protected = AclPermissionRecord(
        "administrators", "local_group", False, False, True, False, True
    )
    visible = AclPermissionRecord(
        "developers", "local_group", False, True, False, True, False
    )
    administrator_read_only = AclPermissionRecord(
        "administrators", "local_group", False, True, False, True, False
    )
    administrator_deny = AclPermissionRecord(
        "administrators", "local_group", True, False, False, True, False
    )
    protected_only = ShareDetails(
        share=ShareRecord(name="protected-only"),
        acl_permissions=(protected,),
        acl_status=EnrichmentStatus.AVAILABLE,
    )
    mixed = ShareDetails(
        share=ShareRecord(name="mixed"),
        acl_permissions=(
            visible,
            protected,
            administrator_read_only,
            administrator_deny,
        ),
        acl_status=EnrichmentStatus.AVAILABLE,
    )

    table = render_share_details((protected_only, mixed), OutputFormat.TABLE)
    json_value = json.loads(
        render_share_details((protected_only, mixed), OutputFormat.JSON)
    )
    yaml_value = yaml.safe_load(
        render_share_details((protected_only, mixed), OutputFormat.YAML)
    )

    protected_row = next(
        line for line in table.splitlines() if "protected-only" in line
    )
    assert protected_row.split() == ["protected-only", "-", "-", "-", "-", "-", "-"]
    assert "developers:read-only" in table
    assert "administrators:read-only" in table
    assert "administrators:deny" in table
    assert "administrators:read-write" not in table
    assert json_value[0]["permissions"] == []
    assert [
        (item["name"], item["is_deny"], item["is_readonly"], item["is_writable"])
        for item in json_value[1]["permissions"]
    ] == [
        ("administrators", True, False, False),
        ("administrators", False, True, False),
        ("developers", False, True, False),
    ]
    assert yaml_value == json_value


def test_detail_table_displays_complete_nfs_rules_in_deterministic_order() -> None:
    permissions = tuple(
        NfsClientPermission(
            client=f"10.192.10.{5 - index}",
            access_mode=NfsAccessMode.READ_WRITE,
            async_enabled=index % 2 == 0,
            insecure=index % 2 == 1,
            crossmnt=index % 2 == 0,
            root_squash=root_squash,
        )
        for index, root_squash in enumerate(NfsRootSquash)
    )
    detail = ShareDetails(
        share=ShareRecord(name="projects"),
        nfs_permissions=permissions,
        nfs_status=EnrichmentStatus.AVAILABLE,
    )

    table = render_share_details((detail,), OutputFormat.TABLE)
    structured = json.loads(render_share_details((detail,), OutputFormat.JSON))

    assert (
        "squash=root,security_flavors=[sys],async=true,insecure=false,crossmnt=true"
        in table
    )
    assert (
        "squash=admin,security_flavors=[sys],async=false,insecure=true,crossmnt=false"
        in table
    )
    assert "squash=guest" in table
    assert "squash=all_admin" in table
    assert "squash=all_guest" in table
    assert [item["client"] for item in structured[0]["nfs_permissions"]] == sorted(
        item.client for item in permissions
    )
    assert all(
        item["security_flavor"]
        == {
            "sys": True,
            "kerberos": False,
            "kerberos_integrity": False,
            "kerberos_privacy": False,
        }
        for item in structured[0]["nfs_permissions"]
    )
    assert "nfs_rule_observations" not in structured[0]


def test_detail_nfs_sorting_is_identity_first_then_full_rule() -> None:
    detail = ShareDetails(
        share=ShareRecord(name="projects"),
        nfs_permissions=(
            NfsClientPermission(
                "10.192.10.10",
                NfsAccessMode.READ_WRITE,
                async_enabled=True,
                root_squash=NfsRootSquash.GUEST,
            ),
            NfsClientPermission(
                "10.192.10.10",
                NfsAccessMode.READ_WRITE,
                async_enabled=False,
                root_squash=NfsRootSquash.GUEST,
            ),
            NfsClientPermission(
                "10.192.10.10",
                NfsAccessMode.READ_WRITE,
                root_squash=NfsRootSquash.ADMIN,
            ),
        ),
        nfs_status=EnrichmentStatus.AVAILABLE,
    )

    rendered = json.loads(render_share_details((detail,), OutputFormat.JSON))

    assert [item["root_squash"] for item in rendered[0]["nfs_permissions"]] == [
        "admin",
        "guest",
        "guest",
    ]
    assert [item["async"] for item in rendered[0]["nfs_permissions"]] == [
        False,
        False,
        True,
    ]


def test_detail_output_distinguishes_unavailable_nfs_from_known_empty() -> None:
    unavailable = ShareDetails(
        share=ShareRecord(name="unavailable"),
        nfs_status=EnrichmentStatus.UNAVAILABLE,
    )
    empty = ShareDetails(
        share=ShareRecord(name="empty"),
        nfs_status=EnrichmentStatus.EMPTY,
    )

    table = render_share_details((unavailable, empty), OutputFormat.TABLE)
    json_value = json.loads(
        render_share_details((unavailable, empty), OutputFormat.JSON)
    )
    yaml_value = yaml.safe_load(
        render_share_details((unavailable, empty), OutputFormat.YAML)
    )

    assert "?" in table
    assert [item["nfs_permissions"] for item in json_value] == [None, []]
    assert yaml_value == json_value


def test_detail_table_renders_effective_admin_permission() -> None:
    detail = ShareDetails(
        share=ShareRecord(name="test14"),
        acl_permissions=(
            AclPermissionRecord(
                name="synadmin",
                category="local_user",
                is_deny=False,
                is_readonly=False,
                is_writable=True,
                is_custom=False,
                is_admin=True,
            ),
        ),
        acl_status=EnrichmentStatus.AVAILABLE,
        nfs_status=EnrichmentStatus.EMPTY,
    )

    rendered = render_share_details((detail,), OutputFormat.TABLE)

    assert "local_user:synadmin:read-write" in rendered


def test_table_renders_fractional_quota() -> None:
    rendered = render_shares(
        (ShareRecord(name="legacy", quota_gib=5 / 1024, quota_api_value=5),),
        OutputFormat.TABLE,
    )

    assert "0.004883" in rendered


def test_table_renders_missing_values_and_empty_results() -> None:
    rendered = render_shares((ShareRecord(name="empty"),), OutputFormat.TABLE)

    assert "empty" in rendered
    assert rendered.count("-") >= 5
    assert render_shares((), OutputFormat.TABLE) == "No shares found."


def test_json_and_yaml_represent_equivalent_records() -> None:
    shares = (
        ShareRecord(
            name="données",
            volume="/volume1",
            description=None,
            uuid="share-uuid",
            is_usb=True,
        ),
    )

    json_value = json.loads(render_shares(shares, OutputFormat.JSON))
    yaml_value = yaml.safe_load(render_shares(shares, OutputFormat.YAML))

    assert json_value == yaml_value
    assert json_value == [
        {
            "name": "données",
            "volume": "/volume1",
            "description": None,
            "uuid": "share-uuid",
            "is_usb": True,
            "quota_gib": None,
            "quota_api_value": None,
            "quota_api_unit": "MiB",
        }
    ]


def test_empty_structured_outputs_are_arrays() -> None:
    assert json.loads(render_shares((), OutputFormat.JSON)) == []
    assert yaml.safe_load(render_shares((), OutputFormat.YAML)) == []


@pytest.mark.parametrize(
    ("output_format", "expected_created"),
    [
        (OutputFormat.JSON, False),
        (OutputFormat.YAML, False),
    ],
)
def test_create_result_structured_output(
    output_format: OutputFormat,
    expected_created: bool,
) -> None:
    options = ShareCreateOptions(
        recycle_bin=RecycleBinOptions(enabled=True, admin_only=False),
        compression_enabled=True,
    )
    rendered = render_share_create(
        ShareCreateResult(
            name="media",
            volume="/volume1",
            description="Media files",
            created=expected_created,
            options=options,
            steps=(
                ShareOperationStep(
                    name="create",
                    status=OperationStatus.PLANNED,
                ),
            ),
        ),
        output_format,
    )

    value = (
        json.loads(rendered)
        if output_format is OutputFormat.JSON
        else yaml.safe_load(rendered)
    )
    assert value == {
        "name": "media",
        "volume": "/volume1",
        "description": "Media files",
        "created": expected_created,
        "options": {
            "recycle_bin": {"enabled": True, "admin_only": False},
            "compression_enabled": True,
            "quota_gib": None,
            "quota_api_value": None,
            "quota_api_unit": "MiB",
        },
        "permissions": [],
        "steps": [{"name": "create", "status": "planned"}],
    }


def test_create_result_table_identifies_plan_status() -> None:
    rendered = render_share_create(
        ShareCreateResult(
            name="media",
            volume="/volume1",
            description="",
            created=False,
        ),
        OutputFormat.TABLE,
    )

    assert rendered.splitlines()[0].split() == [
        "NAME",
        "VOLUME",
        "DESCRIPTION",
        "RECYCLE",
        "RECYCLE",
        "ACCESS",
        "COMPRESSION",
        "NFS_RULES",
        "STATUS",
    ]
    assert "media" in rendered
    assert "/volume1" in rendered
    assert "enabled" in rendered
    assert "admin-only" in rendered
    assert "disabled" in rendered
    assert "planned" in rendered
