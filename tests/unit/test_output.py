import json

import pytest
import yaml

from synology.models import (
    AclPermissionRecord,
    EnrichmentStatus,
    NfsAccessMode,
    NfsClientPermission,
    OperationStatus,
    OutputFormat,
    RecycleBinOptions,
    ShareCreateOptions,
    ShareCreateResult,
    ShareDetails,
    ShareOperationStep,
    ShareRecord,
)
from synology.output import render_share_create, render_share_details, render_shares


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
