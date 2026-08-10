from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from synology_manager.config import EMPTY_ACL, EMPTY_NFS, Host, Share, load_config
from synology_manager.dsm import DsmClient, DsmError
from synology_manager.engine import _shares
from synology_manager.engine import plan as make_plan
from synology_manager.models import ObservedShare, quota_wire_value, share
from synology_manager.plan import build_plan


def raw_share(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "name": "fictional-data",
        "vol_path": "/volume1",
        "desc": "",
        "share_quota_status": "v1",
    }
    result.update(changes)
    return result


@pytest.fixture
def external_share_schema() -> dict[str, object]:
    """Sanitized DSM external-share observation with no quota metadata."""
    return {
        "name": "external-data",
        "vol_path": "/volumeUSB1/external-data",
        "desc": "External storage",
        "display_vol_name": "External volume",
        "external_dev_type": "usb",
        "is_usb_share": True,
        "uuid": "",
    }


@pytest.mark.parametrize("status", ["v1", "v2"])
@pytest.mark.parametrize("mib", [0, 4096])
def test_direct_observed_share_uses_canonical_quota(status: str, mib: int) -> None:
    observed = ObservedShare("fictional-data", "/volume1", "", mib, status, False)
    assert observed.quota.mib == mib
    assert observed.quota.status == status


@pytest.mark.parametrize(
    ("mib", "status"),
    [(True, "v1"), ("0", "v1"), (-1, "v1"), (0, "unsupported")],
)
def test_direct_observed_share_rejects_unsafe_quota(mib: object, status: object) -> None:
    with pytest.raises(DsmError):
        ObservedShare("fictional-data", "/volume1", "", cast(int, mib), cast(str, status), False)


def test_missing_quota_value_uses_nested_finite_quota() -> None:
    observed = share(raw_share(shareinfo={"share_quota": "2048"}))
    assert observed.quota_mib == 2048


def test_missing_quota_status_defaults_to_v1_and_unlimited() -> None:
    raw = raw_share()
    raw.pop("share_quota_status")
    observed = share(raw)
    assert observed.quota.mib == 0
    assert observed.quota.status == "v1"


@pytest.mark.parametrize(("mib", "wire"), [(0, "0"), (4096, 4096)])
def test_quota_wire_value_uses_exact_target_format(mib: int, wire: int | str) -> None:
    assert quota_wire_value(mib) == wire


@pytest.mark.parametrize("mib", [True, -1, "0"])
def test_quota_wire_value_requires_canonical_integer_mib(mib: object) -> None:
    with pytest.raises(DsmError):
        quota_wire_value(cast(int, mib))


@pytest.mark.parametrize("status", ["v1", "v2"])
def test_missing_quota_metadata_is_unlimited_for_supported_statuses(status: str) -> None:
    assert share(raw_share(share_quota_status=status)).quota.mib == 0
    assert share(raw_share(share_quota_status=status, shareinfo={})).quota.mib == 0


@pytest.mark.parametrize("status", ["v1", "v2"])
@pytest.mark.parametrize(("quota", "expected"), [(0, 0), ("0", 0), (4096, 4096)])
def test_explicit_unlimited_and_finite_quotas_are_valid_for_supported_statuses(
    status: str, quota: object, expected: int
) -> None:
    observed = share(raw_share(share_quota_status=status, quota_value=quota))
    assert observed.quota.mib == expected
    assert observed.quota.status == status


@pytest.mark.parametrize(
    "quota_config",
    ["", "        quota: null\n"],
    ids=["omitted", "null"],
)
def test_missing_observed_quota_has_no_drift_for_unlimited_desired(
    tmp_path: Path, quota_config: str
) -> None:
    path = tmp_path / "fictional.yaml"
    path.write_text(
        """version: 1
host: fictional
volumes:
  - name: volume1
    shares:
      - name: fictional-data
        description: ''
        state: present
"""
        + quota_config,
        encoding="utf-8",
    )
    host = load_config(path).host
    observed = {"fictional-data": share(raw_share())}
    assert build_plan(host, observed, {}, {}).actions[0].kind == "noop"


@pytest.mark.parametrize(
    "payload",
    [
        raw_share(quota_value=None),
        raw_share(quota_value=False),
        raw_share(quota_value="not-a-number"),
        raw_share(shareinfo=None),
        raw_share(shareinfo={"share_quota": "not-a-number"}),
        raw_share(share_quota_status="unsupported"),
    ],
)
def test_malformed_quota_observations_fail_closed(payload: dict[str, object]) -> None:
    with pytest.raises(DsmError):
        share(payload)


def test_conflicting_top_level_and_nested_quotas_fail_closed() -> None:
    with pytest.raises(DsmError, match="conflicting"):
        share(raw_share(quota_value=1024, shareinfo={"share_quota": 2048}))


def test_quota_only_plan_is_deterministic_for_reordered_observations() -> None:
    host = Host(
        "fictional",
        ("/volume1",),
        (
            Share("alpha", "/volume1", "", 1024, "present", EMPTY_NFS, EMPTY_ACL),
            Share("beta", "/volume1", "", 2048, "present", EMPTY_NFS, EMPTY_ACL),
        ),
    )
    alpha = ObservedShare("alpha", "/volume1", "", 0, "v1", False)
    beta = ObservedShare("beta", "/volume1", "", 0, "v2", False)
    forward = build_plan(host, {"alpha": alpha, "beta": beta}, {}, {})
    reordered = build_plan(host, {"beta": beta, "alpha": alpha}, {}, {})
    assert forward == reordered
    assert [action.resource for action in forward.actions] == [
        "share:alpha",
        "nfs:alpha",
        "acl:alpha",
        "share:beta",
        "nfs:beta",
        "acl:beta",
    ]


@pytest.mark.parametrize("read_only", ["is_readonly", "is_read_only", "is_force_readonly"])
def test_read_only_quota_drift_is_unsupported(read_only: str) -> None:
    host = Host(
        "fictional",
        ("/volume1",),
        (Share("fictional-data", "/volume1", "", 2048, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    current = share(raw_share(quota_value=1024, **{read_only: True}))
    action = build_plan(host, {"fictional-data": current}, {}, {}).actions[0]
    assert action.kind == "unsupported"


def test_external_schema_ignores_empty_uuid_and_missing_quota(
    external_share_schema: dict[str, object],
) -> None:
    observed = share(external_share_schema)
    assert observed.quota.mib == 0
    assert observed.protected is True


def test_external_schema_accepts_nested_mount_components(
    external_share_schema: dict[str, object],
) -> None:
    external_share_schema["vol_path"] = "/volumeUSB12/media/backup-2026/photos"
    assert share(external_share_schema).protected is True


def test_external_path_is_protected_when_usb_flags_are_false() -> None:
    observed = share(
        raw_share(vol_path="/volumeUSB1/media/backup", is_usb_share=False, is_external=False)
    )
    assert observed.protected is True
    assert share(raw_share(is_usb_share=False, is_external=False)).protected is False


@pytest.mark.parametrize(
    "path",
    [
        "/volumeUSB1/",
        "/volumeUSB1//media",
        "/volumeUSB1/./media",
        "/volumeUSB1/../media",
        "/volumeUSB1/media\x00files",
        "/volumeUSB/media",
        "/volumeUSB01/media",
        "/volumeUSB1/media\\files",
    ],
)
def test_external_schema_rejects_invalid_mount_components(
    external_share_schema: dict[str, object], path: str
) -> None:
    external_share_schema["vol_path"] = path
    with pytest.raises(DsmError, match="^observed share volume path is invalid$"):
        share(external_share_schema)


def test_unknown_external_marker_is_protected_and_invalid_marker_type_fails_closed() -> None:
    assert share(raw_share(external_device="future-device")).protected is True
    with pytest.raises(DsmError, match="^observed share external marker is invalid$"):
        share(raw_share(external_vol=True))


def test_configured_external_share_is_unsupported_and_never_planned_for_mutation(
    external_share_schema: dict[str, object],
) -> None:
    host = Host(
        "fictional",
        ("/volume1",),
        (Share("external-data", "/volume1", "wanted", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    action = build_plan(host, {"external-data": share(external_share_schema)}, {}, {}).actions[0]
    assert (action.kind, action.detail) == ("unsupported", "protected share cannot be managed")
    assert "uuid" not in str(action) and "external" not in action.detail


@pytest.mark.parametrize("marker", [{"is_usb_share": True}, {"external_dev_type": "usb"}])
def test_usb_and_external_markers_protect_configured_share(marker: dict[str, object]) -> None:
    host = Host(
        "fictional",
        ("/volume1",),
        (Share("fictional-data", "/volume1", "wanted", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    action = build_plan(host, {"fictional-data": share(raw_share(**marker))}, {}, {}).actions[0]
    assert action.kind == "unsupported"


def test_unconfigured_external_share_does_not_change_configured_plan(
    external_share_schema: dict[str, object],
) -> None:
    host = Host(
        "fictional",
        ("/volume1",),
        (Share("fictional-data", "/volume1", "", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    observed = {
        "fictional-data": share(raw_share(uuid="normal-id")),
        "external-data": share(external_share_schema),
    }
    assert [
        action.kind
        for action in build_plan(
            host, observed, {}, {"fictional-data": ()}, {"fictional-data": False}
        ).actions
    ] == ["noop", "noop", "noop"]


@pytest.mark.parametrize(
    ("payload", "category"),
    [
        (raw_share(name=None), "observed share name is invalid"),
        (raw_share(vol_path="volume1"), "observed share volume path is invalid"),
        (raw_share(desc=None), "observed share description is invalid"),
        (raw_share(is_usb_share="true"), "observed share protection metadata is invalid"),
    ],
)
def test_invalid_required_share_fields_use_sanitized_categories(
    payload: dict[str, object], category: str
) -> None:
    with pytest.raises(DsmError, match=f"^{category}$") as raised:
        share(payload)
    assert "fictional-data" not in str(raised.value)


def test_plan_display_truncates_oversized_observed_descriptions_deterministically() -> None:
    host = Host(
        "fictional",
        ("/volume1",),
        (Share("fictional-data", "/volume1", "wanted", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    description = "x" * 600
    observed = {
        "fictional-data": ObservedShare("fictional-data", "/volume1", description, 0, "v1", False)
    }
    first = build_plan(host, observed, {}, {"fictional-data": ()}, {"fictional-data": False})
    second = build_plan(host, observed, {}, {"fictional-data": ()}, {"fictional-data": False})
    rendered = first.as_text()
    assert first.as_text() == second.as_text()
    assert first.digest == second.digest
    assert "..." in rendered
    assert max(len(line) for line in rendered.splitlines()) <= 514

    changed = ObservedShare("fictional-data", "/volume1", "x" * 599 + "y", 0, "v1", False)
    changed_plan = build_plan(
        host, {"fictional-data": changed}, {}, {"fictional-data": ()}, {"fictional-data": False}
    )
    assert first.digest != changed_plan.digest


def test_shares_contract_rejects_non_mapping_list_entry() -> None:
    class Client:
        def list_shares(self) -> list[object]:
            return [raw_share(), "invalid"]

    with pytest.raises(
        DsmError,
        match="^share list response is invalid: api=SYNO.Core.Share method=list version=1$",
    ):
        _shares(cast(DsmClient, Client()), frozenset({"fictional-data"}))


def test_shares_contract_filters_before_optional_metadata_normalization() -> None:
    class Client:
        def list_shares(self) -> list[dict[str, object]]:
            return [
                raw_share(),
                {
                    "name": "unconfigured-usb",
                    "vol_path": "/not-a-volume",
                    "desc": None,
                    "quota_value": "invalid",
                    "is_usb_share": "invalid",
                },
            ]

    observed = _shares(cast(DsmClient, Client()), frozenset({"fictional-data"}))
    assert tuple(observed) == ("fictional-data",)


def test_scoped_shares_reject_duplicate_configured_entries_before_lookup() -> None:
    class Client:
        def list_shares(self) -> list[dict[str, object]]:
            return [raw_share(), raw_share()]

    with pytest.raises(
        DsmError,
        match="^observed share names are duplicated: api=SYNO.Core.Share method=list version=1$",
    ):
        _shares(cast(DsmClient, Client()), frozenset({"fictional-data"}))


def test_plan_command_rejects_duplicate_configured_observation() -> None:
    class Client:
        def require(self, required: dict[str, int]) -> None:
            assert "SYNO.Core.Share" in required

        def list_shares(self) -> list[dict[str, object]]:
            return [raw_share(), raw_share()]

    host = Host(
        "fictional",
        ("/volume1",),
        (Share("fictional-data", "/volume1", "", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    with pytest.raises(
        DsmError,
        match="^observed share names are duplicated: api=SYNO.Core.Share method=list version=1$",
    ):
        make_plan(Client(), host)  # type: ignore[arg-type]


def test_plan_command_rejects_malformed_configured_share() -> None:
    class Client:
        def require(self, required: dict[str, int]) -> None:
            assert "SYNO.Core.Share" in required

        def list_shares(self) -> list[dict[str, object]]:
            return [raw_share(desc=None)]

    host = Host(
        "fictional",
        ("/volume1",),
        (Share("fictional-data", "/volume1", "", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    with pytest.raises(
        DsmError,
        match="^observed share description is invalid: api=SYNO.Core.Share method=list version=1$",
    ):
        make_plan(Client(), host)  # type: ignore[arg-type]


@pytest.mark.parametrize("malformed", [{"name": None}, {}, {"name": 3}])
def test_plan_command_rejects_unidentifiable_unconfigured_share(
    malformed: dict[str, object],
) -> None:
    class Client:
        def require(self, required: dict[str, int]) -> None:
            assert "SYNO.Core.Share" in required

        def list_shares(self) -> list[dict[str, object]]:
            return [raw_share(), malformed]

    host = Host(
        "fictional",
        ("/volume1",),
        (Share("fictional-data", "/volume1", "", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    with pytest.raises(
        DsmError,
        match="^observed share name is invalid: api=SYNO.Core.Share method=list version=1$",
    ):
        make_plan(Client(), host)  # type: ignore[arg-type]


def test_plan_command_with_mock_ignores_unconfigured_external_share(
    external_share_schema: dict[str, object],
) -> None:
    class Client:
        def require(self, required: dict[str, int]) -> None:
            assert required in (
                {
                    "SYNO.Core.Share": 1,
                    "SYNO.Core.FileServ.NFS.SharePrivilege": 1,
                    "SYNO.Core.ACL": 1,
                    "SYNO.FileStation.List": 2,
                },
                {"SYNO.Core.FileServ.NFS.SharePrivilege": 1},
            )

        def nfs_rules(self, name: str) -> list[dict[str, object]]:
            assert name == "fictional-data"
            return []

        def list_shares(self) -> list[dict[str, object]]:
            return [
                raw_share(),
                external_share_schema,
                {
                    "name": "unconfigured-usb",
                    "vol_path": "/not-a-volume",
                    "desc": None,
                    "quota_value": "invalid",
                    "is_usb_share": "invalid",
                },
            ]

        def acl(self, path: str) -> dict[str, object]:
            assert path == "/volume1/fictional-data"
            return {
                "acl_editable": True,
                "change_permission": True,
                "is_acl": True,
                "is_inherited": False,
                "acl": [],
            }

    host = Host(
        "fictional",
        ("/volume1",),
        (Share("fictional-data", "/volume1", "", 0, "present", EMPTY_NFS, EMPTY_ACL),),
    )
    result = make_plan(Client(), host)  # type: ignore[arg-type]
    assert [action.resource for action in result.actions] == [
        "share:fictional-data",
        "nfs:fictional-data",
        "acl:fictional-data",
    ]
