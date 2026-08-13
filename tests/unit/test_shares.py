import json
from io import StringIO

import pytest
import yaml
from requests.exceptions import SSLError
from synology_api.exceptions import CoreError, LoginError

from synology.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    PartialOperationError,
    PrincipalNotFoundError,
    TransportError,
)
from synology.logging import configure_logging
from synology.models import (
    ConnectionConfig,
    NfsAccessMode,
    NfsClientPermission,
    NfsDisplayPermission,
    NfsRootSquash,
    NfsSecurityFlavor,
    OperationStatus,
    OutputFormat,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    RecycleBinOptions,
    ShareCreateOptions,
    ShareCreateRequest,
    ShareDeleteRequest,
    ShareOperationStep,
    ShareScalarUpdateRequest,
)
from synology.output import render_share_details
from synology.shares import (
    SynShareClient,
    _mutable_share_state,
    _nfs_rule,
    _normalize_nfs_rule,
    _scalar_update_payload,
    _SharePermissionAdapter,
)


class FakeShare:
    def __init__(
        self,
        response: object | None = None,
        error: Exception | None = None,
        create_response: object | None = None,
        create_error: Exception | None = None,
        delete_response: object | None = None,
        delete_error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.create_response = create_response
        self.create_error = create_error
        self.delete_response = delete_response
        self.delete_error = delete_error
        self.calls: list[tuple[str, list[str]]] = []
        self.delete_calls: list[list[str]] = []
        self.create_calls: list[dict[str, object]] = []

    def list_folders(self, *, share_type: str, additional: list[str]) -> object:
        self.calls.append((share_type, additional))
        if self.error is not None:
            raise self.error
        return self.response

    def create_folder(self, **kwargs: object) -> object:
        self.create_calls.append(kwargs)
        if self.create_error is not None:
            raise self.create_error
        return self.create_response

    def delete_folders(self, name: list[str]) -> object:
        self.delete_calls.append(name)
        if self.delete_error is not None:
            raise self.delete_error
        return self.delete_response


class FakeRawPermissionApi:
    def __init__(self) -> None:
        self.core_list = {
            "SYNO.Core.Share.Permission": {"path": "entry.cgi", "minVersion": 1}
        }
        self.request_calls: list[tuple[str, str, dict[str, object], str]] = []

    def request_data(
        self,
        api_name: str,
        api_path: str,
        request: dict[str, object],
        method: str,
    ) -> object:
        self.request_calls.append((api_name, api_path, request, method))
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
        return _permission_response([])


class FakeNfsApi:
    def __init__(
        self,
        global_response: object,
        save_response: object,
        load_response: object,
    ) -> None:
        self.core_list = {
            "SYNO.Core.FileServ.NFS": {"path": "entry.cgi", "maxVersion": 2},
            "SYNO.Core.FileServ.NFS.SharePrivilege": {
                "path": "entry.cgi",
                "maxVersion": 1,
            },
        }
        self.global_response = global_response
        self.save_response = save_response
        self.load_response = load_response
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
            return self.global_response
        if request["method"] == "save":
            return self.save_response
        return self.load_response


class FakePermissionApi:
    def __init__(
        self,
        responses: dict[str, object],
        set_error: Exception | None = None,
    ) -> None:
        self.responses = responses
        self.set_error = set_error
        self.set_calls: list[tuple[str, str, list[dict[str, object]]]] = []
        self.get_calls: list[tuple[str, str]] = []

    def set_folder_permissions(
        self,
        name: str,
        user_group_type: str,
        permissions: list[dict[str, object]],
    ) -> object:
        self.set_calls.append((name, user_group_type, permissions))
        if self.set_error is not None:
            raise self.set_error
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
        self.get_calls.append((name, user_group_type))
        return self.responses[user_group_type]


class FakeFactory:
    def __init__(self, share: FakeShare, error: Exception | None = None) -> None:
        self.share = share
        self.error = error
        self.arguments: dict[str, object] = {}

    def __call__(self, **kwargs: object) -> FakeShare:
        self.arguments = kwargs
        if self.error is not None:
            raise self.error
        return self.share


def _config(*, insecure: bool = False) -> ConnectionConfig:
    return ConnectionConfig(
        username="user",
        password="password-secret",
        host="nas.example.test",
        port=5000,
        insecure=insecure,
    )


def _logger(stream: StringIO | None = None):
    return configure_logging(True, stream=stream or StringIO())


def _response() -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "shares": [
                {
                    "name": "media",
                    "vol_path": "/volume1",
                    "desc": "Media files",
                    "uuid": "share-uuid",
                    "is_usb_share": False,
                    "quota_value": 5120,
                }
            ],
            "total": 1,
        },
    }


def _permission_response(items: list[dict[str, object]]) -> dict[str, object]:
    normalized = [{**item, "is_admin": item.get("is_admin", False)} for item in items]
    return {"success": True, "data": {"items": normalized, "total": len(normalized)}}


def _nfs_load_response(permission: NfsClientPermission) -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "share_name": "projects",
            "rule": [
                {
                    "async": permission.async_enabled,
                    "client": permission.client,
                    "crossmnt": permission.crossmnt,
                    "insecure": permission.insecure,
                    "privilege": "rw"
                    if permission.access_mode is NfsAccessMode.READ_WRITE
                    else "ro",
                    "root_squash": permission.root_squash.value,
                    "security_flavor": {
                        "sys": permission.security_flavor.sys,
                        "kerberos": permission.security_flavor.kerberos,
                        "kerberos_integrity": (
                            permission.security_flavor.kerberos_integrity
                        ),
                        "kerberos_privacy": (
                            permission.security_flavor.kerberos_privacy
                        ),
                    },
                }
            ],
        },
    }


def test_external_missing_scalar_fields_are_capabilities_not_malformed() -> None:
    state = _mutable_share_state(
        {
            "name": "backups",
            "vol_path": "/volumeUSB1/usbshare",
            "desc": "backup",
            "hidden": False,
        },
        (False, True),
    )

    assert state.quota is None
    assert not state.capabilities.quota_available
    assert not state.capabilities.compression_available
    payload = json.loads(
        _scalar_update_payload(
            state, 1, ShareScalarUpdateRequest("backups", "backup")
        ).shareinfo
    )
    assert "share_quota" not in payload
    assert "enable_share_compress" not in payload
    assert "enable_share_cow" not in payload


@pytest.mark.parametrize(
    "field", ["quota_value", "enable_share_compress", "enable_share_cow"]
)
def test_internal_missing_scalar_fields_fail_closed(field: str) -> None:
    data: dict[str, object] = {
        "name": "projects",
        "vol_path": "/volume1",
        "desc": "projects",
        "hidden": False,
        "quota_value": 0,
        "enable_share_compress": False,
        "enable_share_cow": False,
    }
    del data[field]

    with pytest.raises(ApiError, match="projects.*volume1"):
        _mutable_share_state(data, (False, True))


@pytest.mark.parametrize(
    "field", ["quota_value", "enable_share_compress", "enable_share_cow"]
)
def test_present_external_malformed_scalar_fields_fail_closed(field: str) -> None:
    data: dict[str, object] = {
        "name": "backups",
        "vol_path": "/volumeUSB1/usbshare",
        "desc": "backup",
        "hidden": False,
        "quota_value": 0,
        "enable_share_compress": False,
        "enable_share_cow": False,
    }
    data[field] = "invalid"

    with pytest.raises(ApiError, match="backups.*volumeUSB1"):
        _mutable_share_state(data, (False, True))


def test_permission_adapter_quotes_share_and_principal_type() -> None:
    raw_api = FakeRawPermissionApi()
    adapter = _SharePermissionAdapter(raw_api)

    response = adapter.set_folder_permissions(
        "projects",
        "local_user",
        [
            {
                "name": "alice",
                "is_deny": False,
                "is_readonly": False,
                "is_writable": True,
            }
        ],
    )

    expected_permissions = (
        '[{"name":"alice","is_deny":false,"is_readonly":false,"is_writable":true}]'
    )

    assert response == {"success": True}
    assert raw_api.request_calls == [
        (
            "SYNO.Core.Share.Permission",
            "entry.cgi",
            {
                "version": 1,
                "method": "set",
                "name": '"projects"',
                "user_group_type": '"local_user"',
                "permissions": expected_permissions,
            },
            "get",
        )
    ]


def test_client_uses_secure_upstream_construction_and_normalizes_response() -> None:
    share = FakeShare(_response())
    factory = FakeFactory(share)

    result = SynShareClient(_config(), _logger(), factory=factory).list_shares()

    assert factory.arguments == {
        "ip_address": "nas.example.test",
        "port": "5000",
        "username": "user",
        "password": "password-secret",
        "secure": True,
        "cert_verify": True,
        "dsm_version": 7,
        "debug": False,
    }
    assert share.calls == [
        (
            "all",
            ["share_quota"],
        )
    ]
    assert result[0].name == "media"
    assert result[0].volume == "/volume1"
    assert result[0].description == "Media files"
    assert result[0].uuid == "share-uuid"
    assert result[0].is_usb is False
    assert result[0].quota_gib == 5
    assert result[0].quota_api_value == 5120


def test_insecure_mode_disables_only_certificate_verification() -> None:
    factory = FakeFactory(FakeShare(_response()))

    SynShareClient(_config(insecure=True), _logger(), factory=factory)

    assert factory.arguments["secure"] is True
    assert factory.arguments["cert_verify"] is False
    assert factory.arguments["debug"] is False


def test_empty_shares_are_successful_and_optional_fields_are_none() -> None:
    empty = {"success": True, "data": {"shares": [], "total": 0}}
    optional = {"success": True, "data": {"shares": [{"name": "minimal"}]}}

    assert (
        SynShareClient(
            _config(), _logger(), factory=FakeFactory(FakeShare(empty))
        ).list_shares()
        == ()
    )
    result = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(optional)),
    ).list_shares()
    assert result[0].volume is None
    assert result[0].description is None
    assert result[0].uuid is None
    assert result[0].is_usb is None
    assert result[0].quota_gib is None
    assert result[0].quota_api_value is None


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"success": False},
        {"success": True, "data": {}},
        {"success": True, "data": {"shares": "not-a-list"}},
        {"success": True, "data": {"shares": [{"name": ""}]}},
        {"success": True, "data": {"shares": [], "total": "1"}},
    ],
)
def test_malformed_responses_raise_api_error(response: object) -> None:
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(response)),
    )

    with pytest.raises(ApiError):
        client.list_shares()


@pytest.mark.parametrize("quota", [-1, True, "5120"])
def test_invalid_list_quota_raises_api_error(quota: object) -> None:
    response = {
        "success": True,
        "data": {"shares": [{"name": "media", "quota_value": quota}]},
    }
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(response)),
    )

    with pytest.raises(ApiError):
        client.list_shares()


def test_sub_gib_quota_is_normalized_as_fractional_gib() -> None:
    response = {
        "success": True,
        "data": {"shares": [{"name": "legacy", "quota_value": 5}]},
    }
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(response)),
    )

    result = client.list_shares()

    assert result[0].quota_api_value == 5
    assert result[0].quota_gib == 5 / 1024


def test_upstream_errors_map_to_application_error_categories() -> None:
    with pytest.raises(AuthenticationError):
        SynShareClient(
            _config(),
            _logger(),
            factory=FakeFactory(FakeShare(), error=LoginError(error_code=400)),
        )

    transport_client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(error=SSLError("certificate failed"))),
    )
    with pytest.raises(TransportError):
        transport_client.list_shares()

    api_client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(error=CoreError(error_code=100))),
    )
    with pytest.raises(ApiError):
        api_client.list_shares()


def test_verbose_logging_includes_sanitized_request_and_response() -> None:
    stream = StringIO()
    SynShareClient(
        _config(),
        _logger(stream),
        factory=FakeFactory(FakeShare(_response())),
    ).list_shares()

    logged = stream.getvalue()
    assert "Synology API request" in logged
    assert "Synology API response" in logged
    assert "password-secret" not in logged
    assert "share-uuid" in logged


def test_verbose_logging_excludes_unrecognized_response_fields() -> None:
    response = {
        "success": True,
        "session": "session-secret",
        "data": {
            "shares": [
                {
                    "name": "media",
                    "uuid": "share-uuid",
                    "token": "record-token-secret",
                }
            ]
        },
    }
    stream = StringIO()

    SynShareClient(
        _config(),
        _logger(stream),
        factory=FakeFactory(FakeShare(response)),
    ).list_shares()

    logged = stream.getvalue()
    assert "session-secret" not in logged
    assert "record-token-secret" not in logged
    assert "share-uuid" in logged


def test_delete_share_uses_exact_upstream_arguments() -> None:
    share = FakeShare(delete_response={"success": True})
    client = SynShareClient(_config(), _logger(), factory=FakeFactory(share))

    result = client.delete_share(ShareDeleteRequest(name="media"))

    assert share.delete_calls == [["media"]]
    assert result.name == "media"
    assert result.deleted is True
    assert result.steps == (
        ShareOperationStep(name="delete", status=OperationStatus.SUCCEEDED),
    )


@pytest.mark.parametrize("response", [None, {}, {"success": False}, {"success": 1}])
def test_malformed_delete_responses_raise_api_error(response: object) -> None:
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(delete_response=response)),
    )

    with pytest.raises(ApiError):
        client.delete_share(ShareDeleteRequest(name="media"))


@pytest.mark.parametrize(
    ("upstream_error", "expected_exception"),
    [
        (LoginError(error_code=400), AuthenticationError),
        (SSLError("certificate failed"), TransportError),
        (CoreError(error_code=100), ApiError),
    ],
)
def test_delete_share_maps_upstream_errors(
    upstream_error: Exception,
    expected_exception: type[Exception],
) -> None:
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(delete_error=upstream_error)),
    )

    with pytest.raises(expected_exception):
        client.delete_share(ShareDeleteRequest(name="media"))


def test_create_share_uses_exact_approved_upstream_arguments() -> None:
    share = FakeShare(create_response={"success": True, "data": {"name": "media"}})
    client = SynShareClient(_config(), _logger(), factory=FakeFactory(share))

    result = client.create_share(
        ShareCreateRequest(
            name="media",
            volume_path="/volume1",
            description="Media files",
        )
    )

    assert share.create_calls == [
        {
            "name": "media",
            "vol_path": "/volume1",
            "desc": "Media files",
            "enable_recycle_bin": True,
            "recycle_bin_admin_only": True,
            "enable_share_compress": False,
        }
    ]
    assert result.name == "media"
    assert result.volume == "/volume1"
    assert result.description == "Media files"
    assert result.created is True
    assert result.options == ShareCreateOptions()
    assert result.steps[0].status is OperationStatus.SUCCEEDED


def test_create_share_forwards_quota_when_requested() -> None:
    share = FakeShare(create_response={"success": True, "data": {"name": "media"}})
    client = SynShareClient(_config(), _logger(), factory=FakeFactory(share))

    client.create_share(
        ShareCreateRequest(
            name="media",
            volume_path="/volume1",
            options=ShareCreateOptions(quota_gib=100, quota_api_value=102400),
        )
    )

    assert share.create_calls == [
        {
            "name": "media",
            "vol_path": "/volume1",
            "desc": "",
            "enable_recycle_bin": True,
            "recycle_bin_admin_only": True,
            "enable_share_compress": False,
            "share_quota": 102400,
        }
    ]


def test_create_external_share_omits_unavailable_scalar_options() -> None:
    share = FakeShare(create_response={"success": True, "data": {"name": "backups"}})
    client = SynShareClient(_config(), _logger(), factory=FakeFactory(share))

    client.create_share(
        ShareCreateRequest(
            name="backups",
            volume_path="/volumeUSB1/usbshare",
            options=ShareCreateOptions(scalar_options_available=False),
        )
    )

    assert "share_quota" not in share.create_calls[0]
    assert "enable_share_compress" not in share.create_calls[0]


def test_create_share_omits_quota_when_not_requested() -> None:
    share = FakeShare(create_response={"success": True, "data": {"name": "media"}})
    client = SynShareClient(_config(), _logger(), factory=FakeFactory(share))

    client.create_share(ShareCreateRequest(name="media", volume_path="/volume1"))

    assert "share_quota" not in share.create_calls[0]


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        (
            ShareCreateOptions(
                recycle_bin=RecycleBinOptions(enabled=False, admin_only=True)
            ),
            {
                "enable_recycle_bin": False,
                "recycle_bin_admin_only": True,
                "enable_share_compress": False,
            },
        ),
        (
            ShareCreateOptions(
                recycle_bin=RecycleBinOptions(enabled=True, admin_only=False)
            ),
            {
                "enable_recycle_bin": True,
                "recycle_bin_admin_only": False,
                "enable_share_compress": False,
            },
        ),
        (
            ShareCreateOptions(compression_enabled=True),
            {
                "enable_recycle_bin": True,
                "recycle_bin_admin_only": True,
                "enable_share_compress": True,
            },
        ),
    ],
)
def test_create_share_forwards_phase_one_options(
    options: ShareCreateOptions,
    expected: dict[str, bool],
) -> None:
    share = FakeShare(create_response={"success": True, "data": {"name": "media"}})
    client = SynShareClient(_config(), _logger(), factory=FakeFactory(share))

    client.create_share(
        ShareCreateRequest(
            name="media",
            volume_path="/volume1",
            options=options,
        )
    )

    assert share.create_calls == [
        {
            "name": "media",
            "vol_path": "/volume1",
            "desc": "",
            **expected,
        }
    ]


def test_create_share_applies_and_verifies_nfs_rules() -> None:
    nfs_permission = NfsClientPermission(
        client="10.192.10.20",
        access_mode=NfsAccessMode.READ_WRITE,
    )
    nfs_api = FakeNfsApi(
        {"success": True, "data": {"enable_nfs": True}},
        {"success": True},
        _nfs_load_response(nfs_permission),
    )
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        nfs_factory=lambda _: nfs_api,
    )

    result = client.create_share(
        ShareCreateRequest(
            name="projects",
            volume_path="/volume1",
            nfs_permissions=(nfs_permission,),
        )
    )

    assert result.nfs_permissions == (nfs_permission,)
    assert [step.name for step in result.steps] == [
        "create",
        "nfs-precheck",
        "nfs-save",
        "nfs-verify",
    ]
    assert result.steps[-1].status is OperationStatus.SUCCEEDED
    assert nfs_api.calls[0] == (
        "SYNO.Core.FileServ.NFS",
        "entry.cgi",
        {"version": 2, "method": "get"},
        "get",
    )
    assert nfs_api.calls[1][0:2] == (
        "SYNO.Core.FileServ.NFS.SharePrivilege",
        "entry.cgi",
    )
    assert nfs_api.calls[1][2]["share_name"] == '"projects"'
    assert nfs_api.calls[1][2]["method"] == "save"
    assert json.loads(str(nfs_api.calls[1][2]["rule"])) == [
        {
            "async": False,
            "client": "10.192.10.20",
            "crossmnt": False,
            "insecure": False,
            "privilege": "rw",
            "root_squash": "root",
            "security_flavor": {
                "sys": True,
                "kerberos": False,
                "kerberos_integrity": False,
                "kerberos_privacy": False,
            },
        }
    ]
    assert nfs_api.calls[2][2]["method"] == "load"


@pytest.mark.parametrize("root_squash", list(NfsRootSquash))
def test_nfs_root_squash_values_serialize_and_normalize_exactly(
    root_squash: NfsRootSquash,
) -> None:
    assert (
        NfsClientPermission("10.192.10.20", NfsAccessMode.READ_WRITE).root_squash
        is NfsRootSquash.ROOT
    )
    permission = NfsClientPermission(
        client="10.192.10.20",
        access_mode=NfsAccessMode.READ_WRITE,
        root_squash=root_squash,
    )

    assert _nfs_rule(permission)["root_squash"] == root_squash.value
    assert (
        _normalize_nfs_rule(_nfs_load_response(permission)["data"]["rule"][0])
        == permission
    )


@pytest.mark.parametrize("root_squash", list(NfsRootSquash))
def test_nfs_save_payload_uses_exact_root_squash_token(
    root_squash: NfsRootSquash,
) -> None:
    permission = NfsClientPermission(
        client="10.192.10.20",
        access_mode=NfsAccessMode.READ_WRITE,
        root_squash=root_squash,
    )
    nfs_api = FakeNfsApi(
        {"success": True, "data": {"enable_nfs": True}},
        {"success": True},
        _nfs_load_response(permission),
    )
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        nfs_factory=lambda _: nfs_api,
    )

    client.create_share(
        ShareCreateRequest(
            name="projects", volume_path="/volume1", nfs_permissions=(permission,)
        )
    )

    assert (
        json.loads(str(nfs_api.calls[1][2]["rule"]))[0]["root_squash"]
        == root_squash.value
    )


@pytest.mark.parametrize("root_squash", ["no_root_squash", "none", "unknown", None])
def test_nfs_normalization_rejects_unknown_root_squash(root_squash: object) -> None:
    rule = _nfs_load_response(
        NfsClientPermission("10.192.10.20", NfsAccessMode.READ_WRITE)
    )["data"]["rule"][0]
    rule["root_squash"] = root_squash

    with pytest.raises(ApiError, match="invalid NFS rule"):
        _normalize_nfs_rule(rule)


def test_disabled_global_nfs_prevents_share_creation() -> None:
    nfs_permission = NfsClientPermission(
        client="10.192.10.20",
        access_mode=NfsAccessMode.READ_ONLY,
    )
    nfs_api = FakeNfsApi(
        {"success": True, "data": {"enable_nfs": False}},
        {"success": True},
        _nfs_load_response(nfs_permission),
    )
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        nfs_factory=lambda _: nfs_api,
    )

    with pytest.raises(ConfigurationError, match="global NFS"):
        client.create_share(
            ShareCreateRequest(
                name="projects",
                volume_path="/volume1",
                nfs_permissions=(nfs_permission,),
            )
        )

    assert share.create_calls == []


def test_nfs_readback_mismatch_after_creation_is_partial_operation() -> None:
    nfs_permission = NfsClientPermission(
        client="10.192.10.20",
        access_mode=NfsAccessMode.READ_ONLY,
    )
    mismatched = NfsClientPermission(
        client="10.192.10.21",
        access_mode=NfsAccessMode.READ_ONLY,
    )
    nfs_api = FakeNfsApi(
        {"success": True, "data": {"enable_nfs": True}},
        {"success": True},
        _nfs_load_response(mismatched),
    )
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        nfs_factory=lambda _: nfs_api,
    )

    with pytest.raises(PartialOperationError) as error:
        client.create_share(
            ShareCreateRequest(
                name="projects",
                volume_path="/volume1",
                nfs_permissions=(nfs_permission,),
            )
        )

    assert error.value.result.created is True
    assert error.value.result.steps[-1].name == "nfs"
    assert error.value.result.steps[-1].status is OperationStatus.FAILED


def test_nfs_save_failure_after_creation_is_partial_operation() -> None:
    nfs_permission = NfsClientPermission(
        client="10.192.10.20",
        access_mode=NfsAccessMode.READ_ONLY,
    )
    nfs_api = FakeNfsApi(
        {"success": True, "data": {"enable_nfs": True}},
        {"success": False},
        _nfs_load_response(nfs_permission),
    )
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        nfs_factory=lambda _: nfs_api,
    )

    with pytest.raises(PartialOperationError) as error:
        client.create_share(
            ShareCreateRequest(
                name="projects",
                volume_path="/volume1",
                nfs_permissions=(nfs_permission,),
            )
        )

    assert error.value.result.created is True
    assert error.value.result.steps[-1].name == "nfs"
    assert error.value.result.steps[-1].status is OperationStatus.FAILED


def test_create_share_applies_and_verifies_complete_acl() -> None:
    permissions = (
        PermissionSpec(
            PermissionPrincipalType.LOCAL_USER,
            "alice",
            PermissionAccessMode.READ_WRITE,
        ),
        PermissionSpec(
            PermissionPrincipalType.LDAP_USER,
            "alice@example.org",
            PermissionAccessMode.READ_ONLY,
        ),
    )
    permission_api = FakePermissionApi(
        {
            "local_user": _permission_response(
                [
                    {
                        "name": "alice",
                        "is_custom": True,
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": True,
                        "is_admin": False,
                    }
                ]
            ),
            "local_group": _permission_response([]),
            "ldap_user": _permission_response(
                [
                    {
                        "name": "alice@example.org",
                        "is_custom": True,
                        "is_deny": False,
                        "is_readonly": True,
                        "is_writable": False,
                        "is_admin": False,
                    }
                ]
            ),
            "ldap_group": _permission_response([]),
        }
    )
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        permission_factory=lambda _: permission_api,
    )

    result = client.create_share(
        ShareCreateRequest(
            name="projects",
            volume_path="/volume1",
            permissions=permissions,
        )
    )

    assert permission_api.set_calls == [
        (
            "projects",
            "local_user",
            [
                {
                    "name": "alice",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": True,
                }
            ],
        ),
        ("projects", "local_group", []),
        (
            "projects",
            "ldap_user",
            [
                {
                    "name": "alice@example.org",
                    "is_deny": False,
                    "is_readonly": True,
                    "is_writable": False,
                }
            ],
        ),
        ("projects", "ldap_group", []),
    ]
    assert permission_api.get_calls == [
        ("projects", "local_user"),
        ("projects", "local_group"),
        ("projects", "ldap_user"),
        ("projects", "ldap_group"),
    ]
    assert result.permissions == permissions
    assert result.steps[-1].status is OperationStatus.SUCCEEDED


def test_acl_normalization_renders_active_noncustom_ldap_and_excludes_inventory() -> (
    None
):
    response = _permission_response(
        [
            {
                "name": "konri@jumpcloud.com",
                "is_custom": False,
                "is_admin": False,
                "is_deny": False,
                "is_readonly": False,
                "is_writable": True,
            },
            {
                "name": "unused",
                "is_custom": True,
                "is_admin": False,
                "is_deny": False,
                "is_readonly": False,
                "is_writable": False,
            },
        ]
    )
    share = FakeShare(
        response={
            "success": True,
            "data": {"shares": [{"name": "projects"}], "total": 1},
        }
    )
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        permission_factory=lambda _: FakePermissionApi(
            {
                "local_user": _permission_response([]),
                "local_group": _permission_response([]),
                "ldap_user": response,
                "ldap_group": _permission_response([]),
            }
        ),
        nfs_factory=lambda _: FakeNfsApi(
            {"success": True, "data": {"enable_nfs": True}},
            {"success": True},
            {"success": True, "data": {"rule": []}},
        ),
    )

    details = client.list_share_details()

    assert [item.name for item in details[0].acl_permissions] == ["konri@jumpcloud.com"]
    assert details[0].acl_permissions[0].category == "ldap_user"
    assert details[0].acl_permissions[0].is_custom is False


def test_list_details_preserves_malformed_live_nfs_client_for_display() -> None:
    share = FakeShare(
        response={
            "success": True,
            "data": {"shares": [{"name": "projects"}], "total": 1},
        }
    )
    raw_rule = {
        "async": True,
        "client": "10.192.10.0/2",
        "crossmnt": True,
        "insecure": True,
        "privilege": "rw",
        "root_squash": "all_admin",
        "security_flavor": {
            "sys": True,
            "kerberos": False,
            "kerberos_integrity": False,
            "kerberos_privacy": False,
        },
    }
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        permission_factory=lambda _: FakePermissionApi(
            {
                category: _permission_response([])
                for category in (
                    "local_user",
                    "local_group",
                    "ldap_user",
                    "ldap_group",
                )
            }
        ),
        nfs_factory=lambda _: FakeNfsApi(
            {"success": True, "data": {"enable_nfs": True}},
            {"success": True},
            {"success": True, "data": {"rule": [raw_rule]}},
        ),
    )

    detail = client.list_share_details()[0]

    assert detail.nfs_status.value == "available"
    assert detail.nfs_permissions == ()
    assert detail.nfs_display_permissions == (
        NfsDisplayPermission(
            "10.192.10.0/2",
            NfsAccessMode.READ_WRITE,
            async_enabled=True,
            insecure=True,
            crossmnt=True,
            root_squash=NfsRootSquash.ALL_ADMIN,
        ),
    )


def test_live_kerberos_nfs_detail_preserves_raw_flags_in_all_display_formats() -> None:
    share = FakeShare(
        response={
            "success": True,
            "data": {"shares": [{"name": "projects"}], "total": 1},
        }
    )
    security_flavor = {
        "sys": False,
        "kerberos": True,
        "kerberos_integrity": True,
        "kerberos_privacy": False,
    }
    raw_rule = {
        "async": False,
        "client": "10.192.10.0/24",
        "crossmnt": False,
        "insecure": True,
        "privilege": "rw",
        "root_squash": "guest",
        "security_flavor": security_flavor,
    }
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        permission_factory=lambda _: FakePermissionApi(
            {
                category: _permission_response([])
                for category in (
                    "local_user",
                    "local_group",
                    "ldap_user",
                    "ldap_group",
                )
            }
        ),
        nfs_factory=lambda _: FakeNfsApi(
            {"success": True, "data": {"enable_nfs": True}},
            {"success": True},
            {"success": True, "data": {"rule": [raw_rule]}},
        ),
    )

    details = client.list_share_details()
    table = render_share_details(details, OutputFormat.TABLE)
    json_value = json.loads(render_share_details(details, OutputFormat.JSON))
    yaml_value = yaml.safe_load(render_share_details(details, OutputFormat.YAML))

    assert details[0].nfs_permissions[0].security_flavor == NfsSecurityFlavor(
        sys=False,
        kerberos=True,
        kerberos_integrity=True,
        kerberos_privacy=False,
    )
    assert "security_flavors=[kerberos,kerberos_integrity]" in table
    assert json_value[0]["nfs_permissions"][0]["security_flavor"] == security_flavor
    assert yaml_value == json_value


def test_mutation_safe_nfs_normalization_rejects_live_kerberos_rule() -> None:
    rule = _nfs_load_response(
        NfsClientPermission(
            "10.192.10.20",
            NfsAccessMode.READ_WRITE,
            security_flavor=NfsSecurityFlavor(sys=False, kerberos=True),
        )
    )["data"]["rule"][0]

    with pytest.raises(ApiError, match="unsupported NFS security flavor"):
        _normalize_nfs_rule(rule)


def test_permission_failure_after_creation_is_partial_operation() -> None:

    permission = PermissionSpec(
        PermissionPrincipalType.LOCAL_USER,
        "alice",
        PermissionAccessMode.READ_WRITE,
    )
    permission_api = FakePermissionApi({}, set_error=CoreError(error_code=105))
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        permission_factory=lambda _: permission_api,
    )

    with pytest.raises(PartialOperationError) as error:
        client.create_share(
            ShareCreateRequest(
                name="projects",
                volume_path="/volume1",
                permissions=(permission,),
            )
        )

    result = error.value.result
    assert result.created is True
    assert result.permissions == (permission,)
    assert result.steps[-1].status is OperationStatus.FAILED
    assert len(share.create_calls) == 1


def test_permission_readback_mismatch_is_partial_operation() -> None:
    permission = PermissionSpec(
        PermissionPrincipalType.LOCAL_USER,
        "alice",
        PermissionAccessMode.READ_WRITE,
    )
    permission_api = FakePermissionApi(
        {
            "local_user": _permission_response([]),
            "local_group": _permission_response([]),
            "ldap_user": _permission_response([]),
            "ldap_group": _permission_response([]),
        }
    )
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        permission_factory=lambda _: permission_api,
    )

    with pytest.raises(PartialOperationError) as error:
        client.create_share(
            ShareCreateRequest(
                name="projects",
                volume_path="/volume1",
                permissions=(permission,),
            )
        )

    result = error.value.result
    assert result.created is True
    assert result.steps[-1].status is OperationStatus.FAILED
    assert len(permission_api.set_calls) == 4


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"success": False},
        {"success": True, "data": {}},
        {"success": True, "data": {"items": "not-a-list"}},
        {"success": True, "data": {"items": [{"name": "alice"}]}},
    ],
)
def test_malformed_permission_readback_is_partial_operation(response: object) -> None:
    permission = PermissionSpec(
        PermissionPrincipalType.LOCAL_USER,
        "alice",
        PermissionAccessMode.READ_WRITE,
    )
    permission_api = FakePermissionApi(
        {
            "local_user": response,
            "local_group": _permission_response([]),
            "ldap_user": _permission_response([]),
            "ldap_group": _permission_response([]),
        }
    )
    share = FakeShare(create_response={"success": True, "data": {"name": "projects"}})
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(share),
        permission_factory=lambda _: permission_api,
    )

    with pytest.raises(PartialOperationError) as error:
        client.create_share(
            ShareCreateRequest(
                name="projects",
                volume_path="/volume1",
                permissions=(permission,),
            )
        )

    assert error.value.result.created is True
    assert error.value.result.steps[-1].status is OperationStatus.FAILED


@pytest.mark.parametrize(
    "response",
    [
        None,
        {},
        {"success": False},
        {"success": True, "data": {}},
        {"success": True, "data": {"name": None}},
        {"success": True, "data": {"name": 1}},
        {"success": True, "data": {"name": ""}},
        {"success": True, "data": {"name": "   "}},
    ],
)
def test_malformed_create_responses_raise_api_error(response: object) -> None:
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(create_response=response)),
    )

    with pytest.raises(ApiError):
        client.create_share(ShareCreateRequest(name="media", volume_path="/volume1"))


@pytest.mark.parametrize(
    ("upstream_error", "expected_exception"),
    [
        (LoginError(error_code=400), AuthenticationError),
        (SSLError("certificate failed"), TransportError),
        (CoreError(error_code=100), ApiError),
    ],
)
def test_create_share_maps_upstream_errors(
    upstream_error: Exception,
    expected_exception: type[Exception],
) -> None:
    client = SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(create_error=upstream_error)),
    )

    with pytest.raises(expected_exception):
        client.create_share(ShareCreateRequest(name="media", volume_path="/volume1"))


def test_create_share_logs_sanitized_request_and_response() -> None:
    stream = StringIO()
    client = SynShareClient(
        _config(),
        _logger(stream),
        factory=FakeFactory(
            FakeShare(create_response={"success": True, "data": {"name": "media"}})
        ),
    )

    client.create_share(
        ShareCreateRequest(
            name="media",
            volume_path="/volume1",
            description="password=description-secret",
        )
    )

    logged = stream.getvalue()
    assert "Synology API create request" in logged
    assert "Synology API response" in logged
    assert "password-secret" not in logged
    assert "description-secret" not in logged
    assert "media" in logged


def test_create_share_redacts_sensitive_patterns_in_logged_fields() -> None:
    stream = StringIO()
    client = SynShareClient(
        _config(),
        _logger(stream),
        factory=FakeFactory(
            FakeShare(create_response={"success": True, "data": {"name": "media"}})
        ),
    )

    client.create_share(
        ShareCreateRequest(
            name="token=share-secret",
            volume_path="/volume1?password=path-secret",
            description="Authorization: Bearer header-secret",
        )
    )

    logged = stream.getvalue()
    assert "share-secret" not in logged
    assert "path-secret" not in logged
    assert "header-secret" not in logged


def _lookup_client(permission_api: FakePermissionApi) -> SynShareClient:
    return SynShareClient(
        _config(),
        _logger(),
        factory=FakeFactory(FakeShare(_response())),
        permission_factory=lambda config: permission_api,
    )


def test_global_apply_principal_lookup_validates_exact_all_categories() -> None:
    permission_api = FakePermissionApi(
        {
            "local_user": _permission_response(
                [
                    {
                        "name": "Alice",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": False,
                    }
                ]
            ),
            "local_group": _permission_response(
                [
                    {
                        "name": "administrators",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": True,
                    }
                ]
            ),
            "ldap_user": _permission_response(
                [
                    {
                        "name": "alice@example.test",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": False,
                    }
                ]
            ),
            "ldap_group": _permission_response(
                [
                    {
                        "name": "engineering@example.test",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": False,
                    }
                ]
            ),
        }
    )
    permissions = (
        PermissionSpec(
            PermissionPrincipalType.LOCAL_USER, "Alice", PermissionAccessMode.READ_ONLY
        ),
        PermissionSpec(
            PermissionPrincipalType.LDAP_USER,
            "alice@example.test",
            PermissionAccessMode.READ_ONLY,
        ),
        PermissionSpec(
            PermissionPrincipalType.LDAP_GROUP,
            "engineering@example.test",
            PermissionAccessMode.READ_ONLY,
        ),
    )

    _lookup_client(permission_api).validate_apply_principals_globally(
        "lookup", permissions
    )

    assert permission_api.set_calls == []
    assert permission_api.get_calls == [
        ("lookup", "local_user"),
        ("lookup", "local_group"),
        ("lookup", "ldap_user"),
        ("lookup", "ldap_group"),
    ]


def test_global_apply_principal_lookup_missing_is_distinct() -> None:
    permission_api = FakePermissionApi(
        {
            "local_user": _permission_response([]),
            "local_group": _permission_response(
                [
                    {
                        "name": "administrators",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": True,
                    }
                ]
            ),
            "ldap_user": _permission_response([]),
            "ldap_group": _permission_response([]),
        }
    )

    with pytest.raises(PrincipalNotFoundError):
        _lookup_client(permission_api).validate_apply_principals_globally(
            "lookup",
            (
                PermissionSpec(
                    PermissionPrincipalType.LOCAL_USER,
                    "alice",
                    PermissionAccessMode.READ_ONLY,
                ),
            ),
        )
    assert permission_api.set_calls == []


def test_global_apply_principal_lookup_rejects_malformed_and_duplicate_inventory() -> (
    None
):
    malformed = FakePermissionApi(
        {
            "local_user": {
                "success": True,
                "data": {"items": [{"name": "alice"}], "total": 1},
            },
            "local_group": _permission_response(
                [
                    {
                        "name": "administrators",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": True,
                    }
                ]
            ),
        }
    )
    with pytest.raises(ApiError):
        _lookup_client(malformed).validate_apply_principals_globally(
            "lookup",
            (
                PermissionSpec(
                    PermissionPrincipalType.LOCAL_USER,
                    "alice",
                    PermissionAccessMode.READ_ONLY,
                ),
            ),
        )

    duplicate = FakePermissionApi(
        {
            "local_user": _permission_response(
                [
                    {
                        "name": "alice",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": False,
                    },
                    {
                        "name": "alice",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": False,
                    },
                ]
            ),
            "local_group": _permission_response(
                [
                    {
                        "name": "administrators",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": True,
                    }
                ]
            ),
        }
    )
    with pytest.raises(ApiError):
        _lookup_client(duplicate).validate_apply_principals_globally(
            "lookup",
            (
                PermissionSpec(
                    PermissionPrincipalType.LOCAL_USER,
                    "alice",
                    PermissionAccessMode.READ_ONLY,
                ),
            ),
        )


def test_global_apply_principal_lookup_completes_paginated_inventory() -> None:
    class PagedPermissionApi:
        def __init__(self) -> None:
            self.set_calls: list[object] = []
            self.get_calls: list[tuple[str, str, int]] = []
            self.principals = [
                {
                    "name": f"user-{number}",
                    "is_deny": False,
                    "is_readonly": False,
                    "is_writable": False,
                }
                for number in range(51)
            ]

        def set_folder_permissions(self, name, user_group_type, permissions):
            self.set_calls.append((name, user_group_type, permissions))
            return {"success": True}

        def get_folder_permissions(
            self,
            name,
            offset=0,
            limit=50,
            is_unite_permission=False,
            with_inherit=False,
            user_group_type="local_user",
        ):
            self.get_calls.append((name, user_group_type, offset))
            items = (
                self.principals[offset : offset + limit]
                if user_group_type == "local_user"
                else [
                    {
                        "name": "administrators",
                        "is_deny": False,
                        "is_readonly": False,
                        "is_writable": True,
                    }
                ]
            )
            total = len(self.principals) if user_group_type == "local_user" else 1
            return {"success": True, "data": {"items": items, "total": total}}

    permission_api = PagedPermissionApi()
    _lookup_client(permission_api).validate_apply_principals_globally(
        "lookup",
        (
            PermissionSpec(
                PermissionPrincipalType.LOCAL_USER,
                "user-50",
                PermissionAccessMode.READ_ONLY,
            ),
        ),
    )

    assert permission_api.set_calls == []
    assert permission_api.get_calls == [
        ("lookup", "local_user", 0),
        ("lookup", "local_user", 50),
        ("lookup", "local_group", 0),
        ("lookup", "ldap_user", 0),
        ("lookup", "ldap_group", 0),
    ]
