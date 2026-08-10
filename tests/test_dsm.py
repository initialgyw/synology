from __future__ import annotations

import json

import pytest

from synology_manager.config import EMPTY_NFS, AclConfig, AclRule, Share
from synology_manager.dsm import (
    Api,
    Credentials,
    DsmClient,
    DsmError,
    UnsupportedCapability,
    operation_error,
)
from synology_manager.engine import _acl_payload
from synology_manager.models import ObservedShare


class Response:
    def __init__(self, value: object) -> None:
        self.value = value

    def json(self) -> object:
        return self.value


class Session:
    def __init__(self, responses: list[object] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, str], object]] = []
        self.responses = responses or [
            {
                "success": True,
                "data": {
                    "SYNO.Core.Share": {
                        "path": "entry.cgi",
                        "minVersion": 1,
                        "maxVersion": 1,
                        "requestFormat": "JSON",
                    },
                    "SYNO.API.Auth": {
                        "path": "auth/custom.cgi",
                        "minVersion": 7,
                        "maxVersion": 7,
                    },
                },
            },
            {"success": True, "data": {"sid": "sanitized-session"}},
            {"success": True, "data": {}},
            {"success": True, "data": {}},
        ]

    def post(self, url: str, *, data: dict[str, str], timeout: float, verify: object) -> Response:
        self.calls.append((url, data, verify))
        return Response(self.responses.pop(0))


def test_parameters_are_json_encoded_and_logout_happens() -> None:
    session = Session()
    client = DsmClient(Credentials("https://example.invalid", "user", "password"), session=session)
    with client:
        client.call(
            "SYNO.Core.Share", "list", {"additional": ["share_quota"], "limit": -1}, version=1
        )
    call = session.calls[2][1]
    assert call["additional"] == '["share_quota"]'
    assert call["limit"] == "-1"
    assert session.calls[-1][1]["method"] == "logout"
    assert "password" not in str(session.calls[2])


def test_acl_self_denial_request_json_encodes_the_payload_contract() -> None:
    session = Session([{"success": True, "data": {}}])
    client = DsmClient(
        Credentials("https://fixture.invalid", "fixture", "fictional"), session=session
    )
    client.sid = "fixture-session"
    client.apis = {"SYNO.Core.ACL": Api("/webapi/entry.cgi", 1, 1, "JSON")}
    item = Share(
        "fixture-share",
        "/volume9",
        "",
        0,
        "present",
        EMPTY_NFS,
        AclConfig(
            True, True, True, (AclRule("group", "fixture-group", "allow", "read_write", "all"),)
        ),
    )
    payload = _acl_payload(
        item, ObservedShare("fixture-share", "/volume9", "", 0, "v1", False), "/fixture-id"
    )

    assert client.call("SYNO.Core.ACL", "check_self_denied", payload, version=1) == {}

    request = session.calls[0][1]
    assert {key: request[key] for key in ("api", "method", "version", "_sid")} == {
        "api": "SYNO.Core.ACL",
        "method": "check_self_denied",
        "version": "1",
        "_sid": "fixture-session",
    }
    assert {key: request[key] for key in payload} == {
        key: json.dumps(value, separators=(",", ":")) for key, value in payload.items()
    }
    assert request["file_path"] == '"/volume9/fixture-share"'
    assert request["files"] == '"/volume9/fixture-share"'
    assert request["dirPaths"] == '"/fixture-id"'
    assert request["inherited"] == "true"
    assert request["acl_recur"] == "true"


@pytest.mark.parametrize(
    "apis",
    [
        {},
        {"SYNO.Core.ACL": Api("/webapi/entry.cgi", 1, 1, None)},
    ],
    ids=["api_family_absent", "json_request_format_absent"],
)
def test_acl_self_denial_requires_advertised_json_api_family(apis: dict[str, Api]) -> None:
    client = DsmClient(
        Credentials("https://fixture.invalid", "fixture", "fictional"), session=object()
    )
    client.sid = "fixture-session"
    client.apis = apis

    with pytest.raises(UnsupportedCapability) as raised:
        client.call("SYNO.Core.ACL", "check_self_denied", {}, version=1)

    assert raised.value.operation() == {
        "api": "SYNO.Core.ACL",
        "method": "check_self_denied",
        "version": 1,
    }


def test_list_shares_requests_quota_metadata() -> None:
    client = DsmClient(Credentials("https://example.invalid", "user", "password"), session=object())
    client.sid = "sanitized-session"
    client.apis = {"SYNO.Core.Share": Api("/webapi/entry.cgi", 1, 1, "JSON")}
    calls: list[tuple[str, str, dict[str, object], int]] = []

    def call(
        api: str, method: str, parameters: dict[str, object], *, version: int
    ) -> dict[str, object]:
        calls.append((api, method, parameters, version))
        return {"shares": [{"name": "fictional-data"}]}

    client.call = call  # type: ignore[method-assign]
    assert client.list_shares() == [{"name": "fictional-data"}]
    assert calls == [
        (
            "SYNO.Core.Share",
            "list",
            {"offset": 0, "limit": -1, "additional": ["share_quota"], "shareType": "all"},
            1,
        )
    ]


def test_failure_envelope_is_not_http_success() -> None:
    session = Session([{"success": False, "error": {"code": 123}}])
    client = DsmClient(Credentials("https://example.invalid", "user", "password"), session=session)
    with pytest.raises(DsmError, match="123"):
        client._post("/webapi/entry.cgi", {"x": "y"})


@pytest.mark.parametrize(
    ("api", "method", "version"),
    [
        ("not an api", "get", 1),
        ("SYNO.Core.Share", "not a method", 1),
        ("SYNO.Core.Share", "get", 0),
        ("SYNO.Core.Share", "get", True),
    ],
)
def test_operation_error_rejects_invalid_metadata(api: str, method: str, version: int) -> None:
    with pytest.raises(ValueError, match="^operation metadata is invalid$"):
        operation_error(DsmError, "safe", api=api, method=method, version=version)


def test_api_requires_advertisement() -> None:
    client = DsmClient(
        Credentials("https://example.invalid", "user", "password"), session=Session()
    )
    client.sid = "session"
    client.apis = {"SYNO.Core.Share": Api("/webapi/entry.cgi", 1, 1, "JSON")}
    with pytest.raises(UnsupportedCapability):
        client.call("missing", "get", {}, version=1)


def test_call_precondition_errors_keep_requested_operation_context() -> None:
    client = DsmClient(Credentials("https://example.invalid", "user", "password"), session=object())
    with pytest.raises(UnsupportedCapability) as unsupported:
        client.call("SYNO.Core.Share", "set", {}, version=1)
    assert unsupported.value.operation() == {
        "api": "SYNO.Core.Share",
        "method": "set",
        "version": 1,
    }

    client.apis = {"SYNO.Core.Share": Api("/webapi/entry.cgi", 1, 1, None)}
    with pytest.raises(UnsupportedCapability) as json_required:
        client.call("SYNO.Core.Share", "set", {}, version=1)
    assert json_required.value.operation() == {
        "api": "SYNO.Core.Share",
        "method": "set",
        "version": 1,
    }

    client.apis = {"SYNO.Core.Share": Api("/webapi/entry.cgi", 1, 1, "JSON")}
    with pytest.raises(DsmError) as missing_sid:
        client.call("SYNO.Core.Share", "set", {}, version=1)
    assert missing_sid.value.operation() == {
        "api": "SYNO.Core.Share",
        "method": "set",
        "version": 1,
    }


@pytest.mark.parametrize(
    ("api", "method", "version"),
    [
        ("SYNO.Core.Share", "validate_set", 1),
        ("SYNO.Core.Share", "create", 1),
        ("SYNO.Core.Share", "set", 1),
        ("SYNO.Core.FileServ.NFS.SharePrivilege", "load", 1),
        ("SYNO.Core.FileServ.NFS.SharePrivilege", "save", 1),
        ("SYNO.Core.ACL", "get", 1),
        ("SYNO.Core.ACL", "check_self_denied", 1),
        ("SYNO.Core.ACL", "set", 1),
        ("SYNO.FileStation.List", "list_share", 2),
        ("SYNO.FileStation.List", "getinfo", 2),
    ],
)
def test_api_failure_has_safe_exact_operation_context(api: str, method: str, version: int) -> None:
    sentinel = "password=secret path=/volume1/private principal=administrator"
    session = Session([{"success": False, "error": {"code": 6211, "detail": sentinel}}])
    client = DsmClient(Credentials("https://example.invalid", "user", "password"), session=session)
    client.sid = "sanitized-session"
    client.apis = {api: Api("/webapi/entry.cgi", version, version, "JSON")}

    with pytest.raises(DsmError) as raised:
        client.call(api, method, {"untrusted": sentinel}, version=version)

    error = raised.value
    expected = f"DSM API error: code=6211 api={api} method={method} version={version}"
    assert str(error) == expected
    assert (error.code, error.api, error.method, error.version) == ("6211", api, method, version)
    assert sentinel not in str(error)
    assert "sanitized-session" not in str(error)
