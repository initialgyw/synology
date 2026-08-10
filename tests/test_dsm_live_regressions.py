from __future__ import annotations

from typing import Any

import pytest
import requests

from synology_manager.dsm import (
    Api,
    AuthenticationError,
    Credentials,
    CredentialValidationError,
    DsmClient,
    DsmError,
    UnsupportedCapability,
    credentials,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("nas.invalid", "https://nas.invalid:5001"),
        ("https://nas.invalid", "https://nas.invalid:5001"),
        ("https://nas.invalid:443", "https://nas.invalid:443"),
        ("nas.invalid:7443", "https://nas.invalid:7443"),
        ("[2001:db8::1]", "https://[2001:db8::1]:5001"),
        ("[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ],
)
def test_credentials_default_secure_dsm_port_and_preserve_explicit_port(
    raw: str, expected: str
) -> None:
    assert credentials(raw, "user", "fictional").host == expected


@pytest.mark.parametrize(
    "raw",
    [
        "http://nas.invalid",
        "https://user@nas.invalid",
        "https://nas.invalid/",
        "https://nas.invalid/path",
        "https://nas.invalid?x=y",
        "https://nas.invalid:0",
        "https://nas.invalid:bad",
        "https://[bad-ipv6]",
        "2001:db8::1",
        "2001:db8::1:8443",
        "nas.invalid\n",
    ],
)
def test_credentials_reject_unsafe_hosts(raw: str) -> None:
    with pytest.raises(CredentialValidationError):
        credentials(raw, "user", "fictional")


class Response:
    def __init__(self, data: object) -> None:
        self.data = data

    def json(self) -> object:
        if isinstance(self.data, BaseException):
            raise self.data
        return self.data


class Session:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, str]]] = []

    def post(self, url: str, *, data: dict[str, str], timeout: float, verify: object) -> Response:
        self.calls.append((url, data))
        return Response(self.responses.pop(0))


def descriptor(path: str, request_format: str | None = "JSON") -> dict[str, object]:
    value: dict[str, object] = {"path": path, "minVersion": 1, "maxVersion": 9}
    if request_format is not None:
        value["requestFormat"] = request_format
    return value


def test_discovery_accepts_missing_metadata_but_operations_require_json() -> None:
    client = DsmClient(Credentials("https://example.invalid:5001", "u", "p"), session=object())
    client._post = lambda path, data: {"SYNO.Package.Optional": descriptor("entry.cgi", None)}  # type: ignore[method-assign]
    client.discover()
    assert client.apis["SYNO.Package.Optional"].request_format is None
    client.sid = "fictional"
    with pytest.raises(UnsupportedCapability, match="JSON"):
        client.call("SYNO.Package.Optional", "get", {}, version=1)


def test_login_logout_use_advertised_auth_route_and_raw_parameters() -> None:
    session = Session(
        [
            {
                "success": True,
                "data": {
                    "SYNO.API.Auth": {"path": "auth/custom.cgi", "minVersion": 7, "maxVersion": 7}
                },
            },
            {"success": True, "data": {"sid": "fictional-session"}},
            {"success": True, "data": {}},
        ]
    )
    client = DsmClient(Credentials("https://example.invalid:5001", "u", "p"), session=session)
    with client:
        assert client.sid == "fictional-session"
    assert session.calls[1][0].endswith("/webapi/auth/custom.cgi")
    assert session.calls[1][1]["version"] == "7"
    assert session.calls[2][0].endswith("/webapi/auth/custom.cgi")
    assert session.calls[2][1]["_sid"] == "fictional-session"
    assert client.sid is None


def test_non_json_response_is_protocol_error_not_transport_leak() -> None:
    class JsonDecodeFailure(requests.RequestException, ValueError):
        pass

    client = DsmClient(
        Credentials("https://private.invalid:5001", "u", "p"),
        session=Session([JsonDecodeFailure("body /webapi/secret")]),
    )
    with pytest.raises(DsmError, match="response was not JSON") as raised:
        client._post("/webapi/secret", {"x": "y"})
    assert "private.invalid" not in str(raised.value)
    assert "secret" not in str(raised.value)


@pytest.mark.parametrize(
    "response",
    [
        ValueError("raw-response-password"),
        ["raw-response-password"],
        {"success": True, "data": ["raw-response-password"]},
    ],
)
def test_protocol_response_errors_keep_only_operation_context(response: object) -> None:
    client = DsmClient(
        Credentials("https://example.invalid:5001", "u", "p"), session=Session([response])
    )
    client.apis = {"SYNO.Core.Share": Api("/webapi/entry.cgi", 1, 1, "JSON")}
    client.sid = "sid-sentinel"

    with pytest.raises(DsmError) as raised:
        client.call("SYNO.Core.Share", "list", {"path": "/volume1/private"}, version=1)

    error = raised.value
    assert error.operation() == {"api": "SYNO.Core.Share", "method": "list", "version": 1}
    assert "raw-response-password" not in str(error)
    assert "sid-sentinel" not in str(error)
    assert "/volume1/private" not in str(error)


def test_schema_errors_keep_the_last_fixed_operation_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "path=/volume1/private principal=administrator"
    client = DsmClient(Credentials("https://example.invalid:5001", "u", "p"), session=object())
    client.apis = {
        name: Api("/webapi/entry.cgi", 1, 9, "JSON")
        for name in ("SYNO.DSM.Info", "SYNO.Core.System", "SYNO.Core.FileServ.NFS")
    }
    client.sid = "sid-sentinel"
    replies: list[dict[str, object]] = [
        {"model": "DS1522+", "version_string": "7.4.1-90080"},
        {"model": "DS1522+"},
        {"enable_nfs": sentinel},
    ]
    monkeypatch.setattr(client, "call", lambda *args, **kwargs: replies.pop(0))

    with pytest.raises(DsmError) as raised:
        client.inspect()

    assert raised.value.operation() == {
        "api": "SYNO.Core.FileServ.NFS",
        "method": "get",
        "version": 3,
    }
    assert sentinel not in str(raised.value)


@pytest.mark.parametrize(
    ("operation", "reply", "expected"),
    [
        ("shares", {"shares": "share=/volume1/private"}, ("SYNO.Core.Share", "list", 1)),
        (
            "nfs_enabled",
            {"enable_nfs": "share=/volume1/private"},
            ("SYNO.Core.FileServ.NFS", "get", 3),
        ),
        (
            "nfs_rules",
            {"rule": "share=/volume1/private"},
            ("SYNO.Core.FileServ.NFS.SharePrivilege", "load", 1),
        ),
    ],
)
def test_share_and_nfs_schema_errors_are_contextualized(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    reply: dict[str, object],
    expected: tuple[str, str, int],
) -> None:
    client = DsmClient(Credentials("https://example.invalid:5001", "u", "p"), session=object())
    monkeypatch.setattr(client, "call", lambda *args, **kwargs: reply)

    with pytest.raises(DsmError) as raised:
        if operation == "shares":
            client.list_shares()
        elif operation == "nfs_enabled":
            client.nfs_enabled()
        else:
            client.nfs_rules("private-share")

    assert raised.value.operation() == dict(
        zip(("api", "method", "version"), expected, strict=True)
    )
    assert "private" not in str(raised.value)


def test_resolver_schema_error_is_contextualized_without_request_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = DsmClient(Credentials("https://example.invalid:5001", "u", "p"), session=object())
    monkeypatch.setattr(
        client, "call", lambda *args, **kwargs: {"shares": "raw=/private", "total": 1}
    )

    with pytest.raises(UnsupportedCapability) as raised:
        client.resolve_share_file_id("private-share", "/volume1/private")

    assert raised.value.operation() == {
        "api": "SYNO.FileStation.List",
        "method": "list_share",
        "version": 2,
    }
    assert "private" not in str(raised.value)


def test_resolver_getinfo_schema_error_is_contextualized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = DsmClient(Credentials("https://example.invalid:5001", "u", "p"), session=object())
    replies: list[dict[str, object]] = [
        {
            "shares": [
                {
                    "name": "data",
                    "isdir": True,
                    "additional": {"real_path": "/volume1/data"},
                    "path": "/data",
                }
            ],
            "total": 1,
        },
        {"files": "raw-file-id=/private"},
    ]
    monkeypatch.setattr(client, "call", lambda *args, **kwargs: replies.pop(0))

    with pytest.raises(UnsupportedCapability) as raised:
        client.resolve_share_file_id("data", "/volume1/data")

    assert raised.value.operation() == {
        "api": "SYNO.FileStation.List",
        "method": "getinfo",
        "version": 2,
    }
    assert "private" not in str(raised.value)


@pytest.mark.parametrize("method", ["login", "logout"])
@pytest.mark.parametrize("route", [None, Api("unsafe-route", 7, 7, None)])
def test_unsupported_auth_v7_is_contextualized(method: str, route: Api | None) -> None:
    client = DsmClient(Credentials("https://example.invalid:5001", "u", "p"), session=object())
    if route is not None:
        client.apis = {"SYNO.API.Auth": route}

    with pytest.raises(UnsupportedCapability) as raised:
        client._auth_api(method)

    assert raised.value.operation() == {"api": "SYNO.API.Auth", "method": method, "version": 7}


def test_missing_login_sid_is_contextualized() -> None:
    client = DsmClient(
        Credentials("https://example.invalid:5001", "u", "p"),
        session=Session([{"success": True, "data": {}}]),
    )
    client.apis = {"SYNO.API.Auth": Api("/webapi/auth.cgi", 7, 7, None)}

    with pytest.raises(AuthenticationError) as raised:
        client.login()

    assert raised.value.operation() == {"api": "SYNO.API.Auth", "method": "login", "version": 7}


def test_logout_records_safe_cleanup_without_logging(caplog: pytest.LogCaptureFixture) -> None:
    sentinel = "sid=private-secret path=/volume1/private"
    client = DsmClient(
        Credentials("https://example.invalid:5001", "u", "p"),
        session=Session([{"success": False, "error": {"code": 6211, "detail": sentinel}}]),
    )
    client.apis = {"SYNO.API.Auth": Api("/webapi/auth.cgi", 7, 7, None)}
    client.sid = "sid-sentinel"

    client.logout()

    assert client.sid is None and client.cleanup_failed
    assert client.cleanup_operation == "logout"
    assert caplog.messages == []
    assert sentinel not in caplog.text and "sid-sentinel" not in caplog.text


def test_prefixed_version_is_curated_without_raw_value(monkeypatch: pytest.MonkeyPatch) -> None:
    client = DsmClient(Credentials("https://example.invalid:5001", "u", "p"), session=object())
    client.apis = {
        name: Api("/webapi/entry.cgi", 1, 9, "JSON")
        for name in ("SYNO.DSM.Info", "SYNO.Core.System", "SYNO.Core.FileServ.NFS")
    }
    client.sid = "fictional"
    replies: list[dict[str, Any]] = [
        {"model": "DS1522+", "version_string": "DSM 7.4.1-90080 Update 1"},
        {"model": "DS1522+", "firmware_ver": "ignored"},
        {
            "enable_nfs": True,
            "enable_nfs_v4": False,
            "enabled_minor_ver": 0,
            "support_major_ver": 3,
            "support_minor_ver": 0,
        },
    ]
    monkeypatch.setattr(client, "call", lambda *args, **kwargs: replies.pop(0))
    output = client.inspect()
    assert output["version"] == {"major": 7, "minor": 4, "patch": 1, "build": 90080, "update": 1}
    assert "DSM 7.4" not in str(output)
