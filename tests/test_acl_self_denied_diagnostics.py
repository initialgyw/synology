from __future__ import annotations

from collections import UserDict
from typing import Any, cast

import pytest

from synology_manager.config import EMPTY_NFS, AclConfig, AclRule, Share
from synology_manager.dsm import DsmClient, UnsupportedCapability
from synology_manager.engine import (
    DriftError,
    SafetyError,
    _apply_acl,
    _preflight_acl,
    _validate_acl_self_denied_data,
)
from synology_manager.models import ObservedShare

SENSITIVE = {
    "path": "/volume1/private/customer-data",
    "principal": "alice@example.invalid",
    "id": "file-123",
    "session": "sid-secret",
    "credential": "password-secret",
}


class SensitiveCustomValue:
    def __repr__(self) -> str:
        return f"SensitiveCustomValue({SENSITIVE})"


def _item() -> Share:
    return Share(
        "data",
        "/volume1",
        "wanted",
        1024,
        "present",
        EMPTY_NFS,
        AclConfig(
            True, False, False, (AclRule("special", "Owner", "allow", "full_control", "all"),)
        ),
    )


class SelfDeniedClient:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls: list[str] = []

    def acl(self, path: str) -> dict[str, Any]:
        return {
            "acl_editable": True,
            "change_permission": True,
            "is_acl": True,
            "is_inherited": False,
            "acl": [],
        }

    def resolve_share_file_id(self, name: str, physical: str) -> str:
        return "/data"

    def call(
        self, api: str, method: str, parameters: dict[str, Any], *, version: int
    ) -> dict[str, Any]:
        assert (api, version) == ("SYNO.Core.ACL", 1)
        self.calls.append(method)
        if method == "check_self_denied":
            return cast(dict[str, Any], self.response)
        assert method == "set"
        return {}


@pytest.mark.parametrize(
    ("response", "metadata"),
    [
        ({"warning": SENSITIVE["path"]}, "response keys/types: warning:string"),
        ({"warnings": [SENSITIVE]}, "response keys/types: warnings:array"),
        (
            {"is_denied": False, "warning": SENSITIVE},
            "response keys/types: is_denied:boolean, warning:object",
        ),
        ({"is_denied": 0}, "response keys/types: is_denied:number"),
        ({"is_denied": "false"}, "response keys/types: is_denied:string"),
        ({"confirmation_required": True}, "response keys/types: confirmation_required:boolean"),
        ({"raw": SENSITIVE}, "response keys/types: raw:object"),
        ({"warning-count": 7}, "response keys/types: <nonstandard-key>:number"),
        ({7: 1.5}, "response keys/types: <nonstandard-key>:number"),
        (
            {"count": 7, "ratio": 1.5},
            "response keys/types: count:number, ratio:number",
        ),
        ({"warnings": (SENSITIVE["path"],)}, "response keys/types: warnings:unknown"),
        ({"warnings": {SENSITIVE["session"]}}, "response keys/types: warnings:unknown"),
        ({"raw": SensitiveCustomValue()}, "response keys/types: raw:unknown"),
        ([SENSITIVE], "response type=array"),
        (UserDict({"is_denied": False}), "response type=unknown"),
        (None, "response type=null"),
    ],
    ids=[
        "warning",
        "warnings-list",
        "extra-key-sensitive",
        "integer-not-boolean",
        "string-not-boolean",
        "confirmation",
        "nested-sensitive",
        "unusual-key-integer",
        "non-string-key-float",
        "numeric-values",
        "tuple-value",
        "set-value",
        "custom-value",
        "non-mapping-array-sensitive",
        "non-dict-mapping",
        "malformed",
    ],
)
def test_acl_self_denied_diagnostics_are_safe_and_block_set(response: Any, metadata: str) -> None:
    with pytest.raises(UnsupportedCapability) as raised:
        _validate_acl_self_denied_data(response)

    assert str(raised.value) == (
        f"ACL check_self_denied returned "
        f"{'unverified non-empty data' if isinstance(response, dict) else 'malformed data'} "
        f"({metadata}): api=SYNO.Core.ACL method=check_self_denied version=1"
    )
    assert raised.value.operation() == {
        "api": "SYNO.Core.ACL",
        "method": "check_self_denied",
        "version": 1,
    }
    rendered = str(raised.value)
    for value in SENSITIVE.values():
        assert value not in rendered

    for operation in (_preflight_acl, _apply_acl):
        client = SelfDeniedClient(response)
        with pytest.raises(UnsupportedCapability):
            operation(
                cast(DsmClient, client),
                _item(),
                ObservedShare("data", "/volume1", "wanted", 1024, "v1", False),
            )
        assert client.calls == ["check_self_denied"]


@pytest.mark.parametrize("response", [{}, {"is_denied": False}])
def test_acl_self_denied_accepts_verified_safe_shapes(response: dict[str, Any]) -> None:
    _validate_acl_self_denied_data(response)

    preflight_client = SelfDeniedClient(response)
    _preflight_acl(
        cast(DsmClient, preflight_client),
        _item(),
        ObservedShare("data", "/volume1", "wanted", 1024, "v1", False),
    )
    assert preflight_client.calls == ["check_self_denied"]

    apply_client = SelfDeniedClient(response)
    with pytest.raises(DriftError, match="ACL postcondition verification failed"):
        _apply_acl(
            cast(DsmClient, apply_client),
            _item(),
            ObservedShare("data", "/volume1", "wanted", 1024, "v1", False),
        )
    assert apply_client.calls == ["check_self_denied", "set"]


def test_acl_self_denied_true_is_a_safety_error_and_blocks_set() -> None:
    response = {"is_denied": True}
    with pytest.raises(SafetyError) as raised:
        _validate_acl_self_denied_data(response)

    assert str(raised.value) == (
        "ACL self-denial check denied ACL replacement: "
        "api=SYNO.Core.ACL method=check_self_denied version=1"
    )
    assert raised.value.operation() == {
        "api": "SYNO.Core.ACL",
        "method": "check_self_denied",
        "version": 1,
    }

    for operation in (_preflight_acl, _apply_acl):
        client = SelfDeniedClient(response)
        with pytest.raises(SafetyError):
            operation(
                cast(DsmClient, client),
                _item(),
                ObservedShare("data", "/volume1", "wanted", 1024, "v1", False),
            )
        assert client.calls == ["check_self_denied"]
