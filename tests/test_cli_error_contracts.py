from __future__ import annotations

import json
from typing import Any

import pytest

from synology_manager import cli, dsm
from synology_manager.config import ConfigError
from synology_manager.dsm import (
    AuthenticationError,
    CredentialValidationError,
    DsmError,
    UnsupportedCapability,
)
from synology_manager.engine import DriftError, PartialApplyError, SafetyError
from synology_manager.plan import ActionPlan


class Client:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args: object) -> None:
        pass


def ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_host", lambda path: object())
    monkeypatch.setattr(cli, "validate_ca_bundle", lambda path: None)
    monkeypatch.setattr(cli, "DsmClient", Client)
    monkeypatch.setenv("SYN_HOST", "example.invalid")
    monkeypatch.setenv("SYN_USERNAME", "user")
    monkeypatch.setenv("SYN_PASSWORD", "password")


@pytest.mark.parametrize(
    ("error", "exit_code", "kind"),
    [
        (ConfigError("safe config"), 2, "validation"),
        (CredentialValidationError("safe credential"), 2, "validation"),
        (AuthenticationError("safe auth"), 3, "authentication"),
        (SafetyError("safe safety"), 4, "safety"),
        (UnsupportedCapability("safe capability"), 5, "unsupported_capability"),
        (DriftError("safe drift"), 6, "drift"),
        (DsmError("safe DSM"), 3, "dsm"),
    ],
)
def test_expected_errors_emit_one_json_document(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    exit_code: int,
    kind: str,
) -> None:
    ready(monkeypatch)
    if isinstance(error, (ConfigError, CredentialValidationError)):
        monkeypatch.setattr(cli, "_load_host", lambda path: (_ for _ in ()).throw(error))
    else:
        monkeypatch.setattr(cli, "make_plan", lambda *args: (_ for _ in ()).throw(error))
    assert cli.main(["apply-config", "-c", "config.yaml", "--output", "json"]) == exit_code
    captured = capsys.readouterr()
    assert captured.err == ""
    assert len(captured.out.splitlines()) == 1
    payload = json.loads(captured.out)
    assert payload["status"] == "error" and payload["applied"] is False
    assert payload["exit_code"] == exit_code and payload["error"]["type"] == kind


def test_internal_error_is_redacted_and_timeout_is_finite(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(
        cli, "make_plan", lambda *args: (_ for _ in ()).throw(RuntimeError("raw-secret-value"))
    )
    assert cli.main(["apply-config", "-c", "config.yaml", "--output", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"] == {
        "message": "an unexpected internal error occurred",
        "type": "internal_error",
    }
    # Parser-level timeout failures retain standard argparse exit-2 behavior.
    with pytest.raises(SystemExit) as exited:
        cli.main(["apply-config", "-c", "config.yaml", "--timeout", "nan", "--output", "json"])
    assert exited.value.code == 2


def test_partial_json_never_equates_preplan_and_current_plan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    plan = ActionPlan(())
    error = PartialApplyError("share:data", "share_create", DsmError("DSM API error"))
    attempts = 0

    def make_plan(*args: object) -> ActionPlan:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return plan
        raise DsmError("safe re-observation failure")

    monkeypatch.setattr(cli, "make_plan", make_plan)
    monkeypatch.setattr(cli, "run_apply", lambda *args, **kwargs: (_ for _ in ()).throw(error))
    assert cli.main(["apply-config", "-c", "config.yaml", "--do-it", "--output", "json"]) == 6
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "partial_failure" and payload["pre_apply_plan"] == plan.as_dict()
    assert "current_plan" not in payload and payload["error"]["phase"] == "share_create"


@pytest.mark.parametrize("output", ["json", "text"])
def test_client_enter_failure_is_rendered_after_cleanup(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], output: str
) -> None:
    class EnterFailingClient:
        cleanup_failed = True
        cleanup_error = DsmError("DSM session cleanup did not complete")

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> EnterFailingClient:
            raise AuthenticationError("safe setup failure")

        def __exit__(self, *args: object) -> None:
            raise AssertionError("__exit__ is not called after a failed __enter__")

    ready(monkeypatch)
    monkeypatch.setattr(cli, "DsmClient", EnterFailingClient)
    assert cli.main(["apply-config", "-c", "config.yaml", "--output", output]) == 3
    captured = capsys.readouterr()
    if output == "json":
        assert captured.err == "" and len(captured.out.splitlines()) == 1
        payload = json.loads(captured.out)
        assert payload["pre_apply_plan"] is None
        assert payload["exit_code"] == 3 and payload["error"]["type"] == "authentication"
        assert payload["cleanup"] == {
            "message": "DSM session cleanup did not complete",
            "status": "failed",
        }
    else:
        assert captured.out == ""
        assert captured.err.count("authentication or TLS error: safe setup failure") == 1
        assert captured.err.count("WARNING: DSM session cleanup did not complete") == 1


def test_real_client_setup_failure_with_cleanup_failures_is_silent_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class ClosingSession:
        def close(self) -> None:
            raise RuntimeError("close-secret")

    ready(monkeypatch)
    monkeypatch.setattr(cli, "DsmClient", dsm.DsmClient)
    monkeypatch.setattr("synology_manager.dsm.requests.Session", ClosingSession)
    monkeypatch.setattr(
        dsm.DsmClient,
        "discover",
        lambda self: (_ for _ in ()).throw(AuthenticationError("safe setup failure")),
    )
    monkeypatch.setattr(
        dsm.DsmClient,
        "logout",
        lambda self: (_ for _ in ()).throw(DsmError("logout-secret")),
    )

    assert cli.main(["apply-config", "-c", "config.yaml", "--output", "json"]) == 3
    captured = capsys.readouterr()
    assert captured.err == "" and len(captured.out.splitlines()) == 1
    payload = json.loads(captured.out)
    assert payload["pre_apply_plan"] is None
    assert payload["exit_code"] == 3 and payload["error"]["type"] == "authentication"
    assert payload["cleanup"] == {
        "message": "DSM session cleanup did not complete",
        "status": "failed",
    }
    assert "secret" not in captured.out
