from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from synology_manager import cli
from synology_manager.config import ConfigError
from synology_manager.dsm import AuthenticationError, DsmError
from synology_manager.plan import ActionPlan


class Client:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args: object) -> None:
        pass


def configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_host", lambda path: object())
    monkeypatch.setattr(cli, "validate_ca_bundle", lambda path: None)
    monkeypatch.setattr(cli, "DsmClient", Client)
    monkeypatch.setattr(cli, "make_plan", lambda *args: ActionPlan(()))


def test_connection_values_prefer_explicit_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYN_HOST", "environment.invalid")
    monkeypatch.setenv("SYN_USERNAME", "environment-user")
    monkeypatch.setenv("SYN_PASSWORD", "environment-password")
    args = cli._parser().parse_args(
        ["--host", "cli.invalid", "--username", "cli-user", "apply-config", "-c", "config.yaml"]
    )
    assert cli._option_or_env(args, "host", "SYN_HOST") == "cli.invalid"
    assert cli._option_or_env(args, "username", "SYN_USERNAME") == "cli-user"
    assert cli._option_or_env(args, "password", "SYN_PASSWORD") == "environment-password"


@pytest.mark.parametrize("missing", ["SYN_HOST", "SYN_USERNAME", "SYN_PASSWORD"])
def test_missing_connection_values_are_validation_errors_without_password(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], missing: str
) -> None:
    configured(monkeypatch)
    monkeypatch.setenv("SYN_HOST", "environment.invalid")
    monkeypatch.setenv("SYN_USERNAME", "user")
    monkeypatch.setenv("SYN_PASSWORD", "password-sentinel")
    monkeypatch.delenv(missing)
    assert cli.main(["apply-config", "-c", "config.yaml"]) == 2
    output = capsys.readouterr().err
    assert "validation error:" in output and "password-sentinel" not in output


@pytest.mark.parametrize(
    "option,environment",
    [("host", "SYN_HOST"), ("username", "SYN_USERNAME"), ("password", "SYN_PASSWORD")],
)
def test_explicit_empty_connection_value_blocks_environment_fallback(
    monkeypatch: pytest.MonkeyPatch, option: str, environment: str
) -> None:
    monkeypatch.setenv(environment, "environment-value")
    arguments = [f"--{option}", "", "apply-config", "-c", "config.yaml"]
    args = cli._parser().parse_args(arguments)
    assert cli._option_or_env(args, option, environment) == ""


def test_explicit_empty_password_overrides_environment_and_is_redacted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    configured(monkeypatch)
    monkeypatch.setenv("SYN_HOST", "environment.invalid")
    monkeypatch.setenv("SYN_USERNAME", "user")
    monkeypatch.setenv("SYN_PASSWORD", "password-sentinel")
    assert cli.main(["--password", "", "apply-config", "-c", "config.yaml"]) == 2
    output = capsys.readouterr().err
    assert "password-sentinel" not in output


def test_downstream_errors_do_not_expose_password(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    configured(monkeypatch)
    secret = "password-sentinel"
    monkeypatch.setenv("SYN_HOST", "environment.invalid")
    monkeypatch.setenv("SYN_USERNAME", "user")
    monkeypatch.setenv("SYN_PASSWORD", secret)

    class FailingClient(Client):
        def __enter__(self) -> Client:
            raise DsmError("safe transport failure")

    monkeypatch.setattr(cli, "DsmClient", FailingClient)
    assert cli.main(["apply-config", "-c", "config.yaml"]) == 3
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err


def test_load_or_tls_errors_keep_existing_exit_codes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        cli, "_load_host", lambda path: (_ for _ in ()).throw(ConfigError("bad config"))
    )
    assert cli.main(["apply-config", "-c", "config.yaml"]) == 2
    assert "bad config" in capsys.readouterr().err

    configured(monkeypatch)
    monkeypatch.setenv("SYN_HOST", "example.invalid")
    monkeypatch.setenv("SYN_USERNAME", "user")
    monkeypatch.setenv("SYN_PASSWORD", "password")
    monkeypatch.setattr(
        cli,
        "validate_ca_bundle",
        lambda path: (_ for _ in ()).throw(AuthenticationError("bad TLS")),
    )
    assert cli.main(["apply-config", "-c", "config.yaml"]) == 3
    assert "bad TLS" in capsys.readouterr().err


def test_ca_bundle_path_is_not_read_by_cli_test(tmp_path: Path) -> None:
    # The DSM helper owns CA validation; this test only keeps the public parser path typed.
    args = cli._parser().parse_args(
        ["--ca-bundle", str(tmp_path / "ca.pem"), "apply-config", "-c", "x"]
    )
    assert args.ca_bundle == tmp_path / "ca.pem"
