import json
import logging as stdlib_logging
from io import StringIO

import pytest

from synology.cli import run
from synology.exceptions import ConfigurationError, PartialOperationError
from synology.models import (
    ConnectionConfig,
    OperationStatus,
    ShareOperationStep,
    SubshareCreateRequest,
    SubshareCreateResult,
    SubsharePreflightResult,
)


class FakeSubshareClient:
    def __init__(
        self,
        *,
        result: SubshareCreateResult | None = None,
        preflight: object | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.preflight_result = preflight
        self.error = error
        self.requests: list[SubshareCreateRequest] = []
        self.preflight_requests: list[SubshareCreateRequest] = []
        self.mutation_calls = 0

    def preflight_subshare(self, request: SubshareCreateRequest) -> object:
        self.preflight_requests.append(request)
        if self.error is not None:
            raise self.error
        if self.preflight_result is None:
            raise AssertionError("unexpected add-dir preflight invocation")
        return self.preflight_result

    def create_preflighted_subshare(self, preflight: object) -> SubshareCreateResult:
        self.mutation_calls += 1
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("unexpected add-dir mutation invocation")
        return self.result

    def create_subshare(self, request: SubshareCreateRequest) -> SubshareCreateResult:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("unexpected add-dir invocation")
        return self.result


class CapturingFactory:
    def __init__(self, client: FakeSubshareClient) -> None:
        self.client = client
        self.config: ConnectionConfig | None = None

    def __call__(
        self,
        config: ConnectionConfig,
        logger: stdlib_logging.Logger,
    ) -> FakeSubshareClient:
        self.config = config
        return self.client


def environment() -> dict[str, str]:
    return {
        "SYN_USERNAME": "environment-user",
        "SYN_PASSWORD": "environment-password",
        "SYN_HOST": "environment-host",
    }


def run_command(
    arguments: list[str],
    factory: CapturingFactory,
    *,
    environ: dict[str, str] | None = None,
) -> tuple[int, StringIO, StringIO]:
    stdout = StringIO()
    stderr = StringIO()
    code = run(
        arguments,
        stdout=stdout,
        stderr=stderr,
        environ=environment() if environ is None else environ,
        client_factory=factory,
    )
    return code, stdout, stderr


def test_dry_run_preflights_without_mutating() -> None:
    preflight = SubsharePreflightResult(
        "projects",
        "archive",
        "/volume1/projects/archive",
        "/projects",
        (
            ShareOperationStep("share-resolution", OperationStatus.SUCCEEDED),
            ShareOperationStep("virtual-mapping", OperationStatus.SUCCEEDED),
            ShareOperationStep("child-preflight", OperationStatus.SUCCEEDED),
        ),
    )
    client = FakeSubshareClient(preflight=preflight)
    factory = CapturingFactory(client)

    code, stdout, stderr = run_command(
        ["add-dir", "-s", "projects", "archive", "--output", "json"],
        factory,
    )

    assert code == 0
    assert factory.config == ConnectionConfig(
        "environment-user", "environment-password", "environment-host"
    )
    assert client.preflight_requests == [SubshareCreateRequest("projects", "archive")]
    assert client.mutation_calls == 0
    assert stderr.getvalue() == ""
    output = json.loads(stdout.getvalue())
    assert output["path"] == "/volume1/projects/archive"
    assert output["created"] is False
    assert [step["status"] for step in output["steps"]] == [
        "succeeded",
        "succeeded",
        "succeeded",
        "planned",
        "planned",
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        [
            "--username",
            "cli-user",
            "--password",
            "cli-password",
            "--host",
            "cli-host",
            "add-dir",
            "-s",
            "projects",
            "archive",
            "--yes",
        ],
        [
            "add-dir",
            "-s",
            "projects",
            "archive",
            "--yes",
            "--username",
            "cli-user",
            "--password",
            "cli-password",
            "--host",
            "cli-host",
        ],
    ],
)
def test_confirmed_command_forwards_request_and_global_options(
    arguments: list[str],
) -> None:
    result = SubshareCreateResult(
        "projects",
        "archive",
        "/volume1/projects/archive",
        True,
        (ShareOperationStep("verify", OperationStatus.SUCCEEDED),),
    )
    client = FakeSubshareClient(
        result=result,
        preflight=SubsharePreflightResult(
            "projects",
            "archive",
            "/volume1/projects/archive",
            "/projects",
            (
                ShareOperationStep("share-resolution", OperationStatus.SUCCEEDED),
                ShareOperationStep("virtual-mapping", OperationStatus.SUCCEEDED),
                ShareOperationStep("child-preflight", OperationStatus.SUCCEEDED),
            ),
        ),
    )
    factory = CapturingFactory(client)

    code, stdout, stderr = run_command(arguments, factory)

    assert code == 0
    assert stderr.getvalue() == ""
    assert "/volume1/projects/archive" in stdout.getvalue()
    assert client.preflight_requests == [SubshareCreateRequest("projects", "archive")]
    assert client.mutation_calls == 1
    assert factory.config == ConnectionConfig("cli-user", "cli-password", "cli-host")


def test_existing_target_during_preflight_exits_10() -> None:
    client = FakeSubshareClient(
        error=ConfigurationError("subshare target already exists: archive")
    )
    factory = CapturingFactory(client)

    code, stdout, stderr = run_command(
        ["add-dir", "-s", "projects", "archive"], factory
    )

    assert code == 10
    assert stdout.getvalue() == ""
    assert "subshare target already exists: archive" in stderr.getvalue()
    assert client.mutation_calls == 0


def test_old_command_name_is_rejected() -> None:
    factory = CapturingFactory(FakeSubshareClient())

    code, stdout, stderr = run_command(
        ["create-subshare", "-s", "projects", "archive"],
        factory,
    )

    assert code == 2
    assert stdout.getvalue() == ""
    assert "invalid choice" in stderr.getvalue()
    assert factory.config is None


@pytest.mark.parametrize("option", ["--permission", "--nfs-permission"])
def test_permission_options_are_not_accepted(option: str) -> None:
    factory = CapturingFactory(FakeSubshareClient())

    code, stdout, stderr = run_command(
        ["add-dir", "-s", "projects", "archive", option, "value"],
        factory,
    )

    assert code == 2
    assert stdout.getvalue() == ""
    assert "unrecognized arguments" in stderr.getvalue()
    assert factory.config is None


def test_partial_result_is_rendered_and_exits_60() -> None:
    result = SubshareCreateResult(
        "projects",
        "archive",
        None,
        False,
        (ShareOperationStep("create", OperationStatus.UNKNOWN),),
    )
    client = FakeSubshareClient(
        error=PartialOperationError("subshare creation outcome is uncertain", result)
    )
    factory = CapturingFactory(client)

    code, stdout, stderr = run_command(
        [
            "add-dir",
            "-s",
            "projects",
            "archive",
            "--yes",
            "--output",
            "json",
        ],
        factory,
    )

    assert code == 60
    assert json.loads(stdout.getvalue())["created"] is False
    assert "subshare creation outcome is uncertain" in stderr.getvalue()
