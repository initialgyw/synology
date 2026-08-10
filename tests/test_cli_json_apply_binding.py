from __future__ import annotations

import json
from typing import Any

import pytest

from synology_manager import cli
from synology_manager.engine import ApplyResult, PartialApplyError, ProgressEvent
from synology_manager.plan import Action, ActionPlan


class Client:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.cleanup_failed = False

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args: object) -> None:
        pass


class CleanupFailingClient(Client):
    def __exit__(self, *args: object) -> None:
        self.cleanup_failed = True


def ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_host", lambda path: object())
    monkeypatch.setattr(cli, "validate_ca_bundle", lambda path: None)
    monkeypatch.setattr(cli, "DsmClient", Client)
    monkeypatch.setenv("SYN_HOST", "example.invalid")
    monkeypatch.setenv("SYN_USERNAME", "user")
    monkeypatch.setenv("SYN_PASSWORD", "password")


def command(*arguments: str) -> list[str]:
    return ["apply-config", "-c", "config.yaml", "--do-it", "--output", "json", *arguments]


def test_success_json_uses_exact_displayed_preplan_and_is_one_document(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    displayed = ActionPlan((Action("update", "share:data", "displayed"),))
    foreign = ActionPlan((Action("noop", "share:other", "foreign"),))
    monkeypatch.setattr(cli, "make_plan", lambda *args: displayed)
    monkeypatch.setattr(
        cli,
        "run_apply",
        lambda client, host, plan, **kwargs: ApplyResult(
            foreign, foreign, True, "applied", foreign
        ),
    )

    assert cli.main(["--insecure", *command()]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["pre_apply_plan"] == displayed.as_dict()
    assert payload["expected_plan_hash"] == displayed.digest
    assert payload["current_plan"] == foreign.as_dict()
    assert payload["cleanup"] == {"status": "ok"}


def test_runtime_error_after_mutation_event_is_partial_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    displayed = ActionPlan((Action("update", "share:data", "displayed"),))

    def failing(client: object, host: object, plan: ActionPlan, **kwargs: object) -> ApplyResult:
        callback = kwargs["progress"]
        assert callable(callback)
        callback(ProgressEvent(1, "update", "share:data"))
        raise RuntimeError("raw-secret")

    monkeypatch.setattr(cli, "make_plan", lambda *args: displayed)
    monkeypatch.setattr(cli, "run_apply", failing)
    assert cli.main(command()) == 6
    captured = capsys.readouterr()
    assert captured.err == "" and len(captured.out.splitlines()) == 1
    payload = json.loads(captured.out)
    assert payload["status"] == "partial_failure" and payload["exit_code"] == 6
    assert payload["pre_apply_plan"] == displayed.as_dict()
    assert "raw-secret" not in captured.out


def test_stale_and_partial_json_bind_the_displayed_preplan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    displayed = ActionPlan((Action("noop", "share:data", "displayed"),))
    foreign = ActionPlan((Action("update", "share:data", "current"),))
    monkeypatch.setattr(cli, "make_plan", lambda *args: displayed)
    monkeypatch.setattr(
        cli,
        "run_apply",
        lambda client, host, plan, **kwargs: ApplyResult(foreign, foreign, False, "stale", foreign),
    )
    assert cli.main(command()) == 6
    stale_lines = capsys.readouterr().out.splitlines()
    assert len(stale_lines) == 1
    stale = json.loads(stale_lines[0])
    assert stale["pre_apply_plan"] == displayed.as_dict()
    assert stale["expected_plan_hash"] == displayed.digest

    partial = PartialApplyError("share:data", "share_set")
    attempts = 0

    def make_plan(*args: object) -> ActionPlan:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return displayed
        raise RuntimeError("safe observation failure")

    monkeypatch.setattr(cli, "make_plan", make_plan)
    monkeypatch.setattr(cli, "run_apply", lambda *args, **kwargs: (_ for _ in ()).throw(partial))
    assert cli.main(command()) == 6
    partial_lines = capsys.readouterr().out.splitlines()
    assert len(partial_lines) == 1
    partial_payload = json.loads(partial_lines[0])
    assert partial_payload["pre_apply_plan"] == displayed.as_dict()
    assert partial_payload["expected_plan_hash"] == displayed.digest
    assert partial_payload["cleanup"] == {"status": "ok"}


@pytest.mark.parametrize("do_it", [False, True])
def test_cleanup_failure_changes_success_to_nonzero_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], do_it: bool
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(cli, "DsmClient", CleanupFailingClient)
    plan = ActionPlan(())
    monkeypatch.setattr(cli, "make_plan", lambda *args: plan)
    arguments = ["apply-config", "-c", "config.yaml", "--output", "json"]
    if do_it:
        arguments.append("--do-it")
        monkeypatch.setattr(
            cli,
            "run_apply",
            lambda *args, **kwargs: ApplyResult(plan, plan, True, "applied", plan),
        )

    assert cli.main(arguments) == 1
    captured = capsys.readouterr()
    assert captured.err == "" and len(captured.out.splitlines()) == 1
    payload = json.loads(captured.out)
    assert payload["cleanup"] == {
        "message": "DSM session cleanup did not complete",
        "status": "failed",
    }
    assert payload["exit_code"] == 1


def test_cleanup_failure_preserves_partial_exit_code_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(cli, "DsmClient", CleanupFailingClient)
    plan = ActionPlan(())
    monkeypatch.setattr(cli, "make_plan", lambda *args: plan)
    monkeypatch.setattr(
        cli,
        "run_apply",
        lambda *args, **kwargs: (_ for _ in ()).throw(PartialApplyError("share:data", "share_set")),
    )

    assert cli.main(command()) == 6
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["exit_code"] == 6 and payload["cleanup"]["status"] == "failed"
