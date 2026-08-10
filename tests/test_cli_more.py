from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from synology_manager import cli
from synology_manager.engine import ApplyResult, ProgressEvent
from synology_manager.plan import Action, ActionPlan


class Client:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args: object) -> None:
        pass


def ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_load_host", lambda path: object())
    monkeypatch.setenv("SYN_HOST", "example.invalid")
    monkeypatch.setenv("SYN_USERNAME", "user")
    monkeypatch.setenv("SYN_PASSWORD", "password")
    monkeypatch.setattr(cli, "validate_ca_bundle", lambda path: None)
    monkeypatch.setattr(cli, "DsmClient", Client)


def command(*extra: str) -> list[str]:
    return ["apply-config", "-c", "fictional.yaml", *extra]


def test_dry_run_is_non_mutating_and_has_concise_and_verbose_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    plan = ActionPlan((Action("update", "share:data", "changed"), Action("noop", "nfs:data", "ok")))
    monkeypatch.setattr(cli, "make_plan", lambda *args: plan)
    monkeypatch.setattr(cli, "run_apply", lambda *args, **kwargs: pytest.fail("must not apply"))

    assert cli.main(command()) == 0
    text = capsys.readouterr().out
    assert "Dry run:" in text and f"plan_hash={plan.digest}" in text and "update=1" in text
    assert "share:data [update]" not in text

    assert cli.main(command("--verbose")) == 0
    assert plan.as_text() in capsys.readouterr().out


def test_dry_run_json_is_one_deterministic_document(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    plan = ActionPlan((Action("noop", "share:data", "ok"),))
    monkeypatch.setattr(cli, "make_plan", lambda *args: plan)
    assert cli.main(command("--output", "json")) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == {
        "applied": False,
        "cleanup": {"status": "ok"},
        "mode": "dry_run",
        "plan": plan.as_dict(),
        "plan_hash": plan.digest,
        "status": "dry_run",
    }


def test_apply_prints_preplan_before_mutation_and_binds_the_object(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    plan = ActionPlan((Action("update", "share:data", "changed"),))
    seen: list[ActionPlan] = []

    def apply(client: object, host: object, supplied: ActionPlan, **kwargs: object) -> ApplyResult:
        assert "Plan to apply" in capsys.readouterr().out
        seen.append(supplied)
        return ApplyResult(supplied, supplied, True, "applied", supplied)

    monkeypatch.setattr(cli, "make_plan", lambda *args: plan)
    monkeypatch.setattr(cli, "run_apply", apply)
    assert cli.main(command("--do-it")) == 0
    assert seen == [plan]
    output = capsys.readouterr().out
    assert "Apply result" in output and f"expected_plan_hash={plan.digest}" in output


def test_apply_json_is_single_document_and_stale_has_exit_six(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    displayed = ActionPlan((Action("noop", "share:data", "shown"),))
    current = ActionPlan((Action("update", "share:data", "fresh"),))
    monkeypatch.setattr(cli, "make_plan", lambda *args: displayed)
    monkeypatch.setattr(
        cli,
        "run_apply",
        lambda client, host, supplied, **kwargs: ApplyResult(
            supplied, current, False, "stale", current
        ),
    )
    assert cli.main(command("--do-it", "--output", "json")) == 6
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["mode"] == "apply" and payload["pre_apply_plan"] == displayed.as_dict()
    assert payload["current_plan"] == current.as_dict() and payload["events"] == []


def test_verbose_apply_progress_is_safe_and_ordered_in_text_and_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    plan = ActionPlan((Action("create", "share:data", "x"),))

    def apply(client: object, host: object, supplied: ActionPlan, **kwargs: object) -> ApplyResult:
        callback = kwargs["progress"]
        assert callable(callback)
        callback(ProgressEvent(1, "create", "share:data"))
        callback(ProgressEvent(2, "update", "nfs:data"))
        return ApplyResult(supplied, supplied, True, "applied", supplied)

    monkeypatch.setattr(cli, "make_plan", lambda *args: plan)
    monkeypatch.setattr(cli, "run_apply", apply)
    assert cli.main(command("--do-it", "--verbose")) == 0
    text = capsys.readouterr().out
    assert text.index("Progress: 1 starting create share:data") < text.index(
        "Progress: 2 starting update nfs:data"
    )
    assert "password" not in text and "/volume" not in text

    assert cli.main(command("--do-it", "--verbose", "--output", "json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["events"] == [
        {"kind": "create", "phase": "starting", "resource": "share:data", "sequence": 1},
        {"kind": "update", "phase": "starting", "resource": "nfs:data", "sequence": 2},
    ]


def test_config_is_required_and_timeout_defaults_and_validation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    ready(monkeypatch)
    monkeypatch.setattr(cli, "make_plan", lambda *args: ActionPlan(()))
    assert cli.main(command()) == 0
    with pytest.raises(SystemExit) as exited:
        cli.main(command("--timeout", "0"))
    assert exited.value.code == 2
    assert "finite positive" in capsys.readouterr().err


def test_load_host_returns_the_one_config_host(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("version: 1\nhost: one\nvolumes:\n- name: volume1\n  shares: []\n")
    assert cli._load_host(path).alias == "one"
