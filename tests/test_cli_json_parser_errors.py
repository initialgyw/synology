from __future__ import annotations

import json

import pytest

from synology_manager import cli


@pytest.mark.parametrize(
    "argv",
    [
        ["apply-config", "--output", "json"],
        ["apply-config", "-c", "config.yaml", "--timeout", "nan", "--output=json"],
        ["apply-config", "-c", "config.yaml", "--host", "secret.invalid", "--output", "json"],
        ["unknown", "--output", "json", "--password", "password-sentinel"],
    ],
)
def test_json_parser_errors_are_one_safe_document(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exited:
        cli.main(argv)
    assert exited.value.code == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["status"] == "error" and payload["exit_code"] == 2
    assert payload["pre_apply_plan"] is None and payload["current_plan"] is None
    assert payload["events"] == []
    assert "password-sentinel" not in captured.out


def test_parser_json_mode_does_not_leak_between_main_invocations(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        cli.main(["apply-config", "--output", "json"])
    first = capsys.readouterr()
    assert first.err == "" and json.loads(first.out)["status"] == "error"

    with pytest.raises(SystemExit):
        cli.main(["apply-config"])
    second = capsys.readouterr()
    assert second.out == ""
    assert "usage:" in second.err


def test_preplan_validation_json_has_explicit_null_plan_fields(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SYN_HOST", "example.invalid")
    monkeypatch.setenv("SYN_USERNAME", "user")
    monkeypatch.setenv("SYN_PASSWORD", "password")
    assert (
        cli.main(["--password", "", "apply-config", "-c", "config.yaml", "--output", "json"]) == 2
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["pre_apply_plan"] is None
    assert payload["expected_plan_hash"] is None
    assert payload["current_plan"] is None
    assert payload["current_plan_hash"] is None
    assert payload["events"] == []
