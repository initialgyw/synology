from __future__ import annotations

import pytest

from synology_manager import cli


def test_root_help_has_only_apply_config(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        cli._parser().parse_args(["--help"])
    assert exited.value.code == 0
    output = capsys.readouterr().out
    assert "apply-config" in output
    assert "inspect" not in output and "plan" not in output and " apply\n" not in output


def test_apply_config_help_is_a_real_extensible_subparser(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exited:
        cli._parser().parse_args(["apply-config", "--help"])
    assert exited.value.code == 0
    output = capsys.readouterr().out
    assert "-c CONFIG" in output and "--do-it" in output and "--verbose" in output
    assert "--host" not in output


def test_global_and_command_option_placement() -> None:
    args = cli._parser().parse_args(
        [
            "--host",
            "nas.invalid",
            "--username",
            "user",
            "--password",
            "password",
            "--ca-bundle",
            "ca.pem",
            "--insecure",
            "apply-config",
            "-c",
            "config.yaml",
            "--do-it",
            "--verbose",
            "--timeout",
            "30",
            "--output",
            "json",
        ]
    )
    assert args.command == "apply-config"
    assert args.timeout == 30.0 and args.output == "json" and args.do_it and args.verbose


@pytest.mark.parametrize(
    "argv",
    [
        ["apply-config", "-c", "config.yaml", "--host", "nas.invalid"],
        ["apply-config", "-c", "config.yaml", "--username", "user"],
        ["apply-config", "-c", "config.yaml", "--password", "password"],
        ["apply-config", "-c", "config.yaml", "--ca-bundle", "ca.pem"],
        ["apply-config", "-c", "config.yaml", "--insecure"],
        ["--timeout", "30", "apply-config", "-c", "config.yaml"],
        ["--output", "json", "apply-config", "-c", "config.yaml"],
        ["--verbose", "apply-config", "-c", "config.yaml"],
        ["--do-it", "apply-config", "-c", "config.yaml"],
        ["apply-config"],
    ],
)
def test_bad_option_placement_or_missing_config_is_argparse_error(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        cli._parser().parse_args(argv)
    assert exited.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [
        ["inspect"],
        ["plan"],
        ["apply"],
        ["apply-config", "-c", "config.yaml", "--apply"],
        ["apply-config", "-c", "config.yaml", "--host-alias", "one"],
        ["apply-config", "-c", "config.yaml", "--allow-delete-nfs"],
        ["apply-config", "-c", "config.yaml", "--allow-delete-shares"],
        ["apply-config", "-c", "config.yaml", "--yes"],
    ],
)
def test_removed_public_commands_and_flags_are_rejected(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        cli._parser().parse_args(argv)
    assert exited.value.code == 2
