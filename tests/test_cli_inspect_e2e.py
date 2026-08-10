from __future__ import annotations

import subprocess
import sys


def test_module_help_exposes_only_public_command() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "synology_manager", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "apply-config" in completed.stdout
    assert "inspect" not in completed.stdout and "plan" not in completed.stdout


def test_module_subcommand_help_is_available() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "synology_manager", "apply-config", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "--do-it" in completed.stdout and "--timeout" in completed.stdout
