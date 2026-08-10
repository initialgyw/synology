from __future__ import annotations

import runpy

import pytest


def test_module_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    import synology_manager.cli

    monkeypatch.setattr(synology_manager.cli, "main", lambda: 0)
    with pytest.raises(SystemExit) as exited:
        runpy.run_module("synology_manager.__main__", run_name="__main__")
    assert exited.value.code == 0
