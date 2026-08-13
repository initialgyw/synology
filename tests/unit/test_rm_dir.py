import json
import logging
from io import StringIO

import pytest

from synology.cli import run
from synology.exceptions import ConfigurationError, PartialOperationError
from synology.models import (
    ConnectionConfig,
    OperationStatus,
    ShareOperationStep,
    SubshareDeletePreflightResult,
    SubshareDeleteRequest,
    SubshareDeleteResult,
)
from synology.subshares import SynSubshareClient


class FakeShare:
    def get_folder(self, name: str, additional: list[str]) -> object:
        return {"success": True, "data": {"name": name, "vol_path": "/volume1"}}


class FakeFiles:
    def __init__(self, child_records: dict[str, list[dict[str, object]]]) -> None:
        self.child_records = child_records
        self.delete_calls: list[tuple[str, bool]] = []
        self.deleted = False

    def get_list_share(self, additional: list[str], offset: int, limit: int) -> object:
        return {
            "success": True,
            "data": {
                "shares": [
                    {
                        "name": "projects",
                        "path": "/projects",
                        "isdir": True,
                        "additional": {"real_path": "/volume1/projects"},
                    }
                ],
                "offset": 0,
                "total": 1,
            },
        }

    def get_file_list(
        self, folder_path: str, offset: int, limit: int, additional: list[str]
    ) -> object:
        records = [] if self.deleted else self.child_records.get(folder_path, [])
        page = records[offset : offset + limit]
        return {
            "success": True,
            "data": {"files": page, "offset": offset, "total": len(records)},
        }

    def get_file_info(self, path: str, additional_param: list[str]) -> object:
        return {"success": True, "data": {"files": []}}

    def create_folder(self, **kwargs: object) -> object:
        return {"success": True}

    def delete_blocking_function(self, path: str, recursive: bool) -> object:
        self.delete_calls.append((path, recursive))
        self.deleted = True
        return {"success": True}


def child(name: str, isdir: bool = True) -> dict[str, object]:
    return {"name": name, "isdir": isdir}


def client(files: FakeFiles) -> SynSubshareClient:
    return SynSubshareClient(
        ConnectionConfig("user", "password", "nas"),
        logging.getLogger(),
        share_factory=lambda **_: FakeShare(),
        filestation_factory=lambda **_: files,
    )


def test_rm_dir_preflight_requires_empty_directory() -> None:
    files = FakeFiles(
        {
            "/projects": [child("archive")],
            "/projects/archive": [],
        }
    )
    preflight = client(files).preflight_delete_dir(
        SubshareDeleteRequest("projects", "archive")
    )
    assert preflight.path == "/volume1/projects/archive"
    assert preflight.virtual_path == "/projects/archive"


def test_rm_dir_deletes_non_recursive_and_verifies_absence() -> None:
    files = FakeFiles({"/projects": [child("archive")], "/projects/archive": []})
    service = client(files)
    result = service.delete_preflighted_dir(
        service.preflight_delete_dir(SubshareDeleteRequest("projects", "archive"))
    )
    assert result.deleted is True
    assert result.status == "deleted"
    assert files.delete_calls == [("/projects/archive", False)]


@pytest.mark.parametrize(
    ("records", "message"),
    [
        ({"/projects": []}, "does not exist"),
        ({"/projects": [child("archive", isdir=False)]}, "not a directory"),
        (
            {"/projects": [child("archive")], "/projects/archive": [child("nested")]},
            "not empty",
        ),
    ],
)
def test_rm_dir_preflight_rejects_invalid_targets(
    records: dict[str, list[dict[str, object]]], message: str
) -> None:
    files = FakeFiles(records)
    with pytest.raises(ConfigurationError, match=message):
        client(files).preflight_delete_dir(SubshareDeleteRequest("projects", "archive"))
    assert files.delete_calls == []


def test_rm_dir_stale_preflight_is_partial() -> None:
    files = FakeFiles({"/projects": [child("archive")], "/projects/archive": []})
    service = client(files)
    preflight = service.preflight_delete_dir(
        SubshareDeleteRequest("projects", "archive")
    )
    files.child_records["/projects/archive"] = [child("nested")]

    with pytest.raises(ConfigurationError, match="not empty"):
        service.delete_preflighted_dir(preflight)

    assert files.delete_calls == []


def test_rm_dir_delete_uncertainty_is_partial() -> None:
    files = FakeFiles({"/projects": [child("archive")], "/projects/archive": []})
    service = client(files)
    preflight = service.preflight_delete_dir(
        SubshareDeleteRequest("projects", "archive")
    )

    def uncertain(path: str, recursive: bool) -> object:
        raise RuntimeError("connection lost")

    files.delete_blocking_function = uncertain  # type: ignore[method-assign]
    with pytest.raises(PartialOperationError) as caught:
        service.delete_preflighted_dir(preflight)
    result = caught.value.result
    assert isinstance(result, SubshareDeleteResult)
    assert result.status == "unknown"
    assert result.steps[-1].status is OperationStatus.UNKNOWN


def test_rm_dir_verification_failure_is_partial() -> None:
    files = FakeFiles({"/projects": [child("archive")], "/projects/archive": []})
    service = client(files)
    preflight = service.preflight_delete_dir(
        SubshareDeleteRequest("projects", "archive")
    )
    original = files.get_file_list
    calls = 0

    def failing(
        folder_path: str, offset: int, limit: int, additional: list[str]
    ) -> object:
        nonlocal calls
        calls += 1
        if calls > 2 and folder_path == "/projects":
            raise RuntimeError("verification unavailable")
        return original(folder_path, offset, limit, additional)

    files.get_file_list = failing  # type: ignore[method-assign]
    with pytest.raises(PartialOperationError) as caught:
        service.delete_preflighted_dir(preflight)
    result = caught.value.result
    assert isinstance(result, SubshareDeleteResult)
    assert result.status == "unknown"
    assert result.steps[-1].status is OperationStatus.UNKNOWN


class CliClient:
    def __init__(self, preflight: SubshareDeletePreflightResult) -> None:
        self.preflight = preflight
        self.requests: list[SubshareDeleteRequest] = []
        self.mutations = 0

    def preflight_delete_dir(
        self, request: SubshareDeleteRequest
    ) -> SubshareDeletePreflightResult:
        self.requests.append(request)
        return self.preflight

    def delete_preflighted_dir(
        self, preflight: SubshareDeletePreflightResult
    ) -> SubshareDeleteResult:
        self.mutations += 1
        return SubshareDeleteResult(
            preflight.share,
            preflight.directory,
            preflight.path,
            preflight.virtual_path,
            True,
            "deleted",
            preflight.steps,
        )


class Factory:
    def __init__(self, client: CliClient) -> None:
        self.client = client

    def __call__(self, config: ConnectionConfig, logger: logging.Logger) -> CliClient:
        return self.client


def test_rm_dir_cli_preflight_without_yes_does_not_mutate() -> None:
    preflight = SubshareDeletePreflightResult(
        "projects",
        "archive",
        "/volume1/projects/archive",
        "/projects/archive",
        (ShareOperationStep("empty-directory-preflight", OperationStatus.SUCCEEDED),),
    )
    client_value = CliClient(preflight)
    stdout = StringIO()
    stderr = StringIO()
    code = run(
        ["rm-dir", "-s", "projects", "archive", "--output", "json"],
        stdout=stdout,
        stderr=stderr,
        environ={"SYN_USERNAME": "u", "SYN_PASSWORD": "p", "SYN_HOST": "h"},
        client_factory=Factory(client_value),
    )
    assert code == 0
    assert client_value.mutations == 0
    assert json.loads(stdout.getvalue())["status"] == "planned"
