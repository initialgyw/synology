import json
import logging
from io import StringIO

import pytest
import yaml

from synology.cli import run
from synology.exceptions import ApiError
from synology.models import (
    ConnectionConfig,
    DirectoryRecord,
    ListDirsRequest,
    ListDirsResult,
    OutputFormat,
)
from synology.output import render_list_dirs
from synology.subshares import PAGE_SIZE, SynSubshareClient


class FakeShare:
    def get_folder(self, name: str, additional: list[str]) -> object:
        return {"success": True, "data": {"name": name, "vol_path": "/volume1"}}


class FakeFiles:
    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records
        self.list_calls: list[tuple[str, int, int]] = []
        self.mutations = 0

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
        self.list_calls.append((folder_path, offset, limit))
        page = self.records[offset : offset + limit]
        return {
            "success": True,
            "data": {"files": page, "offset": offset, "total": len(self.records)},
        }

    def get_file_info(self, path: str, additional_param: list[str]) -> object:
        return {"success": True, "data": {"files": []}}

    def create_folder(self, **kwargs: object) -> object:
        self.mutations += 1
        return {"success": True}


def record(name: str, isdir: bool) -> dict[str, object]:
    return {"name": name, "isdir": isdir}


def client(files: FakeFiles) -> SynSubshareClient:
    return SynSubshareClient(
        ConnectionConfig("user", "password", "nas"),
        logging.getLogger(),
        share_factory=lambda **_: FakeShare(),
        filestation_factory=lambda **_: files,
    )


def test_list_dirs_filters_files_sorts_and_consumes_pages() -> None:
    files = FakeFiles(
        [record(f"other-{index}", True) for index in range(PAGE_SIZE)]
        + [record("zeta", True), record("file.txt", False), record("alpha", True)]
    )

    result = client(files).list_dirs(ListDirsRequest("projects"))

    expected = tuple(
        sorted(
            tuple(
                DirectoryRecord(f"other-{index}", f"/projects/other-{index}")
                for index in range(PAGE_SIZE)
            )
            + (
                DirectoryRecord("zeta", "/projects/zeta"),
                DirectoryRecord("alpha", "/projects/alpha"),
            ),
            key=lambda item: (item.name, item.path),
        )
    )
    assert result == ListDirsResult("projects", expected)
    assert files.list_calls == [
        ("/projects", 0, PAGE_SIZE),
        ("/projects", PAGE_SIZE, PAGE_SIZE),
    ]
    assert files.mutations == 0


def test_list_dirs_empty_result() -> None:
    assert client(FakeFiles([])).list_dirs(
        ListDirsRequest("projects")
    ) == ListDirsResult("projects", ())


def test_list_dirs_malformed_child_is_api_error() -> None:
    files = FakeFiles([{"name": "missing-isdir"}])
    with pytest.raises(ApiError):
        client(files).list_dirs(ListDirsRequest("projects"))


@pytest.mark.parametrize(
    "output", [OutputFormat.TABLE, OutputFormat.JSON, OutputFormat.YAML]
)
def test_render_list_dirs(output: OutputFormat) -> None:
    result = ListDirsResult(
        "projects",
        (DirectoryRecord("alpha", "/projects/alpha"),),
    )
    rendered = render_list_dirs(result, output)
    if output is OutputFormat.TABLE:
        assert "NAME" in rendered and "/projects/alpha" in rendered
    elif output is OutputFormat.JSON:
        assert json.loads(rendered)["directories"][0]["name"] == "alpha"
    else:
        assert yaml.safe_load(rendered)["directories"][0]["path"] == "/projects/alpha"


class CliClient:
    def __init__(
        self, result: ListDirsResult | None = None, error: Exception | None = None
    ):
        self.result = result
        self.error = error
        self.requests: list[ListDirsRequest] = []

    def list_dirs(self, request: ListDirsRequest) -> ListDirsResult:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


class Factory:
    def __init__(self, client: CliClient) -> None:
        self.client = client
        self.config: ConnectionConfig | None = None

    def __call__(self, config: ConnectionConfig, logger: logging.Logger) -> CliClient:
        self.config = config
        return self.client


def test_cli_list_dirs_forwards_share_and_credentials() -> None:
    client_value = CliClient(ListDirsResult("projects", ()))
    factory = Factory(client_value)
    stdout = StringIO()
    stderr = StringIO()

    code = run(
        ["list-dirs", "-s", "projects", "--output", "json"],
        stdout=stdout,
        stderr=stderr,
        environ={
            "SYN_USERNAME": "user",
            "SYN_PASSWORD": "password",
            "SYN_HOST": "nas",
        },
        client_factory=factory,
    )

    assert code == 0
    assert client_value.requests == [ListDirsRequest("projects")]
    assert json.loads(stdout.getvalue()) == {"share": "projects", "directories": []}
    assert stderr.getvalue() == ""


def test_cli_list_dirs_api_error_uses_exit_40() -> None:
    factory = Factory(CliClient(error=ApiError("bad response")))
    stdout = StringIO()
    stderr = StringIO()

    code = run(
        ["list-dirs", "-s", "projects"],
        stdout=stdout,
        stderr=stderr,
        environ={
            "SYN_USERNAME": "user",
            "SYN_PASSWORD": "password",
            "SYN_HOST": "nas",
        },
        client_factory=factory,
    )

    assert code == 40
    assert stdout.getvalue() == ""
    assert "bad response" in stderr.getvalue()
