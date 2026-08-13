import logging
import unicodedata
from collections.abc import Mapping

import pytest
from requests.exceptions import RequestException

from synology.config import validate_subshare_create_request
from synology.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    PartialOperationError,
)
from synology.models import (
    ConnectionConfig,
    OperationStatus,
    SubshareCreateRequest,
    SubshareCreateResult,
)
from synology.subshares import PAGE_SIZE, SynSubshareClient


class FakeShare:
    def __init__(self, response: object | None = None) -> None:
        self.response = response or {
            "success": True,
            "data": {"name": "projects", "vol_path": "/volume1"},
        }

    def get_folder(self, name: str, additional: list[str]) -> object:
        return self.response


class PaginatedFiles:
    def __init__(
        self,
        *,
        shares: list[dict[str, object]],
        before_children: list[dict[str, object]],
        after_children: list[dict[str, object]] | None = None,
        create_response: object | None = None,
        create_exception: Exception | None = None,
    ) -> None:
        self.shares = shares
        self.before_children = before_children
        self.after_children = after_children or before_children
        self.create_response = (
            {"success": True} if create_response is None else create_response
        )
        self.create_exception = create_exception
        self.created = False
        self.create_calls: list[dict[str, object]] = []
        self.list_share_calls: list[tuple[int, int]] = []
        self.file_calls: list[tuple[str, int, int]] = []
        self.file_info_calls: list[str] = []

    def get_list_share(self, additional: list[str], offset: int, limit: int) -> object:
        self.list_share_calls.append((offset, limit))
        return {
            "success": True,
            "data": {
                "shares": self.shares[offset : offset + limit],
                "offset": offset,
                "total": len(self.shares),
            },
        }

    def get_file_list(
        self, folder_path: str, offset: int, limit: int, additional: list[str]
    ) -> object:
        self.file_calls.append((folder_path, offset, limit))
        children = self.after_children if self.created else self.before_children
        return {
            "success": True,
            "data": {
                "files": children[offset : offset + limit],
                "offset": offset,
                "total": len(children),
            },
        }

    def get_file_info(self, path: str, additional_param: list[str]) -> object:
        self.file_info_calls.append(path)
        children = self.after_children if self.created else self.before_children
        name = path.rsplit("/", 1)[-1]
        records = [
            {**record, "path": path}
            for record in children
            if record.get("name") == name
        ]
        return {"success": True, "data": {"files": records}}

    def create_folder(self, **kwargs: object) -> object:
        self.create_calls.append(kwargs)
        if self.create_exception is not None:
            raise self.create_exception
        if (
            isinstance(self.create_response, Mapping)
            and self.create_response.get("success") is True
        ):
            self.created = True
        return self.create_response


def share_mapping(
    *,
    name: str = "projects",
    path: str = "/projects",
    real: str = "/volume1/projects",
) -> dict[str, object]:
    return {
        "name": name,
        "path": path,
        "isdir": True,
        "additional": {"real_path": real},
    }


def child(
    name: str = "archive",
    *,
    real: str | None = "/volume1/projects/archive",
    isdir: bool = True,
) -> dict[str, object]:
    additional: dict[str, object] = {} if real is None else {"real_path": real}
    return {"name": name, "isdir": isdir, "additional": additional}


def filler_children() -> list[dict[str, object]]:
    return [
        child(
            f"other-{index}",
            real=f"/volume1/projects/other-{index}",
        )
        for index in range(PAGE_SIZE)
    ]


def make_client(
    files: PaginatedFiles,
    *,
    share: FakeShare | None = None,
    share_factory=None,
    filestation_factory=None,
    insecure: bool = False,
) -> SynSubshareClient:
    return SynSubshareClient(
        ConnectionConfig("user", "password", "nas", insecure=insecure),
        logging.getLogger(),
        share_factory=share_factory or (lambda **_: share or FakeShare()),
        filestation_factory=filestation_factory or (lambda **_: files),
    )


def test_create_uses_virtual_parent_exact_path_and_fields() -> None:
    files = PaginatedFiles(
        shares=[share_mapping()],
        before_children=[],
        after_children=[child()],
    )

    result = make_client(files).create_subshare(
        SubshareCreateRequest("projects", "archive")
    )

    assert result.created is True
    assert result.path == "/volume1/projects/archive"
    assert files.create_calls == [
        {
            "folder_path": "/projects",
            "name": "archive",
            "force_parent": False,
            "additional": ["real_path", "type"],
        }
    ]
    assert files.file_info_calls == ["/projects/archive"]


def test_existing_target_on_later_page_is_rejected_without_create() -> None:
    files = PaginatedFiles(
        shares=[share_mapping()],
        before_children=[*filler_children(), child()],
    )

    with pytest.raises(ConfigurationError):
        make_client(files).create_subshare(SubshareCreateRequest("projects", "archive"))

    assert files.create_calls == []
    assert files.file_calls == [
        ("/projects", 0, PAGE_SIZE),
        ("/projects", PAGE_SIZE, PAGE_SIZE),
    ]


def test_create_readback_on_later_page_succeeds() -> None:
    files = PaginatedFiles(
        shares=[share_mapping()],
        before_children=filler_children(),
        after_children=[*filler_children(), child()],
    )

    result = make_client(files).create_subshare(
        SubshareCreateRequest("projects", "archive")
    )

    assert result.created is True
    assert result.path == "/volume1/projects/archive"
    assert files.file_calls == [
        ("/projects", 0, PAGE_SIZE),
        ("/projects", 0, PAGE_SIZE),
        ("/projects", PAGE_SIZE, PAGE_SIZE),
    ]


def test_virtual_mapping_on_later_page_is_resolved() -> None:
    files = PaginatedFiles(
        shares=[share_mapping(name=f"other-{index}") for index in range(PAGE_SIZE)]
        + [share_mapping()],
        before_children=[],
        after_children=[child()],
    )

    result = make_client(files).create_subshare(
        SubshareCreateRequest("projects", "archive")
    )

    assert result.created is True
    assert files.list_share_calls == [(0, PAGE_SIZE), (PAGE_SIZE, PAGE_SIZE)]


@pytest.mark.parametrize(
    "mapping",
    [
        [],
        [share_mapping(path="/a"), share_mapping(path="/b")],
        [share_mapping(real="/volume2/projects")],
        [{"name": "projects", "path": "/projects", "isdir": True}],
    ],
)
def test_virtual_mapping_invalid_states_are_api_errors(
    mapping: list[dict[str, object]],
) -> None:
    files = PaginatedFiles(shares=mapping, before_children=[])

    with pytest.raises(ApiError):
        make_client(files).create_subshare(SubshareCreateRequest("projects", "archive"))


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"name": "archive"}, ApiError),
        (
            {"name": "archive", "isdir": True, "additional": {}},
            ConfigurationError,
        ),
        (
            {
                "name": "archive",
                "isdir": "true",
                "additional": {"real_path": "/volume1/projects/archive"},
            },
            ApiError,
        ),
        ({"name": "other"}, ApiError),
    ],
)
def test_malformed_preflight_records_fail_before_create(
    record: dict[str, object], expected: type[Exception]
) -> None:
    files = PaginatedFiles(shares=[share_mapping()], before_children=[record])

    with pytest.raises(expected):
        make_client(files).create_subshare(SubshareCreateRequest("projects", "archive"))

    assert files.create_calls == []


@pytest.mark.parametrize(
    ("record", "status"),
    [
        (child(isdir=False), OperationStatus.FAILED),
        (child(real=None), OperationStatus.FAILED),
        (child(real="/volume1/projects/wrong"), OperationStatus.FAILED),
    ],
)
def test_bad_or_missing_readback_is_partial(
    record: dict[str, object], status: OperationStatus
) -> None:
    files = PaginatedFiles(
        shares=[share_mapping()],
        before_children=[],
        after_children=[record],
    )

    with pytest.raises(PartialOperationError) as caught:
        make_client(files).create_subshare(SubshareCreateRequest("projects", "archive"))

    result = caught.value.result
    assert isinstance(result, SubshareCreateResult)
    assert result.created is False
    assert result.steps[-1].status is status


def test_unsuccessful_creation_envelope_is_api_error() -> None:
    files = PaginatedFiles(
        shares=[share_mapping()],
        before_children=[],
        create_response={"success": False},
    )

    with pytest.raises(ApiError):
        make_client(files).create_subshare(SubshareCreateRequest("projects", "archive"))


def test_malformed_creation_response_is_partial_unknown() -> None:
    files = PaginatedFiles(
        shares=[share_mapping()],
        before_children=[],
        create_response="invalid",
    )

    with pytest.raises(PartialOperationError) as caught:
        make_client(files).create_subshare(SubshareCreateRequest("projects", "archive"))

    result = caught.value.result
    assert isinstance(result, SubshareCreateResult)
    assert result.created is False
    assert result.steps[-1].status is OperationStatus.UNKNOWN


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (PermissionError("x"), AuthenticationError),
        (ValueError("x"), ApiError),
    ],
)
def test_definitive_creation_errors_are_mapped(
    exc: Exception, expected: type[Exception]
) -> None:
    files = PaginatedFiles(
        shares=[share_mapping()],
        before_children=[],
        create_exception=exc,
    )

    with pytest.raises(expected):
        make_client(files).create_subshare(SubshareCreateRequest("projects", "archive"))


@pytest.mark.parametrize("exc", [RequestException("x"), RuntimeError("lost")])
def test_uncertain_creation_errors_are_partial_unknown(exc: Exception) -> None:
    files = PaginatedFiles(
        shares=[share_mapping()],
        before_children=[],
        create_exception=exc,
    )

    with pytest.raises(PartialOperationError) as caught:
        make_client(files).create_subshare(SubshareCreateRequest("projects", "archive"))

    result = caught.value.result
    assert isinstance(result, SubshareCreateResult)
    assert result.created is False
    assert result.steps[-1].status is OperationStatus.UNKNOWN


def test_factories_receive_secure_tls_and_dsm_options() -> None:
    calls: list[dict[str, object]] = []
    files = PaginatedFiles(shares=[share_mapping()], before_children=[])

    def factory(**kwargs: object) -> object:
        calls.append(kwargs)
        return FakeShare() if len(calls) == 1 else files

    SynSubshareClient(
        ConnectionConfig("u", "p", "h", insecure=True),
        logging.getLogger(),
        share_factory=factory,
        filestation_factory=factory,
    )

    assert len(calls) == 2
    assert all(
        call["secure"] is True
        and call["cert_verify"] is False
        and call["dsm_version"] == 7
        and call["debug"] is False
        for call in calls
    )


def test_factory_value_error_is_configuration_error() -> None:
    def bad_factory(**kwargs: object) -> object:
        raise ValueError("bad config")

    files = PaginatedFiles(shares=[share_mapping()], before_children=[])
    with pytest.raises(ConfigurationError):
        make_client(files, share_factory=bad_factory)


@pytest.mark.parametrize(
    "candidate",
    [
        None,
        SubshareCreateRequest(1, "x"),
        SubshareCreateRequest("x", 1),
        SubshareCreateRequest("", "x"),
        SubshareCreateRequest("x", ""),
        SubshareCreateRequest("x", "a/b"),
        SubshareCreateRequest("x", "a\\b"),
        SubshareCreateRequest("x", "."),
        SubshareCreateRequest("x", " a"),
        SubshareCreateRequest("x", "a "),
        SubshareCreateRequest("x", "a\n"),
    ],
)
def test_validator_rejects_invalid_requests(candidate: object) -> None:
    with pytest.raises(ConfigurationError):
        validate_subshare_create_request(candidate)


def test_validator_rejects_non_nfc_unicode_and_accepts_valid_request() -> None:
    non_nfc = "e\u0301"
    assert unicodedata.normalize("NFC", non_nfc) != non_nfc
    with pytest.raises(ConfigurationError):
        validate_subshare_create_request(SubshareCreateRequest("projects", non_nfc))
    assert validate_subshare_create_request(
        SubshareCreateRequest(" projects ", "archive")
    ) == SubshareCreateRequest("projects", "archive")
