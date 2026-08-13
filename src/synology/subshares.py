import logging as stdlib_logging
import posixpath
import unicodedata
from collections.abc import Mapping
from typing import NoReturn, Protocol, cast

from requests.exceptions import RequestException
from synology_api.exceptions import (
    CoreError,
    HTTPError,
    JSONDecodeError,
    LoginError,
    SynoBaseException,
    SynoConnectionError,
    UndefinedError,
)

from synology.config import (
    validate_share_create_request,
    validate_subshare_create_request,
)
from synology.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    PartialOperationError,
    TransportError,
)
from synology.logging import sanitize
from synology.models import (
    ApplyDirectoryPreflight,
    ConnectionConfig,
    DirectoryRecord,
    ListDirsRequest,
    ListDirsResult,
    OperationStatus,
    ShareCreateRequest,
    ShareOperationStep,
    SubshareCreateRequest,
    SubshareCreateResult,
    SubshareDeletePreflightResult,
    SubshareDeleteRequest,
    SubshareDeleteResult,
    SubsharePreflightResult,
)

PAGE_SIZE = 100


class ShareApi(Protocol):
    def get_folder(self, name: str, additional: list[str]) -> object: ...


class FileStationApi(Protocol):
    def delete_blocking_function(self, path: str, recursive: bool) -> object: ...

    def get_list_share(
        self, additional: list[str], offset: int, limit: int
    ) -> object: ...

    def get_file_list(
        self, folder_path: str, offset: int, limit: int, additional: list[str]
    ) -> object: ...

    def get_file_info(self, path: str, additional_param: list[str]) -> object: ...

    def create_folder(
        self, folder_path: str, name: str, force_parent: bool, additional: list[str]
    ) -> object: ...


class ShareFactory(Protocol):
    def __call__(
        self,
        *,
        ip_address: str,
        port: str,
        username: str,
        password: str,
        secure: bool,
        cert_verify: bool,
        dsm_version: int,
        debug: bool,
    ) -> ShareApi: ...


class FileStationFactory(Protocol):
    def __call__(
        self,
        *,
        ip_address: str,
        port: str,
        username: str,
        password: str,
        secure: bool,
        cert_verify: bool,
        dsm_version: int,
        debug: bool,
    ) -> FileStationApi: ...


class SynSubshareClient:
    def __init__(
        self,
        config: ConnectionConfig,
        logger: stdlib_logging.Logger,
        *,
        share_factory: ShareFactory | None = None,
        filestation_factory: FileStationFactory | None = None,
    ) -> None:
        self._config = config
        self._logger = logger
        factory_share = share_factory or _default_share_factory
        factory_files = filestation_factory or _default_filestation_factory
        try:
            self._share = factory_share(
                ip_address=config.host,
                port=str(config.port),
                username=config.username,
                password=config.password,
                secure=True,
                cert_verify=not config.insecure,
                dsm_version=7,
                debug=False,
            )
            self._files = factory_files(
                ip_address=config.host,
                port=str(config.port),
                username=config.username,
                password=config.password,
                secure=True,
                cert_verify=not config.insecure,
                dsm_version=7,
                debug=False,
            )
        except ValueError as exc:
            raise ConfigurationError("invalid NAS connection configuration") from exc
        except Exception as exc:
            self._raise_mapped_error(exc, phase="initialization")

    def preflight_apply_directory(
        self, share: str, directory: str
    ) -> ApplyDirectoryPreflight:
        request = validate_subshare_create_request(
            SubshareCreateRequest(share, directory)
        )
        try:
            data = _data(
                self._share.get_folder(request.share, additional=[]), "share lookup"
            )
            name = _component(_text(data, "name"))
            volume = _path(_text(data, "vol_path"))
            if name != request.share:
                raise ApiError("NAS returned a mismatched shared-folder name")
            physical_parent = _join(volume, name)
            virtual_parent = _virtual_share(self._files, name, physical_parent)
            target_kind = _child(self._files, virtual_parent, request.directory)
            if target_kind is None:
                return ApplyDirectoryPreflight(
                    request.share,
                    request.directory,
                    _join(physical_parent, request.directory),
                    _join(virtual_parent, request.directory),
                    "missing",
                    None,
                )
            if not target_kind:
                return ApplyDirectoryPreflight(
                    request.share,
                    request.directory,
                    _join(physical_parent, request.directory),
                    _join(virtual_parent, request.directory),
                    "file",
                    None,
                )
            empty = not _list_children(
                self._files, _join(virtual_parent, request.directory)
            )
            return ApplyDirectoryPreflight(
                request.share,
                request.directory,
                _join(physical_parent, request.directory),
                _join(virtual_parent, request.directory),
                "directory",
                empty,
            )
        except (ConfigurationError, ApiError):
            raise
        except Exception as exc:
            self._raise_mapped_error(exc, phase="apply-directory-preflight")

    def preflight_future_apply_directory(
        self, share: str, volume: str, directory: str
    ) -> ApplyDirectoryPreflight:
        request = validate_subshare_create_request(
            SubshareCreateRequest(share, directory)
        )
        volume_path = validate_share_create_request(
            ShareCreateRequest(request.share, volume)
        ).volume_path
        return ApplyDirectoryPreflight(
            request.share,
            request.directory,
            _join(_join(volume_path, request.share), request.directory),
            None,
            "missing",
            None,
            True,
        )

    def create_apply_directory(self, preflight: ApplyDirectoryPreflight) -> object:
        if preflight.virtual_path is None or preflight.target_kind != "missing":
            raise ConfigurationError("invalid directory creation preflight")
        return self.create_preflighted_subshare(
            SubsharePreflightResult(
                preflight.share,
                preflight.directory,
                preflight.path,
                preflight.virtual_path.rsplit("/", 1)[0],
            )
        )

    def delete_apply_directory(self, preflight: ApplyDirectoryPreflight) -> object:
        if (
            preflight.virtual_path is None
            or preflight.target_kind != "directory"
            or not preflight.empty
        ):
            raise ConfigurationError("invalid directory deletion preflight")
        return self.delete_preflighted_dir(
            SubshareDeletePreflightResult(
                preflight.share,
                preflight.directory,
                preflight.path,
                preflight.virtual_path,
            )
        )

    def preflight_delete_dir(
        self, request: SubshareDeleteRequest
    ) -> SubshareDeletePreflightResult:
        validated = validate_subshare_create_request(
            SubshareCreateRequest(request.share, request.directory)
        )
        data = _data(
            self._share.get_folder(validated.share, additional=[]), "share lookup"
        )
        name = _component(_text(data, "name"))
        volume = _path(_text(data, "vol_path"))
        if name != validated.share:
            raise ApiError("NAS returned a mismatched shared-folder name")
        physical_parent = _join(volume, name)
        virtual_parent = _virtual_share(self._files, name, physical_parent)
        target_type = _child(self._files, virtual_parent, validated.directory)
        if target_type is None:
            raise ConfigurationError(
                f"rm-dir target does not exist: {validated.directory}"
            )
        if not target_type:
            raise ConfigurationError(
                f"rm-dir target is not a directory: {validated.directory}"
            )
        virtual_path = _join(virtual_parent, validated.directory)
        child_records = _list_children(self._files, virtual_path)
        if child_records:
            raise ConfigurationError(
                f"rm-dir target is not empty: {validated.directory}"
            )
        return SubshareDeletePreflightResult(
            validated.share,
            validated.directory,
            _join(physical_parent, validated.directory),
            virtual_path,
            (
                ShareOperationStep("share-resolution", OperationStatus.SUCCEEDED),
                ShareOperationStep("virtual-mapping", OperationStatus.SUCCEEDED),
                ShareOperationStep("child-preflight", OperationStatus.SUCCEEDED),
                ShareOperationStep(
                    "empty-directory-preflight", OperationStatus.SUCCEEDED
                ),
            ),
        )

    def delete_preflighted_dir(
        self, preflight: SubshareDeletePreflightResult
    ) -> SubshareDeleteResult:
        request = SubshareDeleteRequest(preflight.share, preflight.directory)
        current = self.preflight_delete_dir(request)
        if (
            current.path != preflight.path
            or current.virtual_path != preflight.virtual_path
        ):
            raise PartialOperationError(
                "rm-dir preflight target is stale",
                SubshareDeleteResult(
                    preflight.share,
                    preflight.directory,
                    preflight.path,
                    preflight.virtual_path,
                    False,
                    "unknown",
                    (
                        *preflight.steps,
                        ShareOperationStep("delete", OperationStatus.UNKNOWN),
                    ),
                ),
            )
        try:
            response = self._files.delete_blocking_function(
                current.virtual_path, recursive=False
            )
            _success(response, "rm-dir deletion")
        except (
            LoginError,
            PermissionError,
            CoreError,
            UndefinedError,
            SynoBaseException,
            ValueError,
        ) as exc:
            self._raise_mapped_error(exc, phase="delete")
        except Exception as exc:
            raise PartialOperationError(
                "rm-dir deletion outcome is uncertain",
                SubshareDeleteResult(
                    preflight.share,
                    preflight.directory,
                    preflight.path,
                    preflight.virtual_path,
                    False,
                    "unknown",
                    (
                        *preflight.steps,
                        ShareOperationStep("delete", OperationStatus.UNKNOWN),
                    ),
                ),
            ) from exc
        try:
            remaining = _child(
                self._files,
                current.virtual_path.rsplit("/", 1)[0],
                current.directory,
            )
        except Exception as exc:
            raise PartialOperationError(
                "rm-dir deletion verification outcome is uncertain",
                SubshareDeleteResult(
                    current.share,
                    current.directory,
                    current.path,
                    current.virtual_path,
                    False,
                    "unknown",
                    (
                        *preflight.steps,
                        ShareOperationStep("delete", OperationStatus.SUCCEEDED),
                        ShareOperationStep("verify", OperationStatus.UNKNOWN),
                    ),
                ),
            ) from exc
        if remaining is not None:
            raise PartialOperationError(
                "rm-dir deletion verification failed",
                SubshareDeleteResult(
                    preflight.share,
                    preflight.directory,
                    preflight.path,
                    preflight.virtual_path,
                    False,
                    "failed",
                    (
                        *preflight.steps,
                        ShareOperationStep("delete", OperationStatus.SUCCEEDED),
                        ShareOperationStep("verify", OperationStatus.FAILED),
                    ),
                ),
            )
        return SubshareDeleteResult(
            current.share,
            current.directory,
            current.path,
            current.virtual_path,
            True,
            "deleted",
            (
                *preflight.steps,
                ShareOperationStep("delete", OperationStatus.SUCCEEDED),
                ShareOperationStep("verify", OperationStatus.SUCCEEDED),
            ),
        )

    def list_dirs(self, request: ListDirsRequest) -> ListDirsResult:
        share = request.share.strip()
        if not share:
            raise ConfigurationError("share name must not be empty")
        try:
            data = _data(self._share.get_folder(share, additional=[]), "share lookup")
            name = _component(_text(data, "name"))
            volume = _path(_text(data, "vol_path"))
            if name != share:
                raise ApiError("NAS returned a mismatched shared-folder name")
            physical_parent = _join(volume, name)
            virtual_parent = _virtual_share(self._files, name, physical_parent)
            directories = tuple(
                DirectoryRecord(
                    record_name,
                    _join(virtual_parent, record_name),
                )
                for record_name, is_directory in _list_children(
                    self._files, virtual_parent
                )
                if is_directory
            )
            return ListDirsResult(
                share,
                tuple(sorted(directories, key=lambda item: (item.name, item.path))),
            )
        except (ConfigurationError, ApiError):
            raise
        except Exception as exc:
            self._raise_mapped_error(exc, phase="list-dirs")

    def preflight_subshare(
        self, request: SubshareCreateRequest
    ) -> SubsharePreflightResult:
        request = validate_subshare_create_request(request)
        steps: list[ShareOperationStep] = []
        try:
            data = _data(
                self._share.get_folder(request.share, additional=[]), "share lookup"
            )
            name = _component(_text(data, "name"))
            volume = _path(_text(data, "vol_path"))
            if name != request.share:
                raise ApiError("NAS returned a mismatched shared-folder name")
            physical_parent = _join(volume, name)
            steps.append(
                ShareOperationStep("share-resolution", OperationStatus.SUCCEEDED)
            )
            virtual_parent = _virtual_share(self._files, name, physical_parent)
            steps.append(
                ShareOperationStep("virtual-mapping", OperationStatus.SUCCEEDED)
            )
            existing = _child(self._files, virtual_parent, request.directory)
            if existing is not None:
                message = (
                    "subshare target already exists"
                    if existing
                    else "subshare target is not a directory"
                )
                raise ConfigurationError(f"{message}: {request.directory}")
            steps.append(
                ShareOperationStep("child-preflight", OperationStatus.SUCCEEDED)
            )
            self._logger.debug(
                "Synology API add-dir preflight target=%s:%s tls_verify=%s request=%s",
                self._config.host,
                self._config.port,
                not self._config.insecure,
                sanitize(
                    {
                        "share": request.share,
                        "directory": request.directory,
                        "virtual_parent": virtual_parent,
                    }
                ),
            )
            return SubsharePreflightResult(
                request.share,
                request.directory,
                _join(physical_parent, request.directory),
                virtual_parent,
                tuple(steps),
            )
        except (ConfigurationError, ApiError):
            raise
        except Exception as exc:
            self._raise_mapped_error(exc, phase="preflight")

    def create_subshare(self, request: SubshareCreateRequest) -> SubshareCreateResult:
        request = validate_subshare_create_request(request)
        return self.create_preflighted_subshare(self.preflight_subshare(request))

    def create_preflighted_subshare(
        self, preflight: SubsharePreflightResult
    ) -> SubshareCreateResult:
        request = SubshareCreateRequest(preflight.share, preflight.directory)
        steps = list(preflight.steps)
        physical_parent = preflight.path.rsplit("/", 1)[0]
        virtual_parent = preflight.virtual_parent
        self._logger.debug(
            "Synology API add-dir request target=%s:%s tls_verify=%s request=%s",
            self._config.host,
            self._config.port,
            not self._config.insecure,
            sanitize(
                {
                    "share": request.share,
                    "directory": request.directory,
                    "virtual_parent": virtual_parent,
                }
            ),
        )
        try:
            response = self._files.create_folder(
                folder_path=virtual_parent,
                name=request.directory,
                force_parent=False,
                additional=["real_path", "type"],
            )
        except (
            LoginError,
            PermissionError,
            CoreError,
            UndefinedError,
            SynoBaseException,
            ValueError,
        ) as exc:
            self._raise_mapped_error(exc, phase="create")
        except Exception as exc:
            raise _partial(
                "subshare creation outcome is uncertain",
                request,
                steps,
                "create",
                OperationStatus.UNKNOWN,
            ) from exc
        if isinstance(response, Mapping) and response.get("success") is False:
            raise ApiError(
                "NAS API returned an unsuccessful subshare creation response"
            )
        if not isinstance(response, Mapping) or response.get("success") is not True:
            raise _partial(
                "subshare creation outcome is uncertain",
                request,
                steps,
                "create",
                OperationStatus.UNKNOWN,
            )
        steps.append(ShareOperationStep("create", OperationStatus.SUCCEEDED))
        virtual_child = _join(virtual_parent, request.directory)
        try:
            child = _child(self._files, virtual_parent, request.directory)
        except Exception as exc:
            raise _partial(
                "subshare verification outcome is uncertain",
                request,
                steps,
                "verify",
                OperationStatus.UNKNOWN,
            ) from exc
        if child is not True:
            raise _partial(
                "subshare verification failed",
                request,
                steps,
                "verify",
                OperationStatus.FAILED,
            )
        try:
            actual = _file_info_path(self._files, virtual_child, request.directory)
            if not _exact_child(actual, physical_parent, request.directory):
                raise ApiError("subshare read-back path did not match requested child")
        except ApiError as exc:
            raise _partial(
                "subshare verification failed",
                request,
                steps,
                "verify",
                OperationStatus.FAILED,
            ) from exc
        steps.append(ShareOperationStep("verify", OperationStatus.SUCCEEDED))
        return SubshareCreateResult(
            request.share, request.directory, actual, True, tuple(steps)
        )

    def _raise_mapped_error(self, exc: Exception, *, phase: str) -> NoReturn:
        self._logger.debug(
            "Synology API failure phase=%s error_type=%s", phase, type(exc).__name__
        )
        if isinstance(exc, (LoginError, PermissionError)):
            raise AuthenticationError("NAS authentication failed") from exc
        if isinstance(
            exc,
            (
                SynoConnectionError,
                HTTPError,
                JSONDecodeError,
                RequestException,
                OSError,
            ),
        ):
            raise TransportError("NAS transport or TLS request failed") from exc
        if isinstance(exc, (ValueError, CoreError, UndefinedError, SynoBaseException)):
            raise ApiError("NAS API request failed") from exc
        raise exc


def _partial(
    message: str,
    request: SubshareCreateRequest,
    steps: list[ShareOperationStep],
    name: str,
    status: OperationStatus,
) -> PartialOperationError:
    return PartialOperationError(
        message,
        SubshareCreateResult(
            request.share,
            request.directory,
            None,
            False,
            tuple([*steps, ShareOperationStep(name, status, message=message)]),
        ),
    )


def _default_share_factory(**kwargs: object) -> ShareApi:
    from synology_api.core_share import Share

    return cast(ShareApi, Share(**kwargs))


def _default_filestation_factory(**kwargs: object) -> FileStationApi:
    from synology_api.filestation import FileStation

    return cast(FileStationApi, FileStation(**kwargs))


def _success(response: object, operation: str) -> Mapping[str, object]:
    if not isinstance(response, Mapping) or response.get("success") is not True:
        raise ApiError(f"NAS API returned an unsuccessful {operation} response")
    return response


def _data(response: object, operation: str) -> Mapping[str, object]:
    data = _success(response, operation).get("data")
    if not isinstance(data, Mapping):
        raise ApiError(f"invalid {operation} response data")
    return data


def _text(data: Mapping[str, object], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise ApiError(f"invalid {field} in NAS response")
    return value


def _component(value: str) -> str:
    if (
        unicodedata.normalize("NFC", value) != value
        or value.strip() != value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or _control(value)
    ):
        raise ApiError("invalid path component in NAS response")
    return value


def _path(value: str) -> str:
    if (
        unicodedata.normalize("NFC", value) != value
        or not value.startswith("/")
        or _control(value)
    ):
        raise ApiError("invalid path in NAS response")
    parts = value.split("/")
    if (
        any(not part or part in {".", ".."} for part in parts[1:])
        or posixpath.normpath(value) != value
    ):
        raise ApiError("invalid path in NAS response")
    return value


def _join(parent: str, child: str) -> str:
    return _path(f"{parent}/{child}")


def _virtual_share(files: FileStationApi, name: str, expected_real: str) -> str:
    offset = 0
    total: int | None = None
    matches: list[str] = []
    while total is None or offset < total:
        data = _data(
            files.get_list_share(
                additional=["real_path"], offset=offset, limit=PAGE_SIZE
            ),
            "shared-folder listing",
        )
        shares, page_total = _page(data, "shares", offset, "shared-folder listing")
        if total is not None and total != page_total:
            raise ApiError("malformed shared-folder listing pagination")
        total = page_total
        for item in shares:
            if not isinstance(item, Mapping) or item.get("name") != name:
                continue
            if item.get("isdir") is not True:
                raise ApiError("shared-folder mapping is not a directory")
            additional = item.get("additional")
            if (
                not isinstance(additional, Mapping)
                or not isinstance(item.get("path"), str)
                or not isinstance(additional.get("real_path"), str)
            ):
                raise ApiError("shared-folder mapping is incomplete")
            virtual = _path(cast(str, item["path"]))
            real = _path(cast(str, additional["real_path"]))
            if real != expected_real:
                raise ApiError("shared-folder virtual and physical paths do not agree")
            matches.append(virtual)
        offset += len(shares)
        if offset < total and not shares:
            raise ApiError("shared-folder listing pagination made no progress")
    if len(matches) != 1:
        raise ApiError("shared-folder mapping is missing or ambiguous")
    return matches[0]


def _page(
    data: Mapping[str, object], key: str, expected_offset: int, operation: str
) -> tuple[list[object], int]:
    records = data.get(key)
    offset = data.get("offset")
    total = data.get("total")
    if (
        not isinstance(records, list)
        or not isinstance(offset, int)
        or isinstance(offset, bool)
        or offset != expected_offset
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total < offset
        or len(records) > total - offset
    ):
        raise ApiError(f"malformed {operation} pagination")
    return records, total


def _list_children(files: FileStationApi, parent: str) -> tuple[tuple[str, bool], ...]:
    offset = 0
    total: int | None = None
    result: list[tuple[str, bool]] = []
    while total is None or offset < total:
        data = _data(
            files.get_file_list(
                folder_path=parent,
                offset=offset,
                limit=PAGE_SIZE,
                additional=["type"],
            ),
            "child listing",
        )
        records, page_total = _page(data, "files", offset, "child listing")
        if total is not None and total != page_total:
            raise ApiError("malformed child listing pagination")
        total = page_total
        for record in records:
            if not isinstance(record, Mapping):
                raise ApiError("malformed child listing record")
            record_name = record.get("name")
            is_directory = record.get("isdir")
            if not isinstance(record_name, str) or not isinstance(is_directory, bool):
                raise ApiError("malformed child listing record")
            result.append((record_name, is_directory))
        offset += len(records)
        if offset < total and not records:
            raise ApiError("child listing pagination made no progress")
    return tuple(result)


def _child(files: FileStationApi, parent: str, name: str) -> bool | None:
    matches = [
        is_directory
        for record_name, is_directory in _list_children(files, parent)
        if record_name == name
    ]
    if len(matches) > 1:
        raise ApiError("ambiguous child listing match")
    return matches[0] if matches else None


def _file_info_path(files: FileStationApi, path: str, name: str) -> str:
    data = _data(
        files.get_file_info(
            path,
            additional_param=["real_path", "type"],
        ),
        "subshare read-back",
    )
    records = data.get("files")
    if not isinstance(records, list) or len(records) != 1:
        raise ApiError("invalid subshare read-back response")
    record = records[0]
    if not isinstance(record, Mapping):
        raise ApiError("invalid subshare read-back response")
    record_name = record.get("name")
    record_path = record.get("path")
    is_directory = record.get("isdir")
    additional = record.get("additional")
    if (
        record_name != name
        or not isinstance(record_path, str)
        or _path(record_path) != path
        or is_directory is not True
        or not isinstance(additional, Mapping)
    ):
        raise ApiError("invalid subshare read-back response")
    real_path = additional.get("real_path")
    if not isinstance(real_path, str):
        raise ApiError("invalid subshare read-back response")
    return _path(real_path)


def _exact_child(path: str, parent: str, name: str) -> bool:
    return path == _join(parent, name)


def _control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)
