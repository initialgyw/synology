from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests


class DsmError(RuntimeError):
    """A DSM failure whose optional operation fields are safe for user-facing output."""

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        api: str | None = None,
        method: str | None = None,
        version: int | None = None,
    ) -> None:
        self.code = code if code is not None and re.fullmatch(r"(?:[0-9]+|unknown)", code) else None
        self.api = (
            api
            if api is not None and re.fullmatch(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+", api)
            else None
        )
        self.method = (
            method
            if method is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", method)
            else None
        )
        self.version = (
            version
            if isinstance(version, int) and not isinstance(version, bool) and version > 0
            else None
        )
        self.message = message
        super().__init__(message)

    def __str__(self) -> str:
        context = " ".join(
            part
            for part in (
                f"code={self.code}" if self.code is not None else None,
                f"api={self.api}" if self.api is not None else None,
                f"method={self.method}" if self.method is not None else None,
                f"version={self.version}" if self.version is not None else None,
            )
            if part is not None
        )
        return f"{self.message}: {context}" if context else self.message

    def operation(self) -> dict[str, str | int] | None:
        """Return only complete, fixed operation metadata suitable for CLI output."""
        if self.api is None or self.method is None or self.version is None:
            return None
        return {"api": self.api, "method": self.method, "version": self.version}


class AuthenticationError(DsmError):
    pass


class UnsupportedCapability(DsmError):
    pass


def operation_error(
    error_type: type[DsmError], message: str, *, api: str, method: str, version: int
) -> DsmError:
    """Create a schema/capability error with validated request metadata only."""
    if (
        not re.fullmatch(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+", api)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", method)
        or isinstance(version, bool)
        or not isinstance(version, int)
        or version < 1
    ):
        raise ValueError("operation metadata is invalid")
    return error_type(message, api=api, method=method, version=version)


@dataclass(frozen=True)
class Credentials:
    host: str
    username: str
    password: str


class CredentialValidationError(ValueError):
    """Raised when command-line or environment credentials are unsafe or missing."""


def credentials(host: str | None, username: str | None, password: str | None) -> Credentials:
    """Validate connection values and normalize a DSM endpoint without exposing secrets."""
    if not isinstance(host, str) or not host:
        raise CredentialValidationError("host is required")
    if not isinstance(username, str) or not username:
        raise CredentialValidationError("username is required")
    if not isinstance(password, str) or not password:
        raise CredentialValidationError("password is required")
    if any(character.isspace() or ord(character) < 32 for character in host):
        raise CredentialValidationError("host is invalid")
    if "://" in host:
        source = host
    elif host.count(":") > 1 and not host.startswith("["):
        raise CredentialValidationError("IPv6 hosts must be bracketed")
    else:
        source = f"https://{host}"
    try:
        parsed = urlparse(source)
        hostname = parsed.hostname
        explicit_port = parsed.port
    except ValueError as error:
        raise CredentialValidationError("host has an invalid port") from error
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise CredentialValidationError("host must be a plain HTTPS host or URL")
    if explicit_port is not None and not 1 <= explicit_port <= 65535:
        raise CredentialValidationError("host is invalid")
    authority = f"[{hostname}]" if ":" in hostname else hostname
    port = 5001 if explicit_port is None else explicit_port
    return Credentials(f"https://{authority}:{port}", username, password)


@dataclass(frozen=True)
class Api:
    path: str
    minimum: int
    maximum: int
    request_format: str | None


def validate_ca_bundle(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        resolved = path.resolve(strict=True)
        mode = resolved.stat().st_mode
        if not resolved.is_file() or not mode & 0o444:
            raise AuthenticationError("CA bundle must be a non-empty readable regular file")
        with resolved.open("rb") as handle:
            if not handle.read(1):
                raise AuthenticationError("CA bundle must be a non-empty readable regular file")
    except AuthenticationError:
        raise
    except OSError as error:
        raise AuthenticationError("CA bundle must be a non-empty readable regular file") from error
    return str(resolved)


class DsmClient:
    def __init__(
        self,
        credentials: Credentials,
        *,
        timeout: float = 15,
        verify: bool | str = True,
        session: Any | None = None,
    ) -> None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("timeout must be a finite positive number")
        normalized_timeout = float(timeout)
        if not math.isfinite(normalized_timeout) or normalized_timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        self.credentials = credentials
        self.timeout = normalized_timeout
        self.verify = verify
        self._owns_session = session is None
        self.session = requests.Session() if session is None else session
        self.suppress_logout_logging = False
        self.cleanup_failed = False
        self.cleanup_message: str | None = None
        self.cleanup_operation: str | None = None
        self.cleanup_metadata: dict[str, str] | None = None
        self.cleanup_error: DsmError | None = None
        self.apis: dict[str, Api] = {}
        self.sid: str | None = None

    def __enter__(self) -> DsmClient:
        try:
            self.discover()
            self.login()
        except Exception as error:
            # A failed setup never enters the body, so clean up explicitly here.
            self.__exit__(type(error), error, error.__traceback__)
            raise
        return self

    def _record_cleanup_failure(self, operation: str) -> None:
        """Record only fixed cleanup metadata; never retain an exception object."""
        if self.cleanup_operation is not None and self.cleanup_operation != operation:
            operation = "logout_and_close"
        self.cleanup_failed = True
        self.cleanup_message = "DSM session cleanup did not complete"
        self.cleanup_operation = operation
        self.cleanup_metadata = {"category": "session_cleanup", "operation": operation}
        self.cleanup_error = DsmError(self.cleanup_message)

    def __exit__(self, exc_type: object, *_: object) -> None:
        """End the DSM session and always close only a client-owned HTTP session.

        Cleanup never masks an exception raised by the context body. Injected sessions remain
        caller-owned so tests and embedding code can inspect or reuse them.
        """
        try:
            self._logout_request()
        except Exception:
            self._record_cleanup_failure("logout")
        if self._owns_session:
            try:
                self.session.close()
            except Exception:
                self._record_cleanup_failure("close")

    def _post(self, path: str, data: dict[str, str]) -> dict[str, Any]:
        api = data.get("api")
        method = data.get("method")
        raw_version = data.get("version")
        version = int(raw_version) if raw_version is not None and raw_version.isdecimal() else None
        try:
            response = self.session.post(
                f"{self.credentials.host}{path}",
                data=data,
                timeout=self.timeout,
                verify=self.verify,
            )
        except requests.RequestException as error:
            raise DsmError(
                f"DSM transport failed: {type(error).__name__}",
                api=api,
                method=method,
                version=version,
            ) from error
        try:
            payload = response.json()
        except ValueError as error:
            raise DsmError(
                "DSM response was not JSON", api=api, method=method, version=version
            ) from error
        if not isinstance(payload, dict):
            raise DsmError("DSM response JSON was invalid", api=api, method=method, version=version)
        if payload.get("success") is not True:
            failure = payload.get("error")
            raw_code = failure.get("code") if isinstance(failure, dict) else None
            code = (
                str(raw_code)
                if isinstance(raw_code, int) and not isinstance(raw_code, bool)
                else "unknown"
            )
            raise DsmError("DSM API error", code=code, api=api, method=method, version=version)
        data_value = payload.get("data", {})
        if not isinstance(data_value, dict):
            raise DsmError(
                "DSM success response has invalid data", api=api, method=method, version=version
            )
        return data_value

    @staticmethod
    def _api_path(value: Any) -> str:
        if not isinstance(value, str):
            raise UnsupportedCapability("DSM API path is invalid")
        parsed = urlparse(value)
        path = parsed.path.lstrip("/")
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.params
            or parsed.query
            or parsed.fragment
            or not path
            or ".." in path.split("/")
            or not path.endswith(".cgi")
        ):
            raise UnsupportedCapability("DSM API path is unsafe")
        return f"/webapi/{path}"

    def discover(self) -> None:
        data = self._post(
            "/webapi/entry.cgi",
            {"api": "SYNO.API.Info", "method": "query", "version": "1", "query": "all"},
        )
        discovered: dict[str, Api] = {}
        for name, item in data.items():
            if (
                not isinstance(name, str)
                or not isinstance(item, dict)
                or set(item) - {"path", "minVersion", "maxVersion", "requestFormat"}
            ):
                raise operation_error(
                    UnsupportedCapability,
                    "DSM API descriptor is invalid",
                    api="SYNO.API.Info",
                    method="query",
                    version=1,
                )
            minimum, maximum, request_format = (
                item.get("minVersion"),
                item.get("maxVersion"),
                item.get("requestFormat"),
            )
            if (
                isinstance(minimum, bool)
                or isinstance(maximum, bool)
                or not isinstance(minimum, int)
                or not isinstance(maximum, int)
                or minimum < 1
                or maximum < minimum
                or request_format is not None
                and (not isinstance(request_format, str) or not request_format)
            ):
                raise operation_error(
                    UnsupportedCapability,
                    "DSM API descriptor is invalid",
                    api="SYNO.API.Info",
                    method="query",
                    version=1,
                )
            try:
                path = self._api_path(item.get("path"))
            except UnsupportedCapability as error:
                raise operation_error(
                    UnsupportedCapability,
                    "DSM API descriptor is invalid",
                    api="SYNO.API.Info",
                    method="query",
                    version=1,
                ) from error
            discovered[name] = Api(path, minimum, maximum, request_format)
        self.apis = discovered

    def _auth_api(self, method: str) -> Api:
        detail = self.apis.get("SYNO.API.Auth")
        if (
            detail is None
            or not isinstance(detail.path, str)
            or not detail.path.startswith("/webapi/")
            or not detail.minimum <= 7 <= detail.maximum
        ):
            raise operation_error(
                UnsupportedCapability,
                "DSM does not support SYNO.API.Auth v7",
                api="SYNO.API.Auth",
                method=method,
                version=7,
            )
        return detail

    def login(self) -> None:
        detail = self._auth_api("login")
        data = self._post(
            detail.path,
            {
                "api": "SYNO.API.Auth",
                "method": "login",
                "version": "7",
                "account": self.credentials.username,
                "passwd": self.credentials.password,
                "session": "SynologyManager",
                "format": "sid",
            },
        )
        sid = data.get("sid")
        if not isinstance(sid, str) or not sid:
            raise AuthenticationError(
                "DSM login response did not include a session",
                api="SYNO.API.Auth",
                method="login",
                version=7,
            )
        self.sid = sid

    def _logout_request(self) -> None:
        """Perform logout strictly for context cleanup and always discard the session ID."""
        if self.sid is None:
            return
        try:
            detail = self._auth_api("logout")
            self._post(
                detail.path,
                {
                    "api": "SYNO.API.Auth",
                    "method": "logout",
                    "version": "7",
                    "session": "SynologyManager",
                    "_sid": self.sid,
                },
            )
        finally:
            self.sid = None

    def logout(self) -> None:
        """Best-effort public logout that records, but never exposes, cleanup failures."""
        try:
            self._logout_request()
        except Exception:
            self._record_cleanup_failure("logout")

    def require(
        self,
        required: dict[str, int],
        *,
        require_json: bool = False,
        operation: tuple[str, str, int] | None = None,
    ) -> None:
        for name, version in required.items():
            detail = self.apis.get(name)
            if detail is None or not detail.minimum <= version <= detail.maximum:
                if operation is not None:
                    raise operation_error(
                        UnsupportedCapability,
                        f"DSM does not support {name} v{version}",
                        api=operation[0],
                        method=operation[1],
                        version=operation[2],
                    )
                raise UnsupportedCapability(f"DSM does not support {name} v{version}")
            if require_json and detail.request_format != "JSON":
                if operation is not None:
                    raise operation_error(
                        UnsupportedCapability,
                        f"DSM does not advertise JSON requests for {name} v{version}",
                        api=operation[0],
                        method=operation[1],
                        version=operation[2],
                    )
                raise UnsupportedCapability(
                    f"DSM does not advertise JSON requests for {name} v{version}"
                )

    def call(
        self, api: str, method: str, parameters: dict[str, Any], *, version: int
    ) -> dict[str, Any]:
        operation = (
            (api, method, version)
            if re.fullmatch(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)+", api)
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", method)
            and isinstance(version, int)
            and not isinstance(version, bool)
            and version > 0
            else None
        )
        self.require({api: version}, require_json=True, operation=operation)
        if self.sid is None:
            if operation is None:
                raise AuthenticationError("DSM client is not logged in")
            raise operation_error(
                AuthenticationError,
                "DSM client is not logged in",
                api=api,
                method=method,
                version=version,
            )
        detail = self.apis[api]
        data = {"api": api, "method": method, "version": str(version), "_sid": self.sid}
        data.update(
            {key: json.dumps(value, separators=(",", ":")) for key, value in parameters.items()}
        )
        return self._post(detail.path, data)

    def inspect(self) -> dict[str, Any]:
        self.require({"SYNO.DSM.Info": 2, "SYNO.Core.System": 3, "SYNO.Core.FileServ.NFS": 3})
        dsm = self.call("SYNO.DSM.Info", "getinfo", {}, version=2)
        system = self.call("SYNO.Core.System", "info", {}, version=3)
        model = dsm.get("model") or system.get("model")
        version = dsm.get("version_string") or dsm.get("version") or dsm.get("firmware_ver")
        nfs = self.call("SYNO.Core.FileServ.NFS", "get", {}, version=3)
        keys = (
            "enable_nfs",
            "enable_nfs_v4",
            "enabled_minor_ver",
            "support_major_ver",
            "support_minor_ver",
        )
        parsed_version = (
            re.fullmatch(
                r"(?:DSM\s+)?(\d+)\.(\d+)\.(\d+)-(\d+)(?:\s+(?:Update|update)\s+(\d+))?", version
            )
            if isinstance(version, str)
            else None
        )
        if (
            not isinstance(model, str)
            or parsed_version is None
            or any(
                not isinstance(
                    nfs.get(key), bool if key in {"enable_nfs", "enable_nfs_v4"} else int
                )
                for key in keys
            )
        ):
            raise operation_error(
                DsmError,
                "DSM inspect response is invalid",
                api="SYNO.Core.FileServ.NFS",
                method="get",
                version=3,
            )
        major, minor, patch, build, update = parsed_version.groups()
        supported_inspect_apis = {
            "SYNO.DSM.Info",
            "SYNO.Core.System",
            "SYNO.Core.Share",
            "SYNO.Core.ACL",
            "SYNO.Core.FileServ.NFS",
            "SYNO.Core.FileServ.NFS.SharePrivilege",
            "SYNO.FileStation.List",
        }
        return {
            "model": model,
            "version": {
                "major": int(major),
                "minor": int(minor),
                "patch": int(patch),
                "build": int(build),
                "update": int(update) if update is not None else None,
            },
            "nfs": {key: nfs[key] for key in keys},
            "apis": [
                {
                    "name": name,
                    "minVersion": api.minimum,
                    "maxVersion": api.maximum,
                    "requestFormat": api.request_format,
                }
                for name, api in sorted(self.apis.items())
                if name in supported_inspect_apis
            ],
        }

    def list_shares(self) -> list[dict[str, Any]]:
        data = self.call(
            "SYNO.Core.Share",
            "list",
            {"offset": 0, "limit": -1, "additional": ["share_quota"], "shareType": "all"},
            version=1,
        )
        rules = data.get("shares")
        if not isinstance(rules, list) or not all(isinstance(item, dict) for item in rules):
            raise operation_error(
                DsmError,
                "share list response is invalid",
                api="SYNO.Core.Share",
                method="list",
                version=1,
            )
        return rules

    def nfs_enabled(self) -> bool:
        value = self.call("SYNO.Core.FileServ.NFS", "get", {}, version=3).get("enable_nfs")
        if not isinstance(value, bool):
            raise operation_error(
                DsmError,
                "NFS status response is invalid",
                api="SYNO.Core.FileServ.NFS",
                method="get",
                version=3,
            )
        return value

    def nfs_rules(self, share_name: str) -> list[dict[str, Any]]:
        rules = self.call(
            "SYNO.Core.FileServ.NFS.SharePrivilege", "load", {"share_name": share_name}, version=1
        ).get("rule")
        if not isinstance(rules, list) or not all(isinstance(item, dict) for item in rules):
            raise operation_error(
                DsmError,
                "NFS response is invalid",
                api="SYNO.Core.FileServ.NFS.SharePrivilege",
                method="load",
                version=1,
            )
        return rules

    def acl(self, path: str) -> dict[str, Any]:
        return self.call(
            "SYNO.Core.ACL",
            "get",
            {"type": "all", "file_path": path, "include_noname_rules": True},
            version=1,
        )

    def resolve_share_file_id(self, name: str, physical: str) -> str:
        offset = 0
        limit = 100
        maximum_pages = 1000
        maximum_total = 10_000
        total: int | None = None
        matches: list[dict[str, Any]] = []
        for _ in range(maximum_pages):
            data = self.call(
                "SYNO.FileStation.List",
                "list_share",
                {"offset": offset, "limit": limit, "additional": ["real_path"]},
                version=2,
            )
            entries, page_total = data.get("shares"), data.get("total")
            if (
                not isinstance(entries, list)
                or isinstance(page_total, bool)
                or not isinstance(page_total, int)
                or page_total < 0
                or page_total > maximum_total
                or page_total < offset
                or len(entries) > limit
                or not all(isinstance(entry, dict) for entry in entries)
                or (total is not None and page_total != total)
            ):
                raise operation_error(
                    UnsupportedCapability,
                    "FileStation resolver response is invalid",
                    api="SYNO.FileStation.List",
                    method="list_share",
                    version=2,
                )
            if total is None:
                total = page_total
            matches.extend(
                entry
                for entry in entries
                if entry.get("name") == name
                and entry.get("isdir") is True
                and isinstance(entry.get("additional"), dict)
                and entry["additional"].get("real_path") == physical
                and entry.get("path") == f"/{name}"
            )
            next_offset = offset + len(entries)
            if next_offset > page_total:
                raise operation_error(
                    UnsupportedCapability,
                    "FileStation pagination overshot total",
                    api="SYNO.FileStation.List",
                    method="list_share",
                    version=2,
                )
            if next_offset == page_total:
                break
            if not entries or next_offset <= offset:
                raise operation_error(
                    UnsupportedCapability,
                    "FileStation pagination is invalid",
                    api="SYNO.FileStation.List",
                    method="list_share",
                    version=2,
                )
            offset = next_offset
        else:
            raise operation_error(
                UnsupportedCapability,
                "FileStation pagination exceeded maximum pages",
                api="SYNO.FileStation.List",
                method="list_share",
                version=2,
            )
        if len(matches) != 1:
            raise operation_error(
                UnsupportedCapability,
                "FileStation resolver did not identify one share directory",
                api="SYNO.FileStation.List",
                method="list_share",
                version=2,
            )
        file_id = matches[0]["path"]
        if not isinstance(file_id, str):
            raise operation_error(
                UnsupportedCapability,
                "FileStation resolver path is invalid",
                api="SYNO.FileStation.List",
                method="list_share",
                version=2,
            )
        data = self.call(
            "SYNO.FileStation.List",
            "getinfo",
            {"path": [file_id], "additional": ["real_path"]},
            version=2,
        )
        entries = data.get("files")
        if not isinstance(entries, list) or len(entries) != 1 or entries[0] != matches[0]:
            raise operation_error(
                UnsupportedCapability,
                "FileStation resolver reconfirmation failed",
                api="SYNO.FileStation.List",
                method="getinfo",
                version=2,
            )
        return file_id
