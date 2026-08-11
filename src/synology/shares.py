import json
import logging as stdlib_logging
from collections.abc import Mapping, Sequence
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

from synology.config import normalize_nfs_client
from synology.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    PartialOperationError,
    TransportError,
)
from synology.logging import sanitize
from synology.models import (
    AclPermissionRecord,
    ConnectionConfig,
    EnrichmentDiagnostic,
    EnrichmentStatus,
    NfsAccessMode,
    NfsClientPermission,
    NfsSecurityFlavor,
    OperationStatus,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    PermissionStatus,
    ShareCreateRequest,
    ShareCreateResult,
    ShareDetails,
    ShareListRequest,
    ShareOperationStep,
    ShareRecord,
)

SHARE_OPERATION = "SYNO.Core.Share.list"
CREATE_OPERATION = "SYNO.Core.Share.create"


class ShareApi(Protocol):
    def list_folders(
        self,
        *,
        share_type: str,
        additional: list[str],
    ) -> object: ...

    def create_folder(
        self,
        *,
        name: str,
        vol_path: str,
        desc: str = "",
        hidden: bool = False,
        enable_recycle_bin: bool = True,
        recycle_bin_admin_only: bool = True,
        hide_unreadable: bool = False,
        enable_share_cow: bool = False,
        enable_share_compress: bool = False,
        share_quota: int = 0,
        name_org: str = "",
        encryption: bool = False,
        enc_passwd: str = "",
    ) -> object: ...


class SharePermissionApi(Protocol):
    def set_folder_permissions(
        self,
        name: str,
        user_group_type: str,
        permissions: list[dict[str, object]],
    ) -> object: ...

    def get_folder_permissions(
        self,
        name: str,
        offset: int = 0,
        limit: int = 50,
        is_unite_permission: bool = False,
        with_inherit: bool = False,
        user_group_type: str = "local_user",
    ) -> object: ...


class SharePermissionRawApi(SharePermissionApi, Protocol):
    core_list: Mapping[str, Mapping[str, object]]

    def request_data(
        self,
        api_name: str,
        api_path: str,
        req_param: dict[str, object],
        method: str,
    ) -> object: ...


class NfsRawApi(Protocol):
    core_list: Mapping[str, Mapping[str, object]]

    def request_data(
        self, api_name: str, api_path: str, req_param: dict[str, object], method: str
    ) -> object: ...


class NfsFactory(Protocol):
    def __call__(self, config: ConnectionConfig) -> NfsRawApi: ...


class SharePermissionFactory(Protocol):
    def __call__(self, config: ConnectionConfig) -> SharePermissionApi: ...


class ShareApiFactory(Protocol):
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


class SynShareClient:
    def __init__(
        self,
        config: ConnectionConfig,
        logger: stdlib_logging.Logger,
        *,
        factory: ShareApiFactory | None = None,
        permission_factory: SharePermissionFactory | None = None,
        nfs_factory: NfsFactory | None = None,
    ) -> None:
        self._config = config
        self._logger = logger
        self._share = self._create_share(factory or _default_share_factory)
        self._permission_factory = permission_factory or _default_permission_factory
        self._nfs_factory = nfs_factory or _default_nfs_factory
        self._permission: SharePermissionApi | None = None
        self._nfs: NfsRawApi | None = None

    def create_share(self, request: ShareCreateRequest) -> ShareCreateResult:
        self._logger.debug(
            "Synology API create request operation=%s target=%s:%s tls_verify=%s "
            "request=%s",
            CREATE_OPERATION,
            self._config.host,
            self._config.port,
            not self._config.insecure,
            sanitize(
                {
                    "name": request.name,
                    "volume": request.volume_path,
                    "description": request.description,
                    "options": {
                        "recycle_bin": {
                            "enabled": request.options.recycle_bin.enabled,
                            "admin_only": request.options.recycle_bin.admin_only,
                        },
                        "compression_enabled": request.options.compression_enabled,
                        "quota_gib": request.options.quota_gib,
                        "quota_api_value": request.options.quota_api_value,
                        "quota_api_unit": "MiB",
                    },
                }
            ),
        )
        nfs_api: NfsRawApi | None = None
        if request.nfs_permissions:
            try:
                nfs_api = self._nfs_api()
                if not _global_nfs_enabled(nfs_api):
                    raise ConfigurationError("global NFS must already be enabled")
            except ConfigurationError:
                raise
            except Exception as exc:
                self._raise_mapped_error(exc, phase="nfs-global-check")
        create_arguments: dict[str, object] = {
            "name": request.name,
            "vol_path": request.volume_path,
            "desc": request.description,
            "enable_recycle_bin": request.options.recycle_bin.enabled,
            "recycle_bin_admin_only": request.options.recycle_bin.admin_only,
            "enable_share_compress": request.options.compression_enabled,
        }
        if request.options.quota_api_value is not None:
            create_arguments["share_quota"] = request.options.quota_api_value
        try:
            response = _call_create_folder(self._share, create_arguments)

        except Exception as exc:
            self._raise_mapped_error(exc, phase="request")
        result = _normalize_create_response(response, request)
        if nfs_api is not None:
            result = _nfs_precheck_result(result)
        if request.permissions:
            try:
                permission_api = self._permission_api()
                permission_steps = _apply_permissions(
                    permission_api,
                    request.name,
                    request.permissions,
                )
                verified = _verify_permissions(
                    permission_api,
                    request.name,
                    request.permissions,
                )
            except Exception as exc:
                status = _permission_failure_status(exc)
                raise PartialOperationError(
                    "share created but permission configuration failed",
                    _permission_result(
                        result,
                        status,
                        _permission_failure_message(status),
                    ),
                ) from exc
            if not verified:
                raise PartialOperationError(
                    "share created but permission verification failed",
                    _permission_result(
                        result,
                        OperationStatus.FAILED,
                        "permission read-back did not match the requested complete ACL",
                    ),
                )
            result = _permission_result(
                result,
                OperationStatus.SUCCEEDED,
                "permissions verified",
                permission_steps,
            )
        if request.nfs_permissions:
            assert nfs_api is not None
            try:
                _save_nfs_rules(nfs_api, request.name, request.nfs_permissions)
                loaded_rules = _load_nfs_rules(nfs_api, request.name)
            except Exception as exc:
                status = _nfs_failure_status(exc)
                raise PartialOperationError(
                    "share created but NFS configuration failed",
                    _nfs_result(
                        result,
                        status,
                        _nfs_failure_message(status),
                    ),
                ) from exc
            if not _nfs_rules_match(request.nfs_permissions, loaded_rules):
                raise PartialOperationError(
                    "share created but NFS verification failed",
                    _nfs_result(
                        result,
                        OperationStatus.FAILED,
                        "NFS read-back did not match the requested complete rule set",
                    ),
                )
            result = _nfs_result(
                result,
                OperationStatus.SUCCEEDED,
                "NFS rules verified",
            )
        self._logger.debug(
            "Synology API response operation=%s success=%s name=%s",
            CREATE_OPERATION,
            True,
            result.name,
        )
        return result

    def list_shares(self) -> tuple[ShareRecord, ...]:
        request = ShareListRequest()
        self._log_request(request)
        try:
            response = self._share.list_folders(
                share_type=request.share_type,
                additional=list(request.additional),
            )
        except Exception as exc:
            self._raise_mapped_error(exc, phase="request")
        self._log_response(response)
        return _normalize_response(response)

    def list_share_details(self) -> tuple[ShareDetails, ...]:
        shares = self.list_shares()
        permission_api = self._permission_api()
        nfs_api = self._nfs_api()
        details: list[ShareDetails] = []
        for share in shares:
            acl: list[AclPermissionRecord] = []
            diagnostics: list[EnrichmentDiagnostic] = []
            acl_failed = False
            for category in PERMISSION_USER_GROUP_TYPES:
                try:
                    response = permission_api.get_folder_permissions(
                        share.name, user_group_type=category
                    )
                    acl.extend(_normalize_acl_entries(response, category))
                except Exception as exc:
                    acl_failed = True
                    diagnostics.append(
                        EnrichmentDiagnostic(
                            share.name,
                            "ACL enrichment failed",
                            category,
                        )
                    )
                    self._logger.debug(
                        "Share enrichment failed category=%s error_type=%s",
                        category,
                        type(exc).__name__,
                    )
            try:
                nfs = _load_nfs_rules(nfs_api, share.name)
                nfs_status = (
                    EnrichmentStatus.AVAILABLE if nfs else EnrichmentStatus.EMPTY
                )
            except Exception as exc:
                nfs = ()
                nfs_status = EnrichmentStatus.UNAVAILABLE
                diagnostics.append(
                    EnrichmentDiagnostic(share.name, "NFS enrichment failed", "nfs")
                )
                self._logger.debug(
                    "Share enrichment failed category=nfs error_type=%s",
                    type(exc).__name__,
                )
            details.append(
                ShareDetails(
                    share=share,
                    acl_permissions=tuple(acl),
                    nfs_permissions=nfs,
                    acl_status=(
                        EnrichmentStatus.UNAVAILABLE
                        if acl_failed
                        else (
                            EnrichmentStatus.AVAILABLE
                            if acl
                            else EnrichmentStatus.EMPTY
                        )
                    ),
                    nfs_status=nfs_status,
                    diagnostics=tuple(diagnostics),
                )
            )
        return tuple(details)

    def _nfs_api(self) -> NfsRawApi:
        if self._nfs is None:
            self._nfs = self._nfs_factory(self._config)
        return self._nfs

    def _permission_api(self) -> SharePermissionApi:
        if self._permission is None:
            self._permission = self._permission_factory(self._config)
        return self._permission

    def _create_share(self, factory: ShareApiFactory) -> ShareApi:
        try:
            return factory(
                ip_address=self._config.host,
                port=str(self._config.port),
                username=self._config.username,
                password=self._config.password,
                secure=True,
                cert_verify=not self._config.insecure,
                dsm_version=7,
                debug=False,
            )
        except ValueError as exc:
            self._logger.debug(
                "Synology API initialization failed phase=initialization error_type=%s",
                type(exc).__name__,
            )
            raise ConfigurationError("invalid NAS connection configuration") from exc
        except Exception as exc:
            self._raise_mapped_error(exc, phase="initialization")

    def _log_request(self, request: ShareListRequest) -> None:
        parameters = {
            "method": "list",
            "shareType": request.share_type,
            "additional": list(request.additional),
        }
        self._logger.debug(
            "Synology API request operation=%s target=%s:%s "
            "tls_verify=%s parameters=%s",
            SHARE_OPERATION,
            self._config.host,
            self._config.port,
            not self._config.insecure,
            sanitize(parameters),
        )

    def _log_response(self, response: object) -> None:
        try:
            summary = _response_summary(response)
            self._logger.debug(
                "Synology API response operation=%s response=%s",
                SHARE_OPERATION,
                sanitize(summary),
            )
        except Exception as exc:
            self._logger.debug(
                "Synology API response diagnostic failed error_type=%s",
                type(exc).__name__,
            )

    def _raise_mapped_error(self, exc: Exception, *, phase: str) -> NoReturn:
        self._logger.debug(
            "Synology API failure phase=%s error_type=%s",
            phase,
            type(exc).__name__,
        )
        if isinstance(exc, LoginError):
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
        if isinstance(exc, (CoreError, UndefinedError, SynoBaseException)):
            raise ApiError("NAS API request failed") from exc
        raise exc


def _call_create_folder(
    share: ShareApi,
    arguments: Mapping[str, object],
) -> object:
    name = cast(str, arguments["name"])
    volume_path = cast(str, arguments["vol_path"])
    description = cast(str, arguments["desc"])
    enable_recycle_bin = cast(bool, arguments["enable_recycle_bin"])
    recycle_bin_admin_only = cast(bool, arguments["recycle_bin_admin_only"])
    compression_enabled = cast(bool, arguments["enable_share_compress"])
    if "share_quota" in arguments:
        return share.create_folder(
            name=name,
            vol_path=volume_path,
            desc=description,
            enable_recycle_bin=enable_recycle_bin,
            recycle_bin_admin_only=recycle_bin_admin_only,
            enable_share_compress=compression_enabled,
            share_quota=cast(int, arguments["share_quota"]),
        )
    return share.create_folder(
        name=name,
        vol_path=volume_path,
        desc=description,
        enable_recycle_bin=enable_recycle_bin,
        recycle_bin_admin_only=recycle_bin_admin_only,
        enable_share_compress=compression_enabled,
    )


class _SharePermissionAdapter:
    def __init__(self, api: SharePermissionRawApi) -> None:
        self._api = api

    def set_folder_permissions(
        self,
        name: str,
        user_group_type: str,
        permissions: list[dict[str, object]],
    ) -> object:
        info = self._api.core_list["SYNO.Core.Share.Permission"]
        return self._api.request_data(
            "SYNO.Core.Share.Permission",
            cast(str, info["path"]),
            {
                "version": cast(int, info["minVersion"]),
                "method": "set",
                "name": json.dumps(name),
                "user_group_type": json.dumps(user_group_type),
                "permissions": json.dumps(permissions, separators=(",", ":")),
            },
            method="get",
        )

    def get_folder_permissions(
        self,
        name: str,
        offset: int = 0,
        limit: int = 50,
        is_unite_permission: bool = False,
        with_inherit: bool = False,
        user_group_type: str = "local_user",
    ) -> object:
        api = cast(SharePermissionApi, self._api)
        return api.get_folder_permissions(
            name,
            offset=offset,
            limit=limit,
            is_unite_permission=is_unite_permission,
            with_inherit=with_inherit,
            user_group_type=user_group_type,
        )


def _default_nfs_factory(config: ConnectionConfig) -> NfsRawApi:
    from synology_api.core_share import Share

    return cast(
        NfsRawApi,
        Share(
            ip_address=config.host,
            port=str(config.port),
            username=config.username,
            password=config.password,
            secure=True,
            cert_verify=not config.insecure,
            dsm_version=7,
            debug=False,
        ),
    )


NFS_GLOBAL_API = "SYNO.Core.FileServ.NFS"
NFS_SHARE_PRIVILEGE_API = "SYNO.Core.FileServ.NFS.SharePrivilege"


def _required_api_version(info: Mapping[str, object], required: int) -> int:
    maximum = info.get("maxVersion")
    if not isinstance(maximum, int) or maximum < required:
        raise ApiError("NAS does not support the required NFS API version")
    return required


def _global_nfs_enabled(api: NfsRawApi) -> bool:
    info = api.core_list[NFS_GLOBAL_API]
    response = api.request_data(
        NFS_GLOBAL_API,
        cast(str, info["path"]),
        {"version": _required_api_version(info, 2), "method": "get"},
        method="get",
    )
    envelope = _as_mapping(response, "invalid global NFS response")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful global NFS response")
    data = _as_mapping(envelope.get("data"), "invalid global NFS response data")
    enabled = data.get("enable_nfs")
    if not isinstance(enabled, bool):
        raise ApiError("invalid global NFS response data")
    return enabled


def _save_nfs_rules(
    api: NfsRawApi,
    share_name: str,
    permissions: tuple[NfsClientPermission, ...],
) -> None:
    info = api.core_list[NFS_SHARE_PRIVILEGE_API]
    response = api.request_data(
        NFS_SHARE_PRIVILEGE_API,
        cast(str, info["path"]),
        {
            "version": _required_api_version(info, 1),
            "method": "save",
            "share_name": json.dumps(share_name),
            "rule": json.dumps(
                [_nfs_rule(permission) for permission in permissions],
                separators=(",", ":"),
            ),
        },
        method="get",
    )
    if _as_mapping(response, "invalid NFS save response").get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful NFS save response")


def _load_nfs_rules(
    api: NfsRawApi,
    share_name: str,
) -> tuple[NfsClientPermission, ...]:
    info = api.core_list[NFS_SHARE_PRIVILEGE_API]
    response = api.request_data(
        NFS_SHARE_PRIVILEGE_API,
        cast(str, info["path"]),
        {
            "version": _required_api_version(info, 1),
            "method": "load",
            "share_name": json.dumps(share_name),
        },
        method="get",
    )
    envelope = _as_mapping(response, "invalid NFS load response")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful NFS load response")
    data = _as_mapping(envelope.get("data"), "invalid NFS load response data")
    rules = _as_sequence(data.get("rule"), "invalid NFS load response rules")
    return tuple(_normalize_nfs_rule(rule) for rule in rules)


def _nfs_rule(permission: NfsClientPermission) -> dict[str, object]:
    return {
        "async": permission.async_enabled,
        "client": permission.client,
        "crossmnt": permission.crossmnt,
        "insecure": permission.insecure,
        "privilege": "rw"
        if permission.access_mode is NfsAccessMode.READ_WRITE
        else "ro",
        "root_squash": permission.root_squash,
        "security_flavor": {
            "sys": permission.security_flavor.sys,
            "kerberos": permission.security_flavor.kerberos,
            "kerberos_integrity": permission.security_flavor.kerberos_integrity,
            "kerberos_privacy": permission.security_flavor.kerberos_privacy,
        },
    }


def _normalize_nfs_rule(value: object) -> NfsClientPermission:
    rule = _as_mapping(value, "invalid NFS rule")
    client = rule.get("client")
    privilege = rule.get("privilege")
    async_enabled = rule.get("async")
    insecure = rule.get("insecure")
    crossmnt = rule.get("crossmnt")
    root_squash = rule.get("root_squash")
    security = _as_mapping(rule.get("security_flavor"), "invalid NFS security flavor")
    if (
        not isinstance(client, str)
        or privilege not in {"ro", "rw"}
        or not isinstance(async_enabled, bool)
        or not isinstance(insecure, bool)
        or not isinstance(crossmnt, bool)
        or root_squash != "root"
    ):
        raise ApiError("invalid NFS rule")
    try:
        canonical_client = normalize_nfs_client(client)[0]
    except ConfigurationError as exc:
        raise ApiError("invalid NFS rule") from exc
    security_flavor = NfsSecurityFlavor(
        sys=_nfs_security_value(security, "sys"),
        kerberos=_nfs_security_value(security, "kerberos"),
        kerberos_integrity=_nfs_security_value(security, "kerberos_integrity"),
        kerberos_privacy=_nfs_security_value(security, "kerberos_privacy"),
    )
    if security_flavor != NfsSecurityFlavor():
        raise ApiError("invalid NFS security flavor")
    return NfsClientPermission(
        client=canonical_client,
        access_mode=(
            NfsAccessMode.READ_WRITE if privilege == "rw" else NfsAccessMode.READ_ONLY
        ),
        async_enabled=async_enabled,
        insecure=insecure,
        crossmnt=crossmnt,
        root_squash=root_squash,
        security_flavor=security_flavor,
    )


def _nfs_security_value(security: Mapping[str, object], key: str) -> bool:
    value = security.get(key)
    if not isinstance(value, bool):
        raise ApiError("invalid NFS security flavor")
    return value


def _nfs_rules_match(
    expected: tuple[NfsClientPermission, ...],
    actual: tuple[NfsClientPermission, ...],
) -> bool:
    return set(expected) == set(actual)


def _nfs_precheck_result(result: ShareCreateResult) -> ShareCreateResult:
    return ShareCreateResult(
        name=result.name,
        volume=result.volume,
        description=result.description,
        created=result.created,
        options=result.options,
        permissions=result.permissions,
        nfs_permissions=result.nfs_permissions,
        steps=(
            *result.steps,
            ShareOperationStep(name="nfs-precheck", status=OperationStatus.SUCCEEDED),
        ),
    )


def _nfs_result(
    result: ShareCreateResult,
    status: OperationStatus,
    message: str | None = None,
) -> ShareCreateResult:
    if status is OperationStatus.SUCCEEDED:
        steps = (
            *result.steps,
            ShareOperationStep(name="nfs-save", status=OperationStatus.SUCCEEDED),
            ShareOperationStep(name="nfs-verify", status=OperationStatus.SUCCEEDED),
        )
    else:
        steps = (
            *result.steps,
            ShareOperationStep(name="nfs", status=status, message=message),
        )
    return ShareCreateResult(
        name=result.name,
        volume=result.volume,
        description=result.description,
        created=result.created,
        options=result.options,
        permissions=result.permissions,
        nfs_permissions=result.nfs_permissions,
        steps=steps,
    )


def _nfs_failure_status(exc: Exception) -> OperationStatus:
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
        return OperationStatus.UNKNOWN
    return OperationStatus.FAILED


def _nfs_failure_message(status: OperationStatus) -> str:
    if status is OperationStatus.UNKNOWN:
        return "NFS mutation outcome is unknown after share creation"
    return "NFS mutation failed after share creation"


def _default_permission_factory(config: ConnectionConfig) -> SharePermissionApi:
    from synology_api.core_share import SharePermission

    return _SharePermissionAdapter(
        cast(
            SharePermissionRawApi,
            SharePermission(
                ip_address=config.host,
                port=str(config.port),
                username=config.username,
                password=config.password,
                secure=True,
                cert_verify=not config.insecure,
                dsm_version=7,
                debug=False,
            ),
        )
    )


PERMISSION_USER_GROUP_TYPES = (
    "local_user",
    "local_group",
    "ldap_user",
    "ldap_group",
)

# Missing explicitness metadata is excluded conservatively from ACL output.
CUSTOM_ACL_POLICY = "require-is-custom-true"


def _permission_result(
    result: ShareCreateResult,
    status: OperationStatus,
    message: str | None = None,
    permission_steps: tuple[ShareOperationStep, ...] = (),
) -> ShareCreateResult:
    return ShareCreateResult(
        name=result.name,
        volume=result.volume,
        description=result.description,
        created=result.created,
        options=result.options,
        permissions=result.permissions,
        nfs_permissions=result.nfs_permissions,
        steps=(
            *result.steps,
            *permission_steps,
            ShareOperationStep(
                name="permissions",
                status=status,
                message=message,
                permission_status=_permission_status(status),
            ),
        ),
    )


def _permission_status(status: OperationStatus) -> PermissionStatus:
    return {
        OperationStatus.PLANNED: PermissionStatus.PLANNED,
        OperationStatus.SUCCEEDED: PermissionStatus.VERIFIED,
        OperationStatus.FAILED: PermissionStatus.FAILED,
        OperationStatus.UNKNOWN: PermissionStatus.UNVERIFIED,
        OperationStatus.SKIPPED: PermissionStatus.UNVERIFIED,
    }[status]


def _permission_failure_status(exc: Exception) -> OperationStatus:
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
        return OperationStatus.UNKNOWN
    return OperationStatus.FAILED


def _permission_failure_message(status: OperationStatus) -> str:
    if status is OperationStatus.UNKNOWN:
        return "permission mutation outcome is unknown after share creation"
    return "permission mutation failed after share creation"


def _permission_type(permission: PermissionSpec) -> str:
    return {
        PermissionPrincipalType.LOCAL_USER: "local_user",
        PermissionPrincipalType.LOCAL_GROUP: "local_group",
        PermissionPrincipalType.LDAP_USER: "ldap_user",
        PermissionPrincipalType.LDAP_GROUP: "ldap_group",
    }[permission.principal_type]


def _permission_payload(permission: PermissionSpec) -> dict[str, object]:
    return {
        "name": permission.principal_name,
        "is_deny": permission.access_mode is PermissionAccessMode.DENY,
        "is_readonly": permission.access_mode is PermissionAccessMode.READ_ONLY,
        "is_writable": permission.access_mode is PermissionAccessMode.READ_WRITE,
    }


def _grouped_permission_payloads(
    permissions: tuple[PermissionSpec, ...],
) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = {
        user_group_type: [] for user_group_type in PERMISSION_USER_GROUP_TYPES
    }
    for permission in sorted(
        permissions,
        key=lambda item: (_permission_type(item), item.principal_name),
    ):
        grouped[_permission_type(permission)].append(_permission_payload(permission))
    return grouped


def _apply_permissions(
    api: SharePermissionApi,
    name: str,
    permissions: tuple[PermissionSpec, ...],
) -> tuple[ShareOperationStep, ...]:
    grouped = _grouped_permission_payloads(permissions)
    steps: list[ShareOperationStep] = []
    for user_group_type in PERMISSION_USER_GROUP_TYPES:
        response = api.set_folder_permissions(
            name,
            user_group_type,
            grouped[user_group_type],
        )
        envelope = _as_mapping(response, "invalid permission response envelope")
        if envelope.get("success") is not True:
            raise ApiError("NAS API returned an unsuccessful permission response")
        steps.append(
            ShareOperationStep(
                name=f"permissions:{user_group_type}",
                status=OperationStatus.SUCCEEDED,
                permission_status=PermissionStatus.UNVERIFIED,
            )
        )
    return tuple(steps)


def _verify_permissions(
    api: SharePermissionApi,
    name: str,
    expected: tuple[PermissionSpec, ...],
) -> bool:
    grouped = _grouped_permission_payloads(expected)
    for user_group_type in PERMISSION_USER_GROUP_TYPES:
        response = api.get_folder_permissions(
            name,
            user_group_type=user_group_type,
        )
        actual = _permission_entries(response)
        wanted = {
            (
                cast(str, item["name"]),
                cast(bool, item["is_deny"]),
                cast(bool, item["is_readonly"]),
                cast(bool, item["is_writable"]),
            )
            for item in grouped[user_group_type]
        }
        if not wanted.issubset(actual):
            return False
    return True


def _normalize_acl_entries(
    response: object, category: str
) -> tuple[AclPermissionRecord, ...]:
    envelope = _as_mapping(response, "invalid permission response envelope")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful permission response")
    data = _as_mapping(envelope.get("data"), "invalid permission response data")
    values = _as_sequence(
        data.get("permissions", data.get("items")),
        "invalid permission response permissions",
    )
    entries: list[AclPermissionRecord] = []
    for value in values:
        item = _as_mapping(value, "invalid permission response item")
        name = item.get("name")
        is_deny = item.get("is_deny")
        is_readonly = item.get("is_readonly")
        is_writable = item.get("is_writable")
        is_custom = item.get("is_custom", False)
        is_admin = item.get("is_admin", False)
        if (
            not isinstance(name, str)
            or not isinstance(is_deny, bool)
            or not isinstance(is_readonly, bool)
            or not isinstance(is_writable, bool)
            or not isinstance(is_custom, bool)
            or not isinstance(is_admin, bool)
        ):
            raise ApiError("invalid permission response item")
        effective_admin = is_admin and (is_deny or is_readonly or is_writable)
        if is_custom or effective_admin:
            entries.append(
                AclPermissionRecord(
                    name,
                    category,
                    is_deny,
                    is_readonly,
                    is_writable,
                    is_custom,
                    is_admin,
                )
            )
    return tuple(entries)


def _permission_entries(response: object) -> set[tuple[str, bool, bool, bool]]:
    envelope = _as_mapping(response, "invalid permission response envelope")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful permission response")
    data = _as_mapping(envelope.get("data"), "invalid permission response data")
    values = _as_sequence(
        data.get("permissions", data.get("items")),
        "invalid permission response permissions",
    )
    entries: set[tuple[str, bool, bool, bool]] = set()
    for value in values:
        item = _as_mapping(value, "invalid permission response item")
        name = item.get("name")
        is_deny = item.get("is_deny")
        is_readonly = item.get("is_readonly")
        is_writable = item.get("is_writable")
        if (
            not isinstance(name, str)
            or not isinstance(is_deny, bool)
            or not isinstance(is_readonly, bool)
            or not isinstance(is_writable, bool)
        ):
            raise ApiError("invalid permission response item")
        entries.add((name, is_deny, is_readonly, is_writable))
    return entries


def _default_share_factory(
    *,
    ip_address: str,
    port: str,
    username: str,
    password: str,
    secure: bool,
    cert_verify: bool,
    dsm_version: int,
    debug: bool,
) -> ShareApi:
    from synology_api.core_share import Share

    share = Share(
        ip_address=ip_address,
        port=port,
        username=username,
        password=password,
        secure=secure,
        cert_verify=cert_verify,
        dsm_version=dsm_version,
        debug=debug,
    )
    return cast(ShareApi, share)


def _normalize_create_response(
    response: object, request: ShareCreateRequest
) -> ShareCreateResult:
    envelope = _as_mapping(response, "invalid share creation response envelope")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful share creation response")
    data = _as_mapping(envelope.get("data"), "invalid share creation response data")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ApiError("invalid share creation response name")
    return ShareCreateResult(
        name=name,
        volume=request.volume_path,
        description=request.description,
        created=True,
        options=request.options,
        permissions=request.permissions,
        nfs_permissions=request.nfs_permissions,
        steps=(ShareOperationStep(name="create", status=OperationStatus.SUCCEEDED),),
    )


def _normalize_response(response: object) -> tuple[ShareRecord, ...]:
    envelope = _as_mapping(response, "invalid share response envelope")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful share response")
    data = _as_mapping(envelope.get("data"), "invalid share response data")
    shares = _as_sequence(data.get("shares"), "invalid share response shares")
    if "total" in data and not _is_integer(data["total"]):
        raise ApiError("invalid share response total")
    return tuple(_normalize_share(item) for item in shares)


def _as_mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ApiError(message)
    mapping: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ApiError(message)
        mapping[key] = item
    return mapping


def _as_sequence(value: object, message: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ApiError(message)
    return tuple(value)


def _normalize_share(value: object) -> ShareRecord:
    record = _as_mapping(value, "invalid share record")
    name = record.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ApiError("invalid share record name")
    quota_api_value = _optional_quota(record.get("quota_value"))
    return ShareRecord(
        name=name,
        volume=_optional_string(record, "vol_path"),
        description=_optional_string(record, "desc"),
        uuid=_optional_string(record, "uuid"),
        is_usb=_optional_boolean(record, "is_usb_share"),
        quota_gib=(quota_api_value / 1024 if quota_api_value is not None else None),
        quota_api_value=quota_api_value,
    )


def _optional_string(record: Mapping[str, object], field: str) -> str | None:
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ApiError(f"invalid share field: {field}")
    return value


def _optional_quota(value: object) -> int | None:
    if value is None or value == 0:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ApiError("invalid share quota")
    return value


def _optional_boolean(record: Mapping[str, object], field: str) -> bool | None:
    value = record.get(field)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ApiError(f"invalid share field: {field}")
    return value


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _response_summary(response: object) -> dict[str, object]:
    if not isinstance(response, Mapping):
        return {"response_type": type(response).__name__}
    summary: dict[str, object] = {"success": response.get("success")}
    data = response.get("data")
    if not isinstance(data, Mapping):
        return summary
    data_summary: dict[str, object] = {}
    if "total" in data:
        data_summary["total"] = data.get("total")
    shares = data.get("shares")
    if isinstance(shares, Sequence) and not isinstance(
        shares,
        (str, bytes, bytearray),
    ):
        data_summary["shares"] = _response_share_summary(shares)
    else:
        data_summary["shares_type"] = type(shares).__name__
    summary["data"] = data_summary
    return summary


def _response_share_summary(shares: Sequence[object]) -> list[dict[str, object]]:
    fields = (
        "name",
        "vol_path",
        "desc",
        "uuid",
        "is_usb_share",
        "quota_value",
        "share_quota_logical_size",
        "share_quota_physical_size",
        "share_quota_status",
        "share_quota_used",
    )
    summary: list[dict[str, object]] = []
    for index, share in enumerate(shares):
        if index >= 100:
            summary.append({"truncated": "[TRUNCATED]"})
            break
        if isinstance(share, Mapping):
            summary.append(
                {field: share.get(field) for field in fields if field in share}
            )
        else:
            summary.append({"record_type": type(share).__name__})
    return summary
