import json
import logging as stdlib_logging
from collections.abc import Mapping, Sequence
from typing import Any, NoReturn, Protocol, cast

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
    QUOTA_MIB_PER_GIB,
    normalize_nfs_client,
    validate_share_create_request,
    validate_share_modify_request,
)
from synology.exceptions import (
    ApiError,
    AuthenticationError,
    ConfigurationError,
    PartialOperationError,
    PrincipalNotFoundError,
    ScalarUpdatePreflightError,
    TransportError,
)
from synology.logging import sanitize
from synology.models import (
    AclPermissionInventory,
    AclPermissionRecord,
    AclPermissionState,
    AclPrincipal,
    ConnectionConfig,
    EnrichmentDiagnostic,
    EnrichmentStatus,
    MutableShareState,
    NfsAccessMode,
    NfsClientPermission,
    NfsDisplayPermission,
    NfsRootSquash,
    NfsSecurityFlavor,
    OperationStatus,
    PermissionAccessMode,
    PermissionPrincipalType,
    PermissionSpec,
    PermissionStatus,
    PrincipalIdentity,
    PrincipalLookupRequest,
    PrincipalLookupResult,
    ShareCapabilities,
    ShareCreateRequest,
    ShareCreateResult,
    ShareDeleteRequest,
    ShareDeleteResult,
    ShareDetails,
    ShareListRequest,
    ShareModifyRequest,
    ShareModifyResult,
    ShareOperationStep,
    ShareQuotaState,
    ShareRecord,
    ShareScalarUpdatePayload,
    ShareScalarUpdateRequest,
)

SHARE_OPERATION = "SYNO.Core.Share.list"
CREATE_OPERATION = "SYNO.Core.Share.create"
DELETE_OPERATION = "SYNO.Core.Share.delete"
SHARE_SET_API = "SYNO.Core.Share"


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

    def delete_folders(self, name: list[str]) -> object: ...

    def get_folder(self, name: str, additional: list[str]) -> object: ...


class ShareQuotaRawApi(ShareApi, Protocol):
    core_list: Mapping[str, Mapping[str, object]]

    def request_data(
        self,
        api_name: str,
        api_path: str,
        req_param: dict[str, object],
        method: str,
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
        request = validate_share_create_request(request)
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
        }
        if request.options.scalar_options_available:
            create_arguments["enable_share_compress"] = (
                request.options.compression_enabled
            )
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

    def modify_share(self, request: ShareModifyRequest) -> ShareModifyResult:
        request = validate_share_modify_request(request)
        if request.quota_gib is not None:
            return self._modify_quota(request)
        if request.permissions is not None:
            return self._modify_permissions(request)
        if request.nfs_permissions is not None:
            return self._modify_nfs_permissions(request)
        raise ConfigurationError("exactly one modification family must be selected")

    def _modify_quota(self, request: ShareModifyRequest) -> ShareModifyResult:
        assert request.quota_gib is not None
        api = cast(ShareQuotaRawApi, self._share)
        try:
            version = _share_set_version(api)
            current = _read_mutable_share_state(api, request.name)
        except Exception as exc:
            self._raise_mapped_error(exc, phase="quota-preflight")
        if current.quota is None:
            raise ApiError(
                f"share {request.name} on {current.volume_path} "
                "does not support quota management"
            )
        desired_api_value = request.quota_gib * QUOTA_MIB_PER_GIB
        if current.quota.api_value == desired_api_value:
            return ShareModifyResult(
                name=request.name,
                changed=False,
                quota_gib=request.quota_gib,
                observed_quota=current.quota,
                steps=(
                    ShareOperationStep(
                        name="quota",
                        status=OperationStatus.SKIPPED,
                        message="quota already matches requested value",
                    ),
                ),
            )
        payload = _scalar_update_payload(
            current,
            version,
            ShareScalarUpdateRequest(
                request.name, current.description, desired_api_value
            ),
        )
        try:
            response = api.request_data(
                SHARE_SET_API,
                cast(str, api.core_list[SHARE_SET_API]["path"]),
                {
                    "version": payload.version,
                    "method": "set",
                    "name": payload.name,
                    "shareinfo": payload.shareinfo,
                },
                method="post",
            )
        except Exception as exc:
            self._raise_quota_write_failure(exc, request)
        envelope = _quota_set_envelope(response)
        if envelope is None:
            self._raise_quota_partial_failure(
                ApiError("invalid share quota set response"),
                request,
                [],
                "quota set response was malformed",
                step_name="quota:set",
            )
        if envelope.get("success") is False:
            raise ApiError("NAS API returned an unsuccessful share quota set response")
        if envelope.get("success") is not True:
            self._raise_quota_partial_failure(
                ApiError("invalid share quota set response"),
                request,
                [],
                "quota set response was malformed",
                step_name="quota:set",
            )
        steps = [ShareOperationStep(name="quota:set", status=OperationStatus.SUCCEEDED)]
        try:
            observed = _read_mutable_share_state(api, request.name)
        except Exception as exc:
            self._raise_quota_partial_failure(
                exc,
                request,
                steps,
                "quota verification did not complete",
            )
        if (
            observed.quota is None
            or observed.quota.api_value != desired_api_value
            or not _share_state_preserved(current, observed)
        ):
            steps.append(
                ShareOperationStep(
                    name="quota:verify",
                    status=OperationStatus.FAILED,
                    message="quota or preserved share state did not match read-back",
                )
            )
            raise PartialOperationError(
                "share quota modification verification failed",
                ShareModifyResult(
                    name=request.name,
                    changed=True,
                    quota_gib=request.quota_gib,
                    observed_quota=observed.quota,
                    steps=tuple(steps),
                ),
            )
        steps.append(
            ShareOperationStep(name="quota:verify", status=OperationStatus.SUCCEEDED)
        )
        return ShareModifyResult(
            name=request.name,
            changed=True,
            quota_gib=request.quota_gib,
            observed_quota=observed.quota,
            steps=tuple(steps),
        )

    def _raise_quota_write_failure(
        self, exc: Exception, request: ShareModifyRequest
    ) -> NoReturn:
        if isinstance(exc, ApiError):
            raise exc
        if isinstance(exc, (CoreError, UndefinedError, SynoBaseException)):
            raise ApiError("NAS API request failed") from exc
        self._raise_quota_partial_failure(
            exc,
            request,
            [],
            "quota set request outcome is unknown",
            step_name="quota:set",
        )

    def _raise_quota_partial_failure(
        self,
        exc: Exception,
        request: ShareModifyRequest,
        steps: list[ShareOperationStep],
        message: str,
        step_name: str = "quota:verify",
    ) -> NoReturn:
        status = _quota_failure_status(exc)
        steps.append(ShareOperationStep(name=step_name, status=status, message=message))
        raise PartialOperationError(
            "share quota modification outcome is uncertain",
            ShareModifyResult(
                name=request.name,
                changed=True,
                quota_gib=request.quota_gib,
                steps=tuple(steps),
            ),
        ) from exc

    def _modify_permissions(self, request: ShareModifyRequest) -> ShareModifyResult:
        try:
            api = self._permission_api()
            inventory = _read_modify_permission_inventory(api, request.name)
        except Exception as exc:
            self._raise_mapped_error(exc, phase="permission-preflight")
        if request.permissions is not None:
            _validate_requested_principals(inventory, request.permissions)
        current = _active_modify_permissions(inventory)
        desired = request.permissions
        assert desired is not None
        deltas = _permission_deltas(
            current,
            desired,
            clear_mode=request._acl_clear_mode,
            authoritative_mode=request._acl_authoritative_mode,
        )
        if (
            _compare_modify_permissions(
                current,
                desired,
                clear_mode=request._acl_clear_mode,
                authoritative_mode=request._acl_authoritative_mode,
            )
            is None
        ):
            return ShareModifyResult(
                name=request.name,
                changed=False,
                permissions=request.permissions,
                steps=tuple(
                    ShareOperationStep(
                        name=f"permissions:{category}",
                        status=OperationStatus.SKIPPED,
                        message="no ACL delta",
                        permission_status=PermissionStatus.VERIFIED,
                    )
                    for category in PERMISSION_USER_GROUP_TYPES
                ),
            )
        steps: list[ShareOperationStep] = []
        for category in PERMISSION_USER_GROUP_TYPES:
            delta, desired_count, revoked_count = deltas[category]
            if not delta:
                steps.append(
                    ShareOperationStep(
                        name=f"permissions:{category}",
                        status=OperationStatus.SKIPPED,
                        message="no ACL delta",
                        permission_status=PermissionStatus.UNVERIFIED,
                    )
                )
                continue
            message = f"desired={desired_count} revoked={revoked_count}"
            try:
                _set_permissions(api, request.name, category, delta)
            except Exception as exc:
                status = _permission_failure_status(exc)
                steps.append(
                    ShareOperationStep(
                        name=f"permissions:{category}",
                        status=status,
                        message=f"ACL delta did not complete ({message})",
                        permission_status=_permission_status(status),
                    )
                )
                raise PartialOperationError(
                    "share permission modification is uncertain",
                    ShareModifyResult(
                        name=request.name,
                        changed=True,
                        permissions=desired,
                        steps=tuple(steps),
                    ),
                ) from exc
            steps.append(
                ShareOperationStep(
                    name=f"permissions:{category}",
                    status=OperationStatus.SUCCEEDED,
                    message=message,
                    permission_status=PermissionStatus.UNVERIFIED,
                )
            )
        try:
            mismatch = _compare_modify_permissions(
                _active_modify_permissions(
                    _read_modify_permission_inventory(api, request.name)
                ),
                desired,
                clear_mode=request._acl_clear_mode,
                authoritative_mode=request._acl_authoritative_mode,
            )
        except Exception as exc:
            status = _permission_failure_status(exc)
            steps.append(
                ShareOperationStep(
                    name="permissions:verify",
                    status=status,
                    message="ACL replacement verification did not complete",
                    permission_status=_permission_status(status),
                )
            )
            raise PartialOperationError(
                "share permission modification verification is uncertain",
                ShareModifyResult(
                    name=request.name,
                    changed=True,
                    permissions=desired,
                    steps=tuple(steps),
                ),
            ) from exc
        if mismatch is not None:
            steps.append(
                ShareOperationStep(
                    name="permissions:verify",
                    status=OperationStatus.FAILED,
                    message=f"ACL replacement mismatch: {mismatch}",
                    permission_status=PermissionStatus.FAILED,
                )
            )
            raise PartialOperationError(
                "share permission modification verification failed",
                ShareModifyResult(
                    name=request.name,
                    changed=True,
                    permissions=desired,
                    steps=tuple(steps),
                ),
            )
        steps.append(
            ShareOperationStep(
                name="permissions:verify",
                status=OperationStatus.SUCCEEDED,
                permission_status=PermissionStatus.VERIFIED,
            )
        )
        return ShareModifyResult(
            name=request.name,
            changed=True,
            permissions=desired,
            steps=tuple(steps),
        )

    def _modify_nfs_permissions(self, request: ShareModifyRequest) -> ShareModifyResult:
        assert request.nfs_permissions is not None
        try:
            api = self._nfs_api()
            if not _global_nfs_enabled(api):
                raise ConfigurationError("global NFS must already be enabled")
            current = _load_nfs_rules(api, request.name)
        except ConfigurationError:
            raise
        except Exception as exc:
            self._raise_mapped_error(exc, phase="nfs-preflight")
        if _nfs_rules_match(request.nfs_permissions, current):
            return ShareModifyResult(
                name=request.name,
                changed=False,
                nfs_permissions=request.nfs_permissions,
                steps=(
                    ShareOperationStep(
                        name="nfs",
                        status=OperationStatus.SKIPPED,
                        message="NFS rules already match requested replacement",
                    ),
                ),
            )
        try:
            _save_nfs_rules(api, request.name, request.nfs_permissions)
        except Exception as exc:
            status = _nfs_failure_status(exc)
            raise PartialOperationError(
                "share NFS modification is uncertain",
                ShareModifyResult(
                    name=request.name,
                    changed=True,
                    nfs_permissions=request.nfs_permissions,
                    steps=(
                        ShareOperationStep(
                            name="nfs:save",
                            status=status,
                            message="NFS replacement may not have completed",
                        ),
                    ),
                ),
            ) from exc
        steps = [ShareOperationStep(name="nfs:save", status=OperationStatus.SUCCEEDED)]
        try:
            verified = _nfs_rules_match(
                request.nfs_permissions, _load_nfs_rules(api, request.name)
            )
        except Exception as exc:
            status = _nfs_failure_status(exc)
            steps.append(
                ShareOperationStep(
                    name="nfs:verify",
                    status=status,
                    message="NFS replacement verification did not complete",
                )
            )
            raise PartialOperationError(
                "share NFS modification verification is uncertain",
                ShareModifyResult(
                    name=request.name,
                    changed=True,
                    nfs_permissions=request.nfs_permissions,
                    steps=tuple(steps),
                ),
            ) from exc
        if not verified:
            steps.append(
                ShareOperationStep(
                    name="nfs:verify",
                    status=OperationStatus.FAILED,
                    message="NFS read-back did not match requested replacement",
                )
            )
            raise PartialOperationError(
                "share NFS modification verification failed",
                ShareModifyResult(
                    name=request.name,
                    changed=True,
                    nfs_permissions=request.nfs_permissions,
                    steps=tuple(steps),
                ),
            )
        steps.append(
            ShareOperationStep(name="nfs:verify", status=OperationStatus.SUCCEEDED)
        )
        return ShareModifyResult(
            name=request.name,
            changed=True,
            nfs_permissions=request.nfs_permissions,
            steps=tuple(steps),
        )

    def read_apply_details(self, name: str) -> ShareDetails:
        """Read complete normalized state for one configured share."""
        try:
            state = _read_mutable_share_state(cast(ShareQuotaRawApi, self._share), name)
            inventory = _read_modify_permission_inventory(self._permission_api(), name)
            nfs_api = self._nfs_api()
            if not _global_nfs_enabled(nfs_api):
                raise ApiError("global NFS must already be enabled")
            nfs_display = _load_nfs_rule_display_permissions(nfs_api, name)
            nfs = _mutation_safe_nfs_display_permissions(nfs_display)
        except Exception as exc:
            self._raise_mapped_error(exc, phase="apply-preflight")
        return ShareDetails(
            share=ShareRecord(
                name=state.name,
                volume=state.volume_path,
                description=state.description,
                quota_gib=None if state.quota is None else state.quota.gib,
                quota_api_value=None if state.quota is None else state.quota.api_value,
            ),
            acl_permissions=tuple(
                AclPermissionRecord(
                    item.name,
                    item.category,
                    item.access_mode is PermissionAccessMode.DENY,
                    item.access_mode is PermissionAccessMode.READ_ONLY,
                    item.access_mode is PermissionAccessMode.READ_WRITE,
                    item.is_custom,
                    item.is_admin,
                )
                for item in _active_modify_permissions(inventory)
            ),
            nfs_permissions=nfs,
            acl_status=EnrichmentStatus.AVAILABLE
            if inventory
            else EnrichmentStatus.EMPTY,
            nfs_status=(
                EnrichmentStatus.AVAILABLE if nfs_display else EnrichmentStatus.EMPTY
            ),
            nfs_display_permissions=nfs_display,
        )

    def validate_apply_principals(
        self, name: str, permissions: tuple[PermissionSpec, ...]
    ) -> None:
        try:
            _validate_requested_principals(
                _read_modify_permission_inventory(self._permission_api(), name),
                (
                    *permissions,
                    PermissionSpec(
                        PermissionPrincipalType.LOCAL_GROUP,
                        "administrators",
                        PermissionAccessMode.READ_WRITE,
                    ),
                ),
            )
        except Exception as exc:
            self._raise_mapped_error(exc, phase="apply-principal-preflight")

    def validate_apply_principals_globally(
        self, lookup_share: str, permissions: tuple[PermissionSpec, ...]
    ) -> None:
        """Validate apply ACL principals via a read-only existing-share inventory."""
        request = PrincipalLookupRequest(
            lookup_share,
            (
                *(
                    PrincipalIdentity(
                        permission.principal_type, permission.principal_name
                    )
                    for permission in permissions
                ),
                PrincipalIdentity(
                    PermissionPrincipalType.LOCAL_GROUP, "administrators"
                ),
            ),
        )
        try:
            result = _read_apply_principal_lookup(self._permission_api(), request)
            _validate_lookup_result(request, result)
        except Exception as exc:
            self._raise_mapped_error(exc, phase="apply-principal-preflight")

    def preflight_apply_create(self) -> None:
        """Validate create-time API capabilities without creating a share."""
        try:
            _share_set_version(cast(ShareQuotaRawApi, self._share))
            self._permission_api()
            nfs_api = self._nfs_api()
            if not _global_nfs_enabled(nfs_api):
                raise ApiError("global NFS must already be enabled")
            info = nfs_api.core_list.get(NFS_SHARE_PRIVILEGE_API)
            if not isinstance(info, Mapping):
                raise ApiError("NAS does not support the required NFS API")
            _required_api_version(info, 1)
        except ConfigurationError as exc:
            raise ApiError(
                "NAS does not support required apply-config capability"
            ) from exc
        except Exception as exc:
            self._raise_mapped_error(exc, phase="apply-create-preflight")

    def update_share_scalars(self, request: ShareScalarUpdateRequest) -> None:
        """Apply a capability-aware description and optional quota update.

        All reads and payload validation occur before the set request. Once the set
        request begins, every failure is reported as a potentially partial outcome.
        """
        api = cast(ShareQuotaRawApi, self._share)
        try:
            version = _share_set_version(api)
            current = _read_mutable_share_state(api, request.name)
            if request.quota_api_value is not None and current.quota is None:
                raise ApiError(
                    f"share {request.name} on {current.volume_path} "
                    "does not support quota management"
                )
            desired = MutableShareState(
                current.name,
                current.volume_path,
                request.description,
                current.hidden,
                current.recycle_bin_enabled,
                current.recycle_bin_admin_only,
                current.compression_enabled,
                current.cow_enabled,
                (
                    current.quota
                    if request.quota_api_value is None
                    else ShareQuotaState(request.quota_api_value)
                ),
                current.capabilities,
            )
            payload = _scalar_update_payload(desired, version, request)
        except Exception as exc:
            try:
                self._raise_mapped_error(exc, phase="apply-scalar-preflight")
            except ApiError as mapped:
                raise ScalarUpdatePreflightError(str(mapped)) from mapped

        try:
            response = api.request_data(
                SHARE_SET_API,
                cast(str, api.core_list[SHARE_SET_API]["path"]),
                {
                    "version": payload.version,
                    "method": "set",
                    "name": payload.name,
                    "shareinfo": payload.shareinfo,
                },
                method="post",
            )
            if (
                _as_mapping(
                    response, "invalid share scalar update response"
                ).get("success")
                is not True
            ):
                raise ApiError(
                    "NAS API returned an unsuccessful share scalar update response"
                )
            observed = _read_mutable_share_state(api, request.name)
            if not _scalar_update_verified(desired, observed, request):
                raise PartialOperationError(
                    "share scalar update verification failed", None
                )
        except PartialOperationError:
            raise
        except Exception as exc:
            raise PartialOperationError(
                "share scalar update outcome is uncertain", None
            ) from exc

    def replace_apply_acl(
        self, name: str, permissions: tuple[PermissionSpec, ...]
    ) -> None:
        protected = PermissionSpec(
            PermissionPrincipalType.LOCAL_GROUP,
            "administrators",
            PermissionAccessMode.READ_WRITE,
        )
        self.modify_share(
            ShareModifyRequest(
                name=name,
                permissions=(*permissions, protected),
                _acl_authoritative_mode=True,
            )
        )

    def replace_apply_nfs(
        self, name: str, permissions: tuple[NfsClientPermission, ...]
    ) -> None:
        self.modify_share(ShareModifyRequest(name=name, nfs_permissions=permissions))

    def delete_share(self, request: ShareDeleteRequest) -> ShareDeleteResult:
        self._logger.debug(
            "Synology API delete request operation=%s target=%s:%s tls_verify=%s "
            "parameters=%s",
            DELETE_OPERATION,
            self._config.host,
            self._config.port,
            not self._config.insecure,
            sanitize({"name": request.name}),
        )
        try:
            response = self._share.delete_folders([request.name])
        except Exception as exc:
            self._raise_mapped_error(exc, phase="request")
        envelope = _as_mapping(response, "invalid share deletion response envelope")
        if envelope.get("success") is not True:
            raise ApiError("NAS API returned an unsuccessful share deletion response")
        result = ShareDeleteResult(
            name=request.name,
            deleted=True,
            steps=(
                ShareOperationStep(name="delete", status=OperationStatus.SUCCEEDED),
            ),
        )
        self._logger.debug(
            "Synology API response operation=%s success=%s name=%s",
            DELETE_OPERATION,
            result.deleted,
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
                    acl.extend(
                        entry
                        for value in _read_permission_category(
                            permission_api, share.name, category
                        )
                        if (entry := _normalize_acl_entry(value, category)) is not None
                    )
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
                nfs_display = _load_nfs_rule_display_permissions(nfs_api, share.name)
                nfs = tuple(
                    permission
                    for permission in nfs_display
                    if isinstance(permission, NfsClientPermission)
                )
                nfs_status = (
                    EnrichmentStatus.AVAILABLE
                    if nfs_display
                    else EnrichmentStatus.EMPTY
                )
            except Exception as exc:
                nfs = ()
                nfs_display = ()
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
                    nfs_display_permissions=nfs_display,
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


def _share_set_version(api: ShareQuotaRawApi) -> int:
    info = api.core_list.get(SHARE_SET_API)
    if not isinstance(info, Mapping):
        raise ConfigurationError("NAS does not support share quota updates")
    path = info.get("path")
    maximum = info.get("maxVersion")
    if (
        not isinstance(path, str)
        or not path
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or maximum < 1
    ):
        raise ConfigurationError("NAS does not support share quota updates")
    return maximum


def _read_mutable_share_state(api: ShareQuotaRawApi, name: str) -> MutableShareState:
    response = api.get_folder(
        name,
        additional=[
            "share_quota",
            "hidden",
            "enable_share_compress",
            "enable_share_cow",
        ],
    )
    envelope = _as_mapping(response, "invalid share quota read response")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful share quota read response")
    data = _as_mapping(envelope.get("data"), "invalid share quota read response data")
    recycle_bin = _recycle_bin_options(data)
    if recycle_bin is None:
        recycle_bin = _listed_recycle_bin_options(api, name)
    return _mutable_share_state(data, recycle_bin)


def _mutable_share_state(
    data: Mapping[str, object], recycle_bin: tuple[bool, bool]
) -> MutableShareState:
    name = _required_string(data, "name")
    volume_path = _required_string(data, "vol_path")
    description = _required_string(data, "desc")
    hidden = _required_boolean(data, "hidden")
    canonical = _canonical_volume(volume_path)
    compression_enabled = _capability_boolean(
        data, "enable_share_compress", name, volume_path, canonical
    )
    cow_enabled = _capability_boolean(
        data, "enable_share_cow", name, volume_path, canonical
    )
    quota_value = _capability_quota(data, name, volume_path, canonical)
    quota = ShareQuotaState(quota_value) if quota_value is not None else None
    recycle_bin_enabled, recycle_bin_admin_only = recycle_bin
    return MutableShareState(
        name=name,
        volume_path=volume_path,
        description=description,
        hidden=hidden,
        recycle_bin_enabled=recycle_bin_enabled,
        recycle_bin_admin_only=recycle_bin_admin_only,
        compression_enabled=compression_enabled,
        cow_enabled=cow_enabled,
        quota=quota,
        capabilities=ShareCapabilities(
            quota_available=quota is not None,
            compression_available=compression_enabled is not None,
            cow_available=cow_enabled is not None,
        ),
    )


def _recycle_bin_options(data: Mapping[str, object]) -> tuple[bool, bool] | None:
    enabled = data.get("enable_recycle_bin")
    admin_only = data.get("recycle_bin_admin_only")
    if enabled is None and admin_only is None:
        return None
    if not isinstance(enabled, bool) or not isinstance(admin_only, bool):
        raise ApiError("invalid share recycle-bin state")
    if not enabled:
        return False, True
    return enabled, admin_only


def _listed_recycle_bin_options(api: ShareQuotaRawApi, name: str) -> tuple[bool, bool]:
    response = api.list_folders(share_type="all", additional=["recyclebin"])
    envelope = _as_mapping(response, "invalid share recycle-bin response")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful share recycle-bin response")
    data = _as_mapping(envelope.get("data"), "invalid share recycle-bin response data")
    shares = _as_sequence(
        data.get("shares"), "invalid share recycle-bin response shares"
    )
    for value in shares:
        share = _as_mapping(value, "invalid share recycle-bin response share")
        if share.get("name") != name:
            continue
        enabled = share.get("recyclebin")
        if enabled is None:
            return False, True
        if not isinstance(enabled, bool):
            raise ApiError("invalid share recycle-bin state")
        if not enabled:
            return False, True
        admin_only = share.get("recycle_bin_admin_only")
        if not isinstance(admin_only, bool):
            raise ApiError("share recycle-bin admin-only state is unavailable")
        return True, admin_only
    raise ApiError("share was not found in recycle-bin response")


def _canonical_volume(volume_path: str) -> bool:
    suffix = volume_path.removeprefix("/volume")
    return volume_path.startswith("/volume") and suffix.isdigit() and int(suffix) > 0


def _capability_boolean(
    data: Mapping[str, object], field: str, name: str, volume_path: str, canonical: bool
) -> bool | None:
    if field not in data:
        if canonical:
            raise ApiError(f"share {name} on {volume_path} has unavailable {field}")
        return None
    value = data[field]
    if not isinstance(value, bool):
        raise ApiError(f"share {name} on {volume_path} has invalid {field}")
    return value


def _capability_quota(
    data: Mapping[str, object], name: str, volume_path: str, canonical: bool
) -> int | None:
    field = "quota_value" if "quota_value" in data else "share_quota"
    if field not in data:
        if canonical:
            raise ApiError(f"share {name} on {volume_path} has unavailable quota")
        return None
    value = data[field]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ApiError(f"share {name} on {volume_path} has invalid quota")
    return value


def _required_string(data: Mapping[str, object], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str):
        raise ApiError(f"invalid share field: {field}")
    return value


def _required_boolean(data: Mapping[str, object], field: str) -> bool:
    value = data.get(field)
    if not isinstance(value, bool):
        raise ApiError(f"invalid share field: {field}")
    return value


def _scalar_update_payload(
    state: MutableShareState, version: int, request: ShareScalarUpdateRequest
) -> ShareScalarUpdatePayload:
    """Build a set payload using only values DSM reported as available."""
    shareinfo: dict[str, object] = {
        "name": state.name,
        "vol_path": state.volume_path,
        "desc": state.description,
        "hidden": state.hidden,
        "enable_recycle_bin": state.recycle_bin_enabled,
        "recycle_bin_admin_only": state.recycle_bin_admin_only,
    }
    if state.capabilities.compression_available:
        assert state.compression_enabled is not None
        shareinfo["enable_share_compress"] = state.compression_enabled
    if state.capabilities.cow_available:
        assert state.cow_enabled is not None
        shareinfo["enable_share_cow"] = state.cow_enabled
    if request.quota_api_value is not None:
        if not state.capabilities.quota_available:
            raise ApiError(f"share {state.name} does not support quota management")
        shareinfo["share_quota"] = request.quota_api_value
    return ShareScalarUpdatePayload(
        name=state.name,
        version=version,
        shareinfo=json.dumps(shareinfo, separators=(",", ":")),
    )


def _scalar_update_verified(
    desired: MutableShareState,
    observed: MutableShareState,
    request: ShareScalarUpdateRequest,
) -> bool:
    if not _share_state_preserved(desired, observed):
        return False
    if request.quota_api_value is None:
        return desired.quota == observed.quota
    return (
        observed.quota is not None
        and observed.quota.api_value == request.quota_api_value
    )


def _share_state_preserved(
    current: MutableShareState, observed: MutableShareState
) -> bool:
    return (
        current.name == observed.name
        and current.volume_path == observed.volume_path
        and current.description == observed.description
        and current.hidden == observed.hidden
        and current.recycle_bin_enabled == observed.recycle_bin_enabled
        and current.recycle_bin_admin_only == observed.recycle_bin_admin_only
        and current.compression_enabled == observed.compression_enabled
        and current.cow_enabled == observed.cow_enabled
        and current.capabilities == observed.capabilities
    )


def _quota_set_envelope(response: object) -> Mapping[str, object] | None:
    try:
        return _as_mapping(response, "invalid share quota set response")
    except ApiError:
        return None


def _quota_failure_status(exc: Exception) -> OperationStatus:
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


def _call_create_folder(
    share: ShareApi,
    arguments: Mapping[str, object],
) -> object:
    name = cast(str, arguments["name"])
    volume_path = cast(str, arguments["vol_path"])
    description = cast(str, arguments["desc"])
    enable_recycle_bin = cast(bool, arguments["enable_recycle_bin"])
    recycle_bin_admin_only = cast(bool, arguments["recycle_bin_admin_only"])
    kwargs: dict[str, object] = {
        "name": name,
        "vol_path": volume_path,
        "desc": description,
        "enable_recycle_bin": enable_recycle_bin,
        "recycle_bin_admin_only": recycle_bin_admin_only,
    }
    if "enable_share_compress" in arguments:
        kwargs["enable_share_compress"] = cast(bool, arguments["enable_share_compress"])
    if "share_quota" in arguments:
        kwargs["share_quota"] = cast(int, arguments["share_quota"])
    return share.create_folder(**cast(Any, kwargs))


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
    """Load mutation-safe NFS rules, rejecting unsupported live state."""
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


def _load_nfs_rule_display_permissions(
    api: NfsRawApi,
    share_name: str,
) -> tuple[NfsClientPermission | NfsDisplayPermission, ...]:
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
    return tuple(_normalize_nfs_display_rule(rule) for rule in rules)


def _mutation_safe_nfs_display_permissions(
    permissions: tuple[NfsClientPermission | NfsDisplayPermission, ...],
) -> tuple[NfsClientPermission, ...]:
    """Reject display-only or unsupported NFS state before reconciliation."""
    if any(
        not isinstance(permission, NfsClientPermission) for permission in permissions
    ):
        raise ApiError("invalid NFS rule")
    safe_permissions = cast(tuple[NfsClientPermission, ...], permissions)
    if any(
        permission.security_flavor != NfsSecurityFlavor()
        for permission in safe_permissions
    ):
        raise ApiError("unsupported NFS security flavor")
    return safe_permissions


def _nfs_rule(permission: NfsClientPermission) -> dict[str, object]:
    return {
        "async": permission.async_enabled,
        "client": permission.client,
        "crossmnt": permission.crossmnt,
        "insecure": permission.insecure,
        "privilege": "rw"
        if permission.access_mode is NfsAccessMode.READ_WRITE
        else "ro",
        "root_squash": permission.root_squash.value,
        "security_flavor": {
            "sys": permission.security_flavor.sys,
            "kerberos": permission.security_flavor.kerberos,
            "kerberos_integrity": permission.security_flavor.kerberos_integrity,
            "kerberos_privacy": permission.security_flavor.kerberos_privacy,
        },
    }


def _normalize_nfs_rule(value: object) -> NfsClientPermission:
    """Normalize a live NFS rule only when it is safe for reconciliation."""
    permission = _normalize_nfs_display_rule(value)
    return _mutation_safe_nfs_display_permissions((permission,))[0]


def _normalize_nfs_display_rule(
    value: object,
) -> NfsClientPermission | NfsDisplayPermission:
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
        or not isinstance(root_squash, str)
    ):
        raise ApiError("invalid NFS rule")
    try:
        canonical_root_squash = NfsRootSquash(root_squash)
    except ValueError as exc:
        raise ApiError("invalid NFS rule") from exc
    security_flavor = NfsSecurityFlavor(
        sys=_nfs_security_value(security, "sys"),
        kerberos=_nfs_security_value(security, "kerberos"),
        kerberos_integrity=_nfs_security_value(security, "kerberos_integrity"),
        kerberos_privacy=_nfs_security_value(security, "kerberos_privacy"),
    )
    access_mode = (
        NfsAccessMode.READ_WRITE if privilege == "rw" else NfsAccessMode.READ_ONLY
    )
    try:
        canonical_client = normalize_nfs_client(client)[0]
    except ConfigurationError:
        return NfsDisplayPermission(
            client=client,
            access_mode=access_mode,
            async_enabled=async_enabled,
            insecure=insecure,
            crossmnt=crossmnt,
            root_squash=canonical_root_squash,
            security_flavor=security_flavor,
        )
    return NfsClientPermission(
        client=canonical_client,
        access_mode=access_mode,
        async_enabled=async_enabled,
        insecure=insecure,
        crossmnt=crossmnt,
        root_squash=canonical_root_squash,
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
    return sorted(expected, key=_nfs_sort_key) == sorted(actual, key=_nfs_sort_key)


def _nfs_sort_key(permission: NfsClientPermission) -> tuple[object, ...]:
    return (
        permission.client,
        permission.access_mode.value,
        permission.async_enabled,
        permission.insecure,
        permission.crossmnt,
        permission.root_squash.value,
        permission.security_flavor.sys,
        permission.security_flavor.kerberos,
        permission.security_flavor.kerberos_integrity,
        permission.security_flavor.kerberos_privacy,
    )


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
PERMISSION_PAGE_SIZE = 50


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


def _permission_deltas(
    current: tuple[AclPermissionState, ...],
    desired: tuple[PermissionSpec, ...],
    *,
    clear_mode: bool = False,
    authoritative_mode: bool = False,
) -> dict[str, tuple[list[dict[str, object]], int, int]]:
    current_by_identity: dict[tuple[str, str], AclPermissionState] = {}
    for current_permission in current:
        identity = (current_permission.category, current_permission.name)
        if identity in current_by_identity:
            raise ApiError("duplicate active permission response item")
        current_by_identity[identity] = current_permission
    desired_by_identity: dict[tuple[str, str], PermissionSpec] = {}
    for permission in desired:
        identity = (_permission_type(permission), permission.principal_name)
        if identity in desired_by_identity:
            raise ConfigurationError(
                "duplicate permission specifications are not allowed"
            )
        desired_by_identity[identity] = permission
    deltas: dict[str, tuple[list[dict[str, object]], int, int]] = {}
    for category in PERMISSION_USER_GROUP_TYPES:
        active_desired: list[dict[str, object]] = []
        revocations: list[dict[str, object]] = []
        category_desired = sorted(
            (
                permission
                for (permission_category, _), permission in desired_by_identity.items()
                if permission_category == category
            ),
            key=lambda permission: permission.principal_name,
        )
        for permission in category_desired:
            existing_permission = current_by_identity.get(
                (category, permission.principal_name)
            )
            if (
                existing_permission is None
                or existing_permission.access_mode is not permission.access_mode
            ):
                active_desired.append(_permission_payload(permission))
        for (permission_category, principal_name), actual_permission in sorted(
            current_by_identity.items(), key=lambda item: item[0]
        ):
            if (
                permission_category == category
                and (
                    authoritative_mode
                    or not actual_permission.is_admin
                    or (clear_mode and actual_permission.category != "local_group")
                )
                and not (
                    not authoritative_mode
                    and actual_permission.category == "local_group"
                    and actual_permission.name == "administrators"
                )
                and (permission_category, principal_name) not in desired_by_identity
            ):
                revocations.append(_permission_revocation_payload(principal_name))
        deltas[category] = (
            [*active_desired, *revocations],
            len(active_desired),
            len(revocations),
        )
    return deltas


def _permission_revocation_payload(name: str) -> dict[str, object]:
    return {
        "name": name,
        "is_deny": False,
        "is_readonly": False,
        "is_writable": False,
    }


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


def _read_modify_permission_inventory(
    api: SharePermissionApi, name: str
) -> tuple[AclPermissionInventory, ...]:
    inventory: list[AclPermissionInventory] = []
    for category in PERMISSION_USER_GROUP_TYPES:
        principals: list[AclPrincipal] = []
        active_permissions: list[AclPermissionState] = []
        seen_principals: set[AclPrincipal] = set()
        for value in _read_permission_category(api, name, category):
            principal, permission = _modify_permission_inventory_item(value, category)
            if principal in seen_principals:
                raise ApiError("duplicate permission inventory principal")
            seen_principals.add(principal)
            principals.append(principal)
            if permission is not None:
                active_permissions.append(permission)
        inventory.append(
            AclPermissionInventory(
                category=category,
                principals=tuple(principals),
                active_permissions=tuple(active_permissions),
            )
        )
    return tuple(inventory)


def _active_modify_permissions(
    inventory: tuple[AclPermissionInventory, ...],
) -> tuple[AclPermissionState, ...]:
    return tuple(
        permission
        for category_inventory in inventory
        for permission in category_inventory.active_permissions
    )


def _validate_requested_principals(
    inventory: tuple[AclPermissionInventory, ...],
    requested: tuple[PermissionSpec, ...],
) -> None:
    existing = {
        (principal.category, principal.name)
        for category_inventory in inventory
        for principal in category_inventory.principals
    }
    missing = tuple(
        AclPrincipal(permission.principal_name, _permission_type(permission))
        for permission in requested
        if (_permission_type(permission), permission.principal_name) not in existing
    )
    if missing:
        raise PrincipalNotFoundError(missing)


def _read_apply_principal_lookup(
    api: SharePermissionApi,
    request: PrincipalLookupRequest,
) -> PrincipalLookupResult:
    """Read and validate every DSM principal category from the lookup share."""
    found: set[PrincipalIdentity] = set()
    for category in PERMISSION_USER_GROUP_TYPES:
        for value in _read_permission_category(api, request.lookup_share, category):
            principal, _ = _modify_permission_inventory_item(value, category)
            identity = PrincipalIdentity(
                _principal_type_from_permission_category(principal.category),
                principal.name,
            )
            if identity in found:
                raise ApiError("duplicate permission inventory principal")
            found.add(identity)
    return PrincipalLookupResult(
        request.lookup_share,
        tuple(sorted(found, key=lambda item: (item.principal_type.value, item.name))),
    )


def _validate_lookup_result(
    request: PrincipalLookupRequest, result: PrincipalLookupResult
) -> None:
    """Raise when the complete lookup inventory lacks a requested identity."""
    if result.lookup_share != request.lookup_share:
        raise ApiError("invalid principal lookup response")
    found = set(result.identities)
    missing = tuple(
        AclPrincipal(
            identity.name, _permission_type_from_principal_type(identity.principal_type)
        )
        for identity in request.identities
        if identity not in found
    )
    if missing:
        raise PrincipalNotFoundError(missing)


def _permission_type_from_principal_type(
    principal_type: PermissionPrincipalType,
) -> str:
    return {
        PermissionPrincipalType.LOCAL_USER: "local_user",
        PermissionPrincipalType.LOCAL_GROUP: "local_group",
        PermissionPrincipalType.LDAP_USER: "ldap_user",
        PermissionPrincipalType.LDAP_GROUP: "ldap_group",
    }[principal_type]


def _principal_type_from_permission_category(category: str) -> PermissionPrincipalType:
    try:
        return {
            "local_user": PermissionPrincipalType.LOCAL_USER,
            "local_group": PermissionPrincipalType.LOCAL_GROUP,
            "ldap_user": PermissionPrincipalType.LDAP_USER,
            "ldap_group": PermissionPrincipalType.LDAP_GROUP,
        }[category]
    except KeyError as exc:
        raise ApiError("invalid permission inventory category") from exc


def _read_permission_category(
    api: SharePermissionApi, name: str, category: str
) -> tuple[object, ...]:
    offset = 0
    entries: list[object] = []
    while True:
        response = api.get_folder_permissions(
            name,
            offset=offset,
            limit=PERMISSION_PAGE_SIZE,
            user_group_type=category,
        )
        envelope = _as_mapping(response, "invalid permission response envelope")
        if envelope.get("success") is not True:
            raise ApiError("NAS API returned an unsuccessful permission response")
        data = _as_mapping(envelope.get("data"), "invalid permission response data")
        total = data.get("total")
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise ApiError("invalid permission response total")
        page = _as_sequence(
            data.get("permissions", data.get("items")),
            "invalid permission response permissions",
        )
        if offset + len(page) > total:
            raise ApiError("invalid permission response total")
        entries.extend(page)
        offset += len(page)
        if offset == total:
            return tuple(entries)
        if not page:
            raise ApiError("permission response pagination made no progress")


def _modify_permission_inventory_item(
    value: object, category: str
) -> tuple[AclPrincipal, AclPermissionState | None]:
    item = _as_mapping(value, "invalid permission response item")
    name = item.get("name")
    is_deny = item.get("is_deny")
    is_readonly = item.get("is_readonly")
    is_writable = item.get("is_writable")
    is_custom = item.get("is_custom", False)
    is_admin = item.get("is_admin", False)
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(is_deny, bool)
        or not isinstance(is_readonly, bool)
        or not isinstance(is_writable, bool)
        or not isinstance(is_custom, bool)
        or not isinstance(is_admin, bool)
    ):
        raise ApiError("invalid permission response item")
    principal = AclPrincipal(name, category)
    access_mode = _active_permission_access_mode(is_deny, is_readonly, is_writable)
    if access_mode is None:
        return principal, None
    return principal, AclPermissionState(
        name, category, access_mode, is_custom, is_admin
    )


def _active_permission_access_mode(
    is_deny: bool, is_readonly: bool, is_writable: bool
) -> PermissionAccessMode | None:
    active_bits = sum((is_deny, is_readonly, is_writable))
    if active_bits == 0:
        return None
    if active_bits != 1:
        raise ApiError("ambiguous active permission response item")
    if is_deny:
        return PermissionAccessMode.DENY
    if is_readonly:
        return PermissionAccessMode.READ_ONLY
    return PermissionAccessMode.READ_WRITE


def _compare_modify_permissions(
    actual: tuple[AclPermissionState, ...],
    expected: tuple[PermissionSpec, ...],
    *,
    clear_mode: bool = False,
    authoritative_mode: bool = False,
) -> str | None:
    expected_by_identity = {
        (
            _permission_type(permission),
            permission.principal_name,
        ): permission.access_mode
        for permission in expected
    }
    actual_by_identity: dict[tuple[str, str], list[AclPermissionState]] = {}
    for permission in actual:
        actual_by_identity.setdefault(
            (permission.category, permission.name), []
        ).append(permission)
    for identity, expected_access_mode in expected_by_identity.items():
        actual_entries = actual_by_identity.get(identity, [])
        if len(actual_entries) != 1:
            return f"{identity[0]} expected entry is missing or duplicated"
        if actual_entries[0].access_mode is not expected_access_mode:
            return f"{identity[0]} expected entry has a different access mode"
    for identity, actual_entries in actual_by_identity.items():
        if identity in expected_by_identity:
            continue
        if authoritative_mode or clear_mode:
            if any(
                authoritative_mode
                or permission.category != "local_group"
                or (permission.name != "administrators" and not permission.is_admin)
                for permission in actual_entries
            ):
                return f"{identity[0]} has an uncleared active entry"
        elif any(not permission.is_admin for permission in actual_entries):
            return f"{identity[0]} has an unrequested active entry"
    return None


def _set_permissions(
    api: SharePermissionApi,
    name: str,
    category: str,
    permissions: list[dict[str, object]],
) -> None:
    response = api.set_folder_permissions(name, category, permissions)
    envelope = _as_mapping(response, "invalid permission response envelope")
    if envelope.get("success") is not True:
        raise ApiError("NAS API returned an unsuccessful permission response")


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
    return tuple(
        entry
        for value in values
        if (entry := _normalize_acl_entry(value, category)) is not None
    )


def _normalize_acl_entry(value: object, category: str) -> AclPermissionRecord | None:
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
    if _active_permission_access_mode(is_deny, is_readonly, is_writable) is None:
        return None
    return AclPermissionRecord(
        name,
        category,
        is_deny,
        is_readonly,
        is_writable,
        is_custom,
        is_admin,
    )


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
