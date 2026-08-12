from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from synology.models import AclPrincipal


class SynologyCliError(Exception):
    pass


class ConfigurationError(SynologyCliError):
    pass


class AuthenticationError(SynologyCliError):
    pass


class TransportError(SynologyCliError):
    pass


class ApiError(SynologyCliError):
    pass


class PrincipalNotFoundError(SynologyCliError):
    def __init__(self, missing: tuple["AclPrincipal", ...]) -> None:
        self.missing = missing
        identities = ", ".join(
            f"{principal.category}:{principal.name}" for principal in missing
        )
        super().__init__(
            f"requested permission principals were not found: {identities}"
        )


class OutputError(SynologyCliError):
    pass


class PartialOperationError(SynologyCliError):
    def __init__(self, message: str, result: object) -> None:
        super().__init__(message)
        self.result = result


class UnexpectedApplicationError(SynologyCliError):
    pass
