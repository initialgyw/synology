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


class OutputError(SynologyCliError):
    pass


class PartialOperationError(SynologyCliError):
    def __init__(self, message: str, result: object) -> None:
        super().__init__(message)
        self.result = result


class UnexpectedApplicationError(SynologyCliError):
    pass
