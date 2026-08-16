"""Exceptions for VW identity login flow."""

from carconnectivity.errors import AuthenticationError


class LoginError(AuthenticationError):
    """Base for all device-flow login failures."""


class LoginFlowChangedError(LoginError):
    """VW login page structure changed; flow cannot continue safely."""

    def __init__(self, *, stage: str, dump_path: str | None = None) -> None:
        self.stage = stage
        self.dump_path = dump_path
        msg = f"VW login flow changed at stage {stage!r}."
        if dump_path:
            msg += f" HTML snapshot: {dump_path}"
        super().__init__(msg)


class LoginPageParseError(LoginError):
    """IDKit page structure not recognised; cannot extract login state."""


class LoginCredentialsError(LoginError):
    """Authentication rejected; credentials appear to be invalid."""
