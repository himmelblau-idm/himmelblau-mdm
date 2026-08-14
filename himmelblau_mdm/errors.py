from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MDMError(Exception):
    status_code: int
    code: str
    message: str
    retryable: bool = False

    def __str__(self) -> str:
        return self.message


class AuthenticationError(MDMError):
    def __init__(self, message: str = "Authentication failed") -> None:
        super().__init__(401, "authentication_failed", message)


class DeviceBindingError(MDMError):
    def __init__(self, message: str = "Device binding validation failed") -> None:
        super().__init__(403, "device_binding_failed", message)


class InvalidRequestError(MDMError):
    def __init__(self, message: str) -> None:
        super().__init__(400, "invalid_request", message)


class GraphError(MDMError):
    def __init__(self, message: str, retryable: bool = False) -> None:
        super().__init__(503, "graph_failure", message, retryable)


class UpstreamError(MDMError):
    def __init__(self, message: str, retryable: bool = False) -> None:
        super().__init__(502, "intune_upstream_failure", message, retryable)
