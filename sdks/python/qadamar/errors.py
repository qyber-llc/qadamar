"""Typed errors, the same codes as packages/sdk/src/errors.ts."""
from __future__ import annotations

from typing import Optional


class PepError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class PdpHttpError(PepError):
    def __init__(self, status: int, code: str, retry_after: Optional[str] = None) -> None:
        super().__init__(code, f"PDP request failed with HTTP {status} ({code})")
        self.status = status
        self.retry_after = retry_after


class PdpResponseError(PepError):
    def __init__(self, message: str = "PDP returned a malformed response") -> None:
        super().__init__("invalid_response", message)


class PdpNetworkError(PepError):
    pass


class AccessDeniedError(PepError):
    def __init__(self) -> None:
        super().__init__("access_denied", "The PDP denied access; the record was not released")


class ObligationError(PepError):
    def __init__(self, message: str = "The record obligations could not be enforced safely") -> None:
        super().__init__("obligation_failed", message)


class GateAssertionError(PepError):
    """AssertionError in the TypeScript SDK; renamed so it never shadows Python's built-in AssertionError."""
