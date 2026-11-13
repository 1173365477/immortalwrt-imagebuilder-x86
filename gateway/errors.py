"""Stable public errors for the Gateway API."""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    AUTH_REQUIRED = "AUTH_REQUIRED"
    AUTH_INVALID = "AUTH_INVALID"
    AUTH_EXPIRED = "AUTH_EXPIRED"
    ACCESS_DENIED = "ACCESS_DENIED"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_REPOSITORY = "INVALID_REPOSITORY"
    INVALID_COMMIT = "INVALID_COMMIT"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    EVIDENCE_NOT_FOUND = "EVIDENCE_NOT_FOUND"
    EVIDENCE_UNVERIFIED = "EVIDENCE_UNVERIFIED"
    BUILD_BLOCKED = "BUILD_BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    REQUEST_EXPIRED = "REQUEST_EXPIRED"
    STORAGE_UNAVAILABLE = "STORAGE_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    TLS_REQUIRED = "TLS_REQUIRED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"


PUBLIC_MESSAGES = {
    ErrorCode.AUTH_REQUIRED: "Authentication is required.",
    ErrorCode.AUTH_INVALID: "Authentication failed.",
    ErrorCode.AUTH_EXPIRED: "Authentication failed.",
    ErrorCode.ACCESS_DENIED: "Access is denied.",
    ErrorCode.INVALID_REQUEST: "The request is invalid.",
    ErrorCode.INVALID_REPOSITORY: "The repository is not allowed.",
    ErrorCode.INVALID_COMMIT: "The evidence commit is invalid.",
    ErrorCode.IDEMPOTENCY_CONFLICT: "The request identifier is already bound to different evidence.",
    ErrorCode.EVIDENCE_NOT_FOUND: "The requested build task was not found.",
    ErrorCode.EVIDENCE_UNVERIFIED: "The immutable evidence has not been verified.",
    ErrorCode.BUILD_BLOCKED: "The immutable evidence blocks this build.",
    ErrorCode.RATE_LIMITED: "The request limit has been exceeded.",
    ErrorCode.REQUEST_EXPIRED: "The request identifier has expired and remains reserved.",
    ErrorCode.STORAGE_UNAVAILABLE: "Persistent storage is unavailable.",
    ErrorCode.INTERNAL_ERROR: "The request could not be completed.",
    ErrorCode.TLS_REQUIRED: "HTTPS is required.",
    ErrorCode.REQUEST_TOO_LARGE: "The request body is too large.",
}


class GatewayError(RuntimeError):
    """An internal error with a stable, non-sensitive public representation."""

    def __init__(self, code: ErrorCode, status_code: int, *, internal_detail: str = ""):
        super().__init__(code.value)
        self.code = code
        self.status_code = status_code
        self.internal_detail = internal_detail

    @property
    def public_message(self) -> str:
        return PUBLIC_MESSAGES[self.code]
