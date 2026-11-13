"""Strict request and public response models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


SHA256_PATTERN = r"^[a-f0-9]{64}$"
COMMIT_PATTERN = r"^[a-f0-9]{40}$"
REQUEST_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
REPOSITORY_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"


class BuildRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    request_id: str = Field(pattern=REQUEST_PATTERN, min_length=1, max_length=128)
    build_input_id: str = Field(min_length=75, max_length=75)
    build_input_digest: str = Field(pattern=SHA256_PATTERN, min_length=64, max_length=64)
    repository: str = Field(pattern=REPOSITORY_PATTERN, min_length=3, max_length=200)
    evidence_commit_sha: str = Field(pattern=COMMIT_PATTERN, min_length=40, max_length=40)

    @model_validator(mode="after")
    def bind_build_input_id(self) -> "BuildRequest":
        if self.build_input_id != f"urn:sha256:{self.build_input_digest}":
            raise ValueError("build_input_id must bind build_input_digest")
        return self


class BuildTaskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    internal_task_id: str
    status: str
    build_input_id: str
    build_input_digest: str
    repository: str
    evidence_commit_sha: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    failure_code: str | None = None
    evidence_verified: bool
    dispatch_allowed: Literal[False] = False
    flash_ready: Literal[False] = False
    idempotent_replay: bool = False


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
