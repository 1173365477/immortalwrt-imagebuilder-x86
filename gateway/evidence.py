"""T13 verifier adapters for immutable evidence."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .errors import ErrorCode
from .models import BuildRequest


@dataclass(frozen=True)
class EvidenceVerdict:
    trusted: bool
    failure_code: ErrorCode = ErrorCode.EVIDENCE_UNVERIFIED
    internal_detail: str = ""


class EvidenceVerifier(Protocol):
    def verify(self, request: BuildRequest) -> EvidenceVerdict: ...


class RejectingEvidenceVerifier:
    """Production-safe T14-A default: no evidence source means no build authority."""

    def verify(self, request: BuildRequest) -> EvidenceVerdict:
        del request
        return EvidenceVerdict(False, ErrorCode.EVIDENCE_UNVERIFIED, "no trusted evidence adapter configured")


class SubprocessT13Verifier:
    """Verify a controlled checkout with T13; retrieval/dispatch remains T14-B work."""

    def __init__(self, checkout: Path, trusted_repository: str, timeout_seconds: float = 30.0):
        self.checkout = checkout.resolve(strict=True)
        self.trusted_repository = trusted_repository
        self.timeout_seconds = timeout_seconds

    def verify(self, request: BuildRequest) -> EvidenceVerdict:
        if request.repository != self.trusted_repository:
            return EvidenceVerdict(False, ErrorCode.INVALID_REPOSITORY, "repository mismatch")
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.checkout, text=True,
            capture_output=True, check=False, timeout=5,
        )
        if commit.returncode != 0 or commit.stdout.strip() != request.evidence_commit_sha:
            return EvidenceVerdict(False, ErrorCode.EVIDENCE_NOT_FOUND, "controlled checkout commit mismatch")
        input_path = self.checkout / "evidence" / "requests" / request.request_id / "build-input-v1.json"
        if not input_path.is_file() or input_path.is_symlink():
            return EvidenceVerdict(False, ErrorCode.EVIDENCE_NOT_FOUND, "controlled evidence file missing")
        with tempfile.TemporaryDirectory(prefix="gateway-t13-") as temporary:
            output = Path(temporary) / "context.json"
            result = subprocess.run(
                [
                    "python3", "scripts/verify-build-input.py", "--input", str(input_path),
                    "--repo-root", str(self.checkout), "--repository", self.trusted_repository,
                    "--commit", request.evidence_commit_sha, "--output", str(output),
                ],
                cwd=self.checkout, text=True, capture_output=True, check=False,
                timeout=self.timeout_seconds,
            )
        if result.returncode != 0:
            return EvidenceVerdict(False, ErrorCode.BUILD_BLOCKED, "T13 verifier rejected controlled evidence")
        return EvidenceVerdict(True)
