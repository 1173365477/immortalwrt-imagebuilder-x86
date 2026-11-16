"""T13 verifier adapters for immutable evidence."""

from __future__ import annotations

import json
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
    trusted_code_commit_sha: str | None = None
    evidence_commit_sha: str | None = None
    target_version: str | None = None
    snapshot_digest: str | None = None
    plan_digest: str | None = None


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
        try:
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=self.checkout, text=True,
                capture_output=True, check=False, timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return EvidenceVerdict(
                False, ErrorCode.EVIDENCE_UNVERIFIED,
                f"controlled checkout could not be inspected: {type(exc).__name__}",
            )
        if commit.returncode != 0 or commit.stdout.strip() != request.evidence_commit_sha:
            return EvidenceVerdict(False, ErrorCode.EVIDENCE_NOT_FOUND, "controlled checkout commit mismatch")
        input_path = self.checkout / "evidence" / "requests" / request.request_id / "build-input-v1.json"
        if not input_path.is_file() or input_path.is_symlink():
            return EvidenceVerdict(False, ErrorCode.EVIDENCE_NOT_FOUND, "controlled evidence file missing")
        with tempfile.TemporaryDirectory(prefix="gateway-t13-") as temporary:
            output = Path(temporary) / "context.json"
            try:
                result = subprocess.run(
                    [
                        "python3", "scripts/verify-build-input.py", "--input", str(input_path),
                        "--repo-root", str(self.checkout), "--repository", self.trusted_repository,
                        "--commit", request.evidence_commit_sha, "--output", str(output),
                    ],
                    cwd=self.checkout, text=True, capture_output=True, check=False,
                    timeout=self.timeout_seconds,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return EvidenceVerdict(
                    False, ErrorCode.EVIDENCE_UNVERIFIED,
                    f"T13 verifier execution failed: {type(exc).__name__}",
                )
            if result.returncode != 0:
                return EvidenceVerdict(
                    False, ErrorCode.BUILD_BLOCKED, "T13 verifier rejected controlled evidence"
                )
            return self._bind_context(output, request)

    @staticmethod
    def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def _bind_context(
        self, output: Path, request: BuildRequest, *,
        expected_runtime_sha: str | None = None,
    ) -> EvidenceVerdict:
        """Bind the verifier's authenticated result to the HTTP request identity."""
        try:
            if not output.is_file() or output.is_symlink() or output.stat().st_size > 1024 * 1024:
                raise ValueError("missing, unsafe, or oversized context")
            context = json.loads(
                output.read_text(encoding="utf-8"),
                object_pairs_hook=self._reject_duplicate_keys,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            return EvidenceVerdict(
                False, ErrorCode.EVIDENCE_UNVERIFIED,
                f"T13 context is invalid: {type(exc).__name__}",
            )
        if not isinstance(context, dict):
            return EvidenceVerdict(False, ErrorCode.EVIDENCE_UNVERIFIED, "T13 context is not an object")
        expected = {
            "request_id": request.request_id,
            "build_input_id": request.build_input_id,
            "build_input_digest": request.build_input_digest,
            "runtime_commit_sha": expected_runtime_sha or request.evidence_commit_sha,
            "repository": self.trusted_repository,
        }
        for field, expected_value in expected.items():
            actual = context.get(field)
            if type(actual) is not str or actual != expected_value:
                return EvidenceVerdict(
                    False, ErrorCode.EVIDENCE_UNVERIFIED,
                    f"T13 context identity mismatch: {field}",
                )
        if context.get("schema_version") != "1.0.0" or context.get("flash_ready") is not False:
            return EvidenceVerdict(
                False, ErrorCode.EVIDENCE_UNVERIFIED, "T13 context safety fields are invalid"
            )
        snapshot_digest = context.get("snapshot_digest")
        plan_digest = context.get("plan_digest")
        return EvidenceVerdict(
            True,
            snapshot_digest=snapshot_digest if isinstance(snapshot_digest, str) else None,
            plan_digest=plan_digest if isinstance(plan_digest, str) else None,
        )


class CommitBoundT13Verifier(SubprocessT13Verifier):
    """T14-B verifier separating reviewed code from the evidence commit."""

    def verify(self, request: BuildRequest) -> EvidenceVerdict:
        if request.repository != self.trusted_repository:
            return EvidenceVerdict(False, ErrorCode.INVALID_REPOSITORY, "repository mismatch")
        try:
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=self.checkout, text=True,
                capture_output=True, check=False, timeout=5,
            )
            if head.returncode != 0 or head.stdout.strip() != request.evidence_commit_sha:
                raise ValueError("evidence checkout mismatch")
            input_path = (
                self.checkout / "evidence" / "requests" / request.request_id
                / "build-input-v1.json"
            )
            if not input_path.is_file() or input_path.is_symlink() or input_path.stat().st_size > 1024 * 1024:
                raise ValueError("evidence input missing or unsafe")
            build_input = json.loads(
                input_path.read_text(encoding="utf-8"),
                object_pairs_hook=self._reject_duplicate_keys,
            )
            trusted = build_input.get("build", {}).get("git_commit_sha")
            target_version = build_input.get("target", {}).get("version")
            if (not isinstance(trusted, str) or len(trusted) != 40
                    or any(ch not in "0123456789abcdef" for ch in trusted)
                    or not isinstance(target_version, str) or not target_version):
                raise ValueError("trusted code identity missing")
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", trusted, request.evidence_commit_sha],
                cwd=self.checkout, capture_output=True, check=False, timeout=5,
            )
            if ancestor.returncode != 0:
                raise ValueError("trusted code is not an ancestor")
            changed = subprocess.run(
                ["git", "diff", "--name-only", "-z", trusted, request.evidence_commit_sha],
                cwd=self.checkout, capture_output=True, check=False, timeout=5,
            )
            if changed.returncode != 0:
                raise ValueError("protected tree diff failed")
            prefix = f"evidence/requests/{request.request_id}/"
            paths = [item.decode("utf-8") for item in changed.stdout.split(b"\0") if item]
            if not paths or any(not path.startswith(prefix) for path in paths):
                raise ValueError("evidence commit changed protected paths")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError,
                subprocess.SubprocessError) as exc:
            return EvidenceVerdict(
                False, ErrorCode.EVIDENCE_UNVERIFIED,
                f"commit binding failed: {type(exc).__name__}",
            )
        with tempfile.TemporaryDirectory(prefix="gateway-t14b-") as temporary:
            output = Path(temporary) / "context.json"
            try:
                result = subprocess.run(
                    [
                        "python3", "scripts/verify-build-input.py", "--input", str(input_path),
                        "--repo-root", str(self.checkout), "--repository", self.trusted_repository,
                        "--commit", trusted, "--output", str(output),
                    ], cwd=self.checkout, text=True, capture_output=True, check=False,
                    timeout=self.timeout_seconds,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                return EvidenceVerdict(
                    False, ErrorCode.EVIDENCE_UNVERIFIED,
                    f"T13 execution failed: {type(exc).__name__}",
                )
            if result.returncode != 0:
                return EvidenceVerdict(False, ErrorCode.BUILD_BLOCKED, "T13 rejected evidence")
            bound = self._bind_context(output, request, expected_runtime_sha=trusted)
            if not bound.trusted:
                return bound
        return EvidenceVerdict(
            True, trusted_code_commit_sha=trusted,
            evidence_commit_sha=request.evidence_commit_sha,
            target_version=target_version,
            snapshot_digest=bound.snapshot_digest,
            plan_digest=bound.plan_digest,
        )
