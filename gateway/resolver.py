"""Fixed-repository immutable evidence checkout and size/type controls."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol

from .errors import ErrorCode
from .evidence import CommitBoundT13Verifier, EvidenceVerdict
from .models import BuildRequest


class CommitFetcher(Protocol):
    def checkout(self, repository: str, commit_sha: str, destination: Path) -> None: ...


class LocalRepositoryFetcher:
    """Test/sandbox fetcher fixed to one already-controlled local repository."""

    def __init__(self, repository: str, source: Path):
        self.repository = repository
        self.source = source.resolve(strict=True)

    def checkout(self, repository: str, commit_sha: str, destination: Path) -> None:
        if repository != self.repository:
            raise ValueError("repository mismatch")
        subprocess.run(
            ["git", "clone", "--quiet", "--no-local", "--no-checkout", str(self.source),
             str(destination)], check=True, timeout=30, capture_output=True,
        )
        subprocess.run(
            ["git", "checkout", "--quiet", "--detach", commit_sha], cwd=destination,
            check=True, timeout=30, capture_output=True,
        )


class EvidenceResolver:
    def __init__(self, fetcher: CommitFetcher, *, repository: str,
                 max_files: int = 4096, max_total_bytes: int = 128 * 1024 * 1024,
                 verifier_timeout_seconds: float = 30.0):
        self.fetcher = fetcher
        self.repository = repository
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.verifier_timeout_seconds = verifier_timeout_seconds

    def verify(self, request: BuildRequest) -> EvidenceVerdict:
        if request.repository != self.repository:
            return EvidenceVerdict(False, ErrorCode.INVALID_REPOSITORY, "repository mismatch")
        try:
            with tempfile.TemporaryDirectory(prefix="gateway-evidence-") as temporary:
                checkout = Path(temporary) / "checkout"
                self.fetcher.checkout(self.repository, request.evidence_commit_sha, checkout)
                self._validate_tree(checkout)
                return CommitBoundT13Verifier(
                    checkout, self.repository, self.verifier_timeout_seconds
                ).verify(request)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return EvidenceVerdict(
                False, ErrorCode.EVIDENCE_UNVERIFIED,
                f"evidence resolution failed: {type(exc).__name__}",
            )

    def _validate_tree(self, checkout: Path) -> None:
        root = checkout.resolve(strict=True)
        count = 0
        total = 0
        for directory, names, files in os.walk(root, followlinks=False):
            relative_directory = Path(directory).relative_to(root)
            if relative_directory.parts[:1] == (".git",):
                names[:] = []
                continue
            for name in [*names, *files]:
                count += 1
                if count > self.max_files:
                    raise ValueError("evidence file count exceeded")
                path = Path(directory) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not (
                    stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
                ):
                    raise ValueError("unsafe evidence file type")
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    if total > self.max_total_bytes:
                        raise ValueError("evidence size exceeded")

