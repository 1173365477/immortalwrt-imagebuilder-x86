"""Server-controlled GitHub App, dispatch, run, and log boundaries."""

from __future__ import annotations

import json
import io
import re
import stat
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import BinaryIO, Protocol
from urllib.parse import quote, urlparse

from .database import DispatchIntent
from .errors import ErrorCode, GatewayError


WORKFLOW_ID = ".github/workflows/build.yml"
API_VERSION = "2026-03-10"
EXPECTED_PERMISSIONS = {"metadata": "read", "contents": "read", "actions": "write"}


@dataclass(frozen=True)
class InstallationToken:
    value: str
    expires_at: int
    installation_id: int
    repository: str
    permissions: dict[str, str]


class InstallationTokenIssuer(Protocol):
    def issue(self, installation_id: int, repository: str) -> InstallationToken: ...


class GitHubAppTokenProvider:
    """Cache one short-lived, least-privilege installation token in memory."""

    def __init__(self, issuer: InstallationTokenIssuer, *, installation_id: int,
                 repository: str, refresh_before_seconds: int = 60):
        if installation_id <= 0 or not repository:
            raise ValueError("invalid fixed GitHub App identity")
        self.issuer = issuer
        self.installation_id = installation_id
        self.repository = repository
        self.refresh_before_seconds = refresh_before_seconds
        self._cached: InstallationToken | None = None

    def get(self, *, now: int | None = None) -> str:
        timestamp = int(time.time() if now is None else now)
        if self._cached and self._cached.expires_at > timestamp + self.refresh_before_seconds:
            return self._cached.value
        token = self.issuer.issue(self.installation_id, self.repository)
        if token.installation_id != self.installation_id or token.repository != self.repository:
            raise GatewayError(ErrorCode.ACCESS_DENIED, 503)
        if token.permissions != EXPECTED_PERMISSIONS or token.expires_at <= timestamp + 60:
            raise GatewayError(ErrorCode.ACCESS_DENIED, 503)
        if not token.value or len(token.value) > 1024:
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        self._cached = token
        return token.value


@dataclass(frozen=True)
class DispatchResponse:
    run_id: int | None = None


@dataclass(frozen=True)
class WorkflowRun:
    run_id: int
    run_attempt: int
    repository: str
    workflow_id: str
    event: str
    head_sha: str
    dispatch_ref: str
    external_task_id: str
    build_input_digest: str
    status: str
    conclusion: str | None = None


@dataclass
class ArtifactDownload:
    archive: BinaryIO
    size_bytes: int
    repository: str
    run_id: int
    run_attempt: int
    expired: bool = False

    def close(self) -> None:
        self.archive.close()


class GitHubAPI(Protocol):
    def resolve_ref(self, token: str, repository: str, dispatch_ref: str) -> str: ...
    def dispatch(self, token: str, repository: str, workflow_id: str,
                 dispatch_ref: str, inputs: dict[str, object]) -> DispatchResponse: ...
    def get_run(self, token: str, repository: str, run_id: int) -> WorkflowRun: ...
    def find_runs(self, token: str, repository: str, workflow_id: str,
                  head_sha: str) -> list[WorkflowRun]: ...
    def artifact_zip(self, token: str, repository: str, run_id: int,
                     run_attempt: int) -> ArtifactDownload: ...
    def log_archive(self, token: str, repository: str, run_id: int,
                    run_attempt: int) -> bytes: ...


class GitHubRateLimited(RuntimeError):
    def __init__(self, retry_after: float):
        super().__init__("GitHub rate limited")
        self.retry_after = retry_after


class GitHubTransientError(RuntimeError):
    pass


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: bytes


class GitHubHTTPTransport(Protocol):
    """Injected bounded transport; implementations must enforce finite timeouts."""

    def request(self, method: str, path: str, token: str, *,
                api_version: str = API_VERSION,
                query: dict[str, str] | None = None,
                json_body: dict[str, object] | None = None,
                max_bytes: int = 1024 * 1024) -> HTTPResult: ...

    def download(self, method: str, path: str, token: str, destination: BinaryIO, *,
                 api_version: str = API_VERSION,
                 max_bytes: int) -> HTTPResult: ...


_EXTERNAL_TASK = r"gw-[a-f0-9]{32}"
_RUN_TITLE = re.compile(
    rf"^gateway-(?P<external>{_EXTERNAL_TASK})-(?P<digest>[a-f0-9]{{64}})$"
)


class GitHubRESTClient:
    """Fixed-repository REST mapping for API version 2026-03-10.

    The transport is injected so tests cannot make network calls. A production
    transport is a deployment concern and must provide TLS, redirect-host
    controls, response limits, and request timeouts.
    """

    def __init__(self, transport: GitHubHTTPTransport, *, repository: str,
                 workflow_id: str = WORKFLOW_ID):
        owner, separator, repo = repository.partition("/")
        if not separator or not owner or not repo or "/" in repo:
            raise ValueError("invalid fixed repository")
        self.transport = transport
        self.repository = repository
        self.workflow_id = workflow_id
        self._base = f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"

    def _fixed(self, repository: str) -> None:
        if repository != self.repository:
            raise GatewayError(ErrorCode.ACCESS_DENIED, 403)

    @staticmethod
    def _decode(result: HTTPResult, expected: set[int]) -> dict[str, object]:
        if result.status == 429:
            try:
                retry = float(result.headers.get("retry-after", "1"))
            except ValueError:
                retry = 1.0
            raise GitHubRateLimited(max(0.0, min(retry, 30.0)))
        if result.status >= 500:
            raise GitHubTransientError()
        if result.status not in expected:
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        if not result.body:
            return {}
        try:
            value = json.loads(result.body)
        except (UnicodeDecodeError, ValueError) as exc:
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503) from exc
        if not isinstance(value, dict):
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        return value

    def resolve_ref(self, token: str, repository: str, dispatch_ref: str) -> str:
        self._fixed(repository)
        result = self.transport.request(
            "GET", f"{self._base}/git/ref/heads/{quote(dispatch_ref, safe='')}", token,
            api_version=API_VERSION,
        )
        value = self._decode(result, {200})
        obj = value.get("object")
        sha = obj.get("sha") if isinstance(obj, dict) else None
        if not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}", sha):
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        return sha

    def dispatch(self, token: str, repository: str, workflow_id: str,
                 dispatch_ref: str, inputs: dict[str, object]) -> DispatchResponse:
        self._fixed(repository)
        if workflow_id != self.workflow_id:
            raise GatewayError(ErrorCode.ACCESS_DENIED, 403)
        result = self.transport.request(
            "POST",
            f"{self._base}/actions/workflows/{quote(workflow_id, safe='')}/dispatches",
            token, api_version=API_VERSION,
            json_body={"ref": dispatch_ref, "inputs": inputs},
        )
        value = self._decode(result, {200, 204})
        run_id = value.get("workflow_run_id")
        if run_id is None and result.status == 204:
            return DispatchResponse(None)
        if not isinstance(run_id, int) or run_id <= 0:
            raise GatewayError(ErrorCode.DISPATCH_UNKNOWN, 409)
        return DispatchResponse(run_id)

    def _run(self, value: object) -> WorkflowRun:
        if not isinstance(value, dict):
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        title = value.get("display_title")
        match = _RUN_TITLE.fullmatch(title) if isinstance(title, str) else None
        repository = value.get("repository")
        full_name = repository.get("full_name") if isinstance(repository, dict) else None
        path = value.get("path")
        workflow = path.split("@", 1)[0] if isinstance(path, str) else None
        fields = {
            "run_id": value.get("id"), "run_attempt": value.get("run_attempt"),
            "repository": full_name, "workflow_id": workflow,
            "event": value.get("event"), "head_sha": value.get("head_sha"),
            "dispatch_ref": value.get("head_branch"),
            "external_task_id": match.group("external") if match else None,
            "build_input_digest": match.group("digest") if match else None,
            "status": value.get("status"), "conclusion": value.get("conclusion"),
        }
        if (not isinstance(fields["run_id"], int)
                or not isinstance(fields["run_attempt"], int)
                or any(not isinstance(fields[key], str) for key in (
                    "repository", "workflow_id", "event", "head_sha", "dispatch_ref",
                    "external_task_id", "build_input_digest", "status",
                ))
                or (fields["conclusion"] is not None
                    and not isinstance(fields["conclusion"], str))):
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        return WorkflowRun(**fields)

    def get_run(self, token: str, repository: str, run_id: int) -> WorkflowRun:
        self._fixed(repository)
        result = self.transport.request(
            "GET", f"{self._base}/actions/runs/{int(run_id)}", token,
            api_version=API_VERSION,
        )
        return self._run(self._decode(result, {200}))

    def find_runs(self, token: str, repository: str, workflow_id: str,
                  head_sha: str) -> list[WorkflowRun]:
        self._fixed(repository)
        if workflow_id != self.workflow_id:
            raise GatewayError(ErrorCode.ACCESS_DENIED, 403)
        result = self.transport.request(
            "GET", f"{self._base}/actions/workflows/{quote(workflow_id, safe='')}/runs",
            token, api_version=API_VERSION,
            query={"event": "workflow_dispatch", "head_sha": head_sha,
                          "per_page": "100"},
        )
        values = self._decode(result, {200}).get("workflow_runs")
        if not isinstance(values, list):
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        return [self._run(value) for value in values]

    def artifact_zip(self, token: str, repository: str, run_id: int,
                     run_attempt: int) -> ArtifactDownload:
        self._fixed(repository)
        run = self.get_run(token, repository, run_id)
        expected = f"gateway-{run.external_task_id}-{run.build_input_digest}-{run_attempt}"
        result = self.transport.request(
            "GET", f"{self._base}/actions/runs/{int(run_id)}/artifacts", token,
            api_version=API_VERSION, query={"per_page": "100"},
        )
        artifacts = self._decode(result, {200}).get("artifacts")
        matches = [item for item in artifacts or []
                   if isinstance(item, dict) and item.get("name") == expected]
        if len(matches) != 1:
            raise GatewayError(ErrorCode.ARTIFACT_UNVERIFIED, 409)
        artifact = matches[0]
        run_value = artifact.get("workflow_run")
        bound_run = run_value.get("id") if isinstance(run_value, dict) else None
        url = artifact.get("archive_download_url")
        parsed = urlparse(url) if isinstance(url, str) else None
        if (bound_run != run_id or parsed is None or parsed.scheme != "https"
                or parsed.hostname != "api.github.com"
                or not parsed.path.startswith(self._base + "/actions/artifacts/")):
            raise GatewayError(ErrorCode.ARTIFACT_UNVERIFIED, 409)
        spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
        try:
            response = self.transport.download(
                "GET", parsed.path, token, spool, api_version=API_VERSION,
                max_bytes=256 * 1024 * 1024,
            )
            if response.status != 200:
                self._decode(response, {200})
            size = spool.tell()
            spool.seek(0)
            return ArtifactDownload(
                spool, size, repository, run_id, run_attempt,
                expired=artifact.get("expired") is not False,
            )
        except BaseException:
            spool.close()
            raise

    def log_archive(self, token: str, repository: str, run_id: int,
                    run_attempt: int) -> bytes:
        self._fixed(repository)
        result = self.transport.request(
            "GET",
            f"{self._base}/actions/runs/{int(run_id)}/attempts/{int(run_attempt)}/logs",
            token, api_version=API_VERSION, max_bytes=8 * 1024 * 1024,
        )
        if result.status != 200:
            self._decode(result, {200})
        return result.body


def read_with_backoff(operation, *, sleep=time.sleep, max_attempts: int = 3):
    """Retry read-only GitHub calls; never use this helper for dispatch."""
    delay = 0.25
    for attempt in range(max_attempts):
        try:
            return operation()
        except GitHubRateLimited as exc:
            if attempt + 1 == max_attempts:
                break
            sleep(max(delay, min(float(exc.retry_after), 30.0)))
        except GitHubTransientError:
            if attempt + 1 == max_attempts:
                break
            sleep(delay)
        delay = min(delay * 2, 2.0)
    raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)


def validate_run(run: WorkflowRun, intent: DispatchIntent) -> None:
    expected = (
        intent.github_run_id, intent.github_run_attempt, intent.trusted_workflow_id,
        "workflow_dispatch", intent.expected_runtime_sha, intent.dispatch_ref,
        intent.external_task_id, intent.build_input_digest,
    )
    actual = (
        run.run_id, run.run_attempt, run.workflow_id, run.event, run.head_sha,
        run.dispatch_ref, run.external_task_id, run.build_input_digest,
    )
    if actual != expected or run.repository == "":
        raise GatewayError(ErrorCode.RUN_IDENTITY_MISMATCH, 409)


def select_unique_run(candidates: list[WorkflowRun], intent: DispatchIntent) -> WorkflowRun:
    matches = []
    for run in candidates:
        provisional = DispatchIntent(
            **{**intent.__dict__, "github_run_id": run.run_id,
               "github_run_attempt": run.run_attempt}
        )
        try:
            validate_run(run, provisional)
        except GatewayError:
            continue
        matches.append(run)
    if len(matches) != 1:
        raise GatewayError(ErrorCode.DISPATCH_UNKNOWN, 409)
    return matches[0]


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SECRET = re.compile(
    r"(?i)\b(authorization|token|secret|password|proxy[_-]?subscription)\s*[:=].*$"
)
_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
)


@dataclass(frozen=True)
class LogLimits:
    archive_bytes: int = 8 * 1024 * 1024
    expanded_bytes: int = 16 * 1024 * 1024
    member_bytes: int = 2 * 1024 * 1024
    members: int = 128
    compression_ratio: int = 100
    output_bytes: int = 64 * 1024
    output_lines: int = 1000


def _sanitize_line(source: str) -> str:
    line = _CONTROL.sub("", source)[:1000]
    line = _SECRET.sub(lambda match: match.group(1) + "=[REDACTED]", line)
    return _TOKEN.sub("[REDACTED_TOKEN]", line)


def sanitize_log_archive(raw: bytes, *, limits: LogLimits = LogLimits()
                         ) -> tuple[list[str], bool]:
    if not raw or len(raw) > limits.archive_bytes:
        raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
    lines: list[str] = []
    output_bytes = 0
    total = 0
    names: set[str] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > limits.members:
                raise ValueError("log member count")
            for info in infos:
                path = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if (path.is_absolute() or ".." in path.parts or "\\" in info.filename
                        or info.filename in names or info.is_dir()
                        or path.suffix != ".txt" or stat.S_ISLNK(mode)
                        or kind not in {0, stat.S_IFREG}):
                    raise ValueError("unsafe log member")
                names.add(info.filename)
                total += info.file_size
                if (info.file_size > limits.member_bytes or total > limits.expanded_bytes
                        or (info.compress_size == 0 and info.file_size > 0)
                        or (info.compress_size
                            and info.file_size / info.compress_size > limits.compression_ratio)):
                    raise ValueError("log limits")
                content = archive.read(info)
                if b"\0" in content:
                    raise ValueError("binary log")
                text = content.decode("utf-8", errors="strict")
                for source in text.splitlines():
                    line = _sanitize_line(source)
                    encoded = len(line.encode("utf-8"))
                    if (len(lines) >= limits.output_lines
                            or output_bytes + encoded > limits.output_bytes):
                        return lines, True
                    lines.append(line)
                    output_bytes += encoded
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503) from exc
    return lines, False

