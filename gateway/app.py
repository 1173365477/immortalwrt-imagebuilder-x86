"""FastAPI application for the T14-A/T14-B secure build Gateway."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, Path as ApiPath, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from .analysis import DEFAULT_ANALYSIS_TTL, AnalysisService
from .targets import REF_PATTERN, strict_json
from .database import DeviceIdentity, GatewayStore, TaskRecord
from .errors import ErrorCode, GatewayError, PUBLIC_MESSAGES
from .evidence import EvidenceVerifier, RejectingEvidenceVerifier
from .logging import audit, device_fingerprint
from .models import (
    ArtifactResponse, BuildRequest, BuildTaskResponse, LogResponse, REQUEST_PATTERN,
)
from .service import T14BService
from .state import TaskStatus


@dataclass(frozen=True)
class GatewaySettings:
    database_path: Path
    trusted_repository: str = "1173365477/immortalwrt-imagebuilder-x86"
    require_https: bool = True
    max_body_bytes: int = 16 * 1024
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    task_quota: int = 100
    task_ttl_seconds: int = 7 * 24 * 60 * 60
    validation_timeout_seconds: float = 30.0
    validation_workers: int = 4
    external_workers: int = 4
    external_timeout_seconds: float = 30.0
    sqlite_busy_timeout_ms: int = 1_000
    dispatch_enabled: bool = False
    target_catalog_path: Path | None = None
    analysis_enabled: bool = True
    analysis_ttl_seconds: int = DEFAULT_ANALYSIS_TTL
    analysis_workers: int = 2
    analysis_timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> "GatewaySettings":
        return cls(
            database_path=Path(os.environ.get("GATEWAY_DATABASE", "work/gateway/gateway.db")),
            trusted_repository=os.environ.get(
                "GATEWAY_REPOSITORY", "1173365477/immortalwrt-imagebuilder-x86"
            ),
            require_https=os.environ.get("GATEWAY_ALLOW_HTTP", "false").lower() != "true",
            target_catalog_path=Path(os.environ["GATEWAY_TARGET_CATALOG"])
            if "GATEWAY_TARGET_CATALOG" in os.environ else None,
            analysis_enabled=os.environ.get("GATEWAY_ANALYSIS_ENABLED", "true").lower() == "true",
            analysis_ttl_seconds=int(os.environ.get("GATEWAY_ANALYSIS_TTL_SECONDS", DEFAULT_ANALYSIS_TTL)),
            dispatch_enabled=os.environ.get("GATEWAY_DISPATCH_ENABLED", "false").lower() == "true",
        )


class BodySizeLimitMiddleware:
    """Buffer a bounded request body before any route or validation code sees it."""

    def __init__(self, app: Any, max_bytes: int, analysis_timeout: float):
        self.app = app
        self.max_bytes = max_bytes
        self.analysis_timeout = analysis_timeout

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        analysis_paths = ("/analysis", scope.get("root_path", "").rstrip("/") + "/analysis")
        if scope["method"] != "POST" or scope["path"] not in analysis_paths:
            await self._bounded_body(scope, receive, send)
            return

        deadline = time.monotonic() + self.analysis_timeout
        scope["analysis_deadline"] = deadline
        started = False

        async def track_response(message):
            nonlocal started
            if message["type"] == "http.response.start":
                if time.monotonic() >= deadline:
                    raise TimeoutError
                started = True
            await send(message)

        try:
            async with asyncio.timeout(deadline - time.monotonic()):
                await self._bounded_body(scope, receive, track_response)
        except TimeoutError:
            if started:
                raise  # HTTP status has already been sent.
            error = ErrorCode.ANALYSIS_UNAVAILABLE
            audit("request_failed", endpoint="/analysis", error_code=error.value)
            await JSONResponse(
                {"error": {"code": error.value, "message": PUBLIC_MESSAGES[error]}},
                status_code=503,
            )(scope, receive, send)

    async def _bounded_body(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return
        messages: list[dict[str, Any]] = []
        total = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    await self._reject(send)
                    return
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                return
        index = 0

        async def replay() -> dict[str, Any]:
            nonlocal index
            if index < len(messages):
                item = messages[index]
                index += 1
                return item
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send: Any) -> None:
        payload = json.dumps({
            "error": {
                "code": ErrorCode.REQUEST_TOO_LARGE.value,
                "message": PUBLIC_MESSAGES[ErrorCode.REQUEST_TOO_LARGE],
            }
        }, separators=(",", ":")).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json"),
                        (b"content-length", str(len(payload)).encode("ascii"))],
        })
        await send({"type": "http.response.body", "body": payload})


def _utc(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, tz=UTC)


def _response(
    task: TaskRecord, *, store: GatewayStore | None = None, replay: bool = False,
) -> BuildTaskResponse:
    intent = store.get_dispatch_intent(task.internal_task_id) if store else None
    return BuildTaskResponse(
        request_id=task.request_id,
        internal_task_id=task.internal_task_id,
        status=task.status.value,
        build_input_id=task.build_input_id,
        build_input_digest=task.build_input_digest,
        repository=task.repository,
        evidence_commit_sha=task.evidence_commit_sha,
        gateway_task_id=intent.external_task_id if intent else None,
        trusted_code_commit_sha=intent.trusted_code_commit_sha if intent else None,
        github_run_id=task.github_run_id,
        github_run_attempt=task.github_run_attempt,
        created_at=_utc(task.created_at),
        updated_at=_utc(task.updated_at),
        expires_at=_utc(task.expires_at),
        failure_code=task.failure_code,
        evidence_verified=task.status not in {
            TaskStatus.RECEIVED, TaskStatus.VALIDATING, TaskStatus.BLOCKED, TaskStatus.FAILED,
        },
        dispatch_allowed=False,
        flash_ready=False,
        idempotent_replay=replay,
    )


def create_app(
    settings: GatewaySettings | None = None,
    *,
    verifier: EvidenceVerifier | None = None,
    t14b_service: T14BService | None = None,
) -> FastAPI:
    settings = settings or GatewaySettings.from_env()
    verifier = verifier or RejectingEvidenceVerifier()
    store = GatewayStore(settings.database_path, busy_timeout_ms=settings.sqlite_busy_timeout_ms)
    store.initialize()
    if settings.analysis_timeout_seconds <= 0:
        raise ValueError("invalid analysis execution deadline")
    analysis = AnalysisService(
        store, settings.target_catalog_path or store.path.parent / "target-catalog.json",
        settings.analysis_ttl_seconds,
    )
    analysis_executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=settings.analysis_workers, thread_name_prefix="gateway-analysis",
    )
    analysis_slots = asyncio.Semaphore(settings.analysis_workers)
    recovered = store.recover_incomplete_tasks()
    if recovered:
        audit("startup_recovery", status=TaskStatus.FAILED.value)
    if settings.dispatch_enabled and t14b_service is not None:
        if (t14b_service.store.path != store.path
                or t14b_service.repository != settings.trusted_repository):
            raise ValueError("T14-B service identity does not match Gateway settings")

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        if settings.dispatch_enabled and t14b_service is not None:
            try:
                recovery = await run_external(t14b_service.recover_startup)
                if any(recovery.values()):
                    audit("t14b_startup_recovery", status="reconciled")
            except GatewayError:
                audit("t14b_startup_recovery", status="deferred")
        try:
            yield
        finally:
            application.state.validation_executor.shutdown(wait=False, cancel_futures=True)
            application.state.external_executor.shutdown(wait=False, cancel_futures=True)
            analysis_executor.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="OpenWrt Smart Upgrade Build Gateway",
        version="0.2.0-t14b",
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes,
                       analysis_timeout=settings.analysis_timeout_seconds)
    app.state.settings = settings
    app.state.store = store
    app.state.verifier = verifier
    app.state.t14b_service = t14b_service
    app.state.validation_executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=settings.validation_workers,
        thread_name_prefix="gateway-evidence",
    )
    app.state.external_executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=settings.external_workers,
        thread_name_prefix="gateway-github",
    )
    validation_slots = asyncio.Semaphore(settings.validation_workers)
    external_slots = asyncio.Semaphore(settings.external_workers)

    async def run_external(function, *args):
        """Bound sync I/O without releasing capacity while timed-out work runs."""
        try:
            await asyncio.wait_for(
                external_slots.acquire(), timeout=settings.external_timeout_seconds
            )
        except TimeoutError as exc:
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503) from exc
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(
                app.state.external_executor, function, *args
            )
        except BaseException:
            external_slots.release()
            raise
        release_in_callback = False

        def release_slot(_future: object) -> None:
            loop.call_soon_threadsafe(external_slots.release)

        try:
            return await asyncio.wait_for(
                asyncio.shield(future), timeout=settings.external_timeout_seconds
            )
        except TimeoutError as exc:
            release_in_callback = True
            future.add_done_callback(release_slot)
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503) from exc
        except BaseException:
            release_in_callback = True
            future.add_done_callback(release_slot)
            raise
        finally:
            if not release_in_callback:
                external_slots.release()

    async def verify_with_bounded_workers(build_request: BuildRequest):
        """Keep a slot occupied until a timed-out worker actually terminates."""
        await asyncio.wait_for(
            validation_slots.acquire(), timeout=settings.validation_timeout_seconds
        )
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(
                app.state.validation_executor, verifier.verify, build_request
            )
        except BaseException:
            validation_slots.release()
            raise
        release_in_callback = False

        def release_slot(_future: object) -> None:
            loop.call_soon_threadsafe(validation_slots.release)

        try:
            return await asyncio.wait_for(
                asyncio.shield(future), timeout=settings.validation_timeout_seconds
            )
        except BaseException:
            release_in_callback = True
            future.add_done_callback(release_slot)
            raise
        finally:
            if not release_in_callback:
                validation_slots.release()

    @app.exception_handler(GatewayError)
    async def gateway_error_handler(request: Request, exc: GatewayError) -> JSONResponse:
        audit("request_failed", endpoint=request.url.path, error_code=exc.code.value)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code.value, "message": exc.public_message}},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        del request
        code = ErrorCode.INVALID_REQUEST
        if any(error.get("loc", ())[-1:] == ("evidence_commit_sha",) for error in exc.errors()):
            code = ErrorCode.INVALID_COMMIT
        audit("request_failed", error_code=code.value)
        return JSONResponse(
            status_code=422,
            content={"error": {"code": code.value, "message": PUBLIC_MESSAGES[code]}},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # Route and method enumeration does not need a separate public taxonomy.
        audit("request_failed", endpoint=request.url.path, error_code=ErrorCode.INVALID_REQUEST.value)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": ErrorCode.INVALID_REQUEST.value,
                    "message": PUBLIC_MESSAGES[ErrorCode.INVALID_REQUEST],
                }
            },
        )

    @app.exception_handler(Exception)
    async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
        del exc
        audit("request_failed", endpoint=request.url.path, error_code=ErrorCode.INTERNAL_ERROR.value)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR.value,
                    "message": PUBLIC_MESSAGES[ErrorCode.INTERNAL_ERROR],
                }
            },
        )

    def authenticate(
        request: Request,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> DeviceIdentity:
        if settings.require_https and request.url.scheme != "https":
            raise GatewayError(ErrorCode.TLS_REQUIRED, 403)
        if authorization is None:
            raise GatewayError(ErrorCode.AUTH_REQUIRED, 401)
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token or len(token) > 256:
            raise GatewayError(ErrorCode.AUTH_INVALID, 401)
        return store.authenticate(token)

    def apply_rate_limit(identity: DeviceIdentity, endpoint: str, *, deadline: float | None = None) -> None:
        store.consume_rate_limit(
            identity.device_id,
            endpoint,
            limit=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
            deadline=deadline,
        )

    async def run_analysis(function, *args, deadline: float):
        if time.monotonic() >= deadline or analysis_slots.locked():
            raise GatewayError(ErrorCode.ANALYSIS_UNAVAILABLE, 503)
        await analysis_slots.acquire()
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(analysis_executor, function, *args)
        except Exception:
            analysis_slots.release()
            raise GatewayError(ErrorCode.ANALYSIS_UNAVAILABLE, 503) from None

        def release_slot(completed):
            analysis_slots.release()
            if not completed.cancelled():
                completed.exception()

        future.add_done_callback(release_slot)
        try:
            return await asyncio.wait_for(
                asyncio.shield(future), timeout=deadline - time.monotonic(),
            )
        except GatewayError:
            raise
        except Exception:
            raise GatewayError(ErrorCode.ANALYSIS_UNAVAILABLE, 503) from None

    def check_analysis_policy() -> None:
        if not settings.analysis_enabled:
            raise GatewayError(ErrorCode.ACCESS_DENIED, 403)

    @app.get("/targets", responses={401: {}, 403: {}, 413: {}, 422: {}, 429: {}, 503: {}})
    async def get_targets(request: Request, identity: DeviceIdentity = Depends(authenticate)):
        await run_in_threadpool(apply_rate_limit, identity, "GET:/targets")
        check_analysis_policy()
        if request.url.query or await request.body():
            raise GatewayError(ErrorCode.INVALID_REQUEST, 422)
        result = await run_analysis(
            analysis.targets, deadline=time.monotonic() + settings.analysis_timeout_seconds,
        )
        audit("targets_read", endpoint="GET:/targets", device=device_fingerprint(identity.device_id))
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post("/analysis", responses={401: {}, 403: {}, 404: {}, 409: {}, 410: {},
                                      413: {}, 422: {}, 429: {}, 503: {}})
    async def post_analysis(request: Request, identity: DeviceIdentity = Depends(authenticate)):
        deadline = request.scope["analysis_deadline"]
        await run_in_threadpool(apply_rate_limit, identity, "POST:/analysis", deadline=deadline)
        if time.monotonic() >= deadline:
            raise GatewayError(ErrorCode.ANALYSIS_UNAVAILABLE, 503)
        check_analysis_policy()
        media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        try:
            if request.url.query or media_type != "application/json":
                raise ValueError("invalid request envelope")
            body = strict_json(await request.body())
            if (not isinstance(body, dict) or set(body) != {"snapshot_ref", "target_ref"}
                    or not all(isinstance(value, str) and REF_PATTERN.fullmatch(value)
                               for value in body.values())):
                raise ValueError("invalid evidence references")
        except (ValueError, RecursionError):
            raise GatewayError(ErrorCode.INVALID_REQUEST, 422) from None
        result = await run_analysis(
            analysis.analyze, identity, body["snapshot_ref"], body["target_ref"],
            deadline, deadline=deadline,
        )
        if time.monotonic() >= deadline:
            raise GatewayError(ErrorCode.ANALYSIS_UNAVAILABLE, 503)
        audit("analysis_completed", endpoint="POST:/analysis",
              device=device_fingerprint(identity.device_id), status=result["status"])
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post(
        "/builds",
        response_model=BuildTaskResponse,
        responses={400: {}, 401: {}, 409: {}, 413: {}, 422: {}, 429: {}, 503: {}},
    )
    async def create_build(
        build_request: BuildRequest,
        response: Response,
        identity: DeviceIdentity = Depends(authenticate),
    ) -> BuildTaskResponse:
        started = time.monotonic()
        apply_rate_limit(identity, "POST:/builds")
        if build_request.repository != settings.trusted_repository:
            raise GatewayError(ErrorCode.INVALID_REPOSITORY, 400)
        task, created = store.create_or_get_task(
            identity.device_id,
            build_request,
            ttl_seconds=settings.task_ttl_seconds,
            task_quota=settings.task_quota,
        )
        if created:
            task = store.transition_task(task.internal_task_id, TaskStatus.VALIDATING)
            try:
                verdict = await verify_with_bounded_workers(build_request)
            except TimeoutError:
                task = store.transition_task(
                    task.internal_task_id,
                    TaskStatus.FAILED,
                    failure_code=ErrorCode.EVIDENCE_UNVERIFIED,
                    failure_detail="evidence validation timed out",
                )
            except Exception as exc:  # fail closed; raw exception text is never persisted or logged
                task = store.transition_task(
                    task.internal_task_id,
                    TaskStatus.FAILED,
                    failure_code=ErrorCode.INTERNAL_ERROR,
                    failure_detail=f"evidence adapter failed: {type(exc).__name__}",
                )
            else:
                if verdict.trusted:
                    task = store.transition_task(task.internal_task_id, TaskStatus.VALIDATED)
                else:
                    task = store.transition_task(
                        task.internal_task_id,
                        TaskStatus.BLOCKED,
                        failure_code=verdict.failure_code,
                        # Adapter text may include upstream or transport details.
                        # Persist only a stable, non-sensitive classification.
                        failure_detail=f"evidence verifier returned {verdict.failure_code.value}",
                    )
            if task.status == TaskStatus.VALIDATED and settings.dispatch_enabled:
                if t14b_service is None:
                    task = store.transition_task(
                        task.internal_task_id, TaskStatus.FAILED,
                        failure_code=ErrorCode.DISPATCH_DISABLED,
                    )
                else:
                    task = await run_external(t14b_service.dispatch, task, verdict)
            response.status_code = 201
        else:
            response.status_code = 200
        audit(
            "build_request",
            request_id=task.request_id,
            internal_task_id=task.internal_task_id,
            device=device_fingerprint(identity.device_id),
            status=task.status.value,
            duration_ms=int((time.monotonic() - started) * 1000),
            commit=task.evidence_commit_sha[:12],
            idempotent=not created,
        )
        return _response(task, store=store, replay=not created)

    @app.get(
        "/builds/{request_id}",
        response_model=BuildTaskResponse,
        responses={401: {}, 404: {}, 410: {}, 429: {}, 503: {}},
    )
    async def get_build(
        request_id: str = ApiPath(pattern=REQUEST_PATTERN, min_length=1, max_length=128),
        identity: DeviceIdentity = Depends(authenticate),
    ) -> BuildTaskResponse:
        apply_rate_limit(identity, "GET:/builds")
        task = store.get_task(identity.device_id, request_id)
        if t14b_service and task.status == TaskStatus.DISPATCH_UNKNOWN:
            task = await run_external(t14b_service.reconcile, task)
        elif t14b_service and task.status in {TaskStatus.QUEUED, TaskStatus.RUNNING}:
            task = await run_external(t14b_service.poll, task)
        audit(
            "build_query",
            request_id=task.request_id,
            internal_task_id=task.internal_task_id,
            device=device_fingerprint(identity.device_id),
            status=task.status.value,
            commit=task.evidence_commit_sha[:12],
        )
        return _response(task, store=store)

    @app.get("/builds/{request_id}/artifacts", response_model=ArtifactResponse)
    async def get_artifact(
        request_id: str = ApiPath(pattern=REQUEST_PATTERN, min_length=1, max_length=128),
        identity: DeviceIdentity = Depends(authenticate),
    ) -> ArtifactResponse:
        apply_rate_limit(identity, "GET:/builds/artifacts")
        task = store.get_task(identity.device_id, request_id)
        if t14b_service and task.status == TaskStatus.VERIFYING_ARTIFACT:
            task = await run_external(t14b_service.verify_artifact, task)
        raw = store.get_verified_artifact(task.internal_task_id)
        if raw is None:
            raise GatewayError(ErrorCode.ARTIFACT_UNVERIFIED, 409)
        return ArtifactResponse.model_validate_json(raw)

    @app.get("/builds/{request_id}/logs", response_model=LogResponse)
    async def get_logs(
        request_id: str = ApiPath(pattern=REQUEST_PATTERN, min_length=1, max_length=128),
        identity: DeviceIdentity = Depends(authenticate),
    ) -> LogResponse:
        apply_rate_limit(identity, "GET:/builds/logs")
        task = store.get_task(identity.device_id, request_id)
        if t14b_service is None:
            raise GatewayError(ErrorCode.EVIDENCE_NOT_FOUND, 404)
        lines, truncated = await run_external(t14b_service.logs, task)
        return LogResponse(
            request_id=task.request_id, lines=lines, truncated=truncated,
            flash_ready=False,
        )

    return app
