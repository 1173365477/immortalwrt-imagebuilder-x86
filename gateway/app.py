"""FastAPI application for the non-dispatching T14-A Gateway foundation."""

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
from starlette.exceptions import HTTPException as StarletteHTTPException

from .database import DeviceIdentity, GatewayStore, TaskRecord
from .errors import ErrorCode, GatewayError, PUBLIC_MESSAGES
from .evidence import EvidenceVerifier, RejectingEvidenceVerifier
from .logging import audit, device_fingerprint
from .models import BuildRequest, BuildTaskResponse, REQUEST_PATTERN
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
    sqlite_busy_timeout_ms: int = 1_000

    @classmethod
    def from_env(cls) -> "GatewaySettings":
        return cls(
            database_path=Path(os.environ.get("GATEWAY_DATABASE", "work/gateway/gateway.db")),
            trusted_repository=os.environ.get(
                "GATEWAY_REPOSITORY", "1173365477/immortalwrt-imagebuilder-x86"
            ),
            require_https=os.environ.get("GATEWAY_ALLOW_HTTP", "false").lower() != "true",
        )


class BodySizeLimitMiddleware:
    """Buffer a bounded request body before any route or validation code sees it."""

    def __init__(self, app: Any, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
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


def _response(task: TaskRecord, *, replay: bool = False) -> BuildTaskResponse:
    return BuildTaskResponse(
        request_id=task.request_id,
        internal_task_id=task.internal_task_id,
        status=task.status.value,
        build_input_id=task.build_input_id,
        build_input_digest=task.build_input_digest,
        repository=task.repository,
        evidence_commit_sha=task.evidence_commit_sha,
        created_at=_utc(task.created_at),
        updated_at=_utc(task.updated_at),
        expires_at=_utc(task.expires_at),
        failure_code=task.failure_code,
        evidence_verified=task.status == TaskStatus.VALIDATED,
        dispatch_allowed=False,
        flash_ready=False,
        idempotent_replay=replay,
    )


def create_app(
    settings: GatewaySettings | None = None,
    *,
    verifier: EvidenceVerifier | None = None,
) -> FastAPI:
    settings = settings or GatewaySettings.from_env()
    verifier = verifier or RejectingEvidenceVerifier()
    store = GatewayStore(settings.database_path, busy_timeout_ms=settings.sqlite_busy_timeout_ms)
    store.initialize()
    recovered = store.recover_incomplete_tasks()
    if recovered:
        audit("startup_recovery", status=TaskStatus.FAILED.value)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        yield
        application.state.validation_executor.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="OpenWrt Smart Upgrade Build Gateway",
        version="0.1.0-t14a",
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.state.settings = settings
    app.state.store = store
    app.state.verifier = verifier
    app.state.validation_executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=settings.validation_workers,
        thread_name_prefix="gateway-evidence",
    )
    validation_slots = asyncio.Semaphore(settings.validation_workers)

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

    def apply_rate_limit(identity: DeviceIdentity, endpoint: str) -> None:
        store.consume_rate_limit(
            identity.device_id,
            endpoint,
            limit=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
        )

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
        return _response(task, replay=not created)

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
        audit(
            "build_query",
            request_id=task.request_id,
            internal_task_id=task.internal_task_id,
            device=device_fingerprint(identity.device_id),
            status=task.status.value,
            commit=task.evidence_commit_sha[:12],
        )
        return _response(task)

    return app
