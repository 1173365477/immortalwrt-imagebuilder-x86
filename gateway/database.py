"""SQLite persistence, authentication, idempotency, quotas, and state transitions."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .errors import ErrorCode, GatewayError
from .models import BuildRequest
from .state import TaskStatus, ensure_t14a_transition


SCHEMA_VERSION = 1
SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    credential_id: str


@dataclass(frozen=True)
class TaskRecord:
    internal_task_id: str
    device_id: str
    request_id: str
    build_input_id: str
    build_input_digest: str
    repository: str
    evidence_commit_sha: str
    status: TaskStatus
    created_at: int
    updated_at: int
    expires_at: int
    failure_code: str | None
    failure_detail: str | None
    github_run_id: int | None
    github_run_attempt: int | None
    version: int

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "TaskRecord":
        values = dict(row)
        values["status"] = TaskStatus(values["status"])
        return cls(**values)


class GatewayStore:
    def __init__(self, path: Path, *, busy_timeout_ms: int = 1_000):
        self.path = path.resolve()
        self.busy_timeout_ms = busy_timeout_ms

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
        return connection

    @staticmethod
    def _storage_error(exc: BaseException) -> GatewayError:
        return GatewayError(ErrorCode.STORAGE_UNAVAILABLE, 503, internal_detail=type(exc).__name__)

    def initialize(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS gateway_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS device_credentials (
                        credential_id TEXT PRIMARY KEY,
                        device_id TEXT NOT NULL,
                        token_salt BLOB NOT NULL,
                        token_hash BLOB NOT NULL,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        revoked_at INTEGER
                    );
                    CREATE INDEX IF NOT EXISTS credentials_device_idx
                        ON device_credentials(device_id);
                    CREATE TABLE IF NOT EXISTS build_tasks (
                        internal_task_id TEXT PRIMARY KEY,
                        device_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        build_input_id TEXT NOT NULL,
                        build_input_digest TEXT NOT NULL,
                        repository TEXT NOT NULL,
                        evidence_commit_sha TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        failure_code TEXT,
                        failure_detail TEXT,
                        github_run_id INTEGER,
                        github_run_attempt INTEGER,
                        version INTEGER NOT NULL DEFAULT 0,
                        UNIQUE(device_id, request_id)
                    );
                    CREATE INDEX IF NOT EXISTS tasks_device_status_idx
                        ON build_tasks(device_id, status, expires_at);
                    CREATE TABLE IF NOT EXISTS task_transitions (
                        transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        internal_task_id TEXT NOT NULL REFERENCES build_tasks(internal_task_id),
                        from_status TEXT,
                        to_status TEXT NOT NULL,
                        changed_at INTEGER NOT NULL,
                        failure_code TEXT
                    );
                    CREATE TABLE IF NOT EXISTS rate_limits (
                        device_id TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        window_start INTEGER NOT NULL,
                        count INTEGER NOT NULL,
                        PRIMARY KEY(device_id, endpoint, window_start)
                    );
                    INSERT INTO gateway_meta(key, value) VALUES('schema_version', '1')
                        ON CONFLICT(key) DO NOTHING;
                    COMMIT;
                    """
                )
                version = connection.execute(
                    "SELECT value FROM gateway_meta WHERE key='schema_version'"
                ).fetchone()
                if version is None or int(version["value"]) != SCHEMA_VERSION:
                    raise sqlite3.DatabaseError("unsupported schema version")
                integrity = connection.execute("PRAGMA quick_check").fetchone()
                if integrity is None or integrity[0] != "ok":
                    raise sqlite3.DatabaseError("database integrity check failed")
            os.chmod(self.path, 0o600)
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise self._storage_error(exc) from exc

    @staticmethod
    def _token_hash(secret: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            secret.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
        )

    def issue_credential(self, device_id: str, *, ttl_seconds: int, now: int | None = None) -> str:
        if not device_id or len(device_id) > 128 or ttl_seconds <= 0:
            raise ValueError("invalid device credential parameters")
        timestamp = int(time.time() if now is None else now)
        credential_id = secrets.token_hex(16)
        secret = secrets.token_urlsafe(32)
        salt = secrets.token_bytes(16)
        token_hash = self._token_hash(secret, salt)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO device_credentials
                       (credential_id, device_id, token_salt, token_hash, created_at, expires_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (credential_id, device_id, salt, token_hash, timestamp, timestamp + ttl_seconds),
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc
        return f"{credential_id}.{secret}"

    def revoke_credential(self, credential_id: str, *, now: int | None = None) -> None:
        timestamp = int(time.time() if now is None else now)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                changed = connection.execute(
                    "UPDATE device_credentials SET revoked_at=? WHERE credential_id=? AND revoked_at IS NULL",
                    (timestamp, credential_id),
                ).rowcount
                if changed != 1:
                    connection.rollback()
                    raise GatewayError(ErrorCode.AUTH_INVALID, 401)
                connection.commit()
        except GatewayError:
            raise
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc

    def revoke_device_credentials(self, device_id: str, *, now: int | None = None) -> int:
        timestamp = int(time.time() if now is None else now)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                changed = connection.execute(
                    """UPDATE device_credentials SET revoked_at=?
                       WHERE device_id=? AND revoked_at IS NULL""",
                    (timestamp, device_id),
                ).rowcount
                connection.commit()
                return changed
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc

    def authenticate(self, token: str, *, now: int | None = None) -> DeviceIdentity:
        timestamp = int(time.time() if now is None else now)
        try:
            credential_id, secret = token.split(".", 1)
        except ValueError as exc:
            raise GatewayError(ErrorCode.AUTH_INVALID, 401) from exc
        if len(credential_id) != 32 or not secret or len(secret) > 128:
            raise GatewayError(ErrorCode.AUTH_INVALID, 401)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """SELECT credential_id, device_id, token_salt, token_hash, expires_at, revoked_at
                       FROM device_credentials WHERE credential_id=?""",
                    (credential_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc
        if row is None:
            # Equalize the expensive part of unknown and known credential checks.
            self._token_hash(secret, b"\0" * 16)
            raise GatewayError(ErrorCode.AUTH_INVALID, 401)
        actual = self._token_hash(secret, row["token_salt"])
        if not hmac.compare_digest(actual, row["token_hash"]) or row["revoked_at"] is not None:
            raise GatewayError(ErrorCode.AUTH_INVALID, 401)
        if timestamp >= row["expires_at"]:
            raise GatewayError(ErrorCode.AUTH_EXPIRED, 401)
        return DeviceIdentity(row["device_id"], row["credential_id"])

    def consume_rate_limit(
        self, device_id: str, endpoint: str, *, limit: int, window_seconds: int, now: int | None = None
    ) -> None:
        timestamp = int(time.time() if now is None else now)
        window_start = timestamp - (timestamp % window_seconds)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO rate_limits(device_id, endpoint, window_start, count)
                       VALUES (?, ?, ?, 1)
                       ON CONFLICT(device_id, endpoint, window_start)
                       DO UPDATE SET count=count+1""",
                    (device_id, endpoint, window_start),
                )
                count = connection.execute(
                    """SELECT count FROM rate_limits
                       WHERE device_id=? AND endpoint=? AND window_start=?""",
                    (device_id, endpoint, window_start),
                ).fetchone()["count"]
                connection.execute(
                    "DELETE FROM rate_limits WHERE window_start < ?", (window_start - window_seconds,)
                )
                if count > limit:
                    connection.rollback()
                    raise GatewayError(ErrorCode.RATE_LIMITED, 429)
                connection.commit()
        except GatewayError:
            raise
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc

    @staticmethod
    def _same_identity(task: TaskRecord, request: BuildRequest) -> bool:
        return (
            task.build_input_id,
            task.build_input_digest,
            task.repository,
            task.evidence_commit_sha,
        ) == (
            request.build_input_id,
            request.build_input_digest,
            request.repository,
            request.evidence_commit_sha,
        )

    def create_or_get_task(
        self,
        device_id: str,
        request: BuildRequest,
        *,
        ttl_seconds: int,
        task_quota: int,
        now: int | None = None,
    ) -> tuple[TaskRecord, bool]:
        timestamp = int(time.time() if now is None else now)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM build_tasks WHERE device_id=? AND request_id=?",
                    (device_id, request.request_id),
                ).fetchone()
                if row is not None:
                    task = TaskRecord.from_row(row)
                    if not self._same_identity(task, request):
                        connection.rollback()
                        raise GatewayError(ErrorCode.IDEMPOTENCY_CONFLICT, 409)
                    if timestamp >= task.expires_at:
                        connection.rollback()
                        raise GatewayError(ErrorCode.REQUEST_EXPIRED, 410)
                    connection.commit()
                    return task, False
                active = connection.execute(
                    "SELECT COUNT(*) AS count FROM build_tasks WHERE device_id=? AND expires_at>?",
                    (device_id, timestamp),
                ).fetchone()["count"]
                if active >= task_quota:
                    connection.rollback()
                    raise GatewayError(ErrorCode.RATE_LIMITED, 429, internal_detail="task quota exceeded")
                task_id = str(uuid.uuid4())
                expires_at = timestamp + ttl_seconds
                connection.execute(
                    """INSERT INTO build_tasks
                       (internal_task_id, device_id, request_id, build_input_id,
                        build_input_digest, repository, evidence_commit_sha, status,
                        created_at, updated_at, expires_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        task_id, device_id, request.request_id, request.build_input_id,
                        request.build_input_digest, request.repository, request.evidence_commit_sha,
                        TaskStatus.RECEIVED.value, timestamp, timestamp, expires_at,
                    ),
                )
                connection.execute(
                    """INSERT INTO task_transitions
                       (internal_task_id, from_status, to_status, changed_at)
                       VALUES (?, NULL, ?, ?)""",
                    (task_id, TaskStatus.RECEIVED.value, timestamp),
                )
                row = connection.execute(
                    "SELECT * FROM build_tasks WHERE internal_task_id=?", (task_id,)
                ).fetchone()
                connection.commit()
                return TaskRecord.from_row(row), True
        except GatewayError:
            raise
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc

    def get_task(self, device_id: str, request_id: str, *, now: int | None = None) -> TaskRecord:
        timestamp = int(time.time() if now is None else now)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM build_tasks WHERE device_id=? AND request_id=?",
                    (device_id, request_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc
        if row is None:
            raise GatewayError(ErrorCode.EVIDENCE_NOT_FOUND, 404)
        task = TaskRecord.from_row(row)
        if timestamp >= task.expires_at:
            raise GatewayError(ErrorCode.REQUEST_EXPIRED, 410)
        return task

    def transition_task(
        self,
        internal_task_id: str,
        target: TaskStatus,
        *,
        failure_code: ErrorCode | None = None,
        failure_detail: str | None = None,
        now: int | None = None,
    ) -> TaskRecord:
        timestamp = int(time.time() if now is None else now)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM build_tasks WHERE internal_task_id=?", (internal_task_id,)
                ).fetchone()
                if row is None:
                    connection.rollback()
                    raise GatewayError(ErrorCode.INTERNAL_ERROR, 500, internal_detail="task missing")
                task = TaskRecord.from_row(row)
                if not ensure_t14a_transition(task.status, target):
                    connection.commit()
                    return task
                changed = connection.execute(
                    """UPDATE build_tasks
                       SET status=?, updated_at=?, failure_code=?, failure_detail=?, version=version+1
                       WHERE internal_task_id=? AND version=?""",
                    (
                        target.value, timestamp, failure_code.value if failure_code else None,
                        failure_detail, internal_task_id, task.version,
                    ),
                ).rowcount
                if changed != 1:
                    connection.rollback()
                    raise GatewayError(ErrorCode.INTERNAL_ERROR, 500, internal_detail="state compare-and-swap failed")
                connection.execute(
                    """INSERT INTO task_transitions
                       (internal_task_id, from_status, to_status, changed_at, failure_code)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        internal_task_id, task.status.value, target.value, timestamp,
                        failure_code.value if failure_code else None,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM build_tasks WHERE internal_task_id=?", (internal_task_id,)
                ).fetchone()
                connection.commit()
                return TaskRecord.from_row(row)
        except GatewayError:
            raise
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc

    def recover_incomplete_tasks(self, *, now: int | None = None) -> int:
        """Fail closed after a restart; T14-B will add external reconciliation."""
        timestamp = int(time.time() if now is None else now)
        recovered = 0
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT internal_task_id, status FROM build_tasks WHERE status IN (?, ?)",
                    (TaskStatus.RECEIVED.value, TaskStatus.VALIDATING.value),
                ).fetchall()
                for row in rows:
                    connection.execute(
                        """UPDATE build_tasks SET status=?, updated_at=?, failure_code=?,
                           failure_detail=?, version=version+1 WHERE internal_task_id=?""",
                        (
                            TaskStatus.FAILED.value, timestamp, ErrorCode.INTERNAL_ERROR.value,
                            "gateway restarted before evidence validation completed", row["internal_task_id"],
                        ),
                    )
                    connection.execute(
                        """INSERT INTO task_transitions
                           (internal_task_id, from_status, to_status, changed_at, failure_code)
                           VALUES (?, ?, ?, ?, ?)""",
                        (
                            row["internal_task_id"], row["status"], TaskStatus.FAILED.value,
                            timestamp, ErrorCode.INTERNAL_ERROR.value,
                        ),
                    )
                    recovered += 1
                connection.commit()
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc
        return recovered

    def task_count(self, device_id: str | None = None) -> int:
        try:
            with self._connect() as connection:
                if device_id is None:
                    return int(connection.execute("SELECT COUNT(*) FROM build_tasks").fetchone()[0])
                return int(
                    connection.execute(
                        "SELECT COUNT(*) FROM build_tasks WHERE device_id=?", (device_id,)
                    ).fetchone()[0]
                )
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc

    def transition_count(self, internal_task_id: str) -> int:
        try:
            with self._connect() as connection:
                return int(
                    connection.execute(
                        "SELECT COUNT(*) FROM task_transitions WHERE internal_task_id=?",
                        (internal_task_id,),
                    ).fetchone()[0]
                )
        except sqlite3.Error as exc:
            raise self._storage_error(exc) from exc
