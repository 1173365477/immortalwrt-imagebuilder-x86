"""T14-B orchestration with durable intent before every external side effect."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, replace

from .artifacts import verify_artifact_zip
from .database import DispatchIntent, GatewayStore, TaskRecord
from .errors import ErrorCode, GatewayError
from .evidence import EvidenceVerdict
from .github import (
    GitHubAPI, GitHubAppTokenProvider, WORKFLOW_ID, sanitize_log_archive,
    read_with_backoff, select_unique_run, validate_run,
)
from .state import TaskStatus


@dataclass
class _ArtifactLockEntry:
    lock: threading.Lock
    users: int = 0


class T14BService:
    def __init__(self, store: GatewayStore, token_provider: GitHubAppTokenProvider,
                 github: GitHubAPI, *, repository: str,
                 workflow_id: str = WORKFLOW_ID, evidence_ref_prefix: str = "evidence/",
                 sleep=time.sleep, max_concurrent_reads: int = 4,
                 max_concurrent_artifacts: int = 2):
        self.store = store
        self.token_provider = token_provider
        self.github = github
        self.repository = repository
        self.workflow_id = workflow_id
        self.evidence_ref_prefix = evidence_ref_prefix
        self.sleep = sleep
        if max_concurrent_reads <= 0 or max_concurrent_artifacts <= 0:
            raise ValueError("concurrency limits must be positive")
        self._read_slots = threading.BoundedSemaphore(max_concurrent_reads)
        self._artifact_slots = threading.BoundedSemaphore(max_concurrent_artifacts)
        self._artifact_lock_guard = threading.Lock()
        self._artifact_locks: dict[str, _ArtifactLockEntry] = {}

    def _read(self, operation):
        if not self._read_slots.acquire(timeout=1.0):
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        try:
            return read_with_backoff(operation, sleep=self.sleep)
        finally:
            self._read_slots.release()

    def dispatch(self, task: TaskRecord, verdict: EvidenceVerdict) -> TaskRecord:
        if (not verdict.trusted or not verdict.trusted_code_commit_sha
                or not verdict.target_version or not verdict.snapshot_digest
                or not verdict.plan_digest):
            raise GatewayError(ErrorCode.BUILD_BLOCKED, 409)
        external_task_id = self.store.external_task_id(task.internal_task_id)
        dispatch_ref = f"{self.evidence_ref_prefix}{external_task_id}"
        intent, _ = self.store.create_dispatch_intent(
            task, trusted_code_commit_sha=verdict.trusted_code_commit_sha,
            workflow_id=self.workflow_id, dispatch_ref=dispatch_ref,
            snapshot_digest=verdict.snapshot_digest, plan_digest=verdict.plan_digest,
            target_version=verdict.target_version,
        )
        claimed = self.store.claim_dispatch(intent.dispatch_intent_id)
        if claimed is None:
            return self.store.get_task(task.device_id, task.request_id)
        return self._dispatch_claimed(task, claimed)

    def _dispatch_claimed(self, task: TaskRecord, claimed: DispatchIntent) -> TaskRecord:
        try:
            token = self.token_provider.get()
            resolved = self._read(
                lambda: self.github.resolve_ref(
                    token, self.repository, claimed.dispatch_ref
                )
            )
            if resolved != task.evidence_commit_sha:
                raise GatewayError(ErrorCode.DISPATCH_UNKNOWN, 409)
            response = self.github.dispatch(
                token, self.repository, self.workflow_id, claimed.dispatch_ref,
                {
                    "request_id": task.request_id,
                    "gateway_task_id": claimed.external_task_id,
                    "snapshot_ref": f"evidence/requests/{task.request_id}",
                    "target_version": claimed.target_version,
                    "strict_mode": True,
                    "build_input_digest": task.build_input_digest,
                    "trusted_code_commit_sha": claimed.trusted_code_commit_sha,
                },
            )
            if response.run_id is not None:
                run = self._read(
                    lambda: self.github.get_run(token, self.repository, response.run_id)
                )
                candidate = replace(
                    claimed, github_run_id=run.run_id, github_run_attempt=run.run_attempt
                )
                if run.repository != self.repository:
                    raise GatewayError(ErrorCode.RUN_IDENTITY_MISMATCH, 409)
                validate_run(run, candidate)
            else:
                candidates = self._read(
                    lambda: self.github.find_runs(
                        token, self.repository, self.workflow_id, task.evidence_commit_sha
                    )
                )
                run = select_unique_run(candidates, claimed)
                if run.repository != self.repository:
                    raise GatewayError(ErrorCode.RUN_IDENTITY_MISMATCH, 409)
            self.store.bind_dispatch_run(
                claimed.dispatch_intent_id, run.run_id, run.run_attempt
            )
            return self.store.get_task(task.device_id, task.request_id)
        except Exception as exc:
            # Once DISPATCHING, every transport/error result is externally ambiguous.
            self.store.mark_dispatch_unknown(claimed.dispatch_intent_id)
            if isinstance(exc, GatewayError):
                return self.store.get_task(task.device_id, task.request_id)
            return self.store.get_task(task.device_id, task.request_id)

    def recover_startup(self) -> dict[str, int]:
        """Reconcile durable work without ever blindly redispatching ambiguity."""
        summary = {"pending": 0, "unknown": 0, "polled": 0, "artifact": 0,
                   "expired": 0, "deferred": 0}
        for intent in self.store.list_recoverable_intents():
            try:
                task = self.store.get_task_for_recovery(intent.internal_task_id)
                if int(time.time()) >= task.expires_at:
                    # Keep the task and intent untouched for audit/manual
                    # reconciliation. In particular, never claim a pending
                    # expired intent and never redispatch it.
                    summary["expired"] += 1
                    continue
                if task.status == TaskStatus.DISPATCH_PENDING:
                    claimed = self.store.claim_dispatch(intent.dispatch_intent_id)
                    if claimed is not None:
                        self._dispatch_claimed(task, claimed)
                        summary["pending"] += 1
                elif task.status == TaskStatus.DISPATCHING:
                    task = self.store.get_task(intent.device_id, intent.request_id)
                    self.store.mark_dispatch_unknown(intent.dispatch_intent_id)
                    summary["unknown"] += 1
                elif task.status == TaskStatus.DISPATCH_UNKNOWN:
                    self.reconcile(task)
                    summary["unknown"] += 1
                elif task.status in {TaskStatus.QUEUED, TaskStatus.RUNNING}:
                    self.poll(task)
                    summary["polled"] += 1
                elif task.status == TaskStatus.VERIFYING_ARTIFACT:
                    self.verify_artifact(task)
                    summary["artifact"] += 1
            except Exception:
                # One corrupt or temporarily unavailable record must not abort
                # recovery of unrelated tasks. Preserve its durable state for
                # later manual or bounded reconciliation.
                summary["deferred"] += 1
        return summary

    def _register_artifact_lock(self, task_id: str) -> _ArtifactLockEntry:
        with self._artifact_lock_guard:
            entry = self._artifact_locks.get(task_id)
            if entry is None:
                entry = _ArtifactLockEntry(threading.Lock())
                self._artifact_locks[task_id] = entry
            entry.users += 1
            return entry

    def _unregister_artifact_lock(self, task_id: str,
                                  entry: _ArtifactLockEntry) -> None:
        with self._artifact_lock_guard:
            current = self._artifact_locks.get(task_id)
            if current is not entry or entry.users <= 0:
                raise RuntimeError("artifact lock registry invariant violated")
            entry.users -= 1
            if entry.users == 0:
                del self._artifact_locks[task_id]

    def reconcile(self, task: TaskRecord) -> TaskRecord:
        intent = self._intent(task)
        if intent.dispatch_state != "UNKNOWN":
            return task
        self.store.record_reconciliation(intent.dispatch_intent_id, increment_retry=True)
        token = self.token_provider.get()
        candidates = self._read(
            lambda: self.github.find_runs(
                token, self.repository, self.workflow_id, intent.expected_runtime_sha
            )
        )
        run = select_unique_run(candidates, intent)
        if run.repository != self.repository:
            raise GatewayError(ErrorCode.RUN_IDENTITY_MISMATCH, 409)
        self.store.bind_dispatch_run(intent.dispatch_intent_id, run.run_id, run.run_attempt)
        return self.store.get_task(task.device_id, task.request_id)

    def poll(self, task: TaskRecord) -> TaskRecord:
        intent = self._intent(task)
        if not intent.github_run_id or not intent.github_run_attempt:
            raise GatewayError(ErrorCode.DISPATCH_UNKNOWN, 409)
        self.store.record_reconciliation(intent.dispatch_intent_id)
        token = self.token_provider.get()
        run = self._read(
            lambda: self.github.get_run(token, self.repository, intent.github_run_id)
        )
        if run.repository != self.repository:
            raise GatewayError(ErrorCode.RUN_IDENTITY_MISMATCH, 409)
        validate_run(run, intent)
        if run.run_attempt != intent.github_run_attempt:
            raise GatewayError(ErrorCode.RUN_IDENTITY_MISMATCH, 409)
        if run.status in {"queued", "requested", "waiting", "pending"}:
            return task
        if run.status == "in_progress":
            if task.status == TaskStatus.QUEUED:
                return self.store.transition_task(
                    task.internal_task_id, TaskStatus.RUNNING, allow_t14b=True
                )
            return task
        if run.status != "completed":
            raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
        if run.conclusion == "success":
            current = task
            if current.status == TaskStatus.QUEUED:
                current = self.store.transition_task(
                    current.internal_task_id, TaskStatus.RUNNING, allow_t14b=True
                )
            if current.status == TaskStatus.RUNNING:
                return self.store.transition_task(
                    current.internal_task_id, TaskStatus.VERIFYING_ARTIFACT,
                    allow_t14b=True,
                )
            return current
        return self.store.transition_task(
            task.internal_task_id, TaskStatus.BUILD_FAILED,
            failure_code=ErrorCode.BUILD_BLOCKED, allow_t14b=True,
        )

    def verify_artifact(self, task: TaskRecord) -> TaskRecord:
        if task.status != TaskStatus.VERIFYING_ARTIFACT:
            raise GatewayError(ErrorCode.ARTIFACT_UNVERIFIED, 409)
        entry = self._register_artifact_lock(task.internal_task_id)
        lock_acquired = False
        slot_acquired = False
        try:
            lock_acquired = entry.lock.acquire(timeout=1.0)
            if not lock_acquired:
                raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
            slot_acquired = self._artifact_slots.acquire(timeout=1.0)
            if not slot_acquired:
                raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, 503)
            current = self.store.get_task(task.device_id, task.request_id)
            if current.status != TaskStatus.VERIFYING_ARTIFACT:
                return current
            intent = self._intent(current)
            token = self.token_provider.get()
            download = self._read(
                lambda: self.github.artifact_zip(
                    token, self.repository, int(intent.github_run_id),
                    int(intent.github_run_attempt),
                )
            )
            try:
                metadata = verify_artifact_zip(download, current, intent)
            finally:
                download.close()
            return self.store.store_verified_artifact(
                current, json.dumps(metadata, sort_keys=True, separators=(",", ":"))
            )
        except GatewayError as exc:
            if exc.code == ErrorCode.ARTIFACT_UNVERIFIED:
                self.store.transition_task(
                    task.internal_task_id, TaskStatus.ARTIFACT_FAILED,
                    failure_code=ErrorCode.ARTIFACT_UNVERIFIED, allow_t14b=True,
                )
            raise
        finally:
            if slot_acquired:
                self._artifact_slots.release()
            if lock_acquired:
                entry.lock.release()
            self._unregister_artifact_lock(task.internal_task_id, entry)

    def logs(self, task: TaskRecord) -> tuple[list[str], bool]:
        intent = self._intent(task)
        if not intent.github_run_id or not intent.github_run_attempt:
            raise GatewayError(ErrorCode.EVIDENCE_NOT_FOUND, 404)
        token = self.token_provider.get()
        run = self._read(
            lambda: self.github.get_run(token, self.repository, intent.github_run_id)
        )
        if run.repository != self.repository:
            raise GatewayError(ErrorCode.RUN_IDENTITY_MISMATCH, 409)
        validate_run(run, intent)
        raw = self._read(
            lambda: self.github.log_archive(
                token, self.repository, intent.github_run_id, intent.github_run_attempt
            )
        )
        return sanitize_log_archive(raw)

    def _intent(self, task: TaskRecord) -> DispatchIntent:
        intent = self.store.get_dispatch_intent(task.internal_task_id)
        if intent is None:
            raise GatewayError(ErrorCode.EVIDENCE_NOT_FOUND, 404)
        return intent

