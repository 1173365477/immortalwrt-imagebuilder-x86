"""Server-owned build task state machine."""

from __future__ import annotations

from enum import StrEnum

from .errors import ErrorCode, GatewayError


class TaskStatus(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    DISPATCH_PENDING = "DISPATCH_PENDING"
    DISPATCHING = "DISPATCHING"
    DISPATCH_UNKNOWN = "DISPATCH_UNKNOWN"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    VERIFYING_ARTIFACT = "VERIFYING_ARTIFACT"
    SUCCEEDED = "SUCCEEDED"
    BUILD_FAILED = "BUILD_FAILED"
    ARTIFACT_FAILED = "ARTIFACT_FAILED"


T14A_TRANSITIONS = {
    TaskStatus.RECEIVED: {TaskStatus.VALIDATING, TaskStatus.BLOCKED, TaskStatus.FAILED},
    TaskStatus.VALIDATING: {TaskStatus.VALIDATED, TaskStatus.BLOCKED, TaskStatus.FAILED},
    TaskStatus.VALIDATED: set(),
    TaskStatus.BLOCKED: set(),
    TaskStatus.FAILED: set(),
}


def ensure_t14a_transition(current: TaskStatus, target: TaskStatus) -> bool:
    """Return False for an idempotent no-op, otherwise validate the transition."""
    if current == target:
        return False
    if target not in T14A_TRANSITIONS.get(current, set()):
        raise GatewayError(
            ErrorCode.INTERNAL_ERROR,
            500,
            internal_detail=f"illegal state transition {current.value}->{target.value}",
        )
    return True


T14B_TRANSITIONS = {
    **T14A_TRANSITIONS,
    TaskStatus.VALIDATED: {TaskStatus.DISPATCH_PENDING, TaskStatus.BLOCKED, TaskStatus.FAILED},
    TaskStatus.DISPATCH_PENDING: {TaskStatus.DISPATCHING, TaskStatus.DISPATCH_UNKNOWN, TaskStatus.FAILED},
    TaskStatus.DISPATCHING: {TaskStatus.QUEUED, TaskStatus.DISPATCH_UNKNOWN, TaskStatus.FAILED},
    TaskStatus.DISPATCH_UNKNOWN: {TaskStatus.QUEUED, TaskStatus.FAILED},
    TaskStatus.QUEUED: {TaskStatus.RUNNING, TaskStatus.BUILD_FAILED, TaskStatus.FAILED},
    TaskStatus.RUNNING: {
        TaskStatus.VERIFYING_ARTIFACT, TaskStatus.BUILD_FAILED, TaskStatus.FAILED,
    },
    TaskStatus.VERIFYING_ARTIFACT: {TaskStatus.SUCCEEDED, TaskStatus.ARTIFACT_FAILED},
    TaskStatus.SUCCEEDED: set(),
    TaskStatus.BUILD_FAILED: set(),
    TaskStatus.ARTIFACT_FAILED: set(),
}


def ensure_t14b_transition(current: TaskStatus, target: TaskStatus) -> bool:
    if current == target:
        return False
    if target not in T14B_TRANSITIONS.get(current, set()):
        raise GatewayError(
            ErrorCode.INTERNAL_ERROR, 500,
            internal_detail=f"illegal T14-B transition {current.value}->{target.value}",
        )
    return True
