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
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
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
