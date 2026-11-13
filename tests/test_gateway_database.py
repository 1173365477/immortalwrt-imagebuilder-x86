from __future__ import annotations

import concurrent.futures
import sqlite3
from pathlib import Path

import pytest

from gateway.database import GatewayStore
from gateway.errors import ErrorCode, GatewayError
from gateway.models import BuildRequest
from gateway.state import TaskStatus


DIGEST = "a" * 64


def request(request_id="request-001", *, digest=DIGEST, commit="b" * 40):
    return BuildRequest(
        request_id=request_id,
        build_input_id=f"urn:sha256:{digest}",
        build_input_digest=digest,
        repository="1173365477/immortalwrt-imagebuilder-x86",
        evidence_commit_sha=commit,
    )


def store_at(path: Path, **kwargs) -> GatewayStore:
    store = GatewayStore(path, **kwargs)
    store.initialize()
    return store


def test_state_machine_allows_only_t14a_progression_and_idempotent_repeat(tmp_path):
    store = store_at(tmp_path / "gateway.db")
    task, _ = store.create_or_get_task("device", request(), ttl_seconds=100, task_quota=10, now=1)
    validating = store.transition_task(task.internal_task_id, TaskStatus.VALIDATING, now=2)
    repeated = store.transition_task(task.internal_task_id, TaskStatus.VALIDATING, now=3)
    assert repeated.version == validating.version
    assert store.transition_count(task.internal_task_id) == 2
    final = store.transition_task(task.internal_task_id, TaskStatus.VALIDATED, now=4)
    assert final.status == TaskStatus.VALIDATED
    with pytest.raises(GatewayError, match="INTERNAL_ERROR"):
        store.transition_task(task.internal_task_id, TaskStatus.RUNNING, now=5)
    with pytest.raises(GatewayError, match="INTERNAL_ERROR"):
        store.transition_task(task.internal_task_id, TaskStatus.FAILED, now=5)


def test_concurrent_terminal_transitions_cannot_overwrite_each_other(tmp_path):
    store = store_at(tmp_path / "gateway.db")
    task, _ = store.create_or_get_task("device", request(), ttl_seconds=100, task_quota=10)
    store.transition_task(task.internal_task_id, TaskStatus.VALIDATING)

    def transition(target):
        try:
            return store.transition_task(task.internal_task_id, target).status.value
        except GatewayError as exc:
            return exc.code.value

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(transition, [TaskStatus.VALIDATED, TaskStatus.BLOCKED]))
    assert sum(value in {"VALIDATED", "BLOCKED"} for value in results) == 1
    assert "INTERNAL_ERROR" in results
    persisted = store.get_task("device", "request-001")
    assert persisted.status.value in {"VALIDATED", "BLOCKED"}


def test_restart_preserves_idempotency_and_task_identity(tmp_path):
    path = tmp_path / "gateway.db"
    first = store_at(path)
    task, created = first.create_or_get_task("device", request(), ttl_seconds=100, task_quota=10, now=1)
    assert created
    first.transition_task(task.internal_task_id, TaskStatus.VALIDATING, now=2)
    first.transition_task(task.internal_task_id, TaskStatus.VALIDATED, now=3)

    restarted = store_at(path)
    replay, created = restarted.create_or_get_task(
        "device", request(), ttl_seconds=100, task_quota=10, now=4
    )
    assert created is False
    assert replay.internal_task_id == task.internal_task_id
    assert replay.status == TaskStatus.VALIDATED
    assert restarted.task_count() == 1


def test_restart_fails_incomplete_validation_closed(tmp_path):
    path = tmp_path / "gateway.db"
    first = store_at(path)
    task, _ = first.create_or_get_task("device", request(), ttl_seconds=100, task_quota=10, now=1)
    first.transition_task(task.internal_task_id, TaskStatus.VALIDATING, now=2)

    restarted = store_at(path)
    assert restarted.recover_incomplete_tasks(now=3) == 1
    recovered = restarted.get_task("device", "request-001", now=4)
    assert recovered.status == TaskStatus.FAILED
    assert recovered.failure_code == "INTERNAL_ERROR"
    assert restarted.task_count() == 1


def test_database_trigger_failure_rolls_back_without_partial_task(tmp_path):
    store = store_at(tmp_path / "gateway.db")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """CREATE TRIGGER reject_tasks BEFORE INSERT ON build_tasks
               BEGIN SELECT RAISE(ABORT, 'forced failure'); END"""
        )
    with pytest.raises(GatewayError) as raised:
        store.create_or_get_task("device", request(), ttl_seconds=100, task_quota=10)
    assert raised.value.code == ErrorCode.STORAGE_UNAVAILABLE
    assert store.task_count() == 0
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM task_transitions").fetchone()[0] == 0


def test_corrupt_database_fails_closed(tmp_path):
    path = tmp_path / "gateway.db"
    path.write_bytes(b"not a sqlite database")
    with pytest.raises(GatewayError) as raised:
        store_at(path)
    assert raised.value.code == ErrorCode.STORAGE_UNAVAILABLE


def test_unwritable_database_location_fails_closed(tmp_path):
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("x")
    with pytest.raises(GatewayError) as raised:
        store_at(parent_file / "gateway.db")
    assert raised.value.code == ErrorCode.STORAGE_UNAVAILABLE


def test_persistent_rate_limit_survives_store_recreation(tmp_path):
    path = tmp_path / "gateway.db"
    store = store_at(path)
    store.consume_rate_limit("device", "POST:/builds", limit=1, window_seconds=60, now=1)
    restarted = store_at(path)
    with pytest.raises(GatewayError) as raised:
        restarted.consume_rate_limit("device", "POST:/builds", limit=1, window_seconds=60, now=2)
    assert raised.value.code == ErrorCode.RATE_LIMITED


def test_credentials_are_device_scoped_rotatable_and_stored_as_hashes(tmp_path):
    store = store_at(tmp_path / "gateway.db")
    old = store.issue_credential("router-a", ttl_seconds=100, now=1)
    new = store.issue_credential("router-a", ttl_seconds=100, now=1)
    assert store.authenticate(old, now=2).device_id == "router-a"
    assert store.authenticate(new, now=2).device_id == "router-a"
    store.revoke_credential(old.split(".", 1)[0], now=3)
    with pytest.raises(GatewayError):
        store.authenticate(old, now=4)
    assert store.authenticate(new, now=4).device_id == "router-a"

    raw = store.path.read_bytes() + (store.path.parent / f"{store.path.name}-wal").read_bytes()
    assert old.encode() not in raw
    assert new.encode() not in raw


def test_lost_device_recovery_revokes_all_credentials(tmp_path):
    store = store_at(tmp_path / "gateway.db")
    first = store.issue_credential("router-a", ttl_seconds=100, now=1)
    second = store.issue_credential("router-a", ttl_seconds=100, now=1)
    other = store.issue_credential("router-b", ttl_seconds=100, now=1)
    assert store.revoke_device_credentials("router-a", now=2) == 2
    for token in (first, second):
        with pytest.raises(GatewayError):
            store.authenticate(token, now=3)
    assert store.authenticate(other, now=3).device_id == "router-b"
