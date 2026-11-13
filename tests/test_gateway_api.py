from __future__ import annotations

import concurrent.futures
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gateway.app import GatewaySettings, create_app
from gateway.database import GatewayStore
from gateway.errors import ErrorCode
from gateway.evidence import EvidenceVerdict


REPOSITORY = "1173365477/immortalwrt-imagebuilder-x86"
DIGEST = "a" * 64
COMMIT = "b" * 40


@dataclass
class StaticVerifier:
    trusted: bool = True
    delay: float = 0
    failure_code: ErrorCode = ErrorCode.EVIDENCE_UNVERIFIED

    def verify(self, request):
        del request
        if self.delay:
            time.sleep(self.delay)
        return EvidenceVerdict(self.trusted, self.failure_code, "controlled test verdict")


class ExplodingVerifier:
    def __init__(self, secret: str):
        self.secret = secret

    def verify(self, request):
        del request
        raise RuntimeError(self.secret)


class BlockingVerifier:
    def __init__(self):
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.calls = 0

    def verify(self, request):
        del request
        with self.lock:
            self.calls += 1
        self.release.wait(timeout=2)
        return EvidenceVerdict(True)


def payload(request_id: str = "request-001", **changes):
    value = {
        "request_id": request_id,
        "build_input_id": f"urn:sha256:{DIGEST}",
        "build_input_digest": DIGEST,
        "repository": REPOSITORY,
        "evidence_commit_sha": COMMIT,
    }
    value.update(changes)
    return value


def gateway(tmp_path: Path, *, verifier=None, **settings_changes):
    values = {
        "database_path": tmp_path / "gateway.db",
        "trusted_repository": REPOSITORY,
        "require_https": True,
        "rate_limit_requests": 100,
        "rate_limit_window_seconds": 60,
        "task_quota": 100,
        "validation_timeout_seconds": 1,
        "sqlite_busy_timeout_ms": 100,
    }
    values.update(settings_changes)
    app = create_app(GatewaySettings(**values), verifier=verifier or StaticVerifier())
    store: GatewayStore = app.state.store
    token_a = store.issue_credential("router-a", ttl_seconds=3600)
    token_b = store.issue_credential("router-b", ttl_seconds=3600)
    client = TestClient(app, base_url="https://gateway.test", raise_server_exceptions=False)
    return app, store, client, token_a, token_b


def auth(token: str):
    return {"Authorization": f"Bearer {token}"}


def error_code(response):
    return response.json()["error"]["code"]


def test_anonymous_invalid_expired_and_revoked_credentials_are_rejected(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    assert error_code(client.post("/builds", json=payload())) == "AUTH_REQUIRED"
    assert error_code(client.post("/builds", json=payload(), headers=auth("bad.token"))) == "AUTH_INVALID"

    expired = store.issue_credential("expired", ttl_seconds=1, now=1)
    assert error_code(client.post("/builds", json=payload(), headers=auth(expired))) == "AUTH_EXPIRED"

    credential_id = token.split(".", 1)[0]
    store.revoke_credential(credential_id)
    assert error_code(client.post("/builds", json=payload(), headers=auth(token))) == "AUTH_INVALID"


def test_https_is_required_and_forwarded_headers_are_not_trusted(tmp_path):
    app, _, _, token, _ = gateway(tmp_path)
    plain = TestClient(app, base_url="http://gateway.test", raise_server_exceptions=False)
    result = plain.post(
        "/builds", json=payload(), headers=auth(token) | {"X-Forwarded-Proto": "https"}
    )
    assert result.status_code == 403
    assert error_code(result) == "TLS_REQUIRED"


def test_authenticated_build_is_persisted_but_never_dispatchable_or_flash_ready(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    created = client.post("/builds", json=payload(), headers=auth(token))
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "VALIDATED"
    assert body["evidence_verified"] is True
    assert body["dispatch_allowed"] is False
    assert body["flash_ready"] is False
    assert store.task_count("router-a") == 1

    fetched = client.get("/builds/request-001", headers=auth(token))
    assert fetched.status_code == 200
    assert fetched.json()["internal_task_id"] == body["internal_task_id"]


def test_default_or_negative_verifier_blocks_build_authority(tmp_path):
    settings = GatewaySettings(
        database_path=tmp_path / "default.db", trusted_repository=REPOSITORY,
        require_https=False, rate_limit_requests=100,
    )
    app = create_app(settings)
    token = app.state.store.issue_credential("router-a", ttl_seconds=3600)
    with TestClient(app, raise_server_exceptions=False) as client:
        result = client.post("/builds", json=payload(), headers=auth(token))
    assert result.status_code == 201
    assert result.json()["status"] == "BLOCKED"
    assert result.json()["failure_code"] == "EVIDENCE_UNVERIFIED"
    assert result.json()["dispatch_allowed"] is False


def test_exact_replay_returns_existing_task(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    first = client.post("/builds", json=payload(), headers=auth(token))
    second = client.post("/builds", json=payload(), headers=auth(token))
    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["idempotent_replay"] is True
    assert first.json()["internal_task_id"] == second.json()["internal_task_id"]
    assert store.task_count() == 1


def test_service_restart_preserves_http_idempotency(tmp_path):
    app, _, client, token, _ = gateway(tmp_path)
    first = client.post("/builds", json=payload(), headers=auth(token))
    restarted = create_app(app.state.settings, verifier=StaticVerifier())
    with TestClient(restarted, base_url="https://gateway.test", raise_server_exceptions=False) as next_client:
        replay = next_client.post("/builds", json=payload(), headers=auth(token))
    assert replay.status_code == 200
    assert replay.json()["internal_task_id"] == first.json()["internal_task_id"]
    assert replay.json()["idempotent_replay"] is True


@pytest.mark.parametrize("change", [
    {"build_input_digest": "c" * 64, "build_input_id": f"urn:sha256:{'c' * 64}"},
    {"evidence_commit_sha": "d" * 40},
    {"build_input_digest": "e" * 64, "build_input_id": f"urn:sha256:{'e' * 64}"},
])
def test_same_request_id_with_changed_identity_is_conflict(tmp_path, change):
    _, store, client, token, _ = gateway(tmp_path)
    assert client.post("/builds", json=payload(), headers=auth(token)).status_code == 201
    conflict = client.post("/builds", json=payload(**change), headers=auth(token))
    assert conflict.status_code == 409
    assert error_code(conflict) == "IDEMPOTENCY_CONFLICT"
    assert store.task_count() == 1


def test_same_request_id_is_independent_for_different_devices(tmp_path):
    _, store, client, token_a, token_b = gateway(tmp_path)
    a = client.post("/builds", json=payload(), headers=auth(token_a))
    b = client.post("/builds", json=payload(), headers=auth(token_b))
    assert a.status_code == b.status_code == 201
    assert a.json()["internal_task_id"] != b.json()["internal_task_id"]
    assert store.task_count() == 2


def test_ten_concurrent_identical_requests_create_one_task(tmp_path):
    app, store, _, token, _ = gateway(tmp_path, verifier=StaticVerifier(delay=0.15))

    def submit(_):
        with TestClient(app, base_url="https://gateway.test", raise_server_exceptions=False) as client:
            return client.post("/builds", json=payload(), headers=auth(token))

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(submit, range(10)))
    assert {result.status_code for result in results} <= {200, 201}
    assert len({result.json()["internal_task_id"] for result in results}) == 1
    assert store.task_count() == 1
    task = store.get_task("router-a", "request-001")
    assert task.status.value == "VALIDATED"


def test_cross_device_read_is_not_enumerable(tmp_path):
    _, _, client, token_a, token_b = gateway(tmp_path)
    client.post("/builds", json=payload(), headers=auth(token_a))
    denied = client.get("/builds/request-001", headers=auth(token_b))
    assert denied.status_code == 404
    assert error_code(denied) == "EVIDENCE_NOT_FOUND"


def test_client_cannot_claim_device_or_state_or_supply_url_path_or_packages(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    for extra in (
        {"device_id": "router-b"},
        {"status": "SUCCEEDED"},
        {"url": "https://evil.invalid/payload"},
        {"path": "../../etc/shadow"},
        {"packages": ["untrusted"]},
        {"github_token": "secret"},
    ):
        result = client.post("/builds", json=payload(**extra), headers=auth(token))
        assert result.status_code == 422
        assert error_code(result) == "INVALID_REQUEST"
    assert store.task_count() == 0


def test_credentials_in_query_and_client_status_updates_are_not_accepted(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    query_auth = client.post(f"/builds?authorization=Bearer%20{token}", json=payload())
    assert query_auth.status_code == 401
    assert error_code(query_auth) == "AUTH_REQUIRED"
    created = client.post("/builds", json=payload(), headers=auth(token))
    task_id = created.json()["internal_task_id"]
    update = client.patch(
        "/builds/request-001", json={"status": "SUCCEEDED"}, headers=auth(token)
    )
    assert update.status_code == 405
    assert error_code(update) == "INVALID_REQUEST"
    assert store.get_task("router-a", "request-001").internal_task_id == task_id
    assert store.get_task("router-a", "request-001").status.value == "VALIDATED"


@pytest.mark.parametrize("commit", ["main", "b" * 39, "B" * 40, "b" * 41, "../" + "b" * 37])
def test_mutable_or_malformed_commit_is_rejected(tmp_path, commit):
    _, store, client, token, _ = gateway(tmp_path)
    result = client.post(
        "/builds", json=payload(evidence_commit_sha=commit), headers=auth(token)
    )
    assert result.status_code == 422
    assert error_code(result) == "INVALID_COMMIT"
    assert store.task_count() == 0


def test_arbitrary_repository_is_rejected(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    result = client.post(
        "/builds", json=payload(repository="attacker/firmware"), headers=auth(token)
    )
    assert result.status_code == 400
    assert error_code(result) == "INVALID_REPOSITORY"
    assert store.task_count() == 0


def test_build_input_id_must_bind_digest(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    result = client.post(
        "/builds", json=payload(build_input_id=f"urn:sha256:{'c' * 64}"), headers=auth(token)
    )
    assert result.status_code == 422
    assert store.task_count() == 0


def test_request_body_limit_is_enforced_before_validation(tmp_path):
    _, store, client, token, _ = gateway(tmp_path, max_body_bytes=256)
    result = client.post("/builds", content=b"{" + b"x" * 300, headers=auth(token))
    assert result.status_code == 413
    assert error_code(result) == "REQUEST_TOO_LARGE"
    assert store.task_count() == 0


def test_malformed_json_has_stable_non_sensitive_error(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    result = client.post(
        "/builds", content=b'{"request_id":',
        headers=auth(token) | {"Content-Type": "application/json"},
    )
    assert result.status_code == 422
    assert result.json() == {
        "error": {"code": "INVALID_REQUEST", "message": "The request is invalid."}
    }
    assert store.task_count() == 0


def test_persistent_per_device_rate_limit_and_quota(tmp_path):
    app, store, client, token, _ = gateway(
        tmp_path, rate_limit_requests=2, rate_limit_window_seconds=3600, task_quota=1
    )
    assert client.get("/builds/missing", headers=auth(token)).status_code == 404
    assert client.get("/builds/missing", headers=auth(token)).status_code == 404
    limited = client.get("/builds/missing", headers=auth(token))
    assert limited.status_code == 429
    assert error_code(limited) == "RATE_LIMITED"

    # A fresh device demonstrates the separate persistent task quota.
    quota_token = store.issue_credential("quota-device", ttl_seconds=3600)
    assert client.post("/builds", json=payload("one"), headers=auth(quota_token)).status_code == 201
    quota = client.post("/builds", json=payload("two"), headers=auth(quota_token))
    assert quota.status_code == 429
    assert error_code(quota) == "RATE_LIMITED"

    # Recreating the app does not reset the stored counter.
    restarted = create_app(app.state.settings, verifier=StaticVerifier())
    with TestClient(restarted, base_url="https://gateway.test", raise_server_exceptions=False) as next_client:
        again = next_client.get("/builds/missing", headers=auth(token))
    assert again.status_code == 429


def test_validation_timeout_fails_closed(tmp_path):
    _, _, client, token, _ = gateway(
        tmp_path, verifier=StaticVerifier(delay=0.2), validation_timeout_seconds=0.01
    )
    result = client.post("/builds", json=payload(), headers=auth(token))
    assert result.status_code == 201
    assert result.json()["status"] == "FAILED"
    assert result.json()["failure_code"] == "EVIDENCE_UNVERIFIED"
    assert result.json()["dispatch_allowed"] is False


def test_timed_out_workers_continue_but_validation_queue_is_bounded(tmp_path):
    verifier = BlockingVerifier()
    _, _, client, token, _ = gateway(
        tmp_path, verifier=verifier, validation_timeout_seconds=0.02,
        validation_workers=2,
    )
    try:
        first = client.post("/builds", json=payload("one"), headers=auth(token))
        second = client.post("/builds", json=payload("two"), headers=auth(token))
        third = client.post("/builds", json=payload("three"), headers=auth(token))
        assert [first.json()["status"], second.json()["status"], third.json()["status"]] == [
            "FAILED", "FAILED", "FAILED"
        ]
        # wait_for cannot cancel the two running threads. Their slots remain held,
        # so the third request times out before it can submit another worker.
        assert verifier.calls == 2
    finally:
        verifier.release.set()


def test_expired_task_identifier_remains_reserved(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    result = client.post("/builds", json=payload(), headers=auth(token))
    task_id = result.json()["internal_task_id"]
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE build_tasks SET expires_at=0 WHERE internal_task_id=?", (task_id,))
    expired = client.post("/builds", json=payload(), headers=auth(token))
    assert expired.status_code == 410
    assert error_code(expired) == "REQUEST_EXPIRED"
    assert store.task_count() == 1


def test_secrets_do_not_appear_in_logs_responses_or_task_rows(tmp_path, caplog):
    secret = "CANARY-TOKEN-NEVER-LOG"
    app, store, client, token, _ = gateway(tmp_path, verifier=ExplodingVerifier(secret))
    caplog.set_level(logging.INFO, logger="smart_upgrade.gateway")
    result = client.post("/builds", json=payload(), headers=auth(token))
    assert result.status_code == 201
    assert result.json()["status"] == "FAILED"
    output = caplog.text + result.text
    assert token not in output
    assert secret not in output
    with sqlite3.connect(store.path) as connection:
        task_values = " ".join(str(value) for value in connection.execute(
            "SELECT request_id, failure_code, failure_detail FROM build_tasks"
        ).fetchone())
    assert token not in task_values
    assert secret not in task_values
    assert app.state.settings.trusted_repository == REPOSITORY


def test_database_lock_is_fail_closed(tmp_path):
    _, store, client, token, _ = gateway(tmp_path, sqlite_busy_timeout_ms=25)
    lock = sqlite3.connect(store.path, isolation_level=None)
    lock.execute("BEGIN IMMEDIATE")
    try:
        result = client.post("/builds", json=payload(), headers=auth(token))
    finally:
        lock.rollback()
        lock.close()
    assert result.status_code == 503
    assert error_code(result) == "STORAGE_UNAVAILABLE"
    assert store.task_count() == 0


def test_database_insert_failure_is_rolled_back_through_http(tmp_path):
    _, store, client, token, _ = gateway(tmp_path)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """CREATE TRIGGER reject_http_tasks BEFORE INSERT ON build_tasks
               BEGIN SELECT RAISE(ABORT, 'forced failure'); END"""
        )
    result = client.post("/builds", json=payload(), headers=auth(token))
    assert result.status_code == 503
    assert error_code(result) == "STORAGE_UNAVAILABLE"
    assert store.task_count() == 0


def test_t14b_routes_are_not_exposed_as_fake_success(tmp_path):
    _, _, client, token, _ = gateway(tmp_path)
    for method, path in (
        ("get", "/targets"),
        ("post", "/analysis"),
        ("get", "/builds/request-001/artifacts"),
        ("get", "/builds/request-001/logs"),
    ):
        response = getattr(client, method)(path, headers=auth(token))
        assert response.status_code == 404
        assert error_code(response) == "INVALID_REQUEST"
