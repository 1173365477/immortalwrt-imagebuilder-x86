from __future__ import annotations

import concurrent.futures
import asyncio
import hashlib
import io
import json
import os
import threading
import time
import tracemalloc
import warnings
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest
import httpx2 as httpx
from fastapi.testclient import TestClient

from gateway.app import GatewaySettings, create_app
from gateway.database import GatewayStore
from gateway.errors import ErrorCode, GatewayError
from gateway.evidence import EvidenceVerdict
from gateway.github import (
    API_VERSION, ArtifactDownload, DispatchResponse, GitHubAppTokenProvider,
    GitHubRESTClient, GitHubRateLimited, GitHubTransientError, HTTPResult,
    InstallationToken, LogLimits, WorkflowRun, sanitize_log_archive,
)
from gateway.models import BuildRequest
from gateway.service import T14BService
from gateway.state import TaskStatus


REPOSITORY = "1173365477/immortalwrt-imagebuilder-x86"
DIGEST = "a" * 64
EVIDENCE = "c" * 40
CODE = "b" * 40
WORKFLOW = ".github/workflows/build.yml"
EXTERNAL = "gw-" + "1" * 32


class Issuer:
    def __init__(self, *, permissions=None):
        self.calls = 0
        self.permissions = permissions or {
            "metadata": "read", "contents": "read", "actions": "write"
        }

    def issue(self, installation_id, repository):
        self.calls += 1
        return InstallationToken(
            f"CANARY-INSTALLATION-TOKEN-{self.calls}", int(time.time()) + 3600,
            installation_id, repository, self.permissions,
        )


class MockGitHub:
    def __init__(self):
        self.ref_sha = EVIDENCE
        self.dispatch_calls = 0
        self.response = DispatchResponse(101)
        self.raise_after_dispatch = False
        self.last_external_task_id = EXTERNAL
        self.last_dispatch_ref = f"evidence/{EXTERNAL}"
        self.last_digest = DIGEST
        self.runs = []
        self.artifact = b""
        self.logs = log_zip(b"build ok\nAuthorization: secret\n")
        self.artifact_download_calls = 0

    def run(self, **changes):
        values = dict(
            run_id=101, run_attempt=1, repository=REPOSITORY, workflow_id=WORKFLOW,
            event="workflow_dispatch", head_sha=EVIDENCE,
            dispatch_ref=self.last_dispatch_ref,
            external_task_id=self.last_external_task_id,
            build_input_digest=self.last_digest, status="queued", conclusion=None,
        )
        values.update(changes)
        return WorkflowRun(**values)

    def resolve_ref(self, token, repository, dispatch_ref):
        assert token.startswith("CANARY-") and repository == REPOSITORY
        return self.ref_sha

    def dispatch(self, token, repository, workflow_id, dispatch_ref, inputs):
        self.dispatch_calls += 1
        assert workflow_id == WORKFLOW
        assert inputs["gateway_task_id"].startswith("gw-")
        assert dispatch_ref == f"evidence/{inputs['gateway_task_id']}"
        assert inputs["snapshot_ref"] == f"evidence/requests/{inputs['request_id']}"
        assert inputs["target_version"] == "25.12.2"
        assert inputs["strict_mode"] is True
        assert inputs["trusted_code_commit_sha"] == CODE
        self.last_external_task_id = inputs["gateway_task_id"]
        self.last_dispatch_ref = dispatch_ref
        self.last_digest = inputs["build_input_digest"]
        run_id = self.response.run_id or 101
        run = self.run(run_id=run_id)
        self.runs = [item for item in self.runs if item.run_id != run_id]
        self.runs.append(run)
        if self.raise_after_dispatch:
            raise TimeoutError("response lost")
        return self.response

    def get_run(self, token, repository, run_id):
        return next(run for run in self.runs if run.run_id == run_id)

    def find_runs(self, token, repository, workflow_id, head_sha):
        return list(self.runs)

    def artifact_zip(self, token, repository, run_id, run_attempt):
        self.artifact_download_calls += 1
        return ArtifactDownload(
            io.BytesIO(self.artifact), len(self.artifact), repository, run_id,
            run_attempt, expired=False
        )

    def log_archive(self, token, repository, run_id, run_attempt):
        return self.logs


class FakeTransport:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def request(self, method, path, token, **kwargs):
        self.calls.append((method, path, token, kwargs))
        return self.results.pop(0)

    def download(self, method, path, token, destination, **kwargs):
        self.calls.append((method, path, token, kwargs))
        result = self.results.pop(0)
        destination.write(result.body)
        return HTTPResult(result.status, result.headers, b"")


@dataclass
class TrustedVerifier:
    def verify(self, request):
        return EvidenceVerdict(
            True, trusted_code_commit_sha=CODE,
            evidence_commit_sha=request.evidence_commit_sha,
            target_version="25.12.2",
            snapshot_digest="1" * 64,
            plan_digest="2" * 64,
        )


def request(*, request_id="request-001", digest=DIGEST):
    return BuildRequest(
        request_id=request_id, build_input_id=f"urn:sha256:{digest}",
        build_input_digest=digest, repository=REPOSITORY,
        evidence_commit_sha=EVIDENCE,
    )


def validated_task(store: GatewayStore, *, device_id="router-a", build_request=None):
    task, _ = store.create_or_get_task(
        device_id, build_request or request(), ttl_seconds=3600, task_quota=100
    )
    task = store.transition_task(task.internal_task_id, TaskStatus.VALIDATING)
    return store.transition_task(task.internal_task_id, TaskStatus.VALIDATED)


def service(tmp_path: Path, github=None):
    store = GatewayStore(tmp_path / "gateway.db")
    store.initialize()
    issuer = Issuer()
    provider = GitHubAppTokenProvider(
        issuer, installation_id=7, repository=REPOSITORY
    )
    api = github or MockGitHub()
    return store, issuer, api, T14BService(
        store, provider, api, repository=REPOSITORY
    )


def artifact_zip(task, intent, *, firmware=b"firmware", mutate=None):
    provenance = {
        "schema_version": "2.0.0", "provenance_id": "", "digest": "",
        "request_id": task.request_id, "gateway_task_id": intent.external_task_id,
        "created_at": "2026-11-13T00:00:00Z",
        "build_input_id": task.build_input_id, "build_input_digest": task.build_input_digest,
        "snapshot_id": f"urn:sha256:{'1' * 64}", "snapshot_digest": "1" * 64,
        "plan_id": f"urn:sha256:{'2' * 64}", "plan_digest": "2" * 64,
        "target": {}, "resolution_digest": "3" * 64, "official_index_digest": "4" * 64,
        "provider_assets": [],
        "trace": {"repository": task.repository, "commit_sha": CODE,
                  "trusted_code_commit_sha": CODE, "evidence_commit_sha": EVIDENCE,
                  "workflow_runtime_sha": EVIDENCE, "workflow_run_id": intent.github_run_id,
                  "workflow_run_attempt": intent.github_run_attempt},
        "imagebuilder": {"url": "https://example.invalid/builder", "filename": "builder.tar.zst",
                         "sha256": "5" * 64},
        "artifact": {"filename": "firmware.img.gz", "sha256": hashlib.sha256(firmware).hexdigest(),
                     "size_bytes": len(firmware)},
        "build_status": "succeeded", "verification_status": "verified",
        "compatibility_validated": False, "build_allowed": True, "flash_ready": False,
    }
    if mutate:
        mutate(provenance)
    canonical = dict(provenance)
    canonical["provenance_id"] = ""
    canonical["digest"] = ""
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    provenance["digest"] = digest
    provenance["provenance_id"] = f"urn:sha256:{digest}"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("artifact/build-provenance-v2.json", json.dumps(provenance))
        archive.writestr("artifact/firmware.img.gz", firmware)
    return output.getvalue()


def log_zip(content: bytes, *, name: str = "jobs/build.txt") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    return output.getvalue()


def test_installation_token_is_cached_refreshed_and_permission_bound():
    issuer = Issuer()
    provider = GitHubAppTokenProvider(issuer, installation_id=7, repository=REPOSITORY)
    first = provider.get()
    assert provider.get() == first
    assert issuer.calls == 1
    provider._cached = InstallationToken(first, 1, 7, REPOSITORY, issuer.permissions)
    assert provider.get() != first
    with pytest.raises(GatewayError):
        GitHubAppTokenProvider(
            Issuer(permissions={"contents": "write"}), installation_id=7,
            repository=REPOSITORY,
        ).get()


@pytest.mark.parametrize("mutation", ["installation", "repository", "expiry"])
def test_installation_token_identity_and_expiry_fail_closed(mutation):
    class BadIssuer(Issuer):
        def issue(self, installation_id, repository):
            token = super().issue(installation_id, repository)
            values = token.__dict__.copy()
            if mutation == "installation":
                values["installation_id"] = 99
            elif mutation == "repository":
                values["repository"] = "attacker/repo"
            else:
                values["expires_at"] = 1
            return InstallationToken(**values)

    with pytest.raises(GatewayError):
        GitHubAppTokenProvider(
            BadIssuer(), installation_id=7, repository=REPOSITORY
        ).get()


def test_rest_client_uses_current_version_and_parses_returned_run_id():
    transport = FakeTransport([
        HTTPResult(200, {}, json.dumps({"workflow_run_id": 101}).encode())
    ])
    client = GitHubRESTClient(transport, repository=REPOSITORY)
    result = client.dispatch(
        "token", REPOSITORY, WORKFLOW, "evidence/request-001", {"strict_mode": True}
    )
    assert result.run_id == 101
    method, path, token, options = transport.calls[0]
    assert method == "POST" and token == "token"
    assert path.endswith("/.github%2Fworkflows%2Fbuild.yml/dispatches")
    assert options["api_version"] == API_VERSION == "2026-03-10"
    assert options["json_body"]["ref"] == "evidence/request-001"


def test_rest_client_safely_parses_run_marker_and_legacy_dispatch():
    run = {
        "id": 101, "run_attempt": 1, "repository": {"full_name": REPOSITORY},
        "path": f"{WORKFLOW}@refs/heads/evidence/{EXTERNAL}",
        "event": "workflow_dispatch", "head_sha": EVIDENCE,
        "head_branch": f"evidence/{EXTERNAL}",
        "display_title": f"gateway-{EXTERNAL}-{DIGEST}",
        "status": "queued", "conclusion": None,
    }
    transport = FakeTransport([
        HTTPResult(204, {}, b""), HTTPResult(200, {}, json.dumps(run).encode()),
    ])
    client = GitHubRESTClient(transport, repository=REPOSITORY)
    assert client.dispatch("token", REPOSITORY, WORKFLOW, "evidence/request-001", {}).run_id is None
    parsed = client.get_run("token", REPOSITORY, 101)
    assert parsed.external_task_id == EXTERNAL
    assert parsed.build_input_digest == DIGEST
    assert parsed.workflow_id == WORKFLOW


def test_rest_client_rejects_wrong_repository_and_malformed_run():
    client = GitHubRESTClient(
        FakeTransport([HTTPResult(200, {}, b"{}")]), repository=REPOSITORY
    )
    with pytest.raises(GatewayError) as denied:
        client.get_run("token", "attacker/repository", 1)
    assert denied.value.code == ErrorCode.ACCESS_DENIED
    with pytest.raises(GatewayError) as malformed:
        client.get_run("token", REPOSITORY, 1)
    assert malformed.value.code == ErrorCode.UPSTREAM_UNAVAILABLE


def test_dispatch_intent_is_atomic_and_only_one_worker_claims(tmp_path):
    store, _, _, _ = service(tmp_path)
    task = validated_task(store)
    intent, created = store.create_dispatch_intent(
        task, trusted_code_commit_sha=CODE, workflow_id=WORKFLOW,
        dispatch_ref=f"evidence/{store.external_task_id(task.internal_task_id)}",
        snapshot_digest="1" * 64,
        plan_digest="2" * 64, target_version="25.12.2",
    )
    assert created
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        claims = list(pool.map(lambda _: store.claim_dispatch(intent.dispatch_intent_id), range(20)))
    assert sum(item is not None for item in claims) == 1


def test_normal_dispatch_and_replay_create_one_remote_run(tmp_path):
    store, _, api, worker = service(tmp_path)
    task = validated_task(store)
    queued = worker.dispatch(task, TrustedVerifier().verify(request()))
    assert queued.status == TaskStatus.QUEUED
    replay = worker.dispatch(queued, TrustedVerifier().verify(request()))
    assert replay.status == TaskStatus.QUEUED
    assert api.dispatch_calls == 1


def test_lost_dispatch_response_is_unknown_and_never_blindly_retried(tmp_path):
    api = MockGitHub()
    api.raise_after_dispatch = True
    store, _, _, worker = service(tmp_path, api)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    assert task.status == TaskStatus.DISPATCH_UNKNOWN
    assert api.dispatch_calls == 1
    replay = worker.dispatch(task, TrustedVerifier().verify(request()))
    assert replay.status == TaskStatus.DISPATCH_UNKNOWN
    assert api.dispatch_calls == 1
    reconciled = worker.reconcile(task)
    assert reconciled.status == TaskStatus.QUEUED


def test_database_update_failure_after_dispatch_stays_unknown(tmp_path, monkeypatch):
    store, _, api, worker = service(tmp_path)
    original = store.bind_dispatch_run
    calls = 0

    def fail_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise GatewayError(ErrorCode.STORAGE_UNAVAILABLE, 503)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "bind_dispatch_run", fail_once)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    assert api.dispatch_calls == 1
    assert task.status == TaskStatus.DISPATCH_UNKNOWN


def test_untrusted_evidence_cannot_create_dispatch_intent(tmp_path):
    store, _, api, worker = service(tmp_path)
    with pytest.raises(GatewayError) as raised:
        worker.dispatch(validated_task(store), EvidenceVerdict(False))
    assert raised.value.code == ErrorCode.BUILD_BLOCKED
    assert api.dispatch_calls == 0


def test_legacy_dispatch_without_run_id_uses_exact_unique_correlation(tmp_path):
    api = MockGitHub()
    api.response = DispatchResponse(None)
    store, _, _, worker = service(tmp_path, api)
    queued = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    assert queued.status == TaskStatus.QUEUED
    assert queued.github_run_id == 101


def test_ambiguous_or_wrong_ref_fails_closed(tmp_path):
    api = MockGitHub()
    api.ref_sha = "d" * 40
    store, _, _, worker = service(tmp_path, api)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    assert task.status == TaskStatus.DISPATCH_UNKNOWN
    api.runs.append(api.run(run_id=102))
    with pytest.raises(GatewayError) as raised:
        worker.reconcile(task)
    assert raised.value.code == ErrorCode.DISPATCH_UNKNOWN


def test_run_success_requires_artifact_verification(tmp_path):
    store, _, api, worker = service(tmp_path)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    api.runs = [api.run(status="in_progress")]
    task = worker.poll(task)
    assert task.status == TaskStatus.RUNNING
    api.runs = [api.run(status="completed", conclusion="success")]
    task = worker.poll(task)
    assert task.status == TaskStatus.VERIFYING_ARTIFACT
    intent = store.get_dispatch_intent(task.internal_task_id)
    api.artifact = artifact_zip(task, intent)
    task = worker.verify_artifact(task)
    assert task.status == TaskStatus.SUCCEEDED
    metadata = json.loads(store.get_verified_artifact(task.internal_task_id))
    assert metadata["flash_ready"] is False


@pytest.mark.parametrize(
    ("status", "conclusion"),
    [("completed", "failure"), ("completed", "cancelled"),
     ("completed", "timed_out"), ("completed", "skipped")],
)
def test_terminal_unsuccessful_runs_never_become_success(tmp_path, status, conclusion):
    store, _, api, worker = service(tmp_path)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    api.runs = [api.run(status=status, conclusion=conclusion)]
    task = worker.poll(task)
    assert task.status == TaskStatus.BUILD_FAILED


def test_manual_rerun_attempt_cannot_replace_bound_attempt(tmp_path):
    store, _, api, worker = service(tmp_path)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    api.runs = [api.run(run_attempt=2, status="in_progress")]
    with pytest.raises(GatewayError) as raised:
        worker.poll(task)
    assert raised.value.code == ErrorCode.RUN_IDENTITY_MISMATCH


@pytest.mark.parametrize(
    "attack",
    ["bytes", "zip-slip", "run", "expired", "duplicate", "symlink", "bomb",
     "filename", "digest", "missing-provenance"],
)
def test_artifact_attacks_fail_closed(tmp_path, attack):
    store, _, api, worker = service(tmp_path)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    task = store.transition_task(task.internal_task_id, TaskStatus.RUNNING, allow_t14b=True)
    task = store.transition_task(task.internal_task_id, TaskStatus.VERIFYING_ARTIFACT, allow_t14b=True)
    intent = store.get_dispatch_intent(task.internal_task_id)
    if attack == "run":
        api.artifact = artifact_zip(task, intent, mutate=lambda p: p["trace"].update(workflow_run_id=999))
    elif attack == "filename":
        api.artifact = artifact_zip(
            task, intent, mutate=lambda p: p["artifact"].update(filename="other.img.gz")
        )
    elif attack == "digest":
        api.artifact = artifact_zip(
            task, intent, mutate=lambda p: p.update(build_input_digest="9" * 64)
        )
    else:
        api.artifact = artifact_zip(task, intent)
    if attack == "bytes":
        api.artifact = api.artifact.replace(b"firmware", b"tampered")
    elif attack == "zip-slip":
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../escape", b"bad")
        api.artifact = stream.getvalue()
    elif attack == "expired":
        original = api.artifact_zip

        def expired(*args):
            item = original(*args)
            return ArtifactDownload(item.archive, item.size_bytes, item.repository,
                                    item.run_id, item.run_attempt, expired=True)

        api.artifact_zip = expired
    elif attack == "duplicate":
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("same", b"one")
                archive.writestr("same", b"two")
        api.artifact = stream.getvalue()
    elif attack == "symlink":
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            link = zipfile.ZipInfo("link")
            link.external_attr = 0o120777 << 16
            archive.writestr(link, b"target")
        api.artifact = stream.getvalue()
    elif attack == "bomb":
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("bomb", b"0" * (1024 * 1024))
        api.artifact = stream.getvalue()
    elif attack == "missing-provenance":
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("artifact/firmware.img.gz", b"firmware")
        api.artifact = stream.getvalue()
    with pytest.raises(GatewayError) as raised:
        worker.verify_artifact(task)
    assert raised.value.code == ErrorCode.ARTIFACT_UNVERIFIED
    assert store.get_task("router-a", "request-001").status == TaskStatus.ARTIFACT_FAILED


@pytest.mark.parametrize("exception", [GitHubRateLimited(0), GitHubTransientError()])
def test_read_only_github_calls_retry_but_dispatch_does_not(tmp_path, exception):
    api = MockGitHub()
    calls = 0
    original = api.resolve_ref

    def flaky(*args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise exception
        return original(*args)

    api.resolve_ref = flaky
    store, _, _, worker = service(tmp_path, api)
    worker.sleep = lambda _: None
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    assert task.status == TaskStatus.QUEUED
    assert calls == 2
    assert api.dispatch_calls == 1


def test_startup_recovery_marks_inflight_dispatch_unknown_without_redispatch(tmp_path):
    store, _, api, worker = service(tmp_path)
    task = validated_task(store)
    intent, _ = store.create_dispatch_intent(
        task, trusted_code_commit_sha=CODE, workflow_id=WORKFLOW,
        dispatch_ref=f"evidence/{store.external_task_id(task.internal_task_id)}",
        snapshot_digest="1" * 64,
        plan_digest="2" * 64, target_version="25.12.2",
    )
    store.claim_dispatch(intent.dispatch_intent_id)
    api.runs = []
    summary = worker.recover_startup()
    assert api.dispatch_calls == 0
    assert summary["unknown"] == 1
    assert summary["deferred"] == 0
    assert store.get_task("router-a", "request-001").status == TaskStatus.DISPATCH_UNKNOWN


def test_startup_recovery_dispatches_never_claimed_intent_once(tmp_path):
    store, _, api, worker = service(tmp_path)
    task = validated_task(store)
    store.create_dispatch_intent(
        task, trusted_code_commit_sha=CODE, workflow_id=WORKFLOW,
        dispatch_ref=f"evidence/{store.external_task_id(task.internal_task_id)}",
        snapshot_digest="1" * 64,
        plan_digest="2" * 64, target_version="25.12.2",
    )
    summary = worker.recover_startup()
    assert summary["pending"] == 1
    assert api.dispatch_calls == 1
    assert store.get_task("router-a", "request-001").status == TaskStatus.QUEUED


def test_api_dispatch_artifact_logs_and_device_isolation(tmp_path):
    settings = GatewaySettings(
        database_path=tmp_path / "gateway.db", trusted_repository=REPOSITORY,
        require_https=True, rate_limit_requests=100, dispatch_enabled=True,
    )
    store = GatewayStore(settings.database_path)
    store.initialize()
    api = MockGitHub()
    worker = T14BService(
        store, GitHubAppTokenProvider(Issuer(), installation_id=7, repository=REPOSITORY),
        api, repository=REPOSITORY,
    )
    app = create_app(settings, verifier=TrustedVerifier(), t14b_service=worker)
    token_a = app.state.store.issue_credential("router-a", ttl_seconds=3600)
    token_b = app.state.store.issue_credential("router-b", ttl_seconds=3600)
    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    payload = request().model_dump()
    with TestClient(app, base_url="https://gateway.test") as client:
        created = client.post("/builds", json=payload, headers=headers_a)
        assert created.json()["status"] == "QUEUED"
        assert created.json()["flash_ready"] is False
        assert client.get("/builds/request-001", headers=headers_b).status_code == 404
        assert client.get("/builds/request-001/logs", headers=headers_b).status_code == 404
        logs = client.get("/builds/request-001/logs", headers=headers_a).json()
        assert "secret" not in json.dumps(logs).lower()
        task = app.state.store.get_task("router-a", "request-001")
        task = app.state.store.transition_task(task.internal_task_id, TaskStatus.RUNNING, allow_t14b=True)
        task = app.state.store.transition_task(task.internal_task_id, TaskStatus.VERIFYING_ARTIFACT, allow_t14b=True)
        intent = app.state.store.get_dispatch_intent(task.internal_task_id)
        api.artifact = artifact_zip(task, intent)
        artifact = client.get("/builds/request-001/artifacts", headers=headers_a)
        assert artifact.status_code == 200
        assert artifact.json()["flash_ready"] is False


def test_gateway_rejects_mismatched_t14b_service_identity(tmp_path):
    settings = GatewaySettings(
        database_path=tmp_path / "gateway.db", trusted_repository=REPOSITORY,
        dispatch_enabled=True,
    )
    other = GatewayStore(tmp_path / "other.db")
    other.initialize()
    worker = T14BService(
        other, GitHubAppTokenProvider(Issuer(), installation_id=7, repository=REPOSITORY),
        MockGitHub(), repository=REPOSITORY,
    )
    with pytest.raises(ValueError, match="identity"):
        create_app(settings, verifier=TrustedVerifier(), t14b_service=worker)


def test_twenty_concurrent_posts_create_one_intent_and_dispatch(tmp_path):
    settings = GatewaySettings(
        database_path=tmp_path / "gateway.db", trusted_repository=REPOSITORY,
        require_https=True, rate_limit_requests=100, dispatch_enabled=True,
    )
    store = GatewayStore(settings.database_path)
    store.initialize()
    api = MockGitHub()
    worker = T14BService(
        store, GitHubAppTokenProvider(Issuer(), installation_id=7, repository=REPOSITORY),
        api, repository=REPOSITORY,
    )
    app = create_app(settings, verifier=TrustedVerifier(), t14b_service=worker)
    token = app.state.store.issue_credential("router-a", ttl_seconds=3600)
    headers = {"Authorization": f"Bearer {token}"}

    with TestClient(app, base_url="https://gateway.test") as client:
        def submit(_):
            return client.post("/builds", json=request().model_dump(), headers=headers).status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            statuses = list(pool.map(submit, range(20)))
    assert set(statuses) <= {200, 201}
    assert app.state.store.task_count("router-a") == 1
    assert api.dispatch_calls == 1


def test_restart_preserves_external_intent_without_redispatch(tmp_path):
    api = MockGitHub()
    api.raise_after_dispatch = True
    store, _, _, worker = service(tmp_path, api)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    assert task.status == TaskStatus.DISPATCH_UNKNOWN
    restarted = GatewayStore(store.path)
    restarted.initialize()
    assert restarted.recover_incomplete_tasks() == 0
    persisted = restarted.get_task("router-a", "request-001")
    assert persisted.status == TaskStatus.DISPATCH_UNKNOWN
    assert restarted.get_dispatch_intent(persisted.internal_task_id).dispatch_state == "UNKNOWN"


def test_tokens_are_not_persisted_or_returned(tmp_path):
    store, _, _, worker = service(tmp_path)
    worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    raw = store.path.read_bytes()
    assert b"CANARY-INSTALLATION-TOKEN" not in raw


@pytest.mark.parametrize("second_digest", [DIGEST, "9" * 64])
@pytest.mark.parametrize("legacy_response", [False, True])
def test_cross_device_request_id_cannot_share_github_run(
    tmp_path, second_digest, legacy_response
):
    api = MockGitHub()
    if legacy_response:
        api.response = DispatchResponse(None)
    store, _, _, worker = service(tmp_path, api)
    first_request = request()
    first = worker.dispatch(
        validated_task(store, device_id="router-a", build_request=first_request),
        TrustedVerifier().verify(first_request),
    )
    second_request = request(digest=second_digest)
    second = worker.dispatch(
        validated_task(store, device_id="router-b", build_request=second_request),
        TrustedVerifier().verify(second_request),
    )
    first_intent = store.get_dispatch_intent(first.internal_task_id)
    second_intent = store.get_dispatch_intent(second.internal_task_id)
    assert first_intent.external_task_id != second_intent.external_task_id
    assert first_intent.dispatch_ref != second_intent.dispatch_ref
    assert first.github_run_id == 101
    assert second.status == TaskStatus.DISPATCH_UNKNOWN
    assert second.github_run_id is None
    assert api.dispatch_calls == 2


def test_cross_device_tasks_bind_distinct_run_ids(tmp_path):
    api = MockGitHub()
    store, _, _, worker = service(tmp_path, api)
    first_request = request()
    first = worker.dispatch(
        validated_task(store, device_id="router-a", build_request=first_request),
        TrustedVerifier().verify(first_request),
    )
    api.response = DispatchResponse(102)
    second_request = request()
    second = worker.dispatch(
        validated_task(store, device_id="router-b", build_request=second_request),
        TrustedVerifier().verify(second_request),
    )
    assert (first.github_run_id, second.github_run_id) == (101, 102)
    assert first.status == second.status == TaskStatus.QUEUED


def test_log_archive_is_bounded_sanitized_and_binary_safe():
    token = b"ghs_" + b"A" * 30
    raw = log_zip(
        b"ok\x01line\nAuthorization: Bearer arbitrary-secret\nplain " + token + b"\n"
    )
    lines, truncated = sanitize_log_archive(raw)
    rendered = "\n".join(lines)
    assert truncated is False
    assert "\x01" not in rendered
    assert "arbitrary-secret" not in rendered
    assert token.decode() not in rendered
    assert "[REDACTED_TOKEN]" in rendered

    with pytest.raises(GatewayError):
        sanitize_log_archive(log_zip(b"binary\x00content"))
    with pytest.raises(GatewayError):
        sanitize_log_archive(log_zip(b"x" * 1024), limits=LogLimits(member_bytes=64))
    with pytest.raises(GatewayError):
        sanitize_log_archive(log_zip(b"hidden", name="jobs/data.bin"))


def test_logs_require_exact_run_attempt_identity(tmp_path):
    store, _, api, worker = service(tmp_path)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    api.runs = [api.run(run_attempt=2)]
    with pytest.raises(GatewayError) as raised:
        worker.logs(task)
    assert raised.value.code == ErrorCode.RUN_IDENTITY_MISMATCH


def test_rest_client_uses_attempt_specific_log_endpoint():
    archive = log_zip(b"ok\n")
    transport = FakeTransport([HTTPResult(200, {}, archive)])
    client = GitHubRESTClient(transport, repository=REPOSITORY)
    assert client.log_archive("token", REPOSITORY, 101, 3) == archive
    method, path, _, options = transport.calls[0]
    assert method == "GET"
    assert path.endswith("/actions/runs/101/attempts/3/logs")
    assert options["max_bytes"] == 8 * 1024 * 1024


def test_rest_artifact_download_uses_bounded_stream():
    run = {
        "id": 101, "run_attempt": 1, "repository": {"full_name": REPOSITORY},
        "path": f"{WORKFLOW}@refs/heads/evidence/{EXTERNAL}",
        "event": "workflow_dispatch", "head_sha": EVIDENCE,
        "head_branch": f"evidence/{EXTERNAL}",
        "display_title": f"gateway-{EXTERNAL}-{DIGEST}",
        "status": "completed", "conclusion": "success",
    }
    expected_name = f"gateway-{EXTERNAL}-{DIGEST}-1"
    artifacts = {"artifacts": [{
        "name": expected_name, "expired": False,
        "workflow_run": {"id": 101},
        "archive_download_url":
            f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/77/zip",
    }]}
    archive = artifact_zip_bytes = log_zip(b"artifact bytes")
    transport = FakeTransport([
        HTTPResult(200, {}, json.dumps(run).encode()),
        HTTPResult(200, {}, json.dumps(artifacts).encode()),
        HTTPResult(200, {}, archive),
    ])
    client = GitHubRESTClient(transport, repository=REPOSITORY)
    download = client.artifact_zip("token", REPOSITORY, 101, 1)
    try:
        assert download.size_bytes == len(artifact_zip_bytes)
        assert download.archive.read() == artifact_zip_bytes
        assert transport.calls[-1][3]["max_bytes"] == 256 * 1024 * 1024
    finally:
        download.close()


@pytest.mark.anyio
async def test_slow_github_transport_does_not_block_event_loop(tmp_path):
    api = MockGitHub()
    original = api.resolve_ref

    def slow_resolve(*args):
        time.sleep(0.35)
        return original(*args)

    api.resolve_ref = slow_resolve
    settings = GatewaySettings(
        database_path=tmp_path / "gateway.db", trusted_repository=REPOSITORY,
        require_https=False, rate_limit_requests=100, dispatch_enabled=True,
        external_timeout_seconds=2,
    )
    store = GatewayStore(settings.database_path)
    store.initialize()
    worker = T14BService(
        store, GitHubAppTokenProvider(Issuer(), installation_id=7, repository=REPOSITORY),
        api, repository=REPOSITORY,
    )
    app = create_app(settings, verifier=TrustedVerifier(), t14b_service=worker)
    token = app.state.store.issue_credential("router-a", ttl_seconds=3600)
    headers = {"Authorization": f"Bearer {token}"}
    transport = httpx.ASGITransport(app=app)
    started = time.monotonic()

    async def ticker():
        await asyncio.sleep(0.05)
        return time.monotonic() - started

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response, wake = await asyncio.gather(
            client.post("/builds", json=request().model_dump(), headers=headers), ticker()
        )
    assert response.status_code == 201
    assert wake < 0.2


@pytest.mark.anyio
async def test_timed_out_dispatch_finishes_without_duplicate_dispatch(tmp_path):
    api = MockGitHub()
    original = api.dispatch

    def slow_dispatch(*args):
        time.sleep(0.2)
        return original(*args)

    api.dispatch = slow_dispatch
    settings = GatewaySettings(
        database_path=tmp_path / "gateway.db", trusted_repository=REPOSITORY,
        require_https=False, rate_limit_requests=100, dispatch_enabled=True,
        external_timeout_seconds=0.05, external_workers=1,
    )
    store = GatewayStore(settings.database_path)
    store.initialize()
    worker = T14BService(
        store, GitHubAppTokenProvider(Issuer(), installation_id=7, repository=REPOSITORY),
        api, repository=REPOSITORY,
    )
    app = create_app(settings, verifier=TrustedVerifier(), t14b_service=worker)
    token = app.state.store.issue_credential("router-a", ttl_seconds=3600)
    headers = {"Authorization": f"Bearer {token}"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first = await client.post("/builds", json=request().model_dump(), headers=headers)
        assert first.status_code == 503
        await asyncio.sleep(0.3)
        replay = await client.post("/builds", json=request().model_dump(), headers=headers)
    assert replay.status_code in {200, 201}
    assert api.dispatch_calls == 1
    assert app.state.store.get_task("router-a", "request-001").status == TaskStatus.QUEUED


def test_crash_recovery_keeps_cross_device_dispatch_identity_separate(tmp_path):
    store, _, api, worker = service(tmp_path)
    tasks = [
        validated_task(store, device_id="router-a"),
        validated_task(store, device_id="router-b"),
    ]
    intents = []
    for task in tasks:
        external = store.external_task_id(task.internal_task_id)
        intent, _ = store.create_dispatch_intent(
            task, trusted_code_commit_sha=CODE, workflow_id=WORKFLOW,
            dispatch_ref=f"evidence/{external}", snapshot_digest="1" * 64,
            plan_digest="2" * 64, target_version="25.12.2",
        )
        intents.append(store.claim_dispatch(intent.dispatch_intent_id))
    api.runs = []
    summary = worker.recover_startup()
    assert summary["unknown"] == 2
    assert api.dispatch_calls == 0
    assert intents[0].external_task_id != intents[1].external_task_id

    api.runs = [
        WorkflowRun(
            run_id=101 + index, run_attempt=1, repository=REPOSITORY,
            workflow_id=WORKFLOW, event="workflow_dispatch", head_sha=EVIDENCE,
            dispatch_ref=intent.dispatch_ref,
            external_task_id=intent.external_task_id,
            build_input_digest=DIGEST, status="queued", conclusion=None,
        )
        for index, intent in enumerate(intents)
    ]
    recovered = [
        worker.reconcile(store.get_task(task.device_id, task.request_id))
        for task in tasks
    ]
    assert [task.github_run_id for task in recovered] == [101, 102]


def test_artifact_verification_is_streamed_and_serialized_per_task(tmp_path):
    store, _, api, worker = service(tmp_path)
    task = worker.dispatch(validated_task(store), TrustedVerifier().verify(request()))
    task = store.transition_task(task.internal_task_id, TaskStatus.RUNNING, allow_t14b=True)
    task = store.transition_task(
        task.internal_task_id, TaskStatus.VERIFYING_ARTIFACT, allow_t14b=True
    )
    intent = store.get_dispatch_intent(task.internal_task_id)
    firmware = os.urandom(8 * 1024 * 1024)
    api.artifact = artifact_zip(task, intent, firmware=firmware)
    original = api.artifact_zip
    active = 0
    maximum = 0
    guard = threading.Lock()

    def slow_download(*args):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.05)
        try:
            return original(*args)
        finally:
            with guard:
                active -= 1

    api.artifact_zip = slow_download
    tracemalloc.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: worker.verify_artifact(task), range(2)))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert all(item.status == TaskStatus.SUCCEEDED for item in results)
    assert api.artifact_download_calls == 1
    assert maximum == 1
    assert peak < 7 * 1024 * 1024

