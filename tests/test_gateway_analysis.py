from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError

import httpx2 as httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from gateway.admission import validate_snapshot
from gateway.analysis import AnalysisService
from gateway.app import GatewaySettings, create_app
from gateway.errors import GatewayError
from gateway.targets import (
    OfficialTransport, resolve_catalog_entry, verify_url,
)
from scripts.release_utils import ReleaseValidationError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
KEY = bytes(range(32))
VERSION = "25.12.2"
ORIGIN = f"https://downloads.immortalwrt.org/releases/{VERSION}"
TARGET = ORIGIN + "/targets/x86/64"
FEEDS = ORIGIN + "/packages/x86_64"


def encoded(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def frozen_catalog(*, corrupt=False, manager="apk"):
    profiles = json.loads((FIXTURES / "profiles-29.0.json").read_bytes().replace(
        b"29.0.1", VERSION.encode()
    ))
    profiles["default_packages"] = [manager]
    image = next(row for row in profiles["profiles"]["generic"]["images"]
                 if row["type"] == "combined-efi" and row["filesystem"] == "ext4")
    archive = f"immortalwrt-imagebuilder-{VERSION}-x86-64.Linux-x86_64.tar.zst"
    kernel = profiles["linux_kernel"]
    kmods = "kmods/" + "-".join(kernel[key] for key in ("version", "release", "vermagic"))
    profiles_raw = encoded(profiles)
    core = encoded({"packages": {"busybox": {"version": "1"}, "ca-bundle": {"version": "2"}}})
    kmod = b'{"packages":{}}'
    feeds = b'{"packages":{"curl":{"version":"9"}}}'
    resources = {
        TARGET + "/profiles.json": profiles_raw,
        TARGET + "/sha256sums": (
            f"{sha(profiles_raw)}  profiles.json\n{sha(core)}  packages/index.json\n"
            f"{sha(kmod)}  {kmods}/index.json\n{image['sha256']}  {image['name']}\n"
            f"{'d'*64}  {archive}\n"
        ).encode(),
        TARGET + "/packages/index.json": b'{}' if corrupt else core,
        TARGET + f"/{kmods}/index.json": kmod,
        FEEDS + "/sha256sums": f"{sha(feeds)}  base/index.json\n".encode(),
        FEEDS + "/base/index.json": feeds,
    }
    checked = []

    def verify(url):
        verify_url(url)
        checked.append(url)

    entry = resolve_catalog_entry(resources.__getitem__, verify, 3600)
    assert set(checked) == {TARGET + "/" + image["name"], TARGET + "/" + archive}
    return entry


def publish(path, entry):
    path.write_bytes(encoded(entry))
    path.chmod(0o600)


def snapshot():
    return json.loads((FIXTURES / "system-snapshot-sprint2a.json").read_bytes())


def record(raw, *, device="device-one", generation=None, collected=None, key=KEY):
    doc = json.loads(raw)
    observed = int(time.time()) if collected is None else collected
    claims = {
        "version": 1, "device_id": device, "snapshot_sha256": sha(raw),
        "snapshot_id": doc["snapshot_id"], "collected_at": observed,
        "scan_generation": generation or f"{doc['digest']['value']}-{observed}-1",
    }
    mac = hmac.digest(key, b"smart-upgrade/collector/v1\0" + encoded(claims), "sha256").hex()
    return encoded({**claims, "mac": mac})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def gateway(tmp_path):
    settings = GatewaySettings(database_path=tmp_path / "gateway.db")
    app = create_app(settings)
    store = app.state.store
    token = store.issue_credential("device-one", ttl_seconds=3600)
    other = store.issue_credential("device-two", ttl_seconds=3600)
    entry = frozen_catalog()
    path = tmp_path / "target-catalog.json"
    publish(path, entry)
    with TestClient(app, base_url="https://testserver") as client:
        yield store, client, token, other, entry, path


def issue(store, doc):
    raw = encoded(doc)
    claimed = record(raw)
    return store.admit_snapshot(raw, claimed, KEY, ttl=3600), raw, json.loads(claimed)


def analyze(client, token, ref, target):
    return client.post("/analysis", json={"snapshot_ref": ref, "target_ref": target},
                       headers=auth(token))


def assert_no_builds(store):
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM dispatch_intents").fetchone()[0] == 0
    assert store.task_count() == 0


def test_exact_catalog_and_http_analysis_match_cli(gateway, tmp_path, monkeypatch):
    store, client, token, _, entry, _ = gateway
    def cannot_fetch(*args):
        pytest.fail("analysis contacted the upstream")

    monkeypatch.setattr(OfficialTransport, "fetch", cannot_fetch)
    targets = client.get("/targets", headers=auth(token))
    assert targets.status_code == 200
    listing = targets.json()
    assert listing["dispatch_allowed"] is listing["flash_ready"] is False
    target, = listing["targets"]
    assert (target["distribution"], target["version"], target["target"], target["profile"],
            target["filesystem"], target["image_type"], target["architecture"],
            target["package_manager"]) == (
        "immortalwrt", VERSION, "x86/64", "generic", "ext4", "combined-efi", "x86_64", "apk",
    )
    assert target["resolution_digest"] == entry["capabilities"]["resolution_digest"]
    assert target["verified_at"] < target["expires_at"]
    doc = snapshot()
    ref, raw, claims = issue(store, doc)
    response = analyze(client, token, ref, target["target_ref"])
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "eligible" and result["blockers"] == []
    assert result["flash_ready"] is result["dispatch_allowed"] is False
    assert result["snapshot_id"] == doc["snapshot_id"]
    assert result["snapshot_sha256"] == sha(raw)
    assert result["scan_generation"] == claims["scan_generation"]
    assert result["resolution_digest"] == target["resolution_digest"]
    assert result["expires_at"] <= target["expires_at"]
    for name, payload in (("snapshot", doc), ("resolution", entry["capabilities"]),
                          ("index", entry["packages"])):
        (tmp_path / f"{name}.json").write_bytes(encoded(payload))
    cli = subprocess.run([
        sys.executable, "scripts/generate-migration-plan.py",
        "--snapshot", str(tmp_path / "snapshot.json"),
        "--capabilities", str(tmp_path / "resolution.json"),
        "--official-index", str(tmp_path / "index.json"),
        "--output-dir", str(tmp_path / "plan"),
    ], cwd=ROOT, capture_output=True, text=True)
    assert cli.returncode == 0, cli.stderr
    plan = json.loads((tmp_path / "plan/migration-plan-v1.json").read_bytes())
    assert (result["plan_id"], result["plan_digest"]) == (plan["plan_id"], plan["digest"])
    with sqlite3.connect(store.path) as connection:
        binding_json, = connection.execute(
            "SELECT binding_json FROM analysis_receipts WHERE analysis_id=?",
            (result["analysis_id"],),
        ).fetchone()
    binding = json.loads(binding_json)
    assert binding["device_id"] == "device-one"
    assert binding["official_index_digest"] == entry["capabilities"]["official_index_digest"]
    assert len(binding["rules_digest"]) == len(binding["analyzer_digest"]) == 64
    assert_no_builds(store)


@pytest.mark.parametrize("case,blocker", [
    ("conflict", "SYSTEM_IDENTITY_UNVERIFIED"),
    ("unknown", "BOOT_MODE_UNVERIFIED"),
    ("override", "BOOT_MODE_UNVERIFIED"),
    ("thirdparty", "THIRDPARTY_EVIDENCE_UNVERIFIED"),
    ("empty-top-level", "PACKAGE_EVIDENCE_UNVERIFIED"),
    ("opkg", "PACKAGE_EVIDENCE_UNVERIFIED"),
])
def test_incompatible_trusted_evidence_blocks_without_creating_tasks(gateway, case, blocker):
    store, client, token, _, entry, _ = gateway
    doc = snapshot()
    if case == "conflict":
        doc["system"]["identity_status"] = "conflict"
        doc["status"] = "partial"
    elif case == "unknown":
        doc["system"].update(boot_mode="unknown", boot_evidence="no_affirmative_evidence")
    elif case == "override":
        doc["system"]["boot_evidence"] = "fixture_override"
    elif case == "thirdparty":
        doc["packages"]["installed"][-1].update(name="luci-app-openclash", origin="third_party")
        doc["packages"]["top_level"] = ["luci-app-openclash"]
    elif case == "empty-top-level":
        doc["packages"]["top_level"] = []
    else:
        doc["system"]["package_manager"] = "opkg"
    ref, _, _ = issue(store, doc)
    response = analyze(client, token, ref, entry["target_ref"])
    assert response.status_code == 200
    assert response.json()["status"] == "blocked"
    assert blocker in response.json()["blockers"]
    assert not response.json()["flash_ready"] and not response.json()["dispatch_allowed"]
    assert "luci-app-openclash" not in response.text
    assert_no_builds(store)


def test_target_transport_pinning_checksum_and_digest(gateway):
    _, client, token, _, entry, path = gateway
    with pytest.raises(ReleaseValidationError, match="checksum mismatch"):
        frozen_catalog(corrupt=True)
    with pytest.raises(ValueError):
        verify_url(TARGET.replace("immortalwrt", "openwrt") + "/profiles.json")
    with pytest.raises(ValueError):
        verify_url(TARGET + "/%2e%2e/profiles.json")
    entry["packages"]["curl"]["version"] = "10"
    publish(path, entry)
    assert client.get("/targets", headers=auth(token)).status_code == 503
    path.unlink()
    assert client.get("/targets", headers=auth(token)).status_code == 503


def test_transport_checks_redirect_before_contacting_new_host(monkeypatch):
    transport = OfficialTransport()
    entered = []

    def redirect(request, *, timeout):
        entered.append(request.full_url)
        raise HTTPError(request.full_url, 302, "found",
                        {"Location": "https://downloads.openwrt.org/profiles.json"}, None)

    monkeypatch.setattr(transport.opener, "open", redirect)
    with pytest.raises(ValueError):
        transport.fetch(TARGET + "/profiles.json")
    assert entered == [TARGET + "/profiles.json"]


def test_snapshot_auth_privacy_replay_and_retention(gateway, monkeypatch):
    store, client, token, other, entry, _ = gateway
    now = int(time.time())
    doc = snapshot()
    raw = encoded(doc)
    claims = record(raw, collected=now)
    with pytest.raises(ValueError, match="untrusted collector"):
        store.admit_snapshot(raw, record(raw, key=b"b"*32), KEY, ttl=3600)
    with pytest.raises(ValueError, match="snapshot bytes"):
        store.admit_snapshot(raw + b" ", claims, KEY, ttl=3600)
    with pytest.raises(GatewayError) as unenrolled:
        store.admit_snapshot(raw, record(raw, device="unknown"), KEY, ttl=3600)
    assert unenrolled.value.status_code == 403
    ref = store.admit_snapshot(raw, claims, KEY, ttl=20)
    assert store.admit_snapshot(raw, claims, KEY, ttl=3600) == ref
    assert store.get_admitted_snapshot("device-one", ref)["expires_at"] == now + 20
    initial_generation = json.loads(claims)["scan_generation"]
    with pytest.raises(GatewayError) as reused_generation:
        changed_bytes = raw + b" "
        store.admit_snapshot(changed_bytes, record(changed_bytes, generation=initial_generation),
                             KEY, ttl=3600)
    assert reused_generation.value.status_code == 409
    next_generation = initial_generation[:-1] + "2"
    with pytest.raises(GatewayError) as reused_bytes:
        store.admit_snapshot(raw, record(raw, generation=next_generation), KEY, ttl=3600)
    assert reused_bytes.value.status_code == 409
    next_raw = raw + b" "
    next_ref = store.admit_snapshot(next_raw, record(next_raw, generation=next_generation),
                                    KEY, ttl=3600)
    assert next_ref != ref
    a = analyze(client, token, ref, entry["target_ref"]).json()
    b = analyze(client, token, next_ref, entry["target_ref"]).json()
    assert a["snapshot_id"] == b["snapshot_id"]
    assert a["snapshot_sha256"] != b["snapshot_sha256"] and a["scan_generation"] != b["scan_generation"]
    assert analyze(client, other, ref, entry["target_ref"]).json() == analyze(
        client, other, "f"*48, entry["target_ref"]
    ).json()
    monkeypatch.setattr(time, "time", lambda: now + 21)
    assert store.purge_expired_snapshots() == 1
    assert store.purge_expired_analysis() == 1
    with pytest.raises(GatewayError) as expired:
        store.admit_snapshot(raw, claims, KEY, ttl=3600)
    assert expired.value.status_code == 410
    assert analyze(client, token, ref, entry["target_ref"]).status_code == 410
    assert analyze(client, other, ref, entry["target_ref"]).status_code == 404
    assert_no_builds(store)


@pytest.mark.parametrize("mutation", [
    lambda doc: doc.update(privacy_mode="local"),
    lambda doc: doc.update({"x-extra": "secret"}),
    lambda doc: doc["storage"]["docker"].update(root="/root/private"),
    lambda doc: doc["packages"]["installed"][0].update(version="github_pat_example"),
    lambda doc: doc["packages"]["installed"][0].update(evidence=["opaque"]),
    lambda doc: doc["warnings"].append("private diagnostic"),
    lambda doc: doc["system"].update(target="x86/64/hidden"),
    lambda doc: doc["storage"]["targets"].append({"kind": "bind", "name": "private"}),
])
def test_snapshot_remote_allowlist(mutation):
    doc = snapshot()
    mutation(doc)
    with pytest.raises(ValueError):
        validate_snapshot(encoded(doc))


def test_request_envelope_revocation_policy_rate_and_late_mismatch(gateway):
    store, client, token, _, entry, _ = gateway
    ref, _, _ = issue(store, snapshot())
    assert client.get("/targets").status_code == 401
    assert client.get("/targets?latest=1", headers=auth(token)).status_code == 422
    assert client.request("GET", "/targets", content="bad", headers=auth(token)).status_code == 422
    assert client.post("/analysis", content=b"x" * (16 * 1024 + 1),
                       headers=auth(token)).status_code == 413
    for raw in (b'{"target_ref":"x","target_ref":"x","snapshot_ref":"x"}',
                encoded({"snapshot_ref": ref, "target_ref": entry["target_ref"], "strict_mode": False})):
        assert client.post("/analysis", content=raw, headers={
            **auth(token), "Content-Type": "application/json",
        }).status_code == 422
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE admitted_snapshots SET payload=? WHERE snapshot_ref=?", (b"{}", ref))
    assert analyze(client, token, ref, entry["target_ref"]).status_code == 409
    with TestClient(create_app(GatewaySettings(
        database_path=store.path, analysis_enabled=False,
    )), base_url="https://testserver") as disabled:
        assert disabled.get("/targets", headers=auth(token)).status_code == 403
        assert analyze(disabled, token, ref, entry["target_ref"]).status_code == 403
    assert store.revoke_device_credentials("device-one") == 1
    assert client.get("/targets", headers=auth(token)).status_code == 401
    assert analyze(client, token, ref, entry["target_ref"]).status_code == 401


def test_expired_catalog_never_served(gateway, monkeypatch):
    store, client, token, _, entry, _ = gateway
    now = int(time.time())
    ref = store.admit_snapshot(encoded(snapshot()), record(encoded(snapshot()), collected=now),
                               KEY, ttl=7200)
    token = store.issue_credential("device-one", ttl_seconds=7200, now=now)
    monkeypatch.setattr(time, "time", lambda: entry["expires_at"])
    assert client.get("/targets", headers=auth(token)).status_code == 503
    assert analyze(client, token, ref, entry["target_ref"]).status_code == 410


def test_timeout_keeps_running_executor_slot_until_worker_exits(gateway, monkeypatch):
    store, _, token, _, entry, _ = gateway
    ref, _, _ = issue(store, snapshot())
    entered = threading.Event()
    release = threading.Event()
    analyze_real = AnalysisService.analyze

    def blocked(service, *args):
        entered.set()
        assert release.wait(5)
        return analyze_real(service, *args)

    monkeypatch.setattr(AnalysisService, "analyze", blocked)
    app = create_app(GatewaySettings(database_path=store.path, analysis_workers=1,
                                     analysis_timeout_seconds=0.3))

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="https://testserver") as client:
            try:
                first = await client.post("/analysis", headers=auth(token), json={
                    "target_ref": entry["target_ref"], "snapshot_ref": ref,
                })
                assert entered.is_set() and first.status_code == 503
                assert (await client.get("/targets", headers=auth(token))).status_code == 503
            finally:
                release.set()
            for _ in range(40):
                if (await client.get("/targets", headers=auth(token))).status_code == 200:
                    break
                await asyncio.sleep(0.025)
            else:
                pytest.fail("executor slot did not return after actual worker exit")

    asyncio.run(exercise())
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM analysis_receipts").fetchone()[0] == 0
    assert_no_builds(store)


def test_rate_limit_is_separate_per_device_and_route(gateway):
    store, _, token, other, entry, _ = gateway
    settings = GatewaySettings(database_path=store.path, rate_limit_requests=1)
    with TestClient(create_app(settings), base_url="https://testserver") as client:
        assert client.get("/targets", headers=auth(token)).status_code == 200
        assert client.get("/targets", headers=auth(token)).status_code == 429
        assert client.get("/targets", headers=auth(other)).status_code == 200
        assert analyze(client, token, "f"*48, entry["target_ref"]).status_code == 404
        assert analyze(client, token, "f"*48, entry["target_ref"]).status_code == 429
    with TestClient(create_app(settings), base_url="http://testserver") as client:
        assert client.get("/targets", headers=auth(token)).status_code == 403


def test_admission_cli_requires_configured_trusted_record(gateway, tmp_path, monkeypatch):
    store, client, token, _, entry, _ = gateway
    raw = encoded(snapshot())
    snapshot_path = tmp_path / "snapshot.json"
    record_path = tmp_path / "collector.json"
    key_path = tmp_path / "key"
    for path, content in ((snapshot_path, raw), (record_path, record(raw)), (key_path, KEY)):
        path.write_bytes(content)
        path.chmod(0o600)
    argv = [
        sys.executable, "scripts/gateway-analysis.py", "--database", str(store.path),
        "admit-snapshot", "--snapshot", str(snapshot_path), "--collector-record", str(record_path),
    ]
    monkeypatch.delenv("GATEWAY_COLLECTOR_KEY_FILE", raising=False)
    missing = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    assert missing.returncode != 0
    monkeypatch.setenv("GATEWAY_COLLECTOR_KEY_FILE", str(key_path))
    admitted = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    assert admitted.returncode == 0, admitted.stderr
    assert analyze(client, token, admitted.stdout.strip(), entry["target_ref"]).status_code == 200


def test_catalog_rejects_other_release_profiles_identity():
    def simulated_download(url):
        assert url == TARGET + "/profiles.json"
        return b'{"version_number":"25.12.3","arch_packages":"x86_64"}'

    with pytest.raises(ValueError, match="unexpected official profiles identity"):
        resolve_catalog_entry(simulated_download, lambda url: pytest.fail(url), 3600)


def test_refresh_timeout_and_lost_race_preserve_last_verified_catalog(tmp_path, monkeypatch):
    import fcntl

    from gateway import targets

    path = tmp_path / "target-catalog.json"
    entry = frozen_catalog()
    publish(path, entry)
    lifecycle = []

    class TimingOutWorker:
        exitcode = None

        def __init__(self, *, target, args, daemon):
            assert target is targets._refresh_worker and daemon
            self.staging, _ = args

        def start(self):
            self.staging.write_bytes(b"incomplete")

        def join(self, timeout=None):
            lifecycle.append(("join", timeout))

        def is_alive(self):
            return self.exitcode is None

        def kill(self):
            self.exitcode = -9

    class SpawnContext:
        Process = TimingOutWorker

    monkeypatch.setattr(targets.multiprocessing, "get_context", lambda method: SpawnContext())
    lock = path.with_suffix(".json.lock")
    with lock.open("a+") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            targets.refresh_catalog(path, timeout=12)
    with pytest.raises(ValueError, match="refresh failed"):
        targets.refresh_catalog(path, timeout=12)
    assert lifecycle == [("join", 12), ("join", None)]
    assert not list(tmp_path.glob(".catalog-*"))
    assert targets.load_catalog(path) == entry
