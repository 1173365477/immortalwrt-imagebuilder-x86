import json
from pathlib import Path

import pytest

from luci_evidence import (
    EvidenceBundleError,
    canonical_digest,
    create_bundle,
    publish_bundle,
    verify_bundle,
)
from test_luci_smart_upgrade import plan, snapshot


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "d" * 40


def source_bundle(tmp_path, *, snapshot_value=None, plan_value=None, report="# Migration\nBlocked.\n"):
    source = tmp_path / "source"
    source.mkdir()
    snapshot_path = source / "snapshot-source.json"
    plan_path = source / "plan-source.json"
    report_path = source / "report-source.md"
    snapshot_path.write_text(json.dumps(snapshot_value or snapshot()), encoding="utf-8")
    plan_path.write_text(json.dumps(plan_value or plan()), encoding="utf-8")
    report_path.write_text(report, encoding="utf-8")
    output = tmp_path / "bundle"
    create_bundle(snapshot_path, plan_path, report_path, output, ROOT, producer_commit=COMMIT)
    return output


def test_trusted_bundle_validates_and_publishes_atomically(tmp_path):
    bundle_dir = source_bundle(tmp_path)
    bundle = verify_bundle(bundle_dir, ROOT)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    generation = publish_bundle(bundle_dir, state, ROOT)
    assert generation == bundle["digest"]
    assert (state / "current-analysis").read_text().split()[0] == generation
    assert verify_bundle(state / "analyses" / generation, ROOT)["bundle_id"] == bundle["bundle_id"]


@pytest.mark.parametrize("filename", [
    "system-snapshot-v1.json", "migration-plan-v1.json", "migration-report.md",
    "luci-evidence-bundle-v1.json",
])
def test_any_published_file_byte_change_is_rejected(tmp_path, filename):
    bundle_dir = source_bundle(tmp_path)
    path = bundle_dir / filename
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(EvidenceBundleError):
        verify_bundle(bundle_dir, ROOT)


@pytest.mark.parametrize("mutation", [
    "plan-canonical", "plan-required", "plan-type", "plan-id", "snapshot-id",
    "snapshot-schema", "privacy", "flash-ready",
])
def test_untrusted_source_cannot_create_bundle(tmp_path, mutation):
    snapshot_value = snapshot()
    plan_value = plan()
    if mutation == "plan-canonical":
        plan_value["target"]["version"] = "tampered"
    elif mutation == "plan-required":
        del plan_value["release"]
    elif mutation == "plan-type":
        plan_value["strict_mode"] = "true"
    elif mutation == "plan-id":
        plan_value["plan_id"] = f"urn:sha256:{'9' * 64}"
    elif mutation == "snapshot-id":
        snapshot_value["snapshot_id"] = f"urn:sha256:{'9' * 64}"
    elif mutation == "snapshot-schema":
        snapshot_value["schema_version"] = "2.0.0"
    elif mutation == "privacy":
        plan_value["privacy_mode"] = "local"
    elif mutation == "flash-ready":
        plan_value["flash_ready"] = True
    with pytest.raises(EvidenceBundleError):
        source_bundle(tmp_path, snapshot_value=snapshot_value, plan_value=plan_value)


def test_self_consistent_manifest_from_unknown_producer_is_rejected(tmp_path):
    bundle_dir = source_bundle(tmp_path)
    manifest_path = bundle_dir / "luci-evidence-bundle-v1.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["producer"]["name"] = "untrusted-producer"
    digest = canonical_digest(manifest, ("bundle_id", "digest"))
    manifest["digest"] = digest
    manifest["bundle_id"] = f"urn:sha256:{digest}"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(EvidenceBundleError, match="schema validation"):
        verify_bundle(bundle_dir, ROOT)


def test_mixed_snapshot_and_plan_are_rejected(tmp_path):
    changed = snapshot()
    changed["digest"]["value"] = "c" * 64
    changed["snapshot_id"] = f"urn:sha256:{'c' * 64}"
    with pytest.raises(EvidenceBundleError, match="not bound"):
        source_bundle(tmp_path, snapshot_value=changed)


def test_failed_publish_preserves_previous_generation_and_pointer(tmp_path, monkeypatch):
    bundle_dir = source_bundle(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    original = publish_bundle(bundle_dir, state, ROOT)
    original_pointer = (state / "current-analysis").read_text()
    (bundle_dir / "migration-report.md").write_text("tampered", encoding="utf-8")
    with pytest.raises(EvidenceBundleError):
        publish_bundle(bundle_dir, state, ROOT)
    assert (state / "current-analysis").read_text() == original_pointer
    assert (state / "analyses" / original).is_dir()


def test_bundle_manifest_schema_is_registered_with_contract_suite(tmp_path):
    bundle_dir = source_bundle(tmp_path)
    manifest = json.loads((bundle_dir / "luci-evidence-bundle-v1.json").read_text())
    assert manifest["safety"] == {
        "build_allowed": False,
        "compatibility_validated": False,
        "dispatch_allowed": False,
        "flash_ready": False,
    }
