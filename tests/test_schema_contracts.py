import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
HEX = "a" * 64
URN = f"urn:sha256:{HEX}"


def validator(name):
    schema = json.loads((ROOT / "schemas" / name).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


VALID_SYSTEM = {
    "schema_version": "1.0.0", "snapshot_id": URN,
    "digest": {"algorithm": "sha256", "canonicalization": "evidence-sha256-v2", "value": HEX},
    "status": "partial", "privacy_mode": "redacted",
    "system": {"distribution": "ImmortalWrt", "version": "25.12.2", "target": "x86/64", "profile": "generic", "architecture": "x86_64", "package_architecture": "x86_64", "kernel_architecture": "x86_64", "boot_mode": "unknown", "rootfs_type": "overlay", "firmware_image_type": "unknown", "package_manager": "apk", "identity_status": "consistent", "identity_errors": []},
    "packages": {"installed": [{"name": "busybox", "version": "1", "origin": "official", "install_reason": "system_default", "confidence": "high", "evidence": ["firmware-rom-baseline"], "dependencies_raw": None, "depends": [], "provides_raw": None}], "top_level": [], "intent_candidates": [], "classification_status": "partial", "truncated": False},
    "services": {name: {"package_detected": None, "executable_exists": False, "service_definition_exists": False, "running": "unknown"} for name in ("openclash", "lucky", "adguardhome", "docker")},
    "storage": {"status": "partial", "evidence_digest": HEX, "scan_completeness": {"containers": "unavailable", "volumes": "unavailable", "mounts": "unavailable", "container_scope": "unknown", "volume_scope": "unknown"}, "docker": {"installed": False, "daemon_state": "unavailable", "root": None, "configured_root": None, "root_source": "none", "verified": False, "config_mismatch": False}, "mount_inventory": {"state": "complete", "truncated": False, "entries": [{"id": "mount-1", "mountpoint": None, "device": None, "device_major_minor": None, "filesystem": "overlay", "root": None, "block_resolution": "unknown", "size_bytes": None, "risk": "rootfs_or_overlay", "physical_disk_id": None, "physical_disk": None, "partition": None}]}, "targets": [], "errors": []},
    "warnings": ["classification incomplete"], "errors": []
}

VALID_PLAN = {
    "schema_version": "1.0.0", "plan_id": URN, "source_snapshot_id": URN, "source_snapshot_digest": HEX,
    "status": "blocked", "privacy_mode": "redacted", "strict_mode": True, "build_allowed": False, "flash_ready": False,
    "target": {"version": "25.12.2", "target": "x86/64", "profile": "generic", "architecture": "x86_64", "boot_mode": "unknown", "image_type": None, "compatibility": "unknown"},
    "decisions": [{"package": "mystery", "decision": "review", "reason": "install intent unknown", "compatible": None, "evidence": ["apk-installed-db"]}],
    "blockers": ["target image compatibility unknown"], "warnings": [], "errors": []
}

VALID_BUILD = {
    "schema_version": "1.0.0", "build_id": URN, "request_id": "request-1", "source_plan_id": URN, "source_plan_digest": HEX,
    "status": "failed", "build_allowed": False, "flash_ready": False, "target_version": "25.12.2",
    "trace": {"repository": "owner/repo", "commit_sha": "b" * 40, "workflow_run_id": 1, "workflow_run_attempt": 1},
    "artifacts": [], "blockers": [], "warnings": [], "errors": ["build failed"]
}


@pytest.mark.parametrize(("schema", "sample"), [
    ("system-snapshot-v1.json", VALID_SYSTEM),
    ("migration-plan-v1.json", VALID_PLAN),
    ("build-result-v1.json", VALID_BUILD),
])
def test_schema_positive_samples(schema, sample):
    validator(schema).validate(sample)


def test_redacted_snapshot_rejects_local_paths():
    sample = copy.deepcopy(VALID_SYSTEM)
    sample["storage"]["mount_inventory"]["entries"][0]["mountpoint"] = "/"
    with pytest.raises(ValidationError):
        validator("system-snapshot-v1.json").validate(sample)


def test_storage_contract_rejects_implicit_upgrade_safety_or_missing_completeness():
    sample = copy.deepcopy(VALID_SYSTEM)
    del sample["storage"]["scan_completeness"]
    with pytest.raises(ValidationError):
        validator("system-snapshot-v1.json").validate(sample)

    sample = copy.deepcopy(VALID_SYSTEM)
    sample["storage"]["status"] = "ok"
    sample["storage"]["docker"]["installed"] = True
    with pytest.raises(ValidationError):
        validator("system-snapshot-v1.json").validate(sample)

    sample = copy.deepcopy(VALID_SYSTEM)
    sample["storage"]["targets"] = [{
        "kind": "docker_root", "source": None, "destination": None, "name": None,
        "mount_id": "mount-1", "risk": "external_persistent", "persistence": "separate_mount",
        "firmware_overwrite_risk": "safe", "verified": True,
    }]
    with pytest.raises(ValidationError):
        validator("system-snapshot-v1.json").validate(sample)


def test_unknown_target_cannot_allow_build():
    sample = copy.deepcopy(VALID_PLAN)
    sample["build_allowed"] = True
    with pytest.raises(ValidationError):
        validator("migration-plan-v1.json").validate(sample)


@pytest.mark.parametrize("status", ["partial", "blocked", "failed", "unknown"])
def test_incomplete_build_result_cannot_allow_build(status):
    sample = copy.deepcopy(VALID_BUILD)
    sample["status"] = status
    sample["build_allowed"] = True
    if status != "failed":
        sample["errors"] = []
    with pytest.raises(ValidationError):
        validator("build-result-v1.json").validate(sample)


def test_partial_build_result_is_valid_only_when_fail_closed():
    sample = copy.deepcopy(VALID_BUILD)
    sample.update(status="partial", build_allowed=False, errors=[])
    validator("build-result-v1.json").validate(sample)


def test_migration_plan_partial_cannot_allow_build():
    sample = copy.deepcopy(VALID_PLAN)
    sample.update(status="partial", build_allowed=True)
    with pytest.raises(ValidationError):
        validator("migration-plan-v1.json").validate(sample)


@pytest.mark.parametrize("mutation", ["missing_artifact", "missing_plan_id", "bad_plan_digest"])
def test_successful_build_requires_artifact_and_valid_plan_link(mutation):
    sample = copy.deepcopy(VALID_BUILD)
    sample.update(
        status="ok",
        build_allowed=True,
        errors=[],
        artifacts=[{"name": "firmware.img.gz", "sha256": HEX, "size_bytes": 1}],
    )
    if mutation == "missing_artifact":
        sample["artifacts"] = []
    elif mutation == "missing_plan_id":
        del sample["source_plan_id"]
    else:
        sample["source_plan_digest"] = "not-a-sha256"
    with pytest.raises(ValidationError):
        validator("build-result-v1.json").validate(sample)


@pytest.mark.parametrize("schema,sample", [
    ("migration-plan-v1.json", {**VALID_PLAN, "flash_ready": True}),
    ("build-result-v1.json", {**VALID_BUILD, "flash_ready": True}),
    ("build-result-v1.json", {**VALID_BUILD, "errors": []}),
])
def test_schema_negative_samples(schema, sample):
    with pytest.raises(ValidationError):
        validator(schema).validate(sample)

