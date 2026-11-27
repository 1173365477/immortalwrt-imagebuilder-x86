"""Strict offline planning using server-owned evidence and policy."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from scripts.migration_plan import canonical_digest, generate_plan

from .admission import ROOT, validate_snapshot
from .database import DeviceIdentity, GatewayStore
from .errors import ErrorCode, GatewayError
from .targets import load_catalog, public_target

DEFAULT_ANALYSIS_TTL = 3600
SAFETY_FLAGS = {"dispatch_allowed": False, "flash_ready": False}
PLAN_SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas/migration-plan-v1.json").read_bytes()))


class AnalysisService:
    def __init__(self, store: GatewayStore, catalog_path: Path, ttl: int):
        if ttl <= 0:
            raise ValueError("invalid analysis TTL")
        self.store = store
        self.catalog_path = catalog_path
        self.ttl = ttl

    def _catalog(self) -> dict:
        try:
            return load_catalog(self.catalog_path)
        except (OSError, ValueError, RecursionError, TypeError, KeyError):
            raise GatewayError(ErrorCode.ANALYSIS_UNAVAILABLE, 503) from None

    def targets(self) -> dict:
        entry = self._catalog()
        if entry["expires_at"] <= int(time.time()):
            raise GatewayError(ErrorCode.ANALYSIS_UNAVAILABLE, 503)
        return {"targets": [public_target(entry)], **SAFETY_FLAGS}

    def analyze(self, identity: DeviceIdentity, snapshot_ref: str, target_ref: str,
                deadline: float) -> dict:
        # Resolve ownership before checking target evidence or returning its status.
        admitted = self.store.get_admitted_snapshot(identity.device_id, snapshot_ref)
        target = self._catalog()
        if target["target_ref"] != target_ref:
            raise GatewayError(ErrorCode.ANALYSIS_NOT_FOUND, 404)
        started_at = int(time.time())
        expires_at = min(admitted["expires_at"], target["expires_at"], started_at + self.ttl)
        if expires_at <= started_at:
            raise GatewayError(ErrorCode.ANALYSIS_EXPIRED, 410)
        raw = admitted["payload"]
        if hashlib.sha256(raw).hexdigest() != admitted["snapshot_sha256"]:
            raise GatewayError(ErrorCode.ANALYSIS_MISMATCH, 409)
        try:
            snapshot = validate_snapshot(raw)
        except (ValueError, RecursionError):
            raise GatewayError(ErrorCode.ANALYSIS_MISMATCH, 409) from None
        if (snapshot["snapshot_id"] != admitted["snapshot_id"]
                or not admitted["scan_generation"].startswith(snapshot["digest"]["value"] + "-")):
            raise GatewayError(ErrorCode.ANALYSIS_MISMATCH, 409)

        package_policy = (ROOT / "config/package-rules.yml").read_bytes()
        provider_policy = (ROOT / "config/thirdparty.yml").read_bytes()
        analyzer = (ROOT / "scripts/migration_plan.py").read_bytes()
        caps = target["capabilities"]
        plan = generate_plan(
            snapshot, caps, target["packages"], yaml.safe_load(provider_policy),
            package_rules=yaml.safe_load(package_policy), strict_mode=True,
        )
        if not PLAN_SCHEMA.is_valid(plan):
            raise GatewayError(ErrorCode.ANALYSIS_UNAVAILABLE, 503)
        blockers = blocker_codes(snapshot, plan)
        risks = plan["storage_risk"]
        result = {
            "status": "eligible" if not blockers else "blocked",
            "blockers": blockers,
            "package_summary": plan["package_summary"],
            "storage_risk": {
                "status": risks["status"], "docker_present": risks["docker_present"],
                "firmware_overwrite_risks": risks["firmware_overwrite_risks"],
            },
            "snapshot_id": admitted["snapshot_id"], "snapshot_sha256": admitted["snapshot_sha256"],
            "scan_generation": admitted["scan_generation"],
            "resolution_digest": caps["resolution_digest"],
            "plan_id": plan["plan_id"], "plan_digest": plan["digest"], "expires_at": expires_at,
            **SAFETY_FLAGS,
        }
        binding = {
            "internal_contract": "t14-analysis-v1",
            "device_id": identity.device_id,
            "target_ref": target_ref,
            "snapshot_ref": snapshot_ref,
            "official_index_digest": caps["official_index_digest"],
            "rules_digest": canonical_digest({
                "packages": hashlib.sha256(package_policy).hexdigest(),
                "providers": hashlib.sha256(provider_policy).hexdigest(),
            }),
            "analyzer_digest": hashlib.sha256(analyzer).hexdigest(),
            "result": result,
        }
        analysis_id = self.store.record_analysis(identity, binding, expires_at, deadline)
        return {"analysis_id": analysis_id, **result}


def blocker_codes(snapshot: dict, plan: dict) -> list[str]:
    if plan["build_allowed"] is True and not plan["blockers"] and not plan["errors"]:
        return []
    codes = {"STRICT_PLAN_BLOCKED"}
    if snapshot["status"] != "ok":
        codes.add("SNAPSHOT_INCOMPLETE")
    if snapshot["system"]["identity_status"] != "consistent":
        codes.add("SYSTEM_IDENTITY_UNVERIFIED")
    if plan["source"]["boot_mode"] == "unknown":
        codes.add("BOOT_MODE_UNVERIFIED")
    if plan["target"]["compatibility"] != "compatible":
        codes.add("TARGET_COMPATIBILITY_UNVERIFIED")
    if any(row["decision"] in ("review", "block") for row in plan["decisions"]):
        codes.add("PACKAGE_EVIDENCE_UNVERIFIED")
    if any((row["origin"] == "third_party" or row["provider"])
           and row["decision"] in ("review", "block") for row in plan["decisions"]):
        codes.add("THIRDPARTY_EVIDENCE_UNVERIFIED")
    return sorted(codes)
