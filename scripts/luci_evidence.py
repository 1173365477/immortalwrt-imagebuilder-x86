#!/usr/bin/env python3
"""Create and verify the immutable evidence bundle consumed by the T15 UI."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


HEX_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
BUNDLE_FILES = (
    "system-snapshot-v1.json",
    "migration-plan-v1.json",
    "migration-report.md",
    "luci-evidence-bundle-v1.json",
)


class EvidenceBundleError(ValueError):
    """The evidence bundle is incomplete, inconsistent, or untrusted."""


def canonical_digest(value: Any, omit: tuple[str, ...] = ()) -> str:
    payload = dict(value) if isinstance(value, dict) else value
    if isinstance(payload, dict):
        for key in omit:
            payload.pop(key, None)
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceBundleError(f"invalid JSON {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceBundleError(f"{path.name} must contain a JSON object")
    return value


def validate_schema(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = load_json(schema_path)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda row: list(row.absolute_path),
    )
    if errors:
        path = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        raise EvidenceBundleError(f"{label} schema validation failed at {path}: {errors[0].message}")


def _git_commit(repo_root: Path) -> str:
    override = os.environ.get("SMART_UPGRADE_PRODUCER_COMMIT", "")
    if COMMIT_RE.fullmatch(override):
        return override
    head = repo_root / ".git/HEAD"
    try:
        raw = head.read_text(encoding="ascii").strip()
        if raw.startswith("ref: "):
            raw = (repo_root / ".git" / raw[5:]).read_text(encoding="ascii").strip()
        if COMMIT_RE.fullmatch(raw):
            return raw
    except OSError:
        pass
    raise EvidenceBundleError("trusted producer commit is unavailable")


def create_bundle(
    snapshot_path: Path,
    plan_path: Path,
    report_path: Path,
    output_dir: Path,
    repo_root: Path,
    *,
    producer_commit: str | None = None,
) -> dict[str, Any]:
    snapshot = load_json(snapshot_path)
    plan = load_json(plan_path)
    validate_schema(snapshot, repo_root / "schemas/system-snapshot-v1.json", "snapshot")
    validate_schema(plan, repo_root / "schemas/migration-plan-v1.json", "migration plan")
    calculated_plan_digest = canonical_digest(plan, ("plan_id", "digest"))
    if plan.get("digest") != calculated_plan_digest or plan.get("plan_id") != f"urn:sha256:{calculated_plan_digest}":
        raise EvidenceBundleError("migration plan canonical digest is inconsistent")
    snapshot_digest = snapshot["digest"]["value"]
    if snapshot["snapshot_id"] != f"urn:sha256:{snapshot_digest}":
        raise EvidenceBundleError("snapshot evidence identity is inconsistent")
    if plan["source_snapshot_id"] != snapshot["snapshot_id"] or plan["source_snapshot_digest"] != snapshot_digest:
        raise EvidenceBundleError("migration plan is not bound to the supplied snapshot")
    if snapshot["privacy_mode"] != "redacted" or plan["privacy_mode"] != "redacted" or plan["flash_ready"] is not False:
        raise EvidenceBundleError("bundle violates privacy or flash safety invariants")
    if report_path.stat().st_size > 524288:
        raise EvidenceBundleError("migration report exceeds the display limit")

    output_dir.mkdir(parents=True, exist_ok=True)
    snapshot_out = output_dir / "system-snapshot-v1.json"
    plan_out = output_dir / "migration-plan-v1.json"
    report_out = output_dir / "migration-report.md"
    if snapshot_path.resolve() != snapshot_out.resolve():
        shutil.copyfile(snapshot_path, snapshot_out)
    if plan_path.resolve() != plan_out.resolve():
        shutil.copyfile(plan_path, plan_out)
    if report_path.resolve() != report_out.resolve():
        shutil.copyfile(report_path, report_out)
    commit = producer_commit or _git_commit(repo_root)
    if not COMMIT_RE.fullmatch(commit):
        raise EvidenceBundleError("producer commit must be a lowercase 40-character SHA")

    bundle: dict[str, Any] = {
        "schema_version": "1.0.0",
        "bundle_id": "",
        "digest": "",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "producer": {"name": "smart-upgrade-migration-plan", "version": "1", "commit": commit},
        "validation": {
            "snapshot_schema": "passed",
            "plan_schema": "passed",
            "plan_canonical_digest": "passed",
        },
        "snapshot": {
            "filename": snapshot_out.name,
            "file_sha256": sha256_file(snapshot_out),
            "schema_version": snapshot["schema_version"],
            "snapshot_id": snapshot["snapshot_id"],
            "evidence_digest": snapshot_digest,
            "privacy_mode": snapshot["privacy_mode"],
        },
        "plan": {
            "filename": plan_out.name,
            "file_sha256": sha256_file(plan_out),
            "schema_version": plan["schema_version"],
            "plan_id": plan["plan_id"],
            "canonical_digest": plan["digest"],
            "privacy_mode": plan["privacy_mode"],
        },
        "report": {
            "filename": report_out.name,
            "file_sha256": sha256_file(report_out),
            "format": "markdown",
        },
        "binding": {
            "source_snapshot_id": plan["source_snapshot_id"],
            "source_snapshot_digest": plan["source_snapshot_digest"],
        },
        "safety": {
            "build_allowed": plan["build_allowed"],
            "compatibility_validated": plan["compatibility_validated"],
            "dispatch_allowed": False,
            "flash_ready": False,
        },
    }
    digest = canonical_digest(bundle, ("bundle_id", "digest"))
    bundle["digest"] = digest
    bundle["bundle_id"] = f"urn:sha256:{digest}"
    validate_schema(bundle, repo_root / "schemas/luci-evidence-bundle-v1.json", "evidence bundle")
    manifest = output_dir / "luci-evidence-bundle-v1.json"
    manifest.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return bundle


def verify_bundle(bundle_dir: Path, repo_root: Path) -> dict[str, Any]:
    manifest_path = bundle_dir / "luci-evidence-bundle-v1.json"
    bundle = load_json(manifest_path)
    canonical_manifest = (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode()
    if manifest_path.read_bytes() != canonical_manifest:
        raise EvidenceBundleError("evidence bundle manifest bytes are not canonical")
    validate_schema(bundle, repo_root / "schemas/luci-evidence-bundle-v1.json", "evidence bundle")
    digest = canonical_digest(bundle, ("bundle_id", "digest"))
    if bundle["digest"] != digest or bundle["bundle_id"] != f"urn:sha256:{digest}":
        raise EvidenceBundleError("evidence bundle canonical digest is inconsistent")
    expected_names = {
        bundle["snapshot"]["filename"], bundle["plan"]["filename"],
        bundle["report"]["filename"], manifest_path.name,
    }
    if expected_names != set(BUNDLE_FILES):
        raise EvidenceBundleError("evidence bundle uses an unsupported filename set")
    for section in ("snapshot", "plan", "report"):
        path = bundle_dir / bundle[section]["filename"]
        if not path.is_file() or path.is_symlink():
            raise EvidenceBundleError(f"{section} evidence is not a regular file")
        if sha256_file(path) != bundle[section]["file_sha256"]:
            raise EvidenceBundleError(f"{section} file digest mismatch")
    snapshot = load_json(bundle_dir / bundle["snapshot"]["filename"])
    plan = load_json(bundle_dir / bundle["plan"]["filename"])
    validate_schema(snapshot, repo_root / "schemas/system-snapshot-v1.json", "snapshot")
    validate_schema(plan, repo_root / "schemas/migration-plan-v1.json", "migration plan")
    if canonical_digest(plan, ("plan_id", "digest")) != plan["digest"]:
        raise EvidenceBundleError("migration plan canonical digest mismatch")
    if bundle["snapshot"]["snapshot_id"] != snapshot["snapshot_id"] or bundle["plan"]["plan_id"] != plan["plan_id"]:
        raise EvidenceBundleError("bundle identity does not match evidence files")
    if plan["source_snapshot_id"] != snapshot["snapshot_id"] or plan["source_snapshot_digest"] != snapshot["digest"]["value"]:
        raise EvidenceBundleError("bundle contains mixed snapshot and plan evidence")
    return bundle


def publish_bundle(bundle_dir: Path, state_dir: Path, repo_root: Path) -> str:
    bundle = verify_bundle(bundle_dir, repo_root)
    generation = bundle["digest"]
    analyses = state_dir / "analyses"
    analyses.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending = Path(tempfile.mkdtemp(prefix=".pending.", dir=analyses))
    try:
        for name in BUNDLE_FILES:
            shutil.copyfile(bundle_dir / name, pending / name)
            (pending / name).chmod(0o600)
        verify_bundle(pending, repo_root)
        final = analyses / generation
        if final.exists():
            shutil.rmtree(pending)
        else:
            pending.rename(final)
        pointer_tmp = state_dir / f".current-analysis.{os.getpid()}"
        manifest_sha = sha256_file(final / "luci-evidence-bundle-v1.json")
        pointer_tmp.write_text(f"{generation} {manifest_sha}\n", encoding="ascii")
        pointer_tmp.chmod(0o600)
        pointer_tmp.replace(state_dir / "current-analysis")
    except Exception:
        if pending.exists():
            shutil.rmtree(pending)
        raise
    return generation
