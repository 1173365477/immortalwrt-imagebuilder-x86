#!/usr/bin/env python3
"""Create and verify the immutable evidence bundle consumed by the T15 UI."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
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
FILE_LIMITS = dict(zip(BUNDLE_FILES, (4194304, 8388608, 524288, 131072), strict=True))


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


def _validate_private_directory(path: Path, label: str, *, expected_uid: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceBundleError(f"{label} is unavailable: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceBundleError(f"{label} must be a real directory")
    if metadata.st_uid != expected_uid:
        raise EvidenceBundleError(f"{label} has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise EvidenceBundleError(f"{label} must use mode 0700")


def _validate_published_generation(path: Path, repo_root: Path, *, expected_uid: int) -> dict[str, Any]:
    _validate_private_directory(path, "published analysis generation", expected_uid=expected_uid)
    try:
        names = {entry.name for entry in path.iterdir()}
    except OSError as exc:
        raise EvidenceBundleError(f"published analysis generation cannot be listed: {exc}") from exc
    if names != set(BUNDLE_FILES):
        raise EvidenceBundleError("published analysis generation has an unexpected file set")
    for name in BUNDLE_FILES:
        evidence = path / name
        try:
            metadata = evidence.lstat()
        except OSError as exc:
            raise EvidenceBundleError(f"published {name} is unavailable: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise EvidenceBundleError(f"published {name} must be a regular file")
        if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise EvidenceBundleError(f"published {name} has unsafe ownership or mode")
    return verify_bundle(path, repo_root)


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
    for name, limit in FILE_LIMITS.items():
        try:
            info = (bundle_dir / name).lstat()
        except OSError as exc:
            raise EvidenceBundleError(f"bundle file unavailable: {name}") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise EvidenceBundleError(f"bundle file is unsafe or oversized: {name}")
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
    snapshot_digest = snapshot["digest"]["value"]
    if snapshot["snapshot_id"] != f"urn:sha256:{snapshot_digest}" or plan["plan_id"] != f"urn:sha256:{plan['digest']}":
        raise EvidenceBundleError("evidence identity is inconsistent")
    if (
        bundle["snapshot"]["evidence_digest"] != snapshot_digest
        or bundle["plan"]["canonical_digest"] != plan["digest"]
        or bundle["binding"]["source_snapshot_id"] != snapshot["snapshot_id"]
        or bundle["binding"]["source_snapshot_digest"] != snapshot_digest
        or snapshot["privacy_mode"] != "redacted"
        or plan["privacy_mode"] != "redacted"
        or plan["flash_ready"] is not False
        or bundle["safety"]["build_allowed"] != plan["build_allowed"]
        or bundle["safety"]["compatibility_validated"] != plan["compatibility_validated"]
    ):
        raise EvidenceBundleError("bundle binding or safety evidence is inconsistent")
    return bundle


def publish_bundle(bundle_dir: Path, state_dir: Path, repo_root: Path) -> str:
    bundle = verify_bundle(bundle_dir, repo_root)
    generation = bundle["digest"]
    expected_uid = os.geteuid()
    for parent in state_dir.absolute().parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, expected_uid}:
            raise EvidenceBundleError("publisher state path has an unsafe ancestor")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise EvidenceBundleError("publisher state path has a writable ancestor")
    _validate_private_directory(state_dir, "publisher state directory", expected_uid=expected_uid)
    analyses = state_dir / "analyses"
    if analyses.exists() or analyses.is_symlink():
        _validate_private_directory(analyses, "publisher analyses directory", expected_uid=expected_uid)
    else:
        try:
            analyses.mkdir(mode=0o700, exist_ok=True)
        except OSError as exc:
            raise EvidenceBundleError(f"publisher analyses directory cannot be created: {exc}") from exc
        _validate_private_directory(analyses, "publisher analyses directory", expected_uid=expected_uid)
    pointer = state_dir / "current-analysis"
    if pointer.exists() or pointer.is_symlink():
        try:
            pointer_metadata = pointer.lstat()
        except OSError as exc:
            raise EvidenceBundleError(f"current analysis pointer is unavailable: {exc}") from exc
        if (stat.S_ISLNK(pointer_metadata.st_mode) or
                not stat.S_ISREG(pointer_metadata.st_mode) or
                pointer_metadata.st_uid != expected_uid or
                stat.S_IMODE(pointer_metadata.st_mode) != 0o600):
            raise EvidenceBundleError("current analysis pointer is unsafe")
    pending = Path(tempfile.mkdtemp(prefix=".pending.", dir=analyses))
    pointer_tmp = None
    directory_fd = None
    try:
        for name in BUNDLE_FILES:
            shutil.copyfile(bundle_dir / name, pending / name)
            (pending / name).chmod(0o600)
        if verify_bundle(pending, repo_root)["digest"] != generation:
            raise EvidenceBundleError("source generation changed during staging")
        directory_fd = os.open(analyses, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        final = analyses / generation
        if final.exists() or final.is_symlink():
            existing = _validate_published_generation(final, repo_root, expected_uid=expected_uid)
            if existing["digest"] != generation:
                raise EvidenceBundleError("published analysis generation identity is inconsistent")
            shutil.rmtree(pending)
        else:
            pending.rename(final)
            _validate_published_generation(final, repo_root, expected_uid=expected_uid)
        manifest_sha = sha256_file(final / "luci-evidence-bundle-v1.json")
        fd, tmp_name = tempfile.mkstemp(prefix=".current-analysis.", dir=state_dir)
        pointer_tmp = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(f"{generation} {manifest_sha}\n")
        pointer_tmp.replace(pointer)
    except Exception:
        if pending.exists():
            shutil.rmtree(pending)
        if pointer_tmp is not None:
            pointer_tmp.unlink(missing_ok=True)
        raise
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
    return generation
