#!/usr/bin/env python3
"""Explicitly adapt historical system-analysis.json into a blocked v1 snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def adapt(analysis: dict) -> dict:
    canonical = json.dumps(analysis, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    names = sorted(set(analysis.get("installed_packages", [])) | set(analysis.get("packages", {})))
    top_level = sorted(set(analysis.get("top_level_packages", [])))
    installed = []
    for name in names:
        details = analysis.get("packages", {}).get(name, {})
        installed.append({
            "name": name,
            "version": details.get("from"),
            "origin": "unknown",
            "install_reason": "manual" if name in top_level else "unknown",
            "confidence": "low",
            "evidence": ["legacy-system-analysis-adapter"],
            "dependencies_raw": None,
            "depends": [],
            "provides_raw": None,
        })
    sys_type = str(analysis.get("sys_type") or "").lower()
    boot_mode = "efi" if "efi" in sys_type else "unknown"
    service = {
        "package_detected": None, "executable_exists": None,
        "service_definition_exists": None, "running": "unknown",
    }
    return {
        "schema_version": "1.0.0",
        "snapshot_id": f"urn:sha256:{digest}",
        "digest": {"algorithm": "sha256", "canonicalization": "legacy-analysis-adapter-v1", "value": digest},
        "status": "blocked",
        "privacy_mode": "redacted",
        "system": {
            "distribution": str(analysis.get("distribution") or "unknown"),
            "version": analysis.get("source_version"), "target": analysis.get("target"),
            "profile": analysis.get("profile"), "architecture": None,
            "package_architecture": None, "kernel_architecture": None,
            "boot_mode": boot_mode, "boot_evidence": "no_affirmative_evidence",
            "rootfs_type": str(analysis.get("rootfs_type") or "unknown"),
            "firmware_image_type": str(analysis.get("sys_type") or "unknown"),
            "package_manager": "unknown", "identity_status": "unknown",
            "identity_errors": ["legacy analysis lacks raw identity evidence"],
        },
        "packages": {
            "installed": installed, "top_level": top_level,
            "intent_candidates": [], "classification_status": "partial", "truncated": False,
        },
        "services": {name: dict(service) for name in ("openclash", "lucky", "adguardhome", "docker")},
        "storage": {
            "status": "unknown", "evidence_digest": "0" * 64,
            "scan_completeness": {"containers": "unavailable", "volumes": "unavailable", "mounts": "unavailable", "container_scope": "unknown", "volume_scope": "unknown"},
            "docker": {"installed": False, "daemon_state": "unknown", "root": None, "configured_root": None, "root_source": "none", "verified": False, "config_mismatch": False},
            "mount_inventory": {"state": "missing", "truncated": False, "entries": []},
            "targets": [], "errors": ["legacy analysis contains no storage evidence"],
        },
        "warnings": ["legacy adapter cannot reconstruct identity, package provenance, boot, or storage evidence"],
        "errors": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", type=Path, default=Path("generated/system-analysis.json"))
    parser.add_argument("--output", type=Path, default=Path("generated/system-snapshot-v1.json"))
    args = parser.parse_args()
    try:
        snapshot = adapt(json.loads(args.analysis.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::{exc}")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Legacy analysis adapted with status=blocked; missing evidence was not inferred")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
