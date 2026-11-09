#!/usr/bin/env python3
"""Generate a fail-closed migration-plan-v1 from a validated system snapshot."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse


SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
APK_DEPENDENCY_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.+:-]*)(?:(?P<operator><=|>=|=|<|>)(?P<version>\S+))?$"
)
PROTECTED_PACKAGES = {
    "apk", "opkg", "base-files", "busybox", "procd", "ubus", "uci",
    "netifd", "firewall4", "dnsmasq", "dnsmasq-full", "odhcpd", "dropbear",
}


def canonical_digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def _apk_version_compare(candidate: str, required: str) -> str | None:
    """Compare versions with apk-tools itself; return <, =, > or fail closed."""
    apk = shutil.which("apk")
    if not apk:
        return None
    try:
        process = subprocess.run(
            [apk, "version", "-t", candidate, required],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    result = process.stdout.strip()
    return result if process.returncode == 0 and result in {"<", "=", ">"} else None


def _apk_dependency_result(
    dependency: str,
    official_index: dict[str, Any],
    provider_versions: dict[str, str],
) -> tuple[bool, str | None]:
    match = APK_DEPENDENCY_RE.fullmatch(dependency)
    if not match:
        return False, f"unsupported APK dependency expression: {dependency!r}"
    name = match.group("name")
    operator = match.group("operator")
    required_version = match.group("version")
    if name in provider_versions:
        candidate_version = provider_versions[name]
    else:
        package = official_index.get(name)
        if not isinstance(package, dict):
            return False, f"APK dependency is absent from the target index: {name}"
        candidate_version = package.get("version")
    if operator is None:
        return True, None
    if not isinstance(candidate_version, str) or not candidate_version:
        return False, f"APK dependency {name} lacks a target version"
    if not required_version:
        return False, f"APK dependency {name} has an incomplete version constraint"
    comparison = _apk_version_compare(candidate_version, required_version)
    if comparison is None:
        return False, f"APK dependency {dependency} could not be compared with apk-tools"
    accepted = {
        "=": {"="}, "<": {"<"}, "<=": {"<", "="},
        ">": {">"}, ">=": {">", "="},
    }[operator]
    if comparison not in accepted:
        return False, (
            f"APK dependency {dependency} is not satisfied by target version {candidate_version}"
        )
    return True, None


def _provider_map(rules: dict[str, Any]) -> dict[str, str]:
    return {
        package: provider
        for provider, config in rules.get("providers", {}).items()
        for package in config.get("packages", [])
    }


def _exclusion_map(
    exclusions: list[dict[str, Any]], snapshot: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    result: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    digest = snapshot["digest"]["value"]
    version = snapshot["system"].get("version")
    for row in exclusions:
        package = row.get("package")
        if not package or package in result:
            errors.append("explicit exclusion has a missing or duplicate package")
            continue
        if row.get("snapshot_digest") != digest or row.get("source_version") != version:
            errors.append(f"explicit exclusion for {package} is not bound to this snapshot/version")
        if row.get("optional") is not True or not row.get("reason"):
            errors.append(f"explicit exclusion for {package} lacks an optional assertion and reason")
        result[package] = row
    return result, errors


def _metadata_list(metadata: Any, key: str) -> list[str]:
    if not isinstance(metadata, dict):
        return []
    value = metadata.get(key, [])
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value] if isinstance(value, list) else []


def _thirdparty_compatibility(
    provider: str,
    package: str,
    provider_rule: dict[str, Any],
    status: dict[str, Any],
    capabilities: dict[str, Any],
    official_index: dict[str, Any],
    thirdparty_files: dict[str, str],
    source_dependencies: set[str],
    trusted_evidence_digests: set[str],
) -> tuple[bool, str]:
    if status.get("status") != "compatible":
        return False, "provider status is not compatible"
    evidence_digest = status.get("evidence_digest")
    payload = dict(status)
    payload.pop("evidence_digest", None)
    if not SHA256_RE.fullmatch(str(evidence_digest or "")) or canonical_digest(payload) != evidence_digest:
        return False, "provider compatibility evidence digest is missing or inconsistent"
    if evidence_digest not in trusted_evidence_digests:
        return False, "provider evidence was not authenticated against the trusted upstream"
    if status.get("provider") != provider or status.get("rule_version") != provider_rule.get("rule_version"):
        return False, "provider identity or rule version does not match"
    if status.get("repository") != provider_rule.get("repository"):
        return False, "provider repository does not match the trusted rule"
    if not isinstance(status.get("release_id"), int):
        return False, "upstream release identity is missing"
    if package not in status.get("packages", []) or package not in provider_rule.get("packages", []):
        return False, "provider evidence does not cover this package"

    target = status.get("target")
    expected_target = {
        "distribution": capabilities.get("distribution"),
        "version": capabilities.get("target_version"),
        "target": capabilities.get("target"),
        "profile": capabilities.get("profile"),
        "architecture": capabilities.get("arch"),
        "package_manager": capabilities.get("package_manager"),
        "resolution_digest": capabilities.get("resolution_digest"),
        "official_index_digest": capabilities.get("official_index_digest"),
    }
    if target != expected_target:
        return False, "provider evidence is bound to a different target release or architecture"
    if capabilities.get("official_index_digest") != canonical_digest(official_index):
        return False, "official dependency index digest is inconsistent"

    dependency_evidence = status.get("official_dependencies")
    required = sorted(set(provider_rule.get("official_dependencies", [])))
    if not isinstance(dependency_evidence, dict):
        return False, "official dependency evidence is missing"
    if dependency_evidence.get("required") != required or dependency_evidence.get("missing") != []:
        return False, "official dependency resolution is incomplete"
    if dependency_evidence.get("index_digest") != capabilities.get("official_index_digest"):
        return False, "official dependency evidence uses a different index"
    absent = sorted(set(required) - set(official_index))
    if absent:
        return False, "official dependencies are absent: " + ", ".join(absent)
    unresolved_source_dependencies = sorted(
        source_dependencies - set(official_index) - set(provider_rule.get("packages", []))
    )
    if unresolved_source_dependencies:
        return False, "source package dependencies are unresolved: " + ", ".join(unresolved_source_dependencies)

    assets = status.get("assets")
    if not isinstance(assets, list) or not assets:
        return False, "verified upstream asset evidence is missing"
    repository_prefix = f"/{provider_rule.get('repository')}/releases/download/"
    for asset in assets:
        parsed = urlparse(str(asset.get("url") or "")) if isinstance(asset, dict) else None
        if (
            not isinstance(asset, dict)
            or asset.get("provider") != provider
            or not isinstance(asset.get("asset_id"), int)
            or not asset.get("asset")
            or not SHA256_RE.fullmatch(str(asset.get("sha256") or ""))
            or parsed is None
            or parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or not parsed.path.startswith(repository_prefix)
        ):
            return False, "upstream asset identity or SHA-256 evidence is invalid"

    apk_checks = status.get("apk_checks")
    if not isinstance(apk_checks, list) or not apk_checks:
        return False, "APK validation evidence is missing"
    target_arch = capabilities.get("arch")
    verified_packages: set[str] = set()
    verified_dependencies: list[str] = []
    provider_versions: dict[str, str] = {}
    for check in apk_checks:
        relative = PurePosixPath(str(check.get("file") or ""))
        if (
            not isinstance(check, dict)
            or not str(check.get("file") or "").endswith(".apk")
            or check.get("magic_verified") is not True
            or check.get("metadata_status") != "verified"
            or not SHA256_RE.fullmatch(str(check.get("sha256") or ""))
            or check.get("architecture") not in {"all", "noarch", target_arch}
            or check.get("package") not in provider_rule.get("packages", [])
            or not check.get("version")
            or not isinstance(check.get("dependencies"), list)
            or relative.is_absolute()
            or len(relative.parts) != 2
            or relative.parts[0] != provider
            or ".." in relative.parts
        ):
            return False, "APK hash, format, or architecture evidence is invalid"
        if thirdparty_files.get(check["file"]) != check["sha256"]:
            return False, "bundled APK is missing or does not match compatibility evidence"
        verified_packages.add(check["package"])
        provider_versions[check["package"]] = check["version"]
        for dependency in check["dependencies"]:
            if not isinstance(dependency, str) or not dependency:
                return False, "APK dependency metadata cannot be resolved safely"
            verified_dependencies.append(dependency)
    if verified_packages != set(provider_rule.get("packages", [])):
        return False, "verified APK package identities do not cover the provider rule"
    for dependency in verified_dependencies:
        satisfied, reason = _apk_dependency_result(
            dependency, official_index, provider_versions
        )
        if not satisfied:
            return False, reason or "APK dependency constraint is unresolved"
    if not status.get("upstream_release"):
        return False, "upstream release identity is missing"
    return True, "verified provider, release, asset, APK, architecture and dependency evidence matched"


def generate_plan(
    snapshot: dict[str, Any],
    capabilities: dict[str, Any],
    official_index: dict[str, Any],
    thirdparty_rules: dict[str, Any],
    thirdparty_status: dict[str, Any] | None = None,
    exclusions: list[dict[str, Any]] | None = None,
    *,
    package_rules: dict[str, Any] | None = None,
    thirdparty_files: dict[str, str] | None = None,
    trusted_thirdparty_evidence: set[str] | None = None,
    strict_mode: bool = True,
) -> dict[str, Any]:
    thirdparty_status = thirdparty_status or {}
    exclusions = exclusions or []
    package_rules = package_rules or {}
    thirdparty_files = thirdparty_files or {}
    trusted_thirdparty_evidence = trusted_thirdparty_evidence or set()
    blockers: list[str] = []
    warnings = list(snapshot.get("warnings", []))
    errors = list(snapshot.get("errors", []))
    snap_digest = snapshot.get("digest", {}).get("value")
    snap_id = snapshot.get("snapshot_id")
    if snap_id != f"urn:sha256:{snap_digest}":
        errors.append("snapshot ID/digest mismatch")
    if snapshot.get("status") != "ok":
        blockers.append(
            f"snapshot status is {snapshot.get('status', 'unknown')}; complete evidence is required"
        )
    package_set = snapshot.get("packages", {})
    if package_set.get("classification_status") != "complete" or package_set.get("truncated"):
        blockers.append("installed/top-level package evidence is incomplete or truncated")

    frozen = dict(capabilities)
    resolution_digest = frozen.pop("resolution_digest", None)
    if not resolution_digest or canonical_digest(frozen) != resolution_digest:
        errors.append("release resolution digest mismatch")
    if capabilities.get("channel") != "release":
        blockers.append("target is not a formal release")
    if capabilities.get("support_status") != "supported":
        blockers.append("target platform build support is not established")
    if capabilities.get("official_index_digest") != canonical_digest(official_index):
        errors.append("official package index digest mismatch")
    if not official_index:
        errors.append("official package index is missing or empty")

    system = snapshot.get("system", {})
    compatibility = "compatible"
    identity_checks = {
        "target": (system.get("target"), capabilities.get("target")),
        "profile": (system.get("profile"), capabilities.get("profile")),
        "architecture": (system.get("package_architecture"), capabilities.get("arch")),
    }
    for label, (source_value, target_value) in identity_checks.items():
        if not source_value or source_value != target_value:
            blockers.append(
                f"source {label} {source_value!r} does not match target {target_value!r}"
            )
            compatibility = "incompatible" if source_value else "unknown"
    boot_mode = system.get("boot_mode", "unknown")
    image_type = capabilities.get("image_type")
    if boot_mode == "unknown":
        blockers.append("boot mode is unknown; selected image compatibility cannot be proven")
        compatibility = "unknown"
    elif boot_mode == "efi" and image_type != "combined-efi":
        blockers.append("EFI source requires a combined-efi image")
        compatibility = "incompatible"
    elif boot_mode == "bios" and image_type != "combined":
        blockers.append("Legacy BIOS source requires a combined image")
        compatibility = "incompatible"

    exclusion_map, exclusion_errors = _exclusion_map(exclusions, snapshot)
    errors.extend(exclusion_errors)
    provider_map = _provider_map(thirdparty_rules)
    replacements = {}
    target_version = str(capabilities.get("target_version") or "")
    series = ".".join(target_version.split(".")[:2])
    replacements.update(package_rules.get("replacements", {}))
    replacements.update(
        package_rules.get("version_rules", {}).get(series, {}).get("replacements", {})
    )
    decisions: list[dict[str, Any]] = []
    installed_names = {row["name"] for row in package_set.get("installed", [])}
    for excluded in sorted(set(exclusion_map) - installed_names):
        errors.append(f"explicit exclusion names package not present in snapshot: {excluded}")
    top_level = set(package_set.get("top_level", []))
    protected_packages = PROTECTED_PACKAGES | set(package_rules.get("always_keep", []))
    optional_exclusions = set(package_rules.get("optional_exclusions", []))
    required_by: dict[str, set[str]] = {}
    for installed in package_set.get("installed", []):
        for dependency in installed.get("depends", []):
            if dependency.get("relation") == "package" and dependency.get("name"):
                required_by.setdefault(dependency["name"], set()).add(installed["name"])

    for package in package_set.get("installed", []):
        name = package["name"]
        evidence = list(package.get("evidence") or ["system-snapshot-v1"])
        base = {
            "package": name,
            "source_version": package.get("version"),
            "origin": package.get("origin", "unknown"),
            "install_reason": package.get("install_reason", "unknown"),
            "target_package": None,
            "provider": None,
            "dependencies": [dep.get("raw", "") for dep in package.get("depends", [])],
            "replacements": [],
            "conflicts": [],
            "evidence": evidence,
        }
        provider = provider_map.get(name)
        is_thirdparty = bool(provider or package.get("origin") == "third_party")
        if name in exclusion_map:
            row = exclusion_map[name]
            dependents = sorted(required_by.get(name, set()) - set(exclusion_map))
            if is_thirdparty:
                reason = "third-party package exclusion is safety-critical and cannot be treated as compatible"
            elif name in protected_packages:
                reason = "system-critical or explicitly preserved package cannot be excluded"
            elif dependents:
                reason = "exclusion would break required packages: " + ", ".join(dependents)
            elif name not in optional_exclusions:
                reason = "package is not proven optional by the versioned package policy"
            else:
                decisions.append(
                    {**base, "evidence": [*evidence, "package-policy:optional_exclusions"], "decision": "skip", "match_type": "explicit_exclusion", "compatible": True, "reason": row["reason"]}
                )
                continue
            decisions.append(
                {**base, "decision": "block", "match_type": "unresolved", "compatible": None, "reason": reason}
            )
            blockers.append(f"explicit exclusion rejected for {name}: {reason}")
            continue
        if is_thirdparty:
            base["provider"] = provider
            provider_rule = thirdparty_rules.get("providers", {}).get(provider or "", {})
            status = thirdparty_status.get(provider or "", {})
            verified, reason = _thirdparty_compatibility(
                provider or "", name, provider_rule, status, capabilities,
                official_index, thirdparty_files,
                {
                    dependency["name"] for dependency in package.get("depends", [])
                    if dependency.get("relation") == "package" and dependency.get("name")
                },
                trusted_thirdparty_evidence,
            )
            if verified and not (package.get("install_reason") == "manual" and name not in top_level):
                evidence.append(f"thirdparty-evidence:{status['evidence_digest']}")
                decisions.append(
                    {**base, "evidence": evidence, "decision": "keep", "target_package": name, "match_type": "third_party", "compatible": True, "reason": reason}
                )
            else:
                if verified:
                    reason = "manual third-party package is absent from the complete top-level manifest"
                decisions.append(
                    {**base, "decision": "block", "match_type": "unresolved", "compatible": None, "reason": reason}
                )
                blockers.append(f"required third-party package {name} is unresolved: {reason}")
            continue
        if package.get("install_reason") == "manual" and name not in top_level:
            decisions.append(
                {**base, "decision": "review", "match_type": "unresolved", "compatible": None, "reason": "manual package is absent from the complete top-level manifest"}
            )
            blockers.append(f"manual package {name} may be silently omitted")
            continue
        if package.get("install_reason") in {"dependency", "system_default"}:
            metadata = official_index.get(name)
            same_manager = system.get("package_manager") == capabilities.get("package_manager")
            if package.get("origin") == "official" and metadata is not None and same_manager:
                decisions.append(
                    {**base, "decision": "skip", "match_type": "dependency_recalculation", "compatible": True, "reason": "same-package-manager target index proves the resolver can recalculate this official default/dependency"}
                )
            else:
                decisions.append(
                    {**base, "decision": "block", "match_type": "unresolved", "compatible": None, "reason": "dependency/default omission lacks trusted target index and package-manager evidence"}
                )
                blockers.append(f"dependency/default package {name} cannot be safely omitted")
            continue
        replacement = replacements.get(name)
        if replacement:
            if replacement not in official_index:
                decisions.append(
                    {**base, "decision": "block", "match_type": "unresolved", "compatible": None, "reason": f"replacement {replacement} is absent from the official index"}
                )
                blockers.append(f"required replacement {replacement} for {name} is missing")
            else:
                decisions.append(
                    {**base, "decision": "replace", "target_package": replacement, "match_type": "replacement", "compatible": True, "replacements": [name], "reason": f"versioned replacement rule selects {replacement}"}
                )
            continue
        metadata = official_index.get(name)
        same_manager = system.get("package_manager") == capabilities.get("package_manager")
        if metadata is not None and package.get("origin") == "official" and same_manager:
            missing_dependencies = sorted({
                dep.get("name") for dep in package.get("depends", [])
                if dep.get("relation") == "package" and dep.get("name")
                and dep.get("name") not in official_index and dep.get("name") not in installed_names
            })
            conflicts = _metadata_list(metadata, "conflicts")
            unresolved_conflicts = sorted(set(conflicts) & installed_names)
            if missing_dependencies:
                decisions.append(
                    {**base, "decision": "block", "match_type": "official", "compatible": None, "dependencies": base["dependencies"], "reason": f"required dependencies are absent from the target index: {', '.join(missing_dependencies)}"}
                )
                blockers.append(f"required dependencies for {name} are missing: {', '.join(missing_dependencies)}")
            elif unresolved_conflicts:
                decisions.append(
                    {**base, "decision": "block", "match_type": "official", "compatible": None, "conflicts": unresolved_conflicts, "reason": "target package conflicts with another installed package"}
                )
                blockers.append(
                    f"unresolved package conflict for {name}: {', '.join(unresolved_conflicts)}"
                )
            else:
                decisions.append(
                    {**base, "decision": "keep", "target_package": name, "match_type": "official", "compatible": True, "reason": "same package manager and frozen official index entry matched"}
                )
        elif metadata is not None and package.get("origin") == "official":
            decisions.append(
                {**base, "decision": "review", "match_type": "unresolved", "compatible": None, "reason": "OPKG/APK migration requires replacement or binary compatibility evidence; name equality is insufficient"}
            )
            blockers.append(f"package-manager transition for {name} lacks compatibility evidence")
        else:
            decisions.append(
                {**base, "decision": "block", "match_type": "unresolved", "compatible": None, "reason": "package has no trusted official or third-party target match"}
            )
            blockers.append(f"required package {name} has no trusted target match")

    decision_names = [row["package"] for row in decisions]
    if len(decision_names) != len(set(decision_names)) or set(decision_names) != installed_names:
        errors.append("migration decisions do not cover every installed package exactly once")
    counts = Counter(row["decision"] for row in decisions)
    storage = snapshot.get("storage", {})
    risks = sorted(
        {row.get("firmware_overwrite_risk", "unknown") for row in storage.get("targets", [])}
    )
    flash_blockers = ["MVP v1 never authorizes flashing"]
    if storage.get("status") != "ok":
        flash_blockers.append("storage evidence is incomplete")
    if "same_physical_disk" in risks or "unknown" in risks:
        flash_blockers.append("Docker/storage data may be overwritten by a full-disk image")
    warnings.extend(flash_blockers[1:])

    blockers = sorted(set(blockers))
    warnings = sorted(set(warnings))
    errors = sorted(set(errors))
    status = "failed" if errors else "blocked" if blockers else "ok"
    build_allowed = status == "ok" and compatibility == "compatible"
    plan = {
        "schema_version": "1.0.0",
        "plan_id": "",
        "digest": "",
        "source_snapshot_id": snap_id,
        "source_snapshot_digest": snap_digest,
        "status": status,
        "privacy_mode": snapshot.get("privacy_mode", "redacted"),
        "source": {
            "distribution": system.get("distribution", "unknown"),
            "version": system.get("version"), "target": system.get("target"),
            "profile": system.get("profile"), "architecture": system.get("package_architecture"),
            "package_manager": system.get("package_manager", "unknown"), "boot_mode": boot_mode,
        },
        "target": {
            "distribution": capabilities.get("distribution"), "version": capabilities.get("target_version"),
            "target": capabilities.get("target"), "profile": capabilities.get("profile"),
            "architecture": capabilities.get("arch"), "package_manager": capabilities.get("package_manager"),
            "boot_mode": boot_mode, "image_type": image_type,
            "image_name": capabilities.get("expected_image_name"),
            "image_sha256": capabilities.get("expected_image_sha256"), "compatibility": compatibility,
        },
        "release": {key: capabilities.get(key) for key in (
            "channel", "resolution_digest", "profiles_url", "profiles_sha256",
            "official_index_digest", "package_index_sources", "imagebuilder_url", "imagebuilder_sha256",
        )},
        "package_summary": {
            "installed": len(decisions),
            **{name: counts[name] for name in ("keep", "replace", "skip", "review", "block")},
        },
        "storage_risk": {
            "status": storage.get("status", "unknown"),
            "docker_present": bool(storage.get("docker", {}).get("installed")),
            "firmware_overwrite_risks": risks, "flash_blockers": flash_blockers,
        },
        "explicit_exclusions": exclusions,
        "strict_mode": strict_mode, "build_allowed": build_allowed,
        "build_status": "not_started", "compatibility_validated": False, "flash_ready": False,
        "decisions": decisions, "blockers": blockers, "warnings": warnings, "errors": errors,
    }
    identity = dict(plan)
    identity.pop("plan_id")
    identity.pop("digest")
    plan_digest = canonical_digest(identity)
    plan["digest"] = plan_digest
    plan["plan_id"] = f"urn:sha256:{plan_digest}"
    return plan


def write_legacy_outputs(plan: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    groups: dict[str, list[str]] = {
        name: [] for name in ("official", "thirdparty", "missing", "replaced", "skipped")
    }
    decision_map = {}
    for row in plan["decisions"]:
        name = row["package"]
        decision_map[name] = {
            "decision": row["decision"], "reason": row["reason"], "evidence": row["evidence"]
        }
        if row["decision"] in {"keep", "replace"} and row["match_type"] in {"official", "replacement"}:
            groups["official"].append(row["target_package"])
        if row["decision"] == "keep" and row["match_type"] == "third_party":
            groups["thirdparty"].append(f"{row['provider']}:{row['target_package']}")
        if row["decision"] in {"block", "review"}:
            groups["missing"].append(f"{name}\t{row['reason']}")
        if row["decision"] == "replace":
            groups["replaced"].append(
                f"{name} -> {row['target_package']}\t{row['reason']}"
            )
        if row["decision"] == "skip":
            groups["skipped"].append(f"{name}\t{row['reason']}")
    for name, rows in groups.items():
        content = "\n".join(sorted(set(rows))) + ("\n" if rows else "")
        (output / f"packages-{name}.txt").write_text(content, encoding="utf-8")
    (output / "package-decisions.json").write_text(
        json.dumps(decision_map, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report = [
        "# Migration plan", "", f"- Status: `{plan['status']}`",
        f"- Build allowed: `{str(plan['build_allowed']).lower()}`", "- Flash ready: `false`",
        "", "## Blockers", "",
    ]
    report.extend(f"- {row}" for row in plan["blockers"] or ["None"])
    report += ["", "## Package decisions", ""]
    report.extend(
        f"- `{row['package']}`: **{row['decision']}** — {row['reason']}"
        for row in plan["decisions"]
    )
    (output / "migration-report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
