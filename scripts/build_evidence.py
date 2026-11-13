#!/usr/bin/env python3
"""Immutable T13 build-input verification and build provenance helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator


HEX_RE = re.compile(r"^[a-f0-9]{64}$")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
REQUEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class EvidenceError(ValueError):
    """A build input is not safe or does not match its frozen evidence."""


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
        raise EvidenceError(f"cannot read JSON evidence {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"JSON evidence must be an object: {path}")
    return value


def validate_schema(value: dict[str, Any], schema_path: Path, label: str) -> None:
    try:
        Draft202012Validator(load_json(schema_path)).validate(value)
    except Exception as exc:
        raise EvidenceError(f"{label} schema validation failed: {exc}") from exc


def safe_path(root: Path, raw: str, *, file: bool = True) -> Path:
    if not isinstance(raw, str) or not raw:
        raise EvidenceError("evidence path is empty")
    pure = PurePosixPath(raw)
    if pure.is_absolute() or ".." in pure.parts or any(part in {"", "."} for part in pure.parts):
        raise EvidenceError(f"unsafe evidence path: {raw!r}")
    candidate = root.joinpath(*pure.parts)
    cursor = root
    for part in pure.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise EvidenceError(f"symlink is forbidden in evidence path: {raw!r}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"evidence path escapes or is missing: {raw!r}") from exc
    if candidate.is_symlink() or (file and not resolved.is_file()) or (not file and not resolved.is_dir()):
        raise EvidenceError(f"invalid evidence path type: {raw!r}")
    return resolved


def tree_digest(directory: Path) -> str:
    records: list[dict[str, str]] = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise EvidenceError(f"symlink is forbidden in frozen files tree: {path}")
        if path.is_file():
            records.append({"path": path.relative_to(directory).as_posix(), "sha256": sha256_file(path)})
    return canonical_digest(records)


def _expect_sha(path: Path, expected: Any, label: str) -> None:
    if not isinstance(expected, str) or not HEX_RE.fullmatch(expected) or sha256_file(path) != expected:
        raise EvidenceError(f"{label} file SHA256 mismatch")


def _decision_packages(plan: dict[str, Any]) -> set[str]:
    packages: set[str] = set()
    for row in plan.get("decisions", []):
        if (row.get("decision") in {"keep", "replace"}
                and row.get("match_type") in {"official", "replacement"}):
            target = row.get("target_package") or row.get("package")
            if isinstance(target, str):
                packages.add(target)
    return packages


def _package_tokens(path: Path) -> set[str]:
    tokens = path.read_text(encoding="utf-8").split()
    invalid = [token for token in tokens if not re.fullmatch(r"-?[A-Za-z0-9][A-Za-z0-9+_.@-]*", token)]
    if invalid:
        raise EvidenceError(f"invalid package token in frozen package list: {invalid[0]!r}")
    if len(tokens) != len(set(tokens)):
        raise EvidenceError("frozen package list contains duplicate tokens")
    return set(tokens)


def trusted_base_packages(path: Path) -> list[str]:
    values = [
        line.strip() for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(values) != len(set(values)) or any(
        not re.fullmatch(r"-?[A-Za-z0-9][A-Za-z0-9+_.@-]*", value) for value in values
    ):
        raise EvidenceError("trusted base package configuration is invalid")
    return values


def verify_build_input(
    input_path: Path,
    repo_root: Path,
    *,
    expected_repository: str,
    expected_commit: str,
    stage_dir: Path | None = None,
    revalidate_upstream: bool = True,
) -> dict[str, Any]:
    repo_root = repo_root.resolve(strict=True)
    build_input = load_json(input_path)
    validate_schema(build_input, repo_root / "schemas/build-input-v1.json", "build input")
    digest = canonical_digest(build_input, ("build_input_id", "digest"))
    if build_input["digest"] != digest or build_input["build_input_id"] != f"urn:sha256:{digest}":
        raise EvidenceError("build input ID/digest mismatch")
    if not REQUEST_RE.fullmatch(build_input["request_id"]):
        raise EvidenceError("request_id is not safe")

    build = build_input["build"]
    if build["repository"] != expected_repository:
        raise EvidenceError("repository identity does not match the trusted runtime")
    if not SHA_RE.fullmatch(expected_commit):
        raise EvidenceError("trusted runtime Git commit is invalid")
    code_commit = build["git_commit_sha"]
    if code_commit != expected_commit:
        protected = ["scripts", "schemas", "config", ".github/workflows/build.yml",
                     "requirements.txt", "requirements-dev.txt"]
        try:
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", code_commit, expected_commit], cwd=repo_root,
                check=False, capture_output=True, timeout=10,
            )
            changed = subprocess.run(
                ["git", "diff", "--quiet", code_commit, expected_commit, "--", *protected],
                cwd=repo_root, check=False, capture_output=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise EvidenceError(f"cannot verify frozen build-code commit: {exc}") from exc
        if ancestor.returncode != 0 or changed.returncode != 0:
            raise EvidenceError("runtime build code differs from the frozen trusted code commit")
    safety = build_input["safety"]
    if not (safety["strict_mode"] and safety["build_allowed"]):
        raise EvidenceError("immutable build safety state does not allow a strict build")
    if safety["flash_ready"] is not False:
        raise EvidenceError("flash_ready must remain false")
    apk_policy = load_json(repo_root / "config/apk-tools-policy.json")
    if build["apk_tools_version"] != apk_policy.get("apk_tools_version"):
        raise EvidenceError("apk-tools comparator version is not the repository-pinned policy")
    if build["config_digest"] != canonical_digest(build, ("config_digest",)):
        raise EvidenceError("frozen build configuration digest mismatch")

    snap_ref = build_input["snapshot"]
    snapshot_path = safe_path(repo_root, snap_ref["path"])
    _expect_sha(snapshot_path, snap_ref["file_sha256"], "snapshot")
    snapshot = load_json(snapshot_path)
    validate_schema(snapshot, repo_root / "schemas/system-snapshot-v1.json", "snapshot")
    snap_digest = snapshot.get("digest", {}).get("value")
    if snapshot.get("snapshot_id") != f"urn:sha256:{snap_digest}":
        raise EvidenceError("snapshot ID/digest mismatch")
    if snap_ref["snapshot_id"] != snapshot["snapshot_id"] or snap_ref["snapshot_digest"] != snap_digest:
        raise EvidenceError("build input does not bind the supplied snapshot")

    plan_ref = build_input["migration_plan"]
    plan_path = safe_path(repo_root, plan_ref["path"])
    _expect_sha(plan_path, plan_ref["file_sha256"], "migration plan")
    plan = load_json(plan_path)
    validate_schema(plan, repo_root / "schemas/migration-plan-v1.json", "migration plan")
    plan_digest = canonical_digest(plan, ("plan_id", "digest"))
    if plan.get("digest") != plan_digest or plan.get("plan_id") != f"urn:sha256:{plan_digest}":
        raise EvidenceError("migration plan canonical digest mismatch")
    if plan_ref["plan_id"] != plan["plan_id"] or plan_ref["plan_digest"] != plan_digest:
        raise EvidenceError("build input does not bind the supplied migration plan")
    if plan["source_snapshot_id"] != snapshot["snapshot_id"] or plan["source_snapshot_digest"] != snap_digest:
        raise EvidenceError("migration plan does not bind the supplied snapshot")
    if plan["status"] != "ok" or not plan["build_allowed"]:
        raise EvidenceError("migration plan is not approved for an immutable build")
    if safety["build_allowed"] != plan["build_allowed"] or safety["compatibility_validated"] != plan["compatibility_validated"]:
        raise EvidenceError("build safety conclusions do not exactly match the migration plan")
    if plan["flash_ready"] is not False or plan["blockers"] or plan["errors"]:
        raise EvidenceError("migration plan contains a blocker or invalid flash state")

    target = build_input["target"]
    plan_target = plan["target"]
    bindings = {
        "distribution": "distribution", "version": "version",
        "profile": "profile", "architecture": "architecture", "package_manager": "package_manager",
        "image_type": "image_type",
    }
    for input_key, plan_key in bindings.items():
        if target[input_key] != plan_target[plan_key]:
            raise EvidenceError(f"target binding mismatch: {input_key}")
    if f"{target['target']}/{target['subtarget']}" != plan_target["target"]:
        raise EvidenceError("target/subtarget binding mismatch")
    if target["package_manager"] != "apk" or plan_target["compatibility"] != "compatible":
        raise EvidenceError("only a validated compatible APK target is supported")

    release = build_input["release"]
    for key in ("resolution_digest", "official_index_digest", "imagebuilder_url", "imagebuilder_sha256"):
        if release[key] != plan["release"][key]:
            raise EvidenceError(f"release binding mismatch: {key}")
    if release["identity"] != f"{target['distribution']}:{target['version']}:release":
        raise EvidenceError("release identity mismatch")
    if release["profiles_sha256"] != plan["release"]["profiles_sha256"] or release["package_index_sources"] != plan["release"]["package_index_sources"]:
        raise EvidenceError("release profile/index source evidence mismatch")
    capabilities_path = safe_path(repo_root, release["capabilities_path"])
    _expect_sha(capabilities_path, release["capabilities_file_sha256"], "release capabilities")
    capabilities = load_json(capabilities_path)
    frozen_capabilities = dict(capabilities)
    frozen_resolution = frozen_capabilities.pop("resolution_digest", None)
    if frozen_resolution != release["resolution_digest"] or canonical_digest(frozen_capabilities) != frozen_resolution:
        raise EvidenceError("release resolution digest is not reproducible")
    capability_binding = (
        capabilities.get("distribution"), capabilities.get("target_version"), capabilities.get("target"),
        capabilities.get("profile"), capabilities.get("arch"), capabilities.get("package_manager"),
        capabilities.get("filesystem"), capabilities.get("image_type"), capabilities.get("expected_image_name"),
        capabilities.get("imagebuilder_url"), capabilities.get("imagebuilder_sha256"),
        capabilities.get("official_index_digest"),
    )
    input_binding = (
        target["distribution"], target["version"], plan_target["target"], target["profile"],
        target["architecture"], target["package_manager"],
        target["filesystem"], target["image_type"], target["expected_image_name"],
        release["imagebuilder_url"], release["imagebuilder_sha256"], release["official_index_digest"],
    )
    if capability_binding != input_binding:
        raise EvidenceError("release capabilities do not bind the requested target")
    if (capabilities.get("profiles_sha256") != release["profiles_sha256"]
            or capabilities.get("package_index_sources") != release["package_index_sources"]
            or capabilities.get("imagebuilder_filename") != release["imagebuilder_filename"]):
        raise EvidenceError("release capability source or ImageBuilder identity mismatch")
    official_path = safe_path(repo_root, release["official_index_path"])
    _expect_sha(official_path, release["official_index_file_sha256"], "official package index")
    official_index = load_json(official_path)
    if canonical_digest(official_index) != release["official_index_digest"]:
        raise EvidenceError("official package index canonical digest mismatch")

    storage = plan["storage_risk"]
    if storage["status"] != "ok" or any(risk in {"unknown", "same_physical_disk"} for risk in storage["firmware_overwrite_risks"]):
        raise EvidenceError("storage evidence is incomplete for the formal build gate")

    packages_path = safe_path(repo_root, build["packages_path"])
    _expect_sha(packages_path, build["packages_sha256"], "package list")
    actual_packages = _package_tokens(packages_path)
    trusted_base = trusted_base_packages(repo_root / "config/base-packages.txt")
    if build["base_packages"] != trusted_base:
        raise EvidenceError("build base_packages differ from the trusted versioned baseline")
    approved_packages = _decision_packages(plan) | set(build["base_packages"])
    if actual_packages != approved_packages:
        raise EvidenceError("frozen package list differs from approved plan decisions and baseline")
    missing_official = sorted(
        package for package in actual_packages if not package.startswith("-") and package not in official_index
    )
    if missing_official:
        raise EvidenceError(f"approved ImageBuilder package is absent from the frozen index: {missing_official[0]}")

    files_path = safe_path(repo_root, build["files_path"], file=False)
    if tree_digest(files_path) != build["files_digest"]:
        raise EvidenceError("frozen files tree digest mismatch")

    providers = build_input["thirdparty"]
    required_thirdparty: dict[str, set[str]] = {}
    required_evidence: dict[str, set[str]] = {}
    for decision in plan.get("decisions", []):
        if decision.get("decision") not in {"keep", "replace"} or decision.get("match_type") != "third_party":
            continue
        provider_name = decision.get("provider")
        package_name = decision.get("target_package") or decision.get("package")
        if not isinstance(provider_name, str) or not provider_name or not isinstance(package_name, str):
            raise EvidenceError("third-party keep/replace decision lacks provider or target package")
        required_thirdparty.setdefault(provider_name, set()).add(package_name)
        required_evidence.setdefault(provider_name, set()).update(
            evidence.removeprefix("thirdparty-evidence:")
            for evidence in decision.get("evidence", [])
            if isinstance(evidence, str) and evidence.startswith("thirdparty-evidence:")
        )
    declared_provider_names = [provider.get("provider") for provider in providers]
    if len(declared_provider_names) != len(set(declared_provider_names)):
        raise EvidenceError("duplicate third-party Provider declarations")
    if set(declared_provider_names) != set(required_thirdparty):
        raise EvidenceError("Migration Plan third-party Providers do not exactly match Build Input")
    try:
        rules = yaml.safe_load((repo_root / "config/thirdparty.yml").read_text(encoding="utf-8"))["providers"]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise EvidenceError(f"trusted third-party rules are unavailable: {exc}") from exc
    declared_apks: set[str] = set()
    for provider in providers:
        rule = rules.get(provider["provider"])
        if not isinstance(rule, dict) or not rule.get("enabled"):
            raise EvidenceError(f"third-party provider has no enabled trusted rule: {provider['provider']}")
        if (rule.get("repository"), rule.get("rule_version")) != (provider["repository"], provider["rule_version"]):
            raise EvidenceError(f"third-party provider rule binding mismatch: {provider['provider']}")
        if target["package_manager"] not in rule.get("supported_package_managers", []):
            raise EvidenceError(f"third-party provider package manager is unsupported: {provider['provider']}")
        allowed_arches = set(rule.get("supported_architectures", []))
        if target["architecture"] not in allowed_arches and "all" not in allowed_arches:
            raise EvidenceError(f"third-party provider architecture is unsupported: {provider['provider']}")
        status_path = safe_path(repo_root, provider["status_path"])
        status_doc = load_json(status_path)
        status = status_doc.get(provider["provider"])
        if not isinstance(status, dict) or status.get("status") != "compatible":
            raise EvidenceError(f"third-party provider is not compatible: {provider['provider']}")
        if (status.get("provider"), status.get("repository"), status.get("rule_version"),
            status.get("release_id"), status.get("upstream_release")) != (
            provider["provider"], provider["repository"], provider["rule_version"],
            provider["release_id"], provider["release_tag"],
        ):
            raise EvidenceError(f"third-party release identity mismatch: {provider['provider']}")
        status_payload = dict(status)
        status_digest = status_payload.pop("evidence_digest", None)
        if status_digest != provider["evidence_digest"] or canonical_digest(status_payload) != status_digest:
            raise EvidenceError(f"third-party evidence digest mismatch: {provider['provider']}")
        if required_evidence[provider["provider"]] != {provider["evidence_digest"]}:
            raise EvidenceError(f"Migration Plan third-party evidence is not bound: {provider['provider']}")
        bound = status.get("target", {})
        if (bound.get("version"), bound.get("architecture"), bound.get("package_manager")) != (
            target["version"], target["architecture"], target["package_manager"]
        ):
            raise EvidenceError(f"third-party target binding mismatch: {provider['provider']}")
        provider_apk_packages: set[str] = set()
        for apk in provider["apks"]:
            apk_path = safe_path(repo_root, apk["path"])
            _expect_sha(apk_path, apk["sha256"], "third-party APK")
            declared_apks.add(apk_path.relative_to(repo_root).as_posix())
            provider_apk_packages.add(apk["package"])
            checks = status.get("apk_checks", [])
            match = next((row for row in checks if row.get("file") == apk["status_file"]), None)
            if not match or match.get("metadata_status") != "verified":
                raise EvidenceError(f"third-party APK metadata is not verified: {apk['path']}")
            if (match.get("sha256"), match.get("package"), match.get("architecture"), match.get("version")) != (
                apk["sha256"], apk["package"], apk["architecture"], apk["version"]
            ):
                raise EvidenceError(f"third-party APK binding mismatch: {apk['path']}")
            if match.get("dependencies") != apk["dependencies"]:
                raise EvidenceError(f"third-party APK dependency binding mismatch: {apk['path']}")
            if apk["architecture"] not in {"all", "noarch", target["architecture"]}:
                raise EvidenceError(f"third-party APK architecture mismatch: {apk['path']}")
        missing_plan_packages = required_thirdparty[provider["provider"]] - provider_apk_packages
        if missing_plan_packages:
            raise EvidenceError(
                f"Migration Plan third-party package has no bound APK: {sorted(missing_plan_packages)[0]}"
            )
        frozen_assets = {
            (asset.get("asset_id"), asset.get("asset"), asset.get("url"), asset.get("sha256"))
            for asset in status.get("assets", []) if isinstance(asset, dict)
        }
        input_assets = {
            (asset["asset_id"], asset["name"], asset["url"], asset["sha256"])
            for asset in provider["assets"]
        }
        if frozen_assets != input_assets:
            raise EvidenceError(f"third-party asset set mismatch: {provider['provider']}")
        dependency_evidence = status.get("official_dependencies", {})
        if (dependency_evidence.get("index_digest") != release["official_index_digest"]
                or dependency_evidence.get("missing") != []):
            raise EvidenceError(f"third-party official dependency evidence is incomplete: {provider['provider']}")
        if revalidate_upstream:
            spec = importlib.util.spec_from_file_location(
                "build_gate_fetch_thirdparty", repo_root / "scripts/fetch-thirdparty.py"
            )
            if spec is None or spec.loader is None:
                raise EvidenceError("cannot load trusted third-party provenance verifier")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            values = module.template_values(
                target["version"], capabilities, provider["release_tag"].removeprefix("v")
            )
            try:
                verified_digest = module.revalidate_status_provenance(
                    provider["provider"], rule, status, capabilities,
                    files_path / "root/thirdparty", values,
                )
            except module.ProviderError as exc:
                raise EvidenceError(
                    f"third-party upstream provenance failed: {provider['provider']}: {exc.reason}"
                ) from exc
            if verified_digest != provider["evidence_digest"]:
                raise EvidenceError(f"third-party upstream evidence changed: {provider['provider']}")
    bundled = {
        path.relative_to(repo_root).as_posix()
        for path in files_path.rglob("*.apk") if path.is_file()
    }
    if bundled != declared_apks:
        raise EvidenceError("bundled third-party APK set is not exactly declared")

    context = {
        "schema_version": "1.0.0", "request_id": build_input["request_id"],
        "build_input_id": build_input["build_input_id"], "build_input_digest": digest,
        "repository": expected_repository,
        "snapshot_id": snapshot["snapshot_id"], "snapshot_digest": snap_digest,
        "plan_id": plan["plan_id"], "plan_digest": plan_digest,
        "target": target, "release": release, "build": build,
        "runtime_commit_sha": expected_commit,
        "flash_ready": False,
    }
    if stage_dir is not None:
        if stage_dir.exists():
            shutil.rmtree(stage_dir)
        stage_dir.mkdir(parents=True, mode=0o700)
        shutil.copy2(packages_path, stage_dir / "final-packages.txt")
        shutil.copytree(files_path, stage_dir / "files")
        context["staged_packages_sha256"] = sha256_file(stage_dir / "final-packages.txt")
        context["staged_files_digest"] = tree_digest(stage_dir / "files")
    return context


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
