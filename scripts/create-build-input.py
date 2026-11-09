#!/usr/bin/env python3
"""Freeze reviewed Sprint 2A evidence into an immutable T13 build request."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from urllib.parse import urlparse

from build_evidence import REQUEST_RE, canonical_digest, load_json, sha256_file, tree_digest, write_json


def package_tokens(path: Path) -> list[str]:
    return [token for line in path.read_text(encoding="utf-8").splitlines()
            if (token := line.strip()) and not token.startswith("#")]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--official-index", type=Path, required=True)
    parser.add_argument("--release-capabilities", type=Path, required=True)
    parser.add_argument("--thirdparty-status", type=Path)
    parser.add_argument("--files", type=Path, default=Path("files"))
    parser.add_argument("--base-packages", type=Path, default=Path("config/base-packages.txt"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--filesystem", required=True)
    parser.add_argument("--rootfs-size", type=int, default=8192)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.repo_root.resolve(strict=True)
    output = args.output.resolve()
    if not REQUEST_RE.fullmatch(args.request_id):
        parser.error("unsafe --request-id")
    try:
        output.relative_to(root)
    except ValueError:
        parser.error("--output must be inside --repo-root")
    expected_output = root / "evidence/requests" / args.request_id
    if output != expected_output:
        parser.error("--output must be evidence/requests/<request-id>")
    if output.exists():
        parser.error("refusing to overwrite an existing immutable request")
    snapshot = load_json(args.snapshot)
    plan = load_json(args.plan)
    index = load_json(args.official_index)
    capabilities = load_json(args.release_capabilities)
    if plan.get("source_snapshot_id") != snapshot.get("snapshot_id"):
        parser.error("plan does not identify the supplied snapshot")
    output.mkdir(parents=True)
    snapshot_path = output / "system-snapshot-v1.json"
    plan_path = output / "migration-plan-v1.json"
    index_path = output / "official-package-index.json"
    capabilities_path = output / "release-capabilities.json"
    files_path = output / "files"
    shutil.copy2(args.snapshot, snapshot_path)
    shutil.copy2(args.plan, plan_path)
    shutil.copy2(args.official_index, index_path)
    shutil.copy2(args.release_capabilities, capabilities_path)
    shutil.copytree(args.files, files_path)

    base = package_tokens(args.base_packages)
    approved = set(base)
    for row in plan.get("decisions", []):
        if (row.get("decision") in {"keep", "replace"}
                and row.get("match_type") in {"official", "replacement"}):
            approved.add(row.get("target_package") or row.get("package"))
    packages_path = output / "final-packages.txt"
    packages_path.write_text("\n".join(sorted(approved)) + "\n", encoding="utf-8")

    providers = []
    if args.thirdparty_status:
        status_doc = load_json(args.thirdparty_status)
        status_path = output / "thirdparty-status.json"
        shutil.copy2(args.thirdparty_status, status_path)
        for name, status in sorted(status_doc.items()):
            if not isinstance(status, dict) or status.get("status") != "compatible":
                continue
            apks = []
            for check in status.get("apk_checks", []):
                relative = Path("files/root/thirdparty") / check["file"]
                apk_path = output / relative
                apks.append({"path": apk_path.relative_to(root).as_posix(),
                             "status_file": check["file"], "sha256": check["sha256"],
                             "package": check["package"], "architecture": check["architecture"],
                             "version": check["version"], "dependencies": check["dependencies"]})
            providers.append({
                "provider": name, "repository": status["repository"],
                "rule_version": status["rule_version"], "release_id": status["release_id"],
                "release_tag": status["upstream_release"], "evidence_digest": status["evidence_digest"],
                "status_path": status_path.relative_to(root).as_posix(),
                "assets": [{"asset_id": row["asset_id"], "name": row["asset"],
                            "url": row["url"], "sha256": row["sha256"]}
                           for row in status.get("assets", [])],
                "apks": apks,
            })

    policy = load_json(root / "config/apk-tools-policy.json")
    archive = Path(urlparse(plan["release"]["imagebuilder_url"]).path).name
    target = plan["target"]
    target_name, separator, subtarget = target["target"].partition("/")
    if not separator or not target_name or not subtarget:
        parser.error("plan target must be target/subtarget")
    build = {"repository": args.repository, "git_commit_sha": args.commit,
             "workflow": ".github/workflows/build.yml", "rootfs_size_mib": args.rootfs_size,
             "packages_path": packages_path.relative_to(root).as_posix(),
             "packages_sha256": sha256_file(packages_path), "base_packages": base,
             "files_path": files_path.relative_to(root).as_posix(),
             "files_digest": tree_digest(files_path),
             "apk_tools_version": policy["apk_tools_version"], "config_digest": ""}
    build["config_digest"] = canonical_digest(build, ("config_digest",))
    value = {
        "schema_version": "1.0.0", "build_input_id": "", "digest": "",
        "request_id": args.request_id, "created_at": args.created_at,
        "snapshot": {"path": snapshot_path.relative_to(root).as_posix(),
                     "snapshot_id": snapshot["snapshot_id"],
                     "snapshot_digest": snapshot["digest"]["value"],
                     "file_sha256": sha256_file(snapshot_path)},
        "migration_plan": {"path": plan_path.relative_to(root).as_posix(),
                           "plan_id": plan["plan_id"], "plan_digest": plan["digest"],
                           "file_sha256": sha256_file(plan_path)},
        "target": {"distribution": target["distribution"], "version": target["version"],
                   "target": target_name, "subtarget": subtarget, "profile": target["profile"],
                   "architecture": target["architecture"], "package_manager": target["package_manager"],
                   "filesystem": args.filesystem, "image_type": target["image_type"],
                   "expected_image_name": target["image_name"]},
        "release": {"identity": f"{target['distribution']}:{target['version']}:release",
                    "resolution_digest": plan["release"]["resolution_digest"],
                    "capabilities_path": capabilities_path.relative_to(root).as_posix(),
                    "capabilities_file_sha256": sha256_file(capabilities_path),
                    "profiles_sha256": plan["release"]["profiles_sha256"],
                    "official_index_digest": plan["release"]["official_index_digest"],
                    "official_index_path": index_path.relative_to(root).as_posix(),
                    "official_index_file_sha256": sha256_file(index_path),
                    "package_index_sources": plan["release"]["package_index_sources"],
                    "imagebuilder_url": plan["release"]["imagebuilder_url"],
                    "imagebuilder_filename": archive,
                    "imagebuilder_sha256": plan["release"]["imagebuilder_sha256"]},
        "thirdparty": providers,
        "build": build,
        "safety": {"strict_mode": True, "build_allowed": plan["build_allowed"],
                   "compatibility_validated": plan["compatibility_validated"], "flash_ready": False},
    }
    digest = canonical_digest(value, ("build_input_id", "digest"))
    value["digest"] = digest
    value["build_input_id"] = f"urn:sha256:{digest}"
    write_json(output / "build-input-v1.json", value)
    print(f"Created immutable request {args.request_id}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
