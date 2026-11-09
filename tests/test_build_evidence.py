from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from build_evidence import EvidenceError, canonical_digest, sha256_file, tree_digest, verify_build_input


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "b" * 40
REPOSITORY = "1173365477/immortalwrt-imagebuilder-x86"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def frozen_request(tmp_path: Path) -> tuple[Path, dict]:
    repo = tmp_path / "repo"
    (repo / "schemas").mkdir(parents=True)
    (repo / "config").mkdir()
    for name in ("build-input-v1.json", "system-snapshot-v1.json", "migration-plan-v1.json", "build-provenance-v1.json"):
        shutil.copy2(ROOT / "schemas" / name, repo / "schemas" / name)
    shutil.copy2(ROOT / "config/thirdparty.yml", repo / "config/thirdparty.yml")
    shutil.copy2(ROOT / "config/apk-tools-policy.json", repo / "config/apk-tools-policy.json")
    request = repo / "evidence/requests/request-1"
    request.mkdir(parents=True)
    snapshot = json.loads((ROOT / "tests/fixtures/system-snapshot-sprint2a.json").read_text())
    snapshot_path = request / "system-snapshot-v1.json"
    write_json(snapshot_path, snapshot)

    index = {"curl": {"version": "8.16.0"}}
    index_path = request / "official-package-index.json"
    write_json(index_path, index)
    plan = json.loads((ROOT / "examples/migration-plan-v1.example.json").read_text())
    plan["release"]["official_index_digest"] = canonical_digest(index)
    capabilities = {
        "distribution": "immortalwrt", "channel": "release", "target_version": "25.12.2",
        "target": "x86/64", "profile": "generic", "arch": "x86_64", "package_manager": "apk",
        "filesystem": "ext4", "image_type": "combined-efi",
        "expected_image_name": plan["target"]["image_name"],
        "profiles_sha256": plan["release"]["profiles_sha256"],
        "package_index_sources": plan["release"]["package_index_sources"],
        "imagebuilder_filename": "immortalwrt-imagebuilder-25.12.2-x86-64.Linux-x86_64.tar.zst",
        "imagebuilder_url": plan["release"]["imagebuilder_url"],
        "imagebuilder_sha256": plan["release"]["imagebuilder_sha256"],
        "official_index_digest": canonical_digest(index),
    }
    capabilities["resolution_digest"] = canonical_digest(capabilities)
    plan["release"]["resolution_digest"] = capabilities["resolution_digest"]
    plan["digest"] = ""
    plan["plan_id"] = ""
    plan_digest = canonical_digest(plan, ("plan_id", "digest"))
    plan["digest"] = plan_digest
    plan["plan_id"] = f"urn:sha256:{plan_digest}"
    plan_path = request / "migration-plan-v1.json"
    write_json(plan_path, plan)
    capabilities_path = request / "release-capabilities.json"
    write_json(capabilities_path, capabilities)

    packages_path = request / "final-packages.txt"
    packages_path.write_text("curl\n", encoding="utf-8")
    files_path = request / "files"
    files_path.mkdir()
    (files_path / "README").write_text("frozen build overlay\n", encoding="utf-8")
    build_input = {
        "schema_version": "1.0.0", "build_input_id": "", "digest": "",
        "request_id": "request-1", "created_at": "2026-11-09T00:00:00Z",
        "snapshot": {"path": snapshot_path.relative_to(repo).as_posix(),
                     "snapshot_id": snapshot["snapshot_id"],
                     "snapshot_digest": snapshot["digest"]["value"],
                     "file_sha256": sha256_file(snapshot_path)},
        "migration_plan": {"path": plan_path.relative_to(repo).as_posix(),
                           "plan_id": plan["plan_id"], "plan_digest": plan["digest"],
                           "file_sha256": sha256_file(plan_path)},
        "target": {"distribution": "immortalwrt", "version": "25.12.2", "target": "x86", "subtarget": "64",
                   "profile": "generic", "architecture": "x86_64", "package_manager": "apk",
                   "filesystem": "ext4", "image_type": "combined-efi",
                   "expected_image_name": plan["target"]["image_name"]},
        "release": {"identity": "immortalwrt:25.12.2:release",
                    "resolution_digest": plan["release"]["resolution_digest"],
                    "capabilities_path": capabilities_path.relative_to(repo).as_posix(),
                    "capabilities_file_sha256": sha256_file(capabilities_path),
                    "profiles_sha256": plan["release"]["profiles_sha256"],
                    "official_index_digest": canonical_digest(index),
                    "official_index_path": index_path.relative_to(repo).as_posix(),
                    "official_index_file_sha256": sha256_file(index_path),
                    "package_index_sources": plan["release"]["package_index_sources"],
                    "imagebuilder_url": plan["release"]["imagebuilder_url"],
                    "imagebuilder_filename": "immortalwrt-imagebuilder-25.12.2-x86-64.Linux-x86_64.tar.zst",
                    "imagebuilder_sha256": plan["release"]["imagebuilder_sha256"]},
        "thirdparty": [],
        "build": {"repository": REPOSITORY, "git_commit_sha": COMMIT,
                  "workflow": ".github/workflows/build.yml", "rootfs_size_mib": 8192,
                  "packages_path": packages_path.relative_to(repo).as_posix(),
                  "packages_sha256": sha256_file(packages_path), "base_packages": [],
                  "files_path": files_path.relative_to(repo).as_posix(),
                  "files_digest": tree_digest(files_path), "apk_tools_version": "2.14.12",
                  "config_digest": ""},
        "safety": {"strict_mode": True, "build_allowed": True,
                   "compatibility_validated": False, "flash_ready": False},
    }
    build_input["build"]["config_digest"] = canonical_digest(build_input["build"], ("config_digest",))
    digest = canonical_digest(build_input, ("build_input_id", "digest"))
    build_input["digest"] = digest
    build_input["build_input_id"] = f"urn:sha256:{digest}"
    input_path = request / "build-input-v1.json"
    write_json(input_path, build_input)
    return input_path, build_input


def rewrite_input(path: Path, value: dict) -> None:
    value["digest"] = ""
    value["build_input_id"] = ""
    digest = canonical_digest(value, ("build_input_id", "digest"))
    value["digest"] = digest
    value["build_input_id"] = f"urn:sha256:{digest}"
    write_json(path, value)


def add_openclash_provider(path: Path, value: dict) -> None:
    repo = path.parents[3]
    request = path.parent
    apk = request / "files/root/thirdparty/openclash/luci-app-openclash.apk"
    apk.parent.mkdir(parents=True)
    apk.write_bytes(b"ADBfrozen-test-apk")
    check = {"file": "openclash/luci-app-openclash.apk", "sha256": sha256_file(apk),
             "magic_verified": True, "metadata_status": "verified", "architecture": "noarch",
             "package": "luci-app-openclash", "version": "0.48.002", "dependencies": ["curl"]}
    asset = {"provider": "openclash", "release": "v0.48.002", "asset_id": 22,
             "asset": "luci-app-openclash-0.48.002.apk", "sha256": sha256_file(apk),
             "url": "https://github.com/vernesong/OpenClash/releases/download/v0.48.002/luci-app-openclash-0.48.002.apk"}
    status = {"status": "compatible", "provider": "openclash", "rule_version": 1,
              "repository": "vernesong/OpenClash", "packages": ["luci-app-openclash"],
              "target": {"distribution": "immortalwrt", "version": "25.12.2", "target": "x86/64",
                         "profile": "generic", "architecture": "x86_64", "package_manager": "apk",
                         "resolution_digest": value["release"]["resolution_digest"],
                         "official_index_digest": value["release"]["official_index_digest"]},
              "release_id": 11, "upstream_release": "v0.48.002", "assets": [asset],
              "apk_checks": [check],
              "official_dependencies": {"required": ["curl"], "missing": [],
                                        "index_digest": value["release"]["official_index_digest"]},
              "warnings": []}
    status["evidence_digest"] = canonical_digest(status)
    status_path = request / "thirdparty-status.json"
    write_json(status_path, {"openclash": status})
    value["thirdparty"] = [{
        "provider": "openclash", "repository": "vernesong/OpenClash", "rule_version": 1,
        "release_id": 11, "release_tag": "v0.48.002", "evidence_digest": status["evidence_digest"],
        "status_path": status_path.relative_to(repo).as_posix(),
        "assets": [{"asset_id": 22, "name": asset["asset"], "url": asset["url"],
                    "sha256": asset["sha256"]}],
        "apks": [{"path": apk.relative_to(repo).as_posix(), "status_file": check["file"],
                  "sha256": check["sha256"], "package": check["package"],
                  "architecture": check["architecture"], "version": check["version"],
                  "dependencies": check["dependencies"]}],
    }]
    value["build"]["files_digest"] = tree_digest(request / "files")
    value["build"]["config_digest"] = canonical_digest(value["build"], ("config_digest",))
    rewrite_input(path, value)


def test_build_input_positive_stages_exact_bytes(tmp_path):
    path, _ = frozen_request(tmp_path)
    stage = tmp_path / "stage"
    result = verify_build_input(path, tmp_path / "repo", expected_repository=REPOSITORY,
                                expected_commit=COMMIT, stage_dir=stage, revalidate_upstream=False)
    assert result["flash_ready"] is False
    assert result["build_input_id"] == f"urn:sha256:{result['build_input_digest']}"
    assert (stage / "final-packages.txt").read_text() == "curl\n"
    assert tree_digest(stage / "files") == result["staged_files_digest"]


def test_thirdparty_bytes_metadata_dependencies_and_target_are_bound(tmp_path):
    path, value = frozen_request(tmp_path)
    add_openclash_provider(path, value)
    result = verify_build_input(path, tmp_path / "repo", expected_repository=REPOSITORY,
                                expected_commit=COMMIT, revalidate_upstream=False)
    assert result["build_input_digest"] == value["digest"]
    apk = tmp_path / "repo" / value["thirdparty"][0]["apks"][0]["path"]
    apk.write_bytes(b"ADBdifferent")
    with pytest.raises(EvidenceError, match="files tree digest mismatch"):
        verify_build_input(path, tmp_path / "repo", expected_repository=REPOSITORY,
                           expected_commit=COMMIT, revalidate_upstream=False)


def test_self_consistent_provider_status_cannot_hide_missing_official_dependency(tmp_path):
    path, value = frozen_request(tmp_path)
    add_openclash_provider(path, value)
    status_path = tmp_path / "repo" / value["thirdparty"][0]["status_path"]
    document = json.loads(status_path.read_text())
    status = document["openclash"]
    status["official_dependencies"]["missing"] = ["curl"]
    status.pop("evidence_digest")
    status["evidence_digest"] = canonical_digest(status)
    write_json(status_path, document)
    value["thirdparty"][0]["evidence_digest"] = status["evidence_digest"]
    rewrite_input(path, value)
    with pytest.raises(EvidenceError, match="official dependency evidence"):
        verify_build_input(path, tmp_path / "repo", expected_repository=REPOSITORY,
                           expected_commit=COMMIT, revalidate_upstream=False)


@pytest.mark.parametrize("mutation", [
    "strict_false", "wrong_commit", "plan_tamper", "snapshot_tamper", "index_tamper",
    "package_extra", "files_tamper", "storage_unknown", "unsafe_path", "wrong_apk_tools",
])
def test_build_input_fail_closed(tmp_path, mutation):
    path, value = frozen_request(tmp_path)
    repo = tmp_path / "repo"
    expected_commit = COMMIT
    if mutation == "strict_false":
        value["safety"]["strict_mode"] = False
        rewrite_input(path, value)
    elif mutation == "wrong_commit":
        expected_commit = "c" * 40
    elif mutation == "plan_tamper":
        plan = repo / value["migration_plan"]["path"]
        plan.write_text(plan.read_text() + " ")
    elif mutation == "snapshot_tamper":
        snapshot = repo / value["snapshot"]["path"]
        snapshot.write_text(snapshot.read_text() + " ")
    elif mutation == "index_tamper":
        index = repo / value["release"]["official_index_path"]
        index.write_text('{"curl":{"version":"0"}}\n')
    elif mutation == "package_extra":
        packages = repo / value["build"]["packages_path"]
        packages.write_text("curl\nevil\n")
        value["build"]["packages_sha256"] = sha256_file(packages)
        rewrite_input(path, value)
    elif mutation == "files_tamper":
        (repo / value["build"]["files_path"] / "new").write_text("changed")
    elif mutation == "storage_unknown":
        plan_path = repo / value["migration_plan"]["path"]
        plan = json.loads(plan_path.read_text())
        plan["storage_risk"].update(status="unknown", firmware_overwrite_risks=["unknown"])
        plan["digest"] = canonical_digest(plan, ("plan_id", "digest"))
        plan["plan_id"] = f"urn:sha256:{plan['digest']}"
        write_json(plan_path, plan)
        value["migration_plan"].update(plan_id=plan["plan_id"], plan_digest=plan["digest"],
                                      file_sha256=sha256_file(plan_path))
        rewrite_input(path, value)
    elif mutation == "unsafe_path":
        value["snapshot"]["path"] = "../snapshot.json"
        rewrite_input(path, value)
    else:
        value["build"]["apk_tools_version"] = "999"
        rewrite_input(path, value)
    with pytest.raises(EvidenceError):
        verify_build_input(path, repo, expected_repository=REPOSITORY, expected_commit=expected_commit,
                           revalidate_upstream=False)


def test_verifier_cli_and_provenance_use_actual_artifact_bytes(tmp_path):
    path, _ = frozen_request(tmp_path)
    repo = tmp_path / "repo"
    context = tmp_path / "context.json"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/verify-build-input.py"), "--input", str(path),
        "--repo-root", str(repo), "--repository", REPOSITORY, "--commit", COMMIT,
        "--output", str(context),
    ], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    firmware = repo / "generated/firmware.img.gz"
    firmware.parent.mkdir()
    firmware.write_bytes(b"actual firmware bytes")
    provenance = repo / "generated/build-provenance-v1.json"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/generate-build-provenance.py"), "--input", str(path),
        "--repo-root", str(repo), "--repository", REPOSITORY, "--commit", COMMIT,
        "--run-id", "7", "--run-attempt", "2", "--firmware", str(firmware),
        "--output", str(provenance),
    ], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    value = json.loads(provenance.read_text())
    Draft202012Validator(json.loads((repo / "schemas/build-provenance-v1.json").read_text())).validate(value)
    assert value["artifact"]["sha256"] == sha256_file(firmware)
    assert value["flash_ready"] is False


def test_create_build_input_cli_produces_verifiable_request(tmp_path):
    source_input, source = frozen_request(tmp_path)
    repo = tmp_path / "repo"
    base = repo / "config/empty-base.txt"
    base.write_text("# intentionally empty\n")
    source_dir = source_input.parent
    output = repo / "evidence/requests/request-2"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/create-build-input.py"),
        "--request-id", "request-2", "--snapshot", str(source_dir / "system-snapshot-v1.json"),
        "--plan", str(source_dir / "migration-plan-v1.json"),
        "--release-capabilities", str(source_dir / "release-capabilities.json"),
        "--official-index", str(source_dir / "official-package-index.json"),
        "--files", str(source_dir / "files"), "--base-packages", str(base),
        "--filesystem", "ext4", "--repository", REPOSITORY, "--commit", COMMIT,
        "--created-at", "2026-11-09T00:00:00Z", "--output", str(output),
        "--repo-root", str(repo),
    ], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    created = output / "build-input-v1.json"
    context = verify_build_input(created, repo, expected_repository=REPOSITORY, expected_commit=COMMIT,
                                 revalidate_upstream=False)
    assert context["request_id"] == "request-2"
    assert context["flash_ready"] is False


def test_invalid_input_never_reaches_network_or_make(tmp_path):
    path, value = frozen_request(tmp_path)
    value["safety"]["strict_mode"] = False
    rewrite_input(path, value)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "called"
    for command in ("curl", "make"):
        tool = fake_bin / command
        tool.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
        tool.chmod(0o755)
    env = os.environ | {"BUILD_INPUT": str(path), "TRUSTED_REPOSITORY": REPOSITORY,
                        "TRUSTED_COMMIT": COMMIT, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
    result = subprocess.run(["bash", str(ROOT / "scripts/build-image.sh")], cwd=ROOT, env=env,
                            text=True, capture_output=True)
    assert result.returncode != 0
    assert not marker.exists()


def test_real_apk_tools_version_comparison_when_configured():
    apk = os.environ.get("APK_REAL_BINARY")
    if not apk:
        pytest.skip("CI provides the pinned real apk-tools wrapper")
    cases = [("2.0", "3.0", "<"), ("3.0", "3.0", "="), ("3.1", "3.0", ">"),
             ("1.0-r1", "1.0-r0", ">")]
    for candidate, required, expected in cases:
        result = subprocess.run([apk, "version", "-t", candidate, required], text=True,
                                capture_output=True, check=True)
        assert result.stdout.strip() == expected
    invalid = subprocess.run([apk, "version", "-t", "3.0"], text=True, capture_output=True)
    assert invalid.returncode != 0
