from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from migration_plan import canonical_digest, generate_plan, write_legacy_outputs


ROOT = Path(__file__).resolve().parents[1]
HEX = "a" * 64


def snapshot():
    return json.loads((ROOT / "tests/fixtures/system-snapshot-sprint2a.json").read_text())


def target(index):
    value = {
        "distribution": "immortalwrt", "channel": "release", "target_version": "25.12.2",
        "target": "x86/64", "profile": "generic", "arch": "x86_64", "package_manager": "apk",
        "image_type": "combined-efi", "expected_image_name": "immortalwrt-x86-64-generic-ext4-combined-efi.img.gz",
        "expected_image_sha256": HEX, "support_status": "supported",
        "profiles_url": "https://downloads.immortalwrt.org/releases/25.12.2/targets/x86/64/profiles.json",
        "profiles_sha256": HEX, "official_index_digest": canonical_digest(index),
        "package_index_sources": [{"url": "https://downloads.immortalwrt.org/index.json", "sha256": HEX, "checksum_manifest_url": "https://downloads.immortalwrt.org/sha256sums", "checksum_manifest_sha256": HEX, "checksum_entry": "index.json"}],
        "imagebuilder_url": "https://downloads.immortalwrt.org/imagebuilder.tar.zst", "imagebuilder_sha256": HEX,
    }
    value["resolution_digest"] = canonical_digest(value)
    return value


def rules():
    return {"providers": {"openclash": {
        "rule_version": 1,
        "repository": "vernesong/OpenClash",
        "packages": ["luci-app-openclash"],
        "official_dependencies": ["ca-bundle"],
    }}}


def trusted_status(capabilities, index, package="luci-app-openclash"):
    status = {
        "status": "compatible",
        "provider": "openclash",
        "rule_version": 1,
        "repository": "vernesong/OpenClash",
        "packages": [package],
        "target": {
            "distribution": capabilities["distribution"],
            "version": capabilities["target_version"],
            "target": capabilities["target"],
            "profile": capabilities["profile"],
            "architecture": capabilities["arch"],
            "package_manager": capabilities["package_manager"],
            "resolution_digest": capabilities["resolution_digest"],
            "official_index_digest": capabilities["official_index_digest"],
        },
        "release_id": 101,
        "upstream_release": "v0.48.002",
        "assets": [{
            "provider": "openclash", "release": "v0.48.002",
            "asset_id": 202,
            "asset": "luci-app-openclash-0.48.002.apk", "sha256": HEX,
            "url": "https://github.com/vernesong/OpenClash/releases/download/v0.48.002/luci-app-openclash-0.48.002.apk",
        }],
        "apk_checks": [{
            "file": "openclash/luci-app-openclash-0.48.002.apk", "sha256": HEX,
            "magic_verified": True, "metadata_status": "verified",
            "architecture": "noarch",
        }],
        "official_dependencies": {
            "required": ["ca-bundle"], "missing": [],
            "index_digest": canonical_digest(index),
        },
        "warnings": [],
    }
    status["evidence_digest"] = canonical_digest(status)
    return {"openclash": status}


def official_index():
    return {"busybox": {"version": "1"}, "ca-bundle": {"version": "1"}, "curl": {"version": "1"}}


def test_full_snapshot_to_release_to_plan_strict_positive(tmp_path):
    index = official_index()
    source = snapshot()
    Draft202012Validator(json.loads((ROOT / "schemas/system-snapshot-v1.json").read_text())).validate(source)
    plan = generate_plan(source, target(index), index, rules(), strict_mode=True)
    Draft202012Validator(json.loads((ROOT / "schemas/migration-plan-v1.json").read_text())).validate(plan)
    assert plan["status"] == "ok"
    assert plan["build_allowed"] is True
    assert plan["flash_ready"] is False
    assert plan["source_snapshot_digest"] == "1" * 64
    assert len(plan["decisions"]) == len(snapshot()["packages"]["installed"])
    assert plan["plan_id"] == f"urn:sha256:{plan['digest']}"
    write_legacy_outputs(plan, tmp_path)
    for name in ("packages-official.txt", "packages-thirdparty.txt", "packages-missing.txt", "packages-replaced.txt", "packages-skipped.txt", "package-decisions.json", "migration-report.md"):
        assert (tmp_path / name).exists()


def test_missing_required_dependency_blocks_build():
    data = snapshot()
    data["packages"]["installed"][-1]["depends"].append({"raw": "missing-runtime", "relation": "package", "name": "missing-runtime", "operator": None, "version": None})
    index = official_index()
    plan = generate_plan(data, target(index), index, rules())
    assert plan["build_allowed"] is False
    assert any("required dependencies" in blocker for blocker in plan["blockers"])


def test_unknown_boot_and_wrong_architecture_block_build():
    data = snapshot()
    data["system"]["boot_mode"] = "unknown"
    data["system"]["package_architecture"] = "aarch64_cortex-a53"
    index = official_index()
    plan = generate_plan(data, target(index), index, rules())
    assert plan["target"]["compatibility"] in {"unknown", "incompatible"}
    assert plan["build_allowed"] is False


def test_snapshot_and_release_digest_mismatch_fail_closed():
    data = snapshot()
    data["snapshot_id"] = "urn:sha256:" + "9" * 64
    index = official_index()
    capabilities = target(index)
    capabilities["target_version"] = "25.12.3"
    plan = generate_plan(data, capabilities, index, rules())
    assert plan["status"] == "failed"
    assert "snapshot ID/digest mismatch" in plan["errors"]
    assert "release resolution digest mismatch" in plan["errors"]


def test_opkg_to_apk_same_name_is_not_compatibility():
    data = snapshot()
    data["system"]["package_manager"] = "opkg"
    index = official_index()
    plan = generate_plan(data, target(index), index, rules())
    curl = next(row for row in plan["decisions"] if row["package"] == "curl")
    assert curl["decision"] == "review"
    assert plan["build_allowed"] is False


def test_unknown_thirdparty_is_not_silently_skipped():
    data = snapshot()
    package = data["packages"]["installed"][-1]
    package.update(name="luci-app-openclash", origin="third_party")
    data["packages"]["top_level"] = ["luci-app-openclash"]
    index = official_index()
    plan = generate_plan(data, target(index), index, rules(), {})
    row = next(row for row in plan["decisions"] if row["package"] == "luci-app-openclash")
    assert row["decision"] == "block"
    assert plan["build_allowed"] is False


def test_thirdparty_dependency_requires_and_accepts_bound_evidence():
    data = snapshot()
    package = data["packages"]["installed"][-1]
    package.update(name="luci-app-openclash", origin="third_party", install_reason="dependency")
    data["packages"]["top_level"] = []
    index = official_index()
    capabilities = target(index)
    status = trusted_status(capabilities, index)
    trusted = {status["openclash"]["evidence_digest"]}
    plan = generate_plan(
        data, capabilities, index, rules(), status,
        thirdparty_files={"openclash/luci-app-openclash-0.48.002.apk": HEX},
        trusted_thirdparty_evidence=trusted,
    )
    row = next(row for row in plan["decisions"] if row["package"] == "luci-app-openclash")
    assert row["decision"] == "keep"
    assert plan["build_allowed"] is True
    assert len(plan["decisions"]) == len(data["packages"]["installed"])


def test_thirdparty_dependency_without_evidence_is_blocked_not_skipped():
    data = snapshot()
    package = data["packages"]["installed"][-1]
    package.update(name="luci-app-openclash", origin="third_party", install_reason="dependency")
    data["packages"]["top_level"] = []
    index = official_index()
    plan = generate_plan(data, target(index), index, rules(), {})
    row = next(row for row in plan["decisions"] if row["package"] == "luci-app-openclash")
    assert row["decision"] == "block"
    assert row["match_type"] == "unresolved"


def test_forged_compatible_status_cannot_bypass_gate():
    data = snapshot()
    data["packages"]["installed"][-1].update(name="luci-app-openclash", origin="third_party")
    data["packages"]["top_level"] = ["luci-app-openclash"]
    index = official_index()
    forged = {"openclash": {"status": "compatible"}}
    plan = generate_plan(data, target(index), index, rules(), forged)
    assert plan["build_allowed"] is False
    assert next(row for row in plan["decisions"] if row["package"] == "luci-app-openclash")["decision"] == "block"


def test_self_consistent_status_and_local_apk_without_trusted_provenance_cannot_bypass_gate():
    data = snapshot()
    data["packages"]["installed"][-1].update(name="luci-app-openclash", origin="third_party")
    data["packages"]["top_level"] = ["luci-app-openclash"]
    index = official_index()
    capabilities = target(index)
    plan = generate_plan(
        data, capabilities, index, rules(), trusted_status(capabilities, index),
        thirdparty_files={"openclash/luci-app-openclash-0.48.002.apk": HEX},
    )
    row = next(row for row in plan["decisions"] if row["package"] == "luci-app-openclash")
    assert row["decision"] == "block"
    assert "trusted upstream" in row["reason"]


def test_compatible_status_cannot_be_reused_for_other_release():
    data = snapshot()
    data["packages"]["installed"][-1].update(name="luci-app-openclash", origin="third_party")
    data["packages"]["top_level"] = ["luci-app-openclash"]
    index = official_index()
    original = target(index)
    status = trusted_status(original, index)
    trusted = {status["openclash"]["evidence_digest"]}
    changed = target(index)
    changed["target_version"] = "25.12.3"
    frozen = dict(changed)
    frozen.pop("resolution_digest")
    changed["resolution_digest"] = canonical_digest(frozen)
    plan = generate_plan(
        data, changed, index, rules(), status,
        thirdparty_files={"openclash/luci-app-openclash-0.48.002.apk": HEX},
        trusted_thirdparty_evidence=trusted,
    )
    assert plan["build_allowed"] is False
    assert any("different target release" in row["reason"] for row in plan["decisions"] if row["package"] == "luci-app-openclash")


def test_thirdparty_compatible_status_cannot_hide_missing_official_dependency():
    data = snapshot()
    data["packages"]["installed"][-1].update(name="luci-app-openclash", origin="third_party")
    data["packages"]["top_level"] = ["luci-app-openclash"]
    index = official_index()
    capabilities = target(index)
    provider_rules = rules()
    provider_rules["providers"]["openclash"]["official_dependencies"] = ["ca-bundle", "missing-runtime"]
    statuses = trusted_status(capabilities, index)
    status = statuses["openclash"]
    status["official_dependencies"]["required"] = ["ca-bundle", "missing-runtime"]
    status["evidence_digest"] = canonical_digest({key: value for key, value in status.items() if key != "evidence_digest"})
    trusted = {status["evidence_digest"]}
    plan = generate_plan(
        data, capabilities, index, provider_rules, statuses,
        thirdparty_files={"openclash/luci-app-openclash-0.48.002.apk": HEX},
        trusted_thirdparty_evidence=trusted,
    )
    row = next(row for row in plan["decisions"] if row["package"] == "luci-app-openclash")
    assert row["decision"] == "block"
    assert "absent" in row["reason"]


def test_user_optional_flag_cannot_exclude_protected_package():
    data = snapshot()
    exclusion = {"package": "busybox", "source_version": "25.12.2", "snapshot_digest": "1" * 64, "reason": "operator marked it optional", "optional": True}
    index = official_index()
    plan = generate_plan(
        data, target(index), index, rules(), exclusions=[exclusion],
        package_rules={"optional_exclusions": ["busybox"]},
    )
    row = next(row for row in plan["decisions"] if row["package"] == "busybox")
    assert row["decision"] == "block"
    assert plan["build_allowed"] is False


def test_exclusion_cannot_break_another_required_package_dependency():
    data = snapshot()
    exclusion = {"package": "ca-bundle", "source_version": "25.12.2", "snapshot_digest": "1" * 64, "reason": "operator marked it optional", "optional": True}
    index = official_index()
    plan = generate_plan(
        data, target(index), index, rules(), exclusions=[exclusion],
        package_rules={"optional_exclusions": ["ca-bundle"]},
    )
    row = next(row for row in plan["decisions"] if row["package"] == "ca-bundle")
    assert row["decision"] == "block"
    assert "curl" in row["reason"]


def test_policy_proven_optional_package_can_be_explicitly_excluded():
    data = snapshot()
    optional = dict(data["packages"]["installed"][-1])
    optional.update(name="optional-tool", version="1", dependencies_raw=None, depends=[])
    data["packages"]["installed"].append(optional)
    data["packages"]["top_level"].append("optional-tool")
    index = {**official_index(), "optional-tool": {"version": "1"}}
    exclusion = {"package": "optional-tool", "source_version": "25.12.2", "snapshot_digest": "1" * 64, "reason": "versioned policy marks this tool optional", "optional": True}
    plan = generate_plan(
        data, target(index), index, rules(), exclusions=[exclusion],
        package_rules={"optional_exclusions": ["optional-tool"]},
    )
    row = next(row for row in plan["decisions"] if row["package"] == "optional-tool")
    assert row["decision"] == "skip"
    assert plan["build_allowed"] is True


def test_legacy_adapter_is_explicitly_blocked():
    spec = importlib.util.spec_from_file_location("legacy_adapter", ROOT / "scripts/adapt-legacy-analysis.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    result = module.adapt({"source_version": "24.10.4", "installed_packages": ["curl"]})
    assert result["status"] == "blocked"
    assert result["digest"]["canonicalization"] == "legacy-analysis-adapter-v1"
    assert result["system"]["identity_status"] == "unknown"
