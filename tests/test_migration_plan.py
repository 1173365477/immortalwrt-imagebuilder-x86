from __future__ import annotations

import importlib.util
import json
from pathlib import Path

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
    return {"providers": {"openclash": {"packages": ["luci-app-openclash"]}}}


def official_index():
    return {"busybox": {"version": "1"}, "ca-bundle": {"version": "1"}, "curl": {"version": "1"}}


def test_full_snapshot_to_release_to_plan_strict_positive(tmp_path):
    index = official_index()
    plan = generate_plan(snapshot(), target(index), index, rules(), strict_mode=True)
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


def test_explicit_optional_exclusion_is_snapshot_bound():
    data = snapshot()
    exclusion = {"package": "curl", "source_version": "25.12.2", "snapshot_digest": "1" * 64, "reason": "operator intentionally omits optional curl", "optional": True}
    index = official_index()
    plan = generate_plan(data, target(index), index, rules(), exclusions=[exclusion])
    row = next(row for row in plan["decisions"] if row["package"] == "curl")
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
