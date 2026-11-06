from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest
import yaml


SPEC = importlib.util.spec_from_file_location("fetch_thirdparty_rules", "scripts/fetch-thirdparty.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def rules():
    return yaml.safe_load(Path("config/thirdparty.yml").read_text())


def test_all_required_provider_rules_are_versioned_and_verifiable():
    providers = MODULE.validate_provider_config(rules())
    assert set(providers) == {"openclash", "nikki", "lucky"}
    assert all(provider["package_format"] == "apk" for provider in providers.values())
    assert all(provider["install_path"] == "imagebuilder-binary" for provider in providers.values())


def test_unknown_or_incomplete_provider_is_unresolved():
    config = rules()
    config["providers"]["unknown"] = {"repository": "evil/example"}
    with pytest.raises(MODULE.ProviderError, match="incomplete provider rule"):
        MODULE.validate_provider_config(config)


def test_sdk_path_cannot_masquerade_as_imagebuilder_binary():
    config = copy.deepcopy(rules())
    config["providers"]["lucky"]["install_path"] = "sdk-source"
    with pytest.raises(MODULE.ProviderError, match="SDK and ImageBuilder"):
        MODULE.validate_provider_config(config)


def test_asset_url_must_belong_to_configured_repository():
    provider = rules()["providers"]["openclash"]
    with pytest.raises(MODULE.ProviderError, match="outside its trusted upstream"):
        MODULE.validate_asset_url(
            "openclash", provider,
            {"browser_download_url": "https://example.invalid/payload.apk"},
        )


def test_first_boot_script_verifies_hash_before_allow_untrusted():
    script = Path("files/etc/uci-defaults/99-install-thirdparty").read_text()
    assert script.index("sha256sum -c SHA256SUMS") < script.index("apk add --allow-untrusted")
    assert "manifest_count" in script


def test_unknown_selected_provider_is_explicitly_unresolved_and_strict_fails():
    statuses = MODULE.unknown_provider_statuses({"openclash", "unknown"}, {"openclash"})
    assert statuses["unknown"]["status"] == "unresolved"
    assert MODULE.strict_exit_code({"unknown"}, statuses, strict=True) == 1
    assert MODULE.strict_exit_code({"unknown"}, {}, strict=True) == 1


def test_selected_provider_requires_nonempty_bound_official_index(tmp_path):
    missing = tmp_path / "official-package-index.json"
    with pytest.raises(MODULE.ProviderError, match="required"):
        MODULE.load_official_index(missing, {"official_index_digest": "a" * 64}, required=True)

    missing.write_text("{}")
    with pytest.raises(MODULE.ProviderError, match="empty"):
        MODULE.load_official_index(missing, {"official_index_digest": MODULE.canonical_digest({})}, required=True)

    missing.write_text('{"curl": {}}')
    with pytest.raises(MODULE.ProviderError, match="digest"):
        MODULE.load_official_index(missing, {"official_index_digest": "a" * 64}, required=True)


def test_compatible_status_binds_target_assets_apks_and_dependencies():
    cfg = rules()["providers"]["openclash"]
    capabilities = {
        "distribution": "immortalwrt", "target_version": "25.12.2",
        "target": "x86/64", "profile": "generic", "arch": "x86_64",
        "package_manager": "apk", "resolution_digest": "a" * 64,
    }
    status = MODULE.compatible_status(
        "openclash", cfg, capabilities, {"tag_name": "v0.48.002"},
        [{"provider": "openclash", "release": "v0.48.002", "asset": "openclash.apk", "sha256": "b" * 64, "url": "https://github.com/vernesong/OpenClash/releases/download/v0.48.002/openclash.apk"}],
        [{"file": "openclash.apk", "sha256": "c" * 64, "magic_verified": True, "metadata_status": "verified", "architecture": "noarch"}],
        "d" * 64,
        [],
    )
    payload = dict(status)
    digest = payload.pop("evidence_digest")
    assert digest == MODULE.canonical_digest(payload)
    assert status["target"]["version"] == "25.12.2"
    assert status["official_dependencies"]["required"] == sorted(cfg["official_dependencies"])
