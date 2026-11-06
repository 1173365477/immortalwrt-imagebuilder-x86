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
