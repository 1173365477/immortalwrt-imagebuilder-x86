from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import hashlib

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
        "openclash", cfg, capabilities, {"id": 101, "tag_name": "v0.48.002"},
        [{"provider": "openclash", "release": "v0.48.002", "asset_id": 202, "asset": "openclash.apk", "sha256": "b" * 64, "url": "https://github.com/vernesong/OpenClash/releases/download/v0.48.002/openclash.apk"}],
        [{"file": "openclash/openclash.apk", "sha256": "c" * 64, "magic_verified": True, "metadata_status": "verified", "architecture": "noarch"}],
        "d" * 64,
        [],
    )
    payload = dict(status)
    digest = payload.pop("evidence_digest")
    assert digest == MODULE.canonical_digest(payload)
    assert status["target"]["version"] == "25.12.2"
    assert status["official_dependencies"]["required"] == sorted(cfg["official_dependencies"])


@pytest.mark.parametrize("strict", [False, True])
def test_failed_multi_apk_provider_publishes_nothing(strict, tmp_path):
    work = tmp_path / "work"
    destination = tmp_path / "thirdparty"
    work.mkdir()
    destination.mkdir()
    first = work / "first.apk"
    second = work / "second.apk"
    first.write_bytes(b"ADB0first")
    second.write_bytes(b"ADB0second")

    def inspector(path):
        if path.name == "second.apk":
            return None, "synthetic adbdump failure"
        return {"name": "first", "arch": "x86_64", "version": "1", "dependencies": []}, None

    with pytest.raises(MODULE.ProviderError, match="metadata could not be verified"):
        MODULE.validate_and_publish_apks(
            "synthetic", [first, second], {"arch": "x86_64"}, destination,
            inspector=inspector,
        )
    statuses = {"synthetic": {"status": "unresolved"}}
    assert MODULE.strict_exit_code({"synthetic"}, statuses, strict) == (1 if strict else 0)
    assert not (destination / "synthetic").exists()
    assert list(destination.rglob("*.apk")) == []


@pytest.mark.parametrize("metadata", [
    None,
    {"name": "pkg", "version": "1", "dependencies": []},
    {"name": "pkg", "arch": "x86_64", "version": "1"},
])
def test_unknown_or_incomplete_apk_metadata_is_unresolved(metadata, tmp_path):
    work = tmp_path / "work"
    destination = tmp_path / "thirdparty"
    work.mkdir()
    destination.mkdir()
    package = work / "package.apk"
    package.write_bytes(b"ADB0payload")

    def inspector(_path):
        return metadata, "synthetic metadata unavailable" if metadata is None else None

    with pytest.raises(MODULE.ProviderError, match="metadata") as exc:
        MODULE.validate_and_publish_apks(
            "synthetic", [package], {"arch": "x86_64"}, destination,
            inspector=inspector,
        )
    assert exc.value.status == "unresolved"
    assert not (destination / "synthetic").exists()


def test_complete_apk_metadata_publishes_provider_atomically(tmp_path):
    work = tmp_path / "work"
    destination = tmp_path / "thirdparty"
    work.mkdir()
    destination.mkdir()
    package = work / "package.apk"
    package.write_bytes(b"ADB0payload")
    checks = MODULE.validate_and_publish_apks(
        "synthetic", [package], {"arch": "x86_64"}, destination,
        inspector=lambda _: ({"name": "pkg", "arch": "x86_64", "version": "1", "dependencies": []}, None),
    )
    assert (destination / "synthetic/package.apk").read_bytes() == b"ADB0payload"
    assert checks[0]["file"] == "synthetic/package.apk"
    assert checks[0]["metadata_status"] == "verified"


def test_provenance_revalidation_rejects_forged_local_apk(monkeypatch, tmp_path):
    payload = b"ADB0trusted"
    digest = hashlib.sha256(payload).hexdigest()
    url = "https://github.com/vernesong/OpenClash/releases/download/v1/package.apk"
    release = {"id": 101, "tag_name": "v1", "assets": [{
        "id": 202, "name": "package.apk", "digest": f"sha256:{digest}",
        "browser_download_url": url,
    }]}
    monkeypatch.setattr(MODULE, "release_metadata", lambda *args, **kwargs: release)

    def downloader(_url, destination):
        destination.write_bytes(payload)
        return digest

    monkeypatch.setattr(MODULE, "download", downloader)
    bundled = tmp_path / "thirdparty"
    (bundled / "openclash").mkdir(parents=True)
    (bundled / "openclash/package.apk").write_bytes(b"ADB0forged")
    status = {
        "release_id": 101, "upstream_release": "v1", "evidence_digest": "e" * 64,
        "assets": [{"asset_id": 202, "asset": "package.apk", "sha256": digest, "url": url}],
        "apk_checks": [{"file": "openclash/package.apk", "sha256": digest}],
    }
    cfg = {"repository": "vernesong/OpenClash", "archive_member_patterns": []}
    with pytest.raises(MODULE.ProviderError, match="bundled APK bytes"):
        MODULE.revalidate_status_provenance(
            "openclash", cfg, status, {}, bundled, {}
        )


def test_provenance_revalidation_accepts_upstream_identical_bundle(monkeypatch, tmp_path):
    payload = b"ADB0trusted"
    digest = hashlib.sha256(payload).hexdigest()
    url = "https://github.com/vernesong/OpenClash/releases/download/v1/package.apk"
    release = {"id": 101, "tag_name": "v1", "assets": [{
        "id": 202, "name": "package.apk", "digest": f"sha256:{digest}",
        "browser_download_url": url,
    }]}
    monkeypatch.setattr(MODULE, "release_metadata", lambda *args, **kwargs: release)
    monkeypatch.setattr(MODULE, "download", lambda _url, destination: (destination.write_bytes(payload), digest)[1])
    bundled = tmp_path / "thirdparty"
    (bundled / "openclash").mkdir(parents=True)
    (bundled / "openclash/package.apk").write_bytes(payload)
    status = {
        "release_id": 101, "upstream_release": "v1", "evidence_digest": "e" * 64,
        "assets": [{"asset_id": 202, "asset": "package.apk", "sha256": digest, "url": url}],
        "apk_checks": [{"file": "openclash/package.apk", "sha256": digest}],
    }
    cfg = {"repository": "vernesong/OpenClash", "archive_member_patterns": []}
    assert MODULE.revalidate_status_provenance(
        "openclash", cfg, status, {}, bundled, {}
    ) == "e" * 64
