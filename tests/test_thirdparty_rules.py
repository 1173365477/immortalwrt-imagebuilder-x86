from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import hashlib
from types import SimpleNamespace

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


def test_adbdump_json_preserves_dependency_constraints(monkeypatch, tmp_path):
    package = tmp_path / "package.apk"
    package.write_bytes(b"ADB0fixture")
    document = {"info": {
        "name": "luci-app-example", "version": "1.2-r0", "arch": "noarch",
        "depends": [
            {"name": "libexample", "version": "3.0", "match": 5},
            {"name": "libexact", "version": "1.0"},
            {"name": "ca-bundle"},
        ],
    }}
    monkeypatch.setattr(MODULE.shutil, "which", lambda name: "/usr/bin/apk")
    monkeypatch.setattr(MODULE.subprocess, "run", lambda command, **kwargs: SimpleNamespace(
        returncode=0, stdout=json.dumps(document), stderr=""
    ))
    metadata, warning = MODULE.inspect_apk_metadata(package)
    assert warning is None
    assert metadata["dependencies"] == ["libexample>=3.0", "libexact=1.0", "ca-bundle"]


@pytest.mark.parametrize("depends", [
    "libexample>=3.0",
    [{"version": "3.0", "match": 5}],
    [{"name": "libexample", "match": 5}],
    [{"name": "libexample", "version": "3.0", "match": 21}],
])
def test_adbdump_unparseable_dependencies_are_not_treated_as_empty(monkeypatch, tmp_path, depends):
    package = tmp_path / "package.apk"
    package.write_bytes(b"ADB0fixture")
    document = {"info": {
        "name": "luci-app-example", "version": "1.2-r0", "arch": "noarch",
        "depends": depends,
    }}
    monkeypatch.setattr(MODULE.shutil, "which", lambda name: "/usr/bin/apk")
    monkeypatch.setattr(MODULE.subprocess, "run", lambda command, **kwargs: SimpleNamespace(
        returncode=0, stdout=json.dumps(document), stderr=""
    ))
    metadata, warning = MODULE.inspect_apk_metadata(package)
    assert metadata is None
    assert "could not be parsed safely" in warning


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
            {"first", "second"},
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
            {"pkg"},
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
        {"pkg"},
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
    monkeypatch.setattr(MODULE, "inspect_apk_metadata", lambda _path: (
        {"name": "pkg", "arch": "x86_64", "version": "1", "dependencies": []}, None
    ))
    bundled = tmp_path / "thirdparty"
    (bundled / "openclash").mkdir(parents=True)
    (bundled / "openclash/package.apk").write_bytes(b"ADB0forged")
    status = {
        "release_id": 101, "upstream_release": "v1", "evidence_digest": "e" * 64,
        "assets": [{"asset_id": 202, "asset": "package.apk", "sha256": digest, "url": url}],
        "apk_checks": [{
            "file": "openclash/package.apk", "sha256": digest,
            "metadata_status": "verified", "package": "pkg", "architecture": "x86_64",
            "version": "1", "dependencies": [],
        }],
    }
    cfg = {
        "repository": "vernesong/OpenClash", "release": "tag", "tag_template": "{openclash_version}",
        "asset_patterns": [r"^package\.apk$"], "archive_member_patterns": [], "packages": ["pkg"],
        "supported_package_managers": ["apk"], "supported_distributions": ["immortalwrt"],
        "supported_architectures": ["x86_64"],
    }
    capabilities = {
        "distribution": "immortalwrt", "target_version": "25.12.2",
        "arch": "x86_64", "package_manager": "apk",
    }
    values = MODULE.template_values("25.12.2", capabilities, "v1")
    with pytest.raises(MODULE.ProviderError, match="bundled APK bytes"):
        MODULE.revalidate_status_provenance(
            "openclash", cfg, status, capabilities, bundled, values
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
    monkeypatch.setattr(MODULE, "inspect_apk_metadata", lambda _path: (
        {"name": "pkg", "arch": "x86_64", "version": "1", "dependencies": []}, None
    ))
    bundled = tmp_path / "thirdparty"
    (bundled / "openclash").mkdir(parents=True)
    (bundled / "openclash/package.apk").write_bytes(payload)
    status = {
        "release_id": 101, "upstream_release": "v1", "evidence_digest": "e" * 64,
        "assets": [{"asset_id": 202, "asset": "package.apk", "sha256": digest, "url": url}],
        "apk_checks": [{
            "file": "openclash/package.apk", "sha256": digest,
            "metadata_status": "verified", "package": "pkg", "architecture": "x86_64",
            "version": "1", "dependencies": [],
        }],
    }
    cfg = {
        "repository": "vernesong/OpenClash", "release": "tag", "tag_template": "{openclash_version}",
        "asset_patterns": [r"^package\.apk$"], "archive_member_patterns": [], "packages": ["pkg"],
        "supported_package_managers": ["apk"], "supported_distributions": ["immortalwrt"],
        "supported_architectures": ["x86_64"],
    }
    capabilities = {
        "distribution": "immortalwrt", "target_version": "25.12.2",
        "arch": "x86_64", "package_manager": "apk",
    }
    values = MODULE.template_values("25.12.2", capabilities, "v1")
    assert MODULE.revalidate_status_provenance(
        "openclash", cfg, status, capabilities, bundled, values
    ) == "e" * 64


def test_frozen_openclash_release_must_still_match_configured_version():
    cfg = rules()["providers"]["openclash"]
    capabilities = {
        "distribution": "immortalwrt", "target_version": "25.12.2",
        "arch": "x86_64", "package_manager": "apk",
    }
    values = MODULE.template_values("25.12.2", capabilities, "0.48.002")
    asset = {"id": 202, "name": "luci-app-openclash-0.48.999.apk"}
    release = {"id": 101, "tag_name": "v0.48.999", "assets": [asset]}
    status = {
        "upstream_release": "v0.48.999",
        "assets": [{"asset_id": 202, "asset": asset["name"]}],
    }
    with pytest.raises(MODULE.ProviderError, match="violates required tag"):
        MODULE.validate_frozen_release("openclash", cfg, release, status, capabilities, values)


@pytest.mark.parametrize(("provider", "release", "match"), [
    (
        "nikki",
        {"id": 301, "tag_name": "v1.0.0", "assets": [
            {"id": 302, "name": "nikki_aarch64-openwrt-25.12.tar.gz"},
        ]},
        "no release asset matching",
    ),
    (
        "nikki",
        {"id": 311, "tag_name": "v1.0.0", "assets": [
            {"id": 312, "name": "nikki_x86_64-openwrt-24.10.tar.gz"},
        ]},
        "no release asset matching",
    ),
    (
        "lucky",
        {"id": 401, "tag_name": "v2.0.0", "body": "OpenWrt 24.10", "assets": [
            {"id": 402, "name": "lucky-2.0.0_x86_64.apk"},
            {"id": 403, "name": "luci-app-lucky-2.0.0_x86_64.apk"},
            {"id": 404, "name": "luci-i18n-lucky-zh-cn-2.0.0_x86_64.apk"},
        ]},
        "does not declare compatibility",
    ),
    (
        "lucky",
        {"id": 411, "tag_name": "v2.0.0", "body": "ImmortalWrt 25.12", "assets": [
            {"id": 412, "name": "lucky-2.0.0_aarch64.apk"},
            {"id": 413, "name": "luci-app-lucky-2.0.0_x86_64.apk"},
            {"id": 414, "name": "luci-i18n-lucky-zh-cn-2.0.0_x86_64.apk"},
        ]},
        "no release asset matching",
    ),
])
def test_latest_provider_frozen_release_rechecks_series_arch_and_assets(provider, release, match):
    cfg = rules()["providers"][provider]
    capabilities = {
        "distribution": "immortalwrt", "target_version": "25.12.2",
        "arch": "x86_64", "package_manager": "apk",
    }
    values = MODULE.template_values("25.12.2", capabilities, "0.48.002")
    status = {
        "upstream_release": release["tag_name"],
        "assets": [{"asset_id": asset["id"], "asset": asset["name"]} for asset in release["assets"]],
    }
    with pytest.raises(MODULE.ProviderError, match=match):
        MODULE.validate_frozen_release(provider, cfg, release, status, capabilities, values)


def test_frozen_openclash_release_with_complete_rule_evidence_is_accepted():
    cfg = rules()["providers"]["openclash"]
    capabilities = {
        "distribution": "immortalwrt", "target_version": "25.12.2",
        "arch": "x86_64", "package_manager": "apk",
    }
    values = MODULE.template_values("25.12.2", capabilities, "0.48.002")
    asset = {"id": 202, "name": "luci-app-openclash-0.48.002.apk"}
    release = {"id": 101, "tag_name": "v0.48.002", "assets": [asset]}
    status = {
        "upstream_release": "v0.48.002",
        "assets": [{"asset_id": 202, "asset": asset["name"]}],
    }
    assert MODULE.validate_frozen_release(
        "openclash", cfg, release, status, capabilities, values
    ) == [asset]


@pytest.mark.parametrize(("metadata", "match"), [
    ({"name": "other-package", "arch": "x86_64", "version": "1", "dependencies": []}, "package name"),
    ({"name": "pkg", "arch": "aarch64", "version": "1", "dependencies": []}, "architecture"),
    ({"name": "pkg", "arch": "x86_64", "version": "1"}, "metadata is incomplete"),
])
def test_consumer_rejects_apk_internal_identity_arch_or_dependencies(monkeypatch, tmp_path, metadata, match):
    payload = b"ADB0trusted"
    digest = hashlib.sha256(payload).hexdigest()
    url = "https://github.com/vernesong/OpenClash/releases/download/v1/package.apk"
    release = {"id": 101, "tag_name": "v1", "assets": [{
        "id": 202, "name": "package.apk", "digest": f"sha256:{digest}",
        "browser_download_url": url,
    }]}
    monkeypatch.setattr(MODULE, "release_metadata", lambda *args, **kwargs: release)
    monkeypatch.setattr(MODULE, "download", lambda _url, destination: (destination.write_bytes(payload), digest)[1])
    monkeypatch.setattr(MODULE, "inspect_apk_metadata", lambda _path: (metadata, None))
    bundled = tmp_path / "thirdparty"
    (bundled / "openclash").mkdir(parents=True)
    (bundled / "openclash/package.apk").write_bytes(payload)
    status = {
        "release_id": 101, "upstream_release": "v1", "evidence_digest": "e" * 64,
        "assets": [{"asset_id": 202, "asset": "package.apk", "sha256": digest, "url": url}],
        "apk_checks": [{
            "file": "openclash/package.apk", "sha256": digest,
            "metadata_status": "verified", "package": "pkg", "architecture": "x86_64",
            "version": "1", "dependencies": [],
        }],
    }
    cfg = {
        "repository": "vernesong/OpenClash", "release": "tag", "tag_template": "{openclash_version}",
        "asset_patterns": [r"^package\.apk$"], "archive_member_patterns": [], "packages": ["pkg"],
        "supported_package_managers": ["apk"], "supported_distributions": ["immortalwrt"],
        "supported_architectures": ["x86_64"],
    }
    capabilities = {
        "distribution": "immortalwrt", "target_version": "25.12.2",
        "arch": "x86_64", "package_manager": "apk",
    }
    with pytest.raises(MODULE.ProviderError, match=match):
        MODULE.revalidate_status_provenance(
            "openclash", cfg, status, capabilities, bundled,
            MODULE.template_values("25.12.2", capabilities, "v1"),
        )
