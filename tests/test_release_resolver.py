from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from release_resolver import ReleaseCache, ReleaseRequest, resolve_release
from release_utils import ReleaseValidationError, discover_release


def fixture_fetch(*, manager="apk", corrupt_index=False, arch="x86_64"):
    version = "29.0.1"
    profiles = json.loads(Path("tests/fixtures/profiles-29.0.json").read_text())
    profiles["arch_packages"] = arch
    profiles["default_packages"] = [manager]
    profiles_bytes = json.dumps(profiles, separators=(",", ":")).encode()
    target_index = json.dumps({"packages": {"base-files": {"version": "1"}}}).encode()
    feed_index = json.dumps({"packages": {"curl": {"version": "9", "depends": ["libc"]}}}).encode()
    imagebuilder = "immortalwrt-imagebuilder-29.0.1-x86-64.Linux-x86_64.tar.zst"
    image = next(
        item for item in profiles["profiles"]["generic"]["images"]
        if item["type"] == "combined-efi" and item["filesystem"] == "ext4"
    )
    target_sums = (
        f"{hashlib.sha256(profiles_bytes).hexdigest()}  profiles.json\n"
        f"{'d' * 64}  {imagebuilder}\n"
        f"{image['sha256']}  {image['name']}\n"
        f"{hashlib.sha256(target_index).hexdigest()}  packages/index.json\n"
    ).encode()
    feed_sums = (
        f"{hashlib.sha256(feed_index).hexdigest()}  base/index.json\n"
    ).encode()
    base = "https://downloads.immortalwrt.org/releases/29.0.1"
    mapping = {
        f"{base}/targets/x86/64/profiles.json": profiles_bytes,
        f"{base}/targets/x86/64/sha256sums": target_sums,
        f"{base}/targets/x86/64/packages/index.json": b"{}" if corrupt_index else target_index,
        f"{base}/packages/{arch}/sha256sums": feed_sums,
        f"{base}/packages/{arch}/base/index.json": feed_index,
    }

    def fetch(url):
        if url not in mapping:
            raise ReleaseValidationError(f"unexpected fixture URL: {url}")
        return mapping[url]

    return fetch


def test_future_release_is_pinned_with_verified_sources():
    capabilities, packages = resolve_release(
        ReleaseRequest(version="29.0.1"),
        fetch=fixture_fetch(),
        resolved_at="2030-01-01T00:00:00Z",
    )
    assert capabilities["target_version"] == "29.0.1"
    assert capabilities["channel"] == "release"
    assert capabilities["resolution_digest"]
    assert all(source["sha256"] for source in capabilities["package_index_sources"])
    assert set(packages) == {"base-files", "curl"}


def test_corrupt_index_digest_blocks_resolution():
    with pytest.raises(ReleaseValidationError, match="checksum mismatch"):
        resolve_release(ReleaseRequest(version="29.0.1"), fetch=fixture_fetch(corrupt_index=True))


def test_wrong_architecture_cannot_reuse_x86_indexes():
    with pytest.raises(ReleaseValidationError, match="unexpected fixture URL"):
        resolve_release(
            ReleaseRequest(version="29.0.1"), fetch=fixture_fetch(arch="aarch64_cortex-a53")
        )


def test_openwrt_and_immortalwrt_sources_never_mix():
    with pytest.raises(ReleaseValidationError, match="unexpected fixture URL"):
        discover_release("29.0.1", distribution="openwrt", fetch=fixture_fetch())


def test_cache_rejects_stale_and_path_traversal(tmp_path):
    cache = ReleaseCache(tmp_path, ttl_seconds=10)
    cache.store("release_29", b"{}")
    assert cache.load("release_29", now=int((tmp_path / "release_29.json").stat().st_mtime) + 9) == b"{}"
    assert cache.load("release_29", now=int((tmp_path / "release_29.json").stat().st_mtime) + 11) is None
    with pytest.raises(ValueError):
        cache.load("../../escape")


def test_opkg_is_identified_without_claiming_apk_compatibility():
    capabilities, _ = resolve_release(
        ReleaseRequest(version="29.0.1"), fetch=fixture_fetch(manager="opkg")
    )
    assert capabilities["package_manager"] == "opkg"
