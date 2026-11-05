from __future__ import annotations

import json
from pathlib import Path

import pytest

from release_utils import (
    ReleaseValidationError,
    detect_package_manager,
    discover_feed_names,
    discover_imagebuilder,
    discover_release,
    parse_version,
    resolve_image_capability,
)


@pytest.mark.parametrize(
    ("value", "series", "major"),
    [
        ("25.12", "25.12", "25"),
        ("25.12.2", "25.12", "25"),
        ("29.0.1", "29.0", "29"),
        ("29.1.7", "29.1", "29"),
        ("29.0.0-rc1", "29.0", "29"),
    ],
)
def test_version_templates(value: str, series: str, major: str) -> None:
    parsed = parse_version(value)
    assert parsed.target_series == series
    assert parsed.target_major == major


@pytest.mark.parametrize(
    "value",
    ["latest", "foo", "25", " 25.12.2", "25.12.2 ", "../../etc/passwd", "25.12/../../etc", "25.12;rm", "25.12.2;echo", "v25.12.2", "25.12.02"],
)
def test_malformed_versions_are_rejected(value: str) -> None:
    with pytest.raises(ReleaseValidationError):
        parse_version(value)


def test_imagebuilder_discovery_is_metadata_driven() -> None:
    filename = "immortalwrt-imagebuilder-29.0.1-x86-64.Linux-x86_64.tar.xz"
    name, digest = discover_imagebuilder(f"{'a' * 64}  {filename}\n", "29.0.1")
    assert name == filename
    assert digest == "a" * 64


def test_missing_imagebuilder_is_actionable() -> None:
    with pytest.raises(ReleaseValidationError, match="No supported x86_64 ImageBuilder"):
        discover_imagebuilder(f"{'a' * 64}  profiles.json\n", "29.0.1")


def test_missing_required_image_lists_available_images() -> None:
    profiles = json.loads(Path("tests/fixtures/profiles-29.0.json").read_text(encoding="utf-8"))
    profiles["profiles"]["generic"]["images"] = profiles["profiles"]["generic"]["images"][1:]
    with pytest.raises(ReleaseValidationError, match="Available generic images"):
        resolve_image_capability(profiles)


def test_missing_generic_profile_fails_safely() -> None:
    profiles = json.loads(Path("tests/fixtures/profiles-29.0.json").read_text(encoding="utf-8"))
    profiles["profiles"] = {}
    with pytest.raises(ReleaseValidationError, match="PROFILE=generic is unavailable"):
        resolve_image_capability(profiles)


def test_unknown_package_manager_fails_closed() -> None:
    with pytest.raises(ReleaseValidationError, match="unknown"):
        detect_package_manager({"default_packages": ["base-files"]})


def test_feed_names_are_discovered() -> None:
    sums = "\n".join([
        f"{'a' * 64}  base/index.json",
        f"{'b' * 64}  luci/packages.adb",
        f"{'c' * 64}  custom/index.json",
    ])
    assert discover_feed_names(sums) == ["base", "custom", "luci"]


def test_synthetic_future_release_capabilities() -> None:
    profiles = Path("tests/fixtures/profiles-29.0.json").read_bytes()
    archive = "immortalwrt-imagebuilder-29.0.1-x86-64.Linux-x86_64.tar.zst"
    sums = f"{'d' * 64}  {archive}\n".encode()

    def fetch(url: str) -> bytes:
        return profiles if url.endswith("profiles.json") else sums

    capabilities, _ = discover_release("29.0.1", fetch=fetch)
    assert capabilities["target_series"] == "29.0"
    assert capabilities["expected_image_name"].endswith("combined-efi.img.gz")
    assert capabilities["imagebuilder_filename"] == archive


def test_nonexistent_release_stops_during_metadata_discovery() -> None:
    def fetch(url: str) -> bytes:
        raise ReleaseValidationError(f"Official release resource is unavailable (404): {url}")

    with pytest.raises(ReleaseValidationError, match="404"):
        discover_release("99.0.1", fetch=fetch)

