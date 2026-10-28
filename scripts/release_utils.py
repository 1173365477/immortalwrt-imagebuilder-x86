#!/usr/bin/env python3
"""Shared release/version/capability helpers for the migration builder."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable


VERSION_RE = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)"
    r"(?:\.(?P<patch>0|[1-9][0-9]*))?"
    r"(?P<prerelease>-(?:rc|beta|alpha)[0-9]+)?$"
)
SHA256_LINE_RE = re.compile(r"^(?P<digest>[0-9a-f]{64})\s+\*?(?P<name>\S+)$")
SUPPORTED_ARCHIVE_SUFFIXES = (".tar.zst", ".tar.xz", ".tar.gz")


class ReleaseValidationError(ValueError):
    """Raised when official release metadata lacks a required capability."""


@dataclass(frozen=True)
class VersionInfo:
    target_version: str
    target_series: str
    target_major: str
    major: int
    minor: int
    patch: int | None
    prerelease: str | None


def parse_version(value: str) -> VersionInfo:
    """Validate a release string and derive stable template values."""
    if value != value.strip():
        match = None
    else:
        match = VERSION_RE.fullmatch(value)
    if not match:
        raise ReleaseValidationError(
            "Invalid ImmortalWrt release version. Expected forms such as "
            "25.12, 25.12.2, or 25.12.0-rc1."
        )
    major = int(match.group("major"))
    minor = int(match.group("minor"))
    patch_text = match.group("patch")
    prerelease = match.group("prerelease")
    return VersionInfo(
        target_version=value,
        target_series=f"{major}.{minor}",
        target_major=str(major),
        major=major,
        minor=minor,
        patch=int(patch_text) if patch_text is not None else None,
        prerelease=prerelease[1:] if prerelease else None,
    )


def versions_equal(report_version: str, requested_version: str) -> bool:
    try:
        return parse_version(report_version).target_version == parse_version(requested_version).target_version
    except ReleaseValidationError:
        return False


def parse_sha256sums(text: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = SHA256_LINE_RE.fullmatch(line.strip())
        if match:
            entries[match.group("name")] = match.group("digest")
    return entries


def discover_imagebuilder(sha256sums: str, version: str) -> tuple[str, str]:
    parse_version(version)
    entries = parse_sha256sums(sha256sums)
    prefix = f"immortalwrt-imagebuilder-{version}-x86-64."
    candidates = [
        name for name in entries
        if name.startswith(prefix) and name.endswith(SUPPORTED_ARCHIVE_SUFFIXES)
    ]
    preferred = [name for name in candidates if ".Linux-x86_64." in name and name.endswith(".tar.zst")]
    if len(preferred) == 1:
        chosen = preferred[0]
    elif len(candidates) == 1:
        chosen = candidates[0]
    elif not candidates:
        raise ReleaseValidationError(
            f"No supported x86_64 ImageBuilder archive was found for release {version} in sha256sums."
        )
    else:
        raise ReleaseValidationError(
            "Ambiguous ImageBuilder archive match: " + ", ".join(sorted(candidates))
        )
    return chosen, entries[chosen]


def available_images(profile: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    for image in profile.get("images", []):
        filesystem = image.get("filesystem") or "unspecified-fs"
        image_type = image.get("type") or "unspecified-type"
        name = image.get("name") or "unnamed"
        rows.append(f"{filesystem} {image_type}: {name}")
    return sorted(rows)


def resolve_image_capability(
    profiles: dict[str, Any],
    *,
    target: str = "x86/64",
    profile_name: str = "generic",
    filesystem: str = "ext4",
    image_type: str = "combined-efi",
) -> dict[str, Any]:
    if profiles.get("target") != target:
        raise ReleaseValidationError(
            f"Official profiles metadata target is {profiles.get('target')!r}; expected {target!r}."
        )
    profile = profiles.get("profiles", {}).get(profile_name)
    if not isinstance(profile, dict):
        available = ", ".join(sorted(profiles.get("profiles", {}))) or "none"
        raise ReleaseValidationError(
            f"PROFILE={profile_name} is unavailable for {target}. Available profiles: {available}."
        )
    matches = [
        image for image in profile.get("images", [])
        if image.get("filesystem") == filesystem
        and image.get("type") == image_type
        and str(image.get("name", "")).endswith(".img.gz")
    ]
    if len(matches) != 1:
        listing = available_images(profile)
        formatted = "\n  - " + "\n  - ".join(listing) if listing else " none"
        raise ReleaseValidationError(
            f"Required image capability {filesystem}/{image_type} is not uniquely available. "
            f"Available {profile_name} images:{formatted}"
        )
    return matches[0]


def detect_package_manager(profiles: dict[str, Any]) -> str:
    defaults = set(profiles.get("default_packages", []))
    if any(name == "apk" or name.startswith("apk-") for name in defaults):
        return "apk"
    if "opkg" in defaults:
        return "opkg"
    raise ReleaseValidationError(
        "Unsupported target package manager detected: unknown. "
        "Repository logic currently supports APK targets only."
    )


def discover_feed_names(package_sha256sums: str) -> list[str]:
    entries = parse_sha256sums(package_sha256sums)
    feeds = {
        name.split("/", 1)[0]
        for name in entries
        if "/" in name and name.endswith(("/index.json", "/packages.adb"))
    }
    if not feeds:
        # Compatibility fallback for older release layouts without a root feed manifest.
        return ["base", "luci", "packages", "routing", "telephony"]
    return sorted(feeds)


def build_kmod_index_url(base_url: str, profiles: dict[str, Any]) -> str:
    kernel = profiles.get("linux_kernel", {})
    required = (kernel.get("version"), kernel.get("release"), kernel.get("vermagic"))
    if not all(required):
        raise ReleaseValidationError("profiles.json lacks complete linux_kernel version/release/vermagic metadata.")
    directory = "-".join(str(item) for item in required)
    return f"{base_url}/kmods/{directory}/index.json"


def get_url(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "immortalwrt-migration-builder/2"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise ReleaseValidationError(f"Official release resource is unavailable ({exc.code}): {url}") from exc
    except urllib.error.URLError as exc:
        raise ReleaseValidationError(f"Cannot read official release resource: {url}: {exc.reason}") from exc


def discover_release(
    version: str,
    *,
    fetch: Callable[[str], bytes] = get_url,
) -> tuple[dict[str, Any], dict[str, str]]:
    info = parse_version(version)
    base_url = f"https://downloads.immortalwrt.org/releases/{version}/targets/x86/64"
    profiles_url = f"{base_url}/profiles.json"
    sums_url = f"{base_url}/sha256sums"
    profiles = json.loads(fetch(profiles_url).decode("utf-8"))
    sums_text = fetch(sums_url).decode("utf-8")
    expected_image = resolve_image_capability(profiles)
    package_manager = detect_package_manager(profiles)
    if package_manager != "apk":
        raise ReleaseValidationError(
            f"Unsupported target package manager detected: {package_manager}. "
            "Repository logic currently supports APK targets only."
        )
    archive, archive_sha256 = discover_imagebuilder(sums_text, version)
    capabilities: dict[str, Any] = {
        **asdict(info),
        "target": "x86/64",
        "arch": profiles.get("arch_packages") or "x86_64",
        "profile": "generic",
        "filesystem": "ext4",
        "image_type": "combined-efi",
        "expected_image_name": expected_image["name"],
        "expected_image_sha256": expected_image.get("sha256"),
        "package_manager": package_manager,
        "profiles_url": profiles_url,
        "sha256sums_url": sums_url,
        "base_url": base_url,
        "imagebuilder_filename": archive,
        "imagebuilder_sha256": archive_sha256,
        "imagebuilder_url": f"{base_url}/{archive}",
        "kernel": profiles.get("linux_kernel", {}),
        "available_images": available_images(profiles["profiles"]["generic"]),
    }
    return capabilities, profiles


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()

