#!/usr/bin/env python3
"""Resolve and freeze an official release plus its verified package indexes."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from release_utils import (
    ReleaseValidationError,
    discover_feed_names,
    discover_release,
    get_url,
    official_download_root,
    parse_sha256sums,
)


@dataclass(frozen=True)
class ReleaseRequest:
    distribution: str = "immortalwrt"
    version: str = "25.12.2"
    target: str = "x86/64"
    profile: str = "generic"
    filesystem: str = "ext4"
    image_type: str = "combined-efi"
    architecture: str | None = "x86_64"


def _json_object(data: bytes, source: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError(f"Invalid JSON from official source: {source}") from exc
    if not isinstance(value, dict):
        raise ReleaseValidationError(f"Official index is not a JSON object: {source}")
    return value


def _verified_fetch(
    url: str,
    *,
    manifest_url: str,
    manifest_name: str,
    fetch: Callable[[str], bytes],
) -> tuple[bytes, dict[str, str]]:
    manifest = fetch(manifest_url)
    try:
        entries = parse_sha256sums(manifest.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ReleaseValidationError(f"Invalid checksum manifest: {manifest_url}") from exc
    expected = entries.get(manifest_name)
    if not expected:
        raise ReleaseValidationError(
            f"Checksum manifest {manifest_url} does not authenticate {manifest_name}"
        )
    data = fetch(url)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ReleaseValidationError(
            f"Official index checksum mismatch for {url}: expected {expected}, got {actual}"
        )
    return data, {
        "url": url,
        "sha256": actual,
        "checksum_manifest_url": manifest_url,
        "checksum_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "checksum_entry": manifest_name,
    }


def resolve_release(
    request: ReleaseRequest,
    *,
    fetch: Callable[[str], bytes] = get_url,
    resolved_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    capabilities, profiles = discover_release(
        request.version,
        distribution=request.distribution,
        target=request.target,
        profile_name=request.profile,
        filesystem=request.filesystem,
        image_type=request.image_type,
        fetch=fetch,
    )
    if request.architecture and capabilities.get("arch") != request.architecture:
        raise ReleaseValidationError(
            f"Official target package architecture is {capabilities.get('arch')!r}; "
            f"expected {request.architecture!r}."
        )
    arch = capabilities["arch"]
    root = official_download_root(request.distribution)
    package_root = f"{root}/releases/{request.version}/packages/{arch}"
    package_sums_url = f"{package_root}/sha256sums"
    package_sums = fetch(package_sums_url)
    try:
        feed_names = discover_feed_names(package_sums.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ReleaseValidationError(f"Invalid package checksum manifest: {package_sums_url}") from exc

    source_specs = [
        (
            f"{capabilities['base_url']}/packages/index.json",
            capabilities["sha256sums_url"],
            "packages/index.json",
        ),
        *(
            (f"{package_root}/{feed}/index.json", package_sums_url, f"{feed}/index.json")
            for feed in feed_names
        ),
    ]
    packages: dict[str, Any] = {}
    sources: list[dict[str, str]] = []
    for url, sums_url, name in source_specs:
        data, provenance = _verified_fetch(
            url, manifest_url=sums_url, manifest_name=name, fetch=fetch
        )
        index = _json_object(data, url)
        rows = index.get("packages")
        if not isinstance(rows, dict):
            raise ReleaseValidationError(f"Official index lacks a packages object: {url}")
        for package, metadata in rows.items():
            if package in packages and packages[package] != metadata:
                raise ReleaseValidationError(
                    f"Inconsistent duplicate package metadata for {package!r}"
                )
            packages[package] = metadata
        sources.append(provenance)

    resolved_at = resolved_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    capabilities.update(
        {
            "resolved_at": resolved_at,
            "feed_names": feed_names,
            "package_index_sources": sources,
            "official_package_count": len(packages),
            "official_index_digest": hashlib.sha256(
                json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "profiles_content_digest": hashlib.sha256(
                json.dumps(profiles, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
    )
    pin_payload = json.dumps(capabilities, sort_keys=True, separators=(",", ":")).encode()
    capabilities["resolution_digest"] = hashlib.sha256(pin_payload).hexdigest()
    return capabilities, packages


class ReleaseCache:
    """Small fail-closed cache; stale data is never silently accepted."""

    def __init__(self, directory: Path, ttl_seconds: int = 3600):
        if ttl_seconds < 1 or ttl_seconds > 7 * 24 * 3600:
            raise ValueError("cache TTL must be between 1 second and 7 days")
        self.directory = directory
        self.ttl_seconds = ttl_seconds

    def load(self, name: str, now: int | None = None) -> bytes | None:
        if not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("unsafe cache key")
        path = self.directory / f"{name}.json"
        if not path.exists():
            return None
        now = int(time.time()) if now is None else now
        if now - int(path.stat().st_mtime) > self.ttl_seconds:
            return None
        return path.read_bytes()

    def store(self, name: str, value: bytes) -> None:
        if not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("unsafe cache key")
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self.directory / f"{name}.json"
        temporary = self.directory / f".{name}.tmp"
        temporary.write_bytes(value)
        temporary.replace(target)
