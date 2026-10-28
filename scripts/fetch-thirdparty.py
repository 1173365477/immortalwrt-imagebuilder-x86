#!/usr/bin/env python3
"""Fetch selected third-party release assets through GitHub API metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

import yaml


def api_json(url: str) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "immortalwrt-migration-builder/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        return json.load(response)


def download(url: str, destination: Path) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "immortalwrt-migration-builder/1"})
    digest = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=180) as response, destination.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)
            digest.update(chunk)
    return digest.hexdigest()


def selected_providers(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.split(":", 1)[0].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#") and ":" in line
    }


def format_pattern(pattern: str, args: argparse.Namespace) -> str:
    return pattern.format(openclash_version=re.escape(args.openclash_version))


def verify_digest(asset: dict[str, Any], actual: str, required: bool) -> None:
    declared = asset.get("digest")
    if not declared:
        if required:
            raise RuntimeError(f"GitHub API did not provide a digest for {asset['name']}")
        return
    algorithm, expected = declared.split(":", 1)
    if algorithm.lower() != "sha256" or actual.lower() != expected.lower():
        raise RuntimeError(f"digest mismatch for {asset['name']}: expected {declared}, got sha256:{actual}")


def copy_archive_members(archive: Path, patterns: list[re.Pattern[str]], destination: Path) -> list[Path]:
    copied: list[Path] = []
    matched = [False] * len(patterns)
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise RuntimeError(f"unsafe archive member: {member.name}")
            basename = pure.name
            for index, pattern in enumerate(patterns):
                if pattern.fullmatch(basename):
                    source = tar.extractfile(member)
                    if source is None:
                        raise RuntimeError(f"cannot read archive member: {member.name}")
                    target = destination / basename
                    with source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
                    copied.append(target)
                    matched[index] = True
                    break
    missing = [patterns[index].pattern for index, state in enumerate(matched) if not state]
    if missing:
        raise RuntimeError(f"archive lacks required APK pattern(s): {missing}")
    return copied


def release_metadata(provider: str, cfg: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    base = f"https://api.github.com/repos/{cfg['repository']}/releases"
    if cfg.get("release") == "latest":
        return api_json(f"{base}/latest")
    if cfg.get("release") == "tag":
        tag = cfg["tag_template"].format(openclash_version=args.openclash_version)
        return api_json(f"{base}/tags/{tag}")
    raise RuntimeError(f"{provider}: unsupported release strategy {cfg.get('release')!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("config/thirdparty.yml"))
    parser.add_argument("--selection", type=Path, default=Path("generated/packages-thirdparty.txt"))
    parser.add_argument("--destination", type=Path, default=Path("files/root/thirdparty"))
    parser.add_argument("--metadata", type=Path, default=Path("generated/thirdparty-assets.json"))
    parser.add_argument("--openclash-version", default="0.48.002")
    args = parser.parse_args()
    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))["providers"]
    selected = selected_providers(args.selection)
    args.destination.mkdir(parents=True, exist_ok=True)
    for stale in args.destination.glob("*.apk"):
        stale.unlink()
    records: list[dict[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="thirdparty-") as temp_name:
        temp = Path(temp_name)
        for provider in sorted(selected):
            if provider not in config:
                raise RuntimeError(f"selected provider is not configured: {provider}")
            cfg = config[provider]
            release = release_metadata(provider, cfg, args)
            compatibility = cfg.get("compatibility_body_regex")
            if compatibility and not re.search(compatibility, release.get("body") or "", re.IGNORECASE):
                raise RuntimeError(f"{provider}: release notes do not confirm required compatibility: {compatibility}")
            assets = release.get("assets", [])
            patterns = [re.compile(format_pattern(pattern, args)) for pattern in cfg.get("asset_patterns", [])]
            matches: list[dict[str, Any]] = []
            for pattern in patterns:
                found = [asset for asset in assets if pattern.fullmatch(asset.get("name", ""))]
                if len(found) != 1:
                    raise RuntimeError(f"{provider}: expected exactly one asset matching {pattern.pattern!r}, found {len(found)}")
                matches.extend(found)
            extracted: list[Path] = []
            for asset in matches:
                target = temp / asset["name"]
                actual = download(asset["browser_download_url"], target)
                verify_digest(asset, actual, bool(cfg.get("require_digest")))
                records.append({
                    "provider": provider,
                    "release": release.get("tag_name", ""),
                    "asset": asset["name"],
                    "sha256": actual,
                    "url": asset["browser_download_url"],
                })
                if target.name.endswith(".tar.gz"):
                    archive_patterns = [re.compile(pattern) for pattern in cfg.get("archive_member_patterns", [])]
                    extracted.extend(copy_archive_members(target, archive_patterns, args.destination))
                elif target.name.endswith(".apk"):
                    final = args.destination / target.name
                    shutil.copy2(target, final)
                    extracted.append(final)
                else:
                    raise RuntimeError(f"{provider}: unsupported asset type: {target.name}")
            if not extracted:
                raise RuntimeError(f"{provider}: no APK was produced")

    apk_files = sorted(args.destination.glob("*.apk"))
    for path in apk_files:
        with path.open("rb") as package_file:
            magic = package_file.read(3)
        if path.stat().st_size < 4 or magic != b"ADB":
            raise RuntimeError(f"downloaded file is not an APK v3 package: {path.name}")
    sums = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in apk_files]
    (args.metadata.parent / "thirdparty-sha256sums").write_text("\n".join(sums) + ("\n" if sums else ""), encoding="utf-8")
    args.metadata.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Third-party APK files:")
    for path in apk_files:
        print(f"  {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

