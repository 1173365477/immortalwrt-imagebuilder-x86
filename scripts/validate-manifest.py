#!/usr/bin/env python3
"""Validate generated manifests and optionally verify official upstream metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

import yaml


PACKAGE_RE = re.compile(r"^-?[A-Za-z0-9][A-Za-z0-9+_.@-]*$")


def lines(path: Path) -> list[str]:
    if not path.exists():
        raise ValueError(f"required file is missing: {path}")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def get_url(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "immortalwrt-migration-builder/1"})
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read()


def validate(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []
    official = lines(args.generated / "packages-official.txt")
    thirdparty = lines(args.generated / "packages-thirdparty.txt")
    missing = lines(args.generated / "packages-missing.txt")
    analysis = json.loads((args.generated / "system-analysis.json").read_text(encoding="utf-8"))
    provider_cfg = yaml.safe_load(args.thirdparty.read_text(encoding="utf-8"))["providers"]

    for package in official:
        if not PACKAGE_RE.fullmatch(package):
            errors.append(f"invalid official package token: {package!r}")
    if len(official) != len(set(official)):
        errors.append("packages-official.txt contains duplicates")
    positive = {item for item in official if not item.startswith("-")}
    negative = {item[1:] for item in official if item.startswith("-")}
    overlap = positive & negative
    if overlap:
        errors.append(f"packages are both added and removed: {sorted(overlap)}")
    if "dnsmasq-full" in positive and "dnsmasq" not in negative:
        errors.append("dnsmasq-full requires an explicit -dnsmasq removal")
    for item in thirdparty:
        if ":" not in item:
            errors.append(f"third-party entry must be provider:package: {item}")
            continue
        provider, package = item.split(":", 1)
        if provider not in provider_cfg:
            errors.append(f"undefined third-party provider: {provider}")
        if not PACKAGE_RE.fullmatch(package):
            errors.append(f"invalid third-party package name: {package}")

    expected = {
        "target": "x86/64",
        "profile": "generic",
        "rootfs_type": "ext4",
    }
    for key, value in expected.items():
        actual = analysis.get(key)
        if actual and actual.lower() != value.lower():
            errors.append(f"report {key} is {actual!r}; expected {value!r}")
    report_target = analysis.get("target_version")
    if report_target and not str(report_target).startswith("25.12"):
        errors.append(f"owut report target version is {report_target!r}, not 25.12.x")

    if args.strict and missing:
        errors.append(f"strict mode: {len(missing)} unresolved package(s) remain")

    if args.online:
        base = f"https://downloads.immortalwrt.org/releases/{args.version}/targets/x86/64"
        try:
            profiles = json.loads(get_url(f"{base}/profiles.json"))
            if profiles.get("target") != "x86/64" or "generic" not in profiles.get("profiles", {}):
                errors.append("official profiles.json does not contain x86/64 PROFILE=generic")
            images = profiles.get("profiles", {}).get("generic", {}).get("images", [])
            wanted = [
                image for image in images
                if image.get("filesystem") == "ext4" and image.get("type") == "combined-efi" and image.get("name", "").endswith(".img.gz")
            ]
            if not wanted:
                errors.append("profiles.json lacks the generic ext4 combined-efi .img.gz image")
            sums = get_url(f"{base}/sha256sums").decode("utf-8", errors="replace")
            imagebuilder = f"immortalwrt-imagebuilder-{args.version}-x86-64.Linux-x86_64.tar.zst"
            if not re.search(rf"^[0-9a-f]{{64}} \*{re.escape(imagebuilder)}$", sums, re.MULTILINE):
                errors.append(f"sha256sums lacks {imagebuilder}")

            kernel = profiles.get("linux_kernel", {})
            kmod_dir = f"{kernel.get('version')}-{kernel.get('release')}-{kernel.get('vermagic')}"
            index_urls = [
                f"{base}/packages/index.json",
                f"{base}/kmods/{kmod_dir}/index.json",
                *(
                    f"https://downloads.immortalwrt.org/releases/{args.version}/packages/x86_64/{feed}/index.json"
                    for feed in ("base", "luci", "packages", "routing", "telephony")
                ),
            ]
            available: set[str] = set()
            for index_url in index_urls:
                index = json.loads(get_url(index_url))
                available.update(index.get("packages", {}).keys())
            unavailable = sorted(positive - available)
            if unavailable:
                errors.append(f"official package index has no entry for: {', '.join(unavailable)}")
        except Exception as exc:  # network errors must fail validation in online mode
            errors.append(f"official metadata verification failed: {exc}")

    # This is the exact whitespace-separated PACKAGES value consumed by ImageBuilder.
    (args.generated / "final-packages.txt").write_text(" ".join(official) + "\n", encoding="utf-8")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generated", type=Path, default=Path("generated"))
    parser.add_argument("--thirdparty", type=Path, default=Path("config/thirdparty.yml"))
    parser.add_argument("--version", default="25.12.2")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()
    try:
        errors = validate(args)
    except (ValueError, KeyError, json.JSONDecodeError, yaml.YAMLError) as exc:
        errors = [str(exc)]
    if errors:
        for error in errors:
            print(f"::error::{error}")
        return 1
    print("Manifest validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

