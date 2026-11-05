#!/usr/bin/env python3
"""Validate generated manifests and optionally verify official upstream metadata."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Callable

import yaml

from release_utils import (
    ReleaseValidationError,
    build_kmod_index_url,
    discover_feed_names,
    discover_release,
    get_url,
    parse_version,
    versions_equal,
)


PACKAGE_RE = re.compile(r"^-?[A-Za-z0-9][A-Za-z0-9+_.@-]*$")


def lines(path: Path) -> list[str]:
    if not path.exists():
        raise ValueError(f"required file is missing: {path}")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def validate(args: argparse.Namespace, fetch: Callable[[str], bytes] = get_url) -> list[str]:
    errors: list[str] = []
    try:
        parse_version(args.version)
    except ReleaseValidationError as exc:
        return [str(exc)]
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

    expected: dict[str, str] = {
        "target": "x86/64",
        "profile": "generic",
        "rootfs_type": "ext4",
    }
    for key, value in expected.items():
        actual = analysis.get(key)
        if not actual:
            errors.append(f"migration report is missing required field: {key}")
        elif str(actual).lower() != value.lower():
            errors.append(f"report {key} is {actual!r}; expected {value!r}")
    report_target = analysis.get("target_version")
    if not report_target:
        errors.append("migration report is missing required field: target_version")
    elif not versions_equal(str(report_target), args.version):
        errors.append(
            "Migration report target version does not match requested build version: "
            f"report={report_target!r}, requested={args.version!r}."
        )

    if args.strict and missing:
        errors.append(f"strict mode: {len(missing)} unresolved package(s) remain")

    if args.online:
        try:
            capabilities, profiles = discover_release(args.version, fetch=fetch)
            arch = capabilities["arch"]
            package_root = f"https://downloads.immortalwrt.org/releases/{args.version}/packages/{arch}"
            package_sums = fetch(f"{package_root}/sha256sums").decode("utf-8")
            feeds = discover_feed_names(package_sums)
            index_urls = [
                f"{capabilities['base_url']}/packages/index.json",
                build_kmod_index_url(capabilities["base_url"], profiles),
                *(f"{package_root}/{feed}/index.json" for feed in feeds),
            ]
            available: dict[str, str] = {}
            for index_url in index_urls:
                index = json.loads(fetch(index_url))
                available.update(index.get("packages", {}))
            unavailable = sorted(positive - set(available))
            if unavailable:
                errors.append(f"official package index has no entry for: {', '.join(unavailable)}")
            capabilities["feed_names"] = feeds
            capabilities["package_index_urls"] = index_urls
            capabilities["official_package_count"] = len(available)
            (args.generated / "release-capabilities.json").write_text(
                json.dumps(capabilities, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            (args.generated / "official-package-index.json").write_text(
                json.dumps(available, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        except (ReleaseValidationError, KeyError, json.JSONDecodeError) as exc:
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

