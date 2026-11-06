#!/usr/bin/env python3
"""CLI for the pinned official release resolver."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from release_resolver import ReleaseRequest, resolve_release
from release_utils import ReleaseValidationError
from resolve_version import resolve


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--distribution", choices=("immortalwrt", "openwrt"), default="immortalwrt")
    parser.add_argument("--version", default="latest")
    parser.add_argument("--target", default="x86/64")
    parser.add_argument("--profile", default="generic")
    parser.add_argument("--filesystem", default="ext4")
    parser.add_argument("--image-type", default="combined-efi")
    parser.add_argument("--output-dir", type=Path, default=Path("generated"))
    args = parser.parse_args()
    try:
        version = resolve(args.version, distribution=args.distribution)
        capabilities, packages = resolve_release(ReleaseRequest(
            distribution=args.distribution, version=version, target=args.target,
            profile=args.profile, filesystem=args.filesystem, image_type=args.image_type,
        ))
    except (ReleaseValidationError, OSError) as exc:
        print(f"::error::{exc}")
        return 2
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "resolved-version.txt").write_text(version + "\n", encoding="utf-8")
    (args.output_dir / "release-capabilities.json").write_text(
        json.dumps(capabilities, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "official-package-index.json").write_text(
        json.dumps(packages, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Pinned {args.distribution} {version}: {len(packages)} official packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
