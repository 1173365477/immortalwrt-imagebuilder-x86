#!/usr/bin/env python3
"""Verify and atomically publish a trusted T15 analysis bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from luci_evidence import EvidenceBundleError, publish_bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    try:
        generation = publish_bundle(args.bundle_dir, args.state_dir, repo_root)
    except (EvidenceBundleError, OSError) as exc:
        print(f"::error::{exc}")
        return 2
    print(f"Published LuCI evidence generation {generation}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
