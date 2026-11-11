#!/usr/bin/env python3
"""Verify and stage an immutable T13 build request."""

from __future__ import annotations

import argparse
from pathlib import Path

from build_evidence import EvidenceError, verify_build_input, write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline-recheck", action="store_true",
                        help="Skip upstream re-download; never use this mode as the ImageBuilder gate")
    args = parser.parse_args()
    try:
        context = verify_build_input(
            args.input, args.repo_root, expected_repository=args.repository,
            expected_commit=args.commit, stage_dir=args.stage,
            revalidate_upstream=not args.offline_recheck,
        )
    except EvidenceError as exc:
        print(f"::error::BUILD GATE BLOCKED: {exc}")
        return 2
    write_json(args.output, context)
    print(f"Verified immutable build input {context['build_input_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
