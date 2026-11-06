#!/usr/bin/env python3
"""CLI for migration-plan-v1 generation and strict validation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from migration_plan import generate_plan, write_legacy_outputs


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--capabilities", type=Path, default=Path("generated/release-capabilities.json"))
    parser.add_argument("--official-index", type=Path, default=Path("generated/official-package-index.json"))
    parser.add_argument("--thirdparty-rules", type=Path, default=Path("config/thirdparty.yml"))
    parser.add_argument("--thirdparty-status", type=Path)
    parser.add_argument("--exclusions", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("generated"))
    parser.add_argument("--strict", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        snapshot = load(args.snapshot)
        Draft202012Validator(load(root / "schemas/system-snapshot-v1.json")).validate(snapshot)
        status = load(args.thirdparty_status) if args.thirdparty_status else {}
        exclusions = load(args.exclusions) if args.exclusions else []
        plan = generate_plan(
            snapshot, load(args.capabilities), load(args.official_index),
            yaml.safe_load(args.thirdparty_rules.read_text()), status, exclusions,
            strict_mode=args.strict,
        )
        Draft202012Validator(load(root / "schemas/migration-plan-v1.json")).validate(plan)
    except Exception as exc:
        print(f"::error::{exc}")
        return 2
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "migration-plan-v1.json").write_text(
        json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_legacy_outputs(plan, args.output_dir)
    print(
        f"Migration plan: {plan['status']}; "
        f"build_allowed={str(plan['build_allowed']).lower()}; flash_ready=false"
    )
    return 0 if plan["build_allowed"] or not args.strict else 1


if __name__ == "__main__":
    raise SystemExit(main())
