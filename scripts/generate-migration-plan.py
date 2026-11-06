#!/usr/bin/env python3
"""CLI for migration-plan-v1 generation and strict validation."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from migration_plan import generate_plan, write_legacy_outputs
from release_utils import sha256_file


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--capabilities", type=Path, default=Path("generated/release-capabilities.json"))
    parser.add_argument("--official-index", type=Path, default=Path("generated/official-package-index.json"))
    parser.add_argument("--thirdparty-rules", type=Path, default=Path("config/thirdparty.yml"))
    parser.add_argument("--package-rules", type=Path, default=Path("config/package-rules.yml"))
    parser.add_argument("--thirdparty-status", type=Path)
    parser.add_argument("--thirdparty-dir", type=Path, default=Path("files/root/thirdparty"))
    parser.add_argument("--openclash-version", default="0.48.002")
    parser.add_argument("--exclusions", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("generated"))
    parser.add_argument("--strict", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[1]
        snapshot = load(args.snapshot)
        Draft202012Validator(load(root / "schemas/system-snapshot-v1.json")).validate(snapshot)
        capabilities = load(args.capabilities)
        official_index = load(args.official_index)
        thirdparty_rules = yaml.safe_load(args.thirdparty_rules.read_text())
        package_rules = yaml.safe_load(args.package_rules.read_text())
        status = load(args.thirdparty_status) if args.thirdparty_status else {}
        thirdparty_files = {
            path.relative_to(args.thirdparty_dir).as_posix(): sha256_file(path)
            for path in sorted(args.thirdparty_dir.rglob("*.apk"))
        }
        trusted_evidence: set[str] = set()
        if status:
            spec = importlib.util.spec_from_file_location(
                "fetch_thirdparty_evidence", root / "scripts/fetch-thirdparty.py"
            )
            if not spec or not spec.loader:
                raise RuntimeError("cannot load trusted third-party evidence verifier")
            verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier)
            values = verifier.template_values(
                capabilities["target_version"], capabilities, args.openclash_version
            )
            for provider, provider_status in status.items():
                if provider_status.get("status") != "compatible":
                    continue
                rule = thirdparty_rules.get("providers", {}).get(provider)
                if not rule:
                    continue
                try:
                    trusted_evidence.add(verifier.revalidate_status_provenance(
                        provider, rule, provider_status, capabilities,
                        args.thirdparty_dir, values,
                    ))
                except verifier.ProviderError as exc:
                    print(f"::warning title={provider} evidence unresolved::{exc.reason}")
        exclusions = load(args.exclusions) if args.exclusions else []
        plan = generate_plan(
            snapshot, capabilities, official_index,
            thirdparty_rules, status, exclusions,
            package_rules=package_rules,
            thirdparty_files=thirdparty_files,
            trusted_thirdparty_evidence=trusted_evidence,
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
