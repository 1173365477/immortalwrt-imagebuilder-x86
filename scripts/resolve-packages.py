#!/usr/bin/env python3
"""Resolve a small, functional ImageBuilder manifest from parsed migration data."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml

from release_utils import ReleaseValidationError, parse_version


VALID_PACKAGE = re.compile(r"^-?[A-Za-z0-9][A-Za-z0-9+_.@-]*$")


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a YAML mapping in {path}")
    return value


def read_package_file(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def write_lines(path: Path, values: list[str] | set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(values)) + ("\n" if values else ""), encoding="utf-8")


def provider_enabled(name: str, args: argparse.Namespace, providers: dict[str, Any]) -> bool:
    cli_value = getattr(args, f"include_{name}", None)
    return bool(providers.get(name, {}).get("enabled", False)) if cli_value is None else cli_value


def render_report(analysis: dict[str, Any], resolved: dict[str, Any]) -> str:
    def block(title: str, rows: list[str]) -> list[str]:
        return [f"## {title}", "", *(f"- `{row}`" for row in rows), ""] if rows else [f"## {title}", "", "_None._", ""]

    lines = [
        "# ImmortalWrt migration report",
        "",
        "> Generated from package metadata only. No router configuration is embedded.",
        "",
        "## System",
        "",
        f"- Source: `{analysis.get('source_version') or 'unknown'}`",
        f"- Target: `{analysis.get('target_version') or 'unknown'}`",
        f"- Target/profile: `{analysis.get('target') or 'unknown'}` / `{analysis.get('profile') or 'unknown'}`",
        f"- RootFS / boot: `{analysis.get('rootfs_type') or 'unknown'}` / `{analysis.get('sys_type') or 'unknown'}`",
        f"- Reported installed/top-level/user-installed: `{analysis.get('installed_count', 0)}` / `{analysis.get('top_level_count', 0)}` / `{analysis.get('user_installed_count', 0)}`",
        "",
        "## Resolution summary",
        "",
        f"- Official manifest entries: `{len(resolved['official'])}`",
        f"- Third-party package entries: `{len(resolved['thirdparty'])}`",
        f"- Missing/unresolved entries: `{len(resolved['missing'])}`",
        f"- Skipped entries: `{len(resolved['skipped'])}`",
        f"- Replacements: `{len(resolved['replaced'])}`",
        f"- Enabled feature groups: `{', '.join(resolved['features']) or 'none'}`",
        "",
    ]
    lines += block("Official packages", sorted(resolved["official"]))
    lines += block("Third-party packages", sorted(resolved["thirdparty"]))
    lines += block("Missing / unresolved", sorted(resolved["missing"]))
    lines += block("Skipped", sorted(resolved["skipped"]))
    lines += block("Replacements", sorted(resolved["replaced"]))
    downgrade_rows = [
        f"{name}: {details.get('from')} -> {details.get('to')} (not silently accepted)"
        for name, details in sorted(analysis.get("packages", {}).items())
        if details.get("status") == "downgrade"
    ]
    lines += block("Downgrade warnings", downgrade_rows)
    lines += block("owut warnings", [str(item) for item in analysis.get("warnings", [])])
    lines += block("owut errors / build failures", [str(item) for item in analysis.get("errors", [])])
    missing_fields = [
        field for field in ("source_version", "target_version", "target", "profile", "rootfs_type", "sys_type")
        if not analysis.get(field)
    ]
    lines += block("Missing report fields", [f"{field}: unknown" for field in missing_fields])
    if analysis.get("sensitive_input_warning"):
        lines += [
            "## Sensitive-input warning",
            "",
            "The input matched a token/password/private-key pattern. The parser redacted copied diagnostics, but you must review the original report before publishing it.",
            "",
        ]
    lines += [
        "## Safety note",
        "",
        "The combined EFI image is a full-disk image. This project does not claim that writing it over an existing, manually repartitioned GPT disk preserves any partition or data.",
        "",
    ]
    return "\n".join(lines)


def resolve(args: argparse.Namespace) -> dict[str, Any]:
    analysis = json.loads(args.analysis.read_text(encoding="utf-8"))
    rules = load_yaml(args.rules)
    thirdparty_cfg = load_yaml(args.thirdparty)
    providers = thirdparty_cfg.get("providers", {})
    base = set(read_package_file(args.base))
    installed = set(analysis.get("installed_packages", [])) | set(analysis.get("packages", {}))
    primary = set(analysis.get("top_level_packages", [])) | set(analysis.get("user_installed_packages", []))
    package_evidence = analysis.get("package_evidence", {})
    manifest = analysis.get("top_level_manifest", {"state": "missing"})

    official: set[str] = {item for item in base if not item.startswith("-")}
    removals: set[str] = {item for item in base if item.startswith("-")}
    missing: set[str] = set()
    # Missing top-level provenance must block strict migration rather than silently
    # treating the unknown package set as removable dependencies.
    if installed and manifest.get("state") != "complete":
        missing.add(
            "unknown-provenance\t"
            f"top-level/user-installed manifest is {manifest.get('state', 'missing')}; "
            "manual package classification required"
        )
    skipped: set[str] = set()
    replaced: set[str] = set()
    thirdparty: set[str] = set()
    features: list[str] = []
    provider_requests: set[str] = set()
    decisions: dict[str, dict[str, Any]] = {}

    replacements = dict(rules.get("replacements", {}))
    try:
        target_series = parse_version(str(analysis.get("target_version", ""))).target_series
    except ReleaseValidationError:
        target_series = None
    if target_series:
        replacements.update(
            rules.get("version_rules", {}).get(target_series, {}).get("replacements", {})
        )
    ignore = set(rules.get("ignore", []))
    ignore_prefixes = tuple(rules.get("ignore_prefixes", []))
    never_downgrade = set(rules.get("never_downgrade", []))
    remove = set(rules.get("remove_if_present", []))
    thirdparty_map = rules.get("thirdparty", {})
    kernel_patterns = [re.compile(pattern) for pattern in rules.get("kernel_keep_patterns", [])]

    # Functional groups are evidence based and do not require the package to be top-level.
    for feature, cfg in rules.get("feature_groups", {}).items():
        if installed.intersection(cfg.get("when_any", [])):
            features.append(feature)
            official.update(cfg.get("add", []))
            official.update(installed.intersection(cfg.get("preserve_present", [])))

    candidates = primary | set(rules.get("always_keep", []))
    # Known third-party applications and explicit hardware drivers remain
    # functional evidence even when an owut variant omits top-level markers.
    candidates.update(package for package in installed if package in thirdparty_map)
    candidates.update(
        package for package in installed
        if package.startswith("kmod-") and any(pattern.fullmatch(package) for pattern in kernel_patterns)
    )
    # Every installed package must have either explicit migration intent or
    # positive dependency/default evidence.  Reverse dependencies are never
    # treated as user intent and an incomplete primary list is not trusted.
    for package in sorted(installed):
        proof = package_evidence.get(package, {})
        reason = proof.get("install_reason", "unknown")
        if package in primary:
            decisions[package] = {
                "decision": "keep",
                "reason": "explicit top-level/user-installed evidence",
                "evidence": proof.get("evidence", []) + ["primary-manifest"],
            }
        elif reason == "dependency":
            decisions[package] = {
                "decision": "skip",
                "reason": "package manager explicitly marks automatic dependency; target resolver will recalculate",
                "evidence": proof.get("evidence", []),
            }
        elif reason == "system_default":
            decisions[package] = {
                "decision": "skip",
                "reason": "source firmware default; target firmware baseline will provide defaults",
                "evidence": proof.get("evidence", []),
            }
        elif package not in candidates:
            decisions[package] = {
                "decision": "review",
                "reason": "installation reason is not proven and package is absent from explicit primary manifest",
                "evidence": proof.get("evidence", []),
            }
            missing.add(f"{package}\tunknown install reason; explicit keep/skip decision required")
    for package in sorted(candidates):
        details = analysis.get("packages", {}).get(package, {})
        status = details.get("status", "unknown")
        if package in remove:
            removals.add(f"-{package}")
            skipped.add(f"{package}\tremoved because a conflicting replacement is selected")
            if package in installed:
                decisions[package] = {"decision": "skip", "reason": "conflicting replacement selected", "evidence": ["remove-if-present-rule"]}
            continue
        # The current owut report is authoritative. Static rules only fill gaps
        # when owut did not emit replacement metadata.
        if status in {"replacement", "removed"}:
            target = details.get("to")
            if target and VALID_PACKAGE.fullmatch(target):
                official.add(target)
                replaced.add(f"{package} -> {target}\towut replacement")
                decisions[package] = {"decision": "replace", "reason": f"owut replacement: {target}", "evidence": ["owut-package-change"]}
            else:
                skipped.add(f"{package}\tremoved/replaced by target defaults")
                decisions[package] = {"decision": "skip", "reason": "owut reports removal by target defaults", "evidence": ["owut-package-change"]}
            continue
        if package in replacements:
            target = replacements[package]
            official.add(target)
            replaced.add(f"{package} -> {target}\trule replacement")
            decisions[package] = {"decision": "replace", "reason": f"versioned replacement rule: {target}", "evidence": ["package-rule"]}
            continue
        if package in ignore or (package.startswith(ignore_prefixes) and package not in rules.get("always_keep", [])):
            if package in primary:
                missing.add(f"{package}\texplicitly selected package matches dependency ignore rule; manual review required")
                decisions[package] = {"decision": "review", "reason": "explicit user intent conflicts with dependency ignore rule", "evidence": ["primary-manifest", "dependency-ignore-rule"]}
            else:
                skipped.add(f"{package}\tpackage-manager evidence marks dependency; ImageBuilder will resolve it")
                decisions[package] = {"decision": "skip", "reason": "explicit dependency evidence; target resolver will recalculate", "evidence": package_evidence.get(package, {}).get("evidence", [])}
            continue
        provider = thirdparty_map.get(package, {}).get("provider")
        if provider:
            if provider_enabled(provider, args, providers):
                provider_requests.add(provider)
            else:
                missing.add(f"{package}\tthird-party provider '{provider}' is disabled")
            continue
        if status == "missing":
            missing.add(f"{package}\tmissing in target version and no provider rule matched")
            decisions[package] = {"decision": "block", "reason": "missing in target and no replacement/provider", "evidence": ["owut-package-change"]}
            continue
        if status == "downgrade":
            reason = "downgrade blocked by never_downgrade rule" if package in never_downgrade else "downgrade requires explicit user review"
            missing.add(f"{package}\t{reason}: {details.get('from')} -> {details.get('to')}")
            decisions[package] = {"decision": "review", "reason": reason, "evidence": ["owut-package-change"]}
            continue
        if package.startswith("kmod-") and not any(pattern.fullmatch(package) for pattern in kernel_patterns):
            skipped.add(f"{package}\told kernel module not on the functional/hardware allowlist")
            continue
        official.add(package)

    # A report may show a replacement outside top-level lists; replacements are safe
    # to record, but only their target package is selected.
    for package, details in analysis.get("packages", {}).items():
        if details.get("status") == "replacement":
            target = details.get("to") or replacements.get(package)
            if target and VALID_PACKAGE.fullmatch(target):
                official.add(target)
                replaced.add(f"{package} -> {target}\tpackage-manager/owut replacement")
        if details.get("status") == "missing" and package not in candidates:
            skipped.add(
                f"{package}\tmissing in target, but not selected because it was not top-level/user-installed; dependencies will be re-resolved"
            )

    for provider in sorted(provider_requests):
        cfg = providers.get(provider)
        if not cfg:
            missing.add(f"{provider}\tprovider requested but not defined in thirdparty.yml")
            continue
        for package in cfg.get("packages", []):
            thirdparty.add(f"{provider}:{package}")
        official.update(cfg.get("official_dependencies", []))

    for package in sorted(installed):
        if package not in decisions:
            proof = package_evidence.get(package, {})
            decisions[package] = {
                "decision": "review",
                "reason": "package was functionally detected but its installation reason is not authoritative",
                "evidence": proof.get("evidence", []),
            }
            missing.add(f"{package}\tinstallation intent unresolved; explicit review required")

    official.difference_update(remove)
    official = {item for item in official if VALID_PACKAGE.fullmatch(item)}
    final_official = official | removals
    resolved = {
        "official": final_official,
        "thirdparty": thirdparty,
        "missing": missing,
        "skipped": skipped,
        "replaced": replaced,
        "features": sorted(features),
        "decisions": decisions,
    }
    out = args.output_dir
    write_lines(out / "packages-official.txt", resolved["official"])
    write_lines(out / "packages-thirdparty.txt", resolved["thirdparty"])
    write_lines(out / "packages-missing.txt", resolved["missing"])
    write_lines(out / "packages-skipped.txt", resolved["skipped"])
    write_lines(out / "packages-replaced.txt", resolved["replaced"])
    (out / "migration-report.md").write_text(render_report(analysis, resolved), encoding="utf-8")
    (out / "package-decisions.json").write_text(
        json.dumps(decisions, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return resolved


def bool_arg(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", type=Path, default=Path("generated/system-analysis.json"))
    parser.add_argument("--rules", type=Path, default=Path("config/package-rules.yml"))
    parser.add_argument("--thirdparty", type=Path, default=Path("config/thirdparty.yml"))
    parser.add_argument("--base", type=Path, default=Path("config/base-packages.txt"))
    parser.add_argument("--output-dir", type=Path, default=Path("generated"))
    for provider in ("openclash", "nikki", "lucky"):
        parser.add_argument(f"--include-{provider}", type=bool_arg, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    resolved = resolve(args)
    print(f"Resolved {len(resolved['official'])} official, {len(resolved['thirdparty'])} third-party, "
          f"{len(resolved['missing'])} unresolved packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

