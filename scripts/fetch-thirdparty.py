#!/usr/bin/env python3
"""Resolve, fetch, and verify third-party assets for the requested target release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlparse
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from release_utils import ReleaseValidationError, parse_version, sha256_file


MAX_ARCHIVE_MEMBERS = 64
MAX_ARCHIVE_UNPACKED_BYTES = 512 * 1024 * 1024


class ProviderError(RuntimeError):
    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def canonical_digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def api_json(url: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "immortalwrt-migration-builder/2",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        remaining = exc.headers.get("X-RateLimit-Remaining")
        reset = exc.headers.get("X-RateLimit-Reset")
        detail = f"GitHub API returned HTTP {exc.code} for {url}"
        if remaining == "0":
            detail += f"; rate limit exhausted (reset={reset or 'unknown'})"
        raise ProviderError("unresolved", detail) from exc
    except urllib.error.URLError as exc:
        raise ProviderError("unresolved", f"GitHub API request failed for {url}: {exc.reason}") from exc


def download(url: str, destination: Path) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "immortalwrt-migration-builder/2"})
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=240) as response, destination.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise ProviderError("unresolved", f"asset download failed: {url}: {exc}") from exc
    return digest.hexdigest()


def selected_providers(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.split(":", 1)[0].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#") and ":" in line
    }


def template_values(version: str, capabilities: dict[str, Any], openclash_version: str) -> dict[str, str]:
    info = parse_version(version)
    return {
        "target_version": re.escape(info.target_version),
        "target_series": re.escape(info.target_series),
        "target_major": re.escape(info.target_major),
        "arch": re.escape(str(capabilities.get("arch") or "x86_64")),
        "profile": re.escape(str(capabilities.get("profile") or "generic")),
        "openclash_version": re.escape(openclash_version),
    }


def format_template(template: str, values: dict[str, str]) -> str:
    try:
        return template.format(**values)
    except KeyError as exc:
        raise ProviderError("unresolved", f"unknown provider template variable: {exc.args[0]}") from exc


def verify_digest(asset: dict[str, Any], actual: str, required: bool) -> None:
    declared = asset.get("digest")
    if not declared:
        if required:
            raise ProviderError("unresolved", f"GitHub API did not provide a digest for {asset['name']}")
        return
    if ":" not in declared:
        raise ProviderError("unresolved", f"unsupported digest format for {asset['name']}: {declared}")
    algorithm, expected = declared.split(":", 1)
    if algorithm.lower() != "sha256" or actual.lower() != expected.lower():
        raise ProviderError(
            "incompatible",
            f"digest mismatch for {asset['name']}: expected {declared}, got sha256:{actual}",
        )


def copy_archive_members(archive: Path, patterns: list[re.Pattern[str]], destination: Path) -> list[Path]:
    copied: list[Path] = []
    matched = [False] * len(patterns)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS or sum(max(0, member.size) for member in members) > MAX_ARCHIVE_UNPACKED_BYTES:
            raise ProviderError("incompatible", "third-party archive exceeds extraction safety limits")
        for member in members:
            if not member.isfile():
                continue
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise ProviderError("incompatible", f"unsafe archive member: {member.name}")
            basename = pure.name
            for index, pattern in enumerate(patterns):
                if pattern.fullmatch(basename):
                    source = tar.extractfile(member)
                    if source is None:
                        raise ProviderError("incompatible", f"cannot read archive member: {member.name}")
                    target = destination / basename
                    if target.exists():
                        raise ProviderError("incompatible", f"duplicate archive member filename: {basename}")
                    with source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
                    copied.append(target)
                    matched[index] = True
                    break
    missing = [patterns[index].pattern for index, state in enumerate(matched) if not state]
    if missing:
        raise ProviderError("unresolved", f"archive lacks required APK pattern(s): {missing}")
    return copied


def release_metadata(provider: str, cfg: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    base = f"https://api.github.com/repos/{cfg['repository']}/releases"
    if cfg.get("release") == "latest":
        release = api_json(f"{base}/latest")
    elif cfg.get("release") == "tag":
        tag = format_template(cfg["tag_template"], values).replace("\\", "")
        release = api_json(f"{base}/tags/{tag}")
    else:
        raise ProviderError("unresolved", f"{provider}: unsupported release strategy {cfg.get('release')!r}")
    if not isinstance(release, dict):
        raise ProviderError("unresolved", f"{provider}: GitHub returned invalid release metadata")

    # Use the paginated assets endpoint when available. This avoids silently
    # missing a matching file in a release with many assets.
    assets_url = release.get("assets_url")
    if assets_url:
        assets: list[dict[str, Any]] = []
        for page in range(1, 101):
            separator = "&" if "?" in assets_url else "?"
            batch = api_json(f"{assets_url}{separator}per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ProviderError("unresolved", f"{provider}: GitHub returned invalid asset metadata")
            assets.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < 100:
                break
        else:
            raise ProviderError("unresolved", f"{provider}: release asset pagination exceeded 100 pages")
        release["assets"] = assets
    return release


def validate_provider_config(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if config.get("schema_version") != "1.0.0":
        raise ProviderError("unresolved", "third-party rules require schema_version 1.0.0")
    policy = config.get("policy")
    if not isinstance(policy, dict) or policy.get("unknown_provider") != "unresolved":
        raise ProviderError("unresolved", "third-party rules must fail closed for unknown providers")
    if policy.get("execute_upstream_scripts") is not False:
        raise ProviderError("unresolved", "executing upstream installation scripts is forbidden")
    providers = config.get("providers")
    if not isinstance(providers, dict):
        raise ProviderError("unresolved", "third-party providers mapping is missing")
    required = {
        "rule_version", "source_type", "upstream", "repository", "install_path",
        "package_format", "supported_package_managers", "supported_architectures",
        "require_digest", "compatibility_evidence", "confidence",
    }
    for name, cfg in providers.items():
        missing = sorted(required - set(cfg))
        if missing:
            raise ProviderError("unresolved", f"{name}: incomplete provider rule: {', '.join(missing)}")
        expected_upstream = f"https://github.com/{cfg['repository']}"
        if cfg["source_type"] != "github_release" or cfg["upstream"] != expected_upstream:
            raise ProviderError("unresolved", f"{name}: upstream does not match the pinned GitHub repository")
        if cfg["install_path"] != "imagebuilder-binary" or cfg["package_format"] != "apk":
            raise ProviderError("unresolved", f"{name}: SDK and ImageBuilder paths must remain distinct")
        if not cfg["require_digest"] or not cfg["compatibility_evidence"]:
            raise ProviderError("unresolved", f"{name}: verifiable digest/evidence is required")
    return providers


def validate_asset_url(provider: str, cfg: dict[str, Any], asset: dict[str, Any]) -> None:
    raw = str(asset.get("browser_download_url") or "")
    parsed = urlparse(raw)
    prefix = f"/{cfg['repository']}/releases/download/"
    if parsed.scheme != "https" or parsed.netloc != "github.com" or not parsed.path.startswith(prefix):
        raise ProviderError("unresolved", f"{provider}: asset URL is outside its trusted upstream")


def match_assets(
    provider: str,
    cfg: dict[str, Any],
    release: dict[str, Any],
    values: dict[str, str],
    target_series: str,
) -> list[dict[str, Any]]:
    compatibility = cfg.get("compatibility_body_regex")
    if compatibility:
        pattern = format_template(compatibility, values)
        if not re.search(pattern, release.get("body") or "", re.IGNORECASE | re.DOTALL):
            status = "incompatible" if cfg.get("strict_compatibility", False) else "unresolved"
            raise ProviderError(
                status,
                f"{provider} release {release.get('tag_name', 'unknown')} does not declare compatibility "
                f"with target series {target_series}.",
            )
    assets = release.get("assets", [])
    matches: list[dict[str, Any]] = []
    for raw_pattern in cfg.get("asset_patterns", []):
        pattern = re.compile(format_template(raw_pattern, values))
        found = [asset for asset in assets if pattern.fullmatch(asset.get("name", ""))]
        if not found:
            raise ProviderError(
                "unresolved",
                f"{provider} currently has no release asset matching target series {target_series}: {pattern.pattern}",
            )
        if len(found) > 1:
            names = ", ".join(sorted(asset.get("name", "") for asset in found))
            raise ProviderError("unresolved", f"Ambiguous provider asset match for {provider}: {names}")
        matches.extend(found)
    return matches


def inspect_apk_metadata(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    apk = shutil.which("apk")
    if not apk:
        return None, "APK metadata inspection tool is unavailable; magic, digest, configured architecture and dependencies were checked."
    process = subprocess.run(
        [apk, "adbdump", str(path)], capture_output=True, text=True, check=False, timeout=30
    )
    if process.returncode != 0:
        return None, "APK metadata inspection was unavailable for this APK format; configured compatibility checks were used."
    metadata: dict[str, Any] = {"raw_summary": process.stdout[:2000]}
    for key in ("name", "arch", "version"):
        match = re.search(rf"(?mi)^\s*{key}\s*[:=]\s*(\S+)", process.stdout)
        if match:
            metadata[key] = match.group(1)
    metadata["dependencies"] = re.findall(r"(?mi)^\s*(?:depend|depends)\s*[:=]\s*(\S+)", process.stdout)
    return metadata, None


def render_compatibility_report(
    capabilities: dict[str, Any], statuses: dict[str, dict[str, Any]]
) -> str:
    rows = [
        "# Compatibility report",
        "",
        f"Target: ImmortalWrt `{capabilities['target_version']}` (`{capabilities['target_series']}`), "
        f"`{capabilities['target']}` / `{capabilities['profile']}` / `{capabilities['filesystem']}`",
        "",
        "| Component | Target | Status | Detail |",
        "|---|---|---|---|",
        f"| ImmortalWrt official packages | {capabilities['target_series']} | compatible | "
        f"{capabilities.get('official_package_count', 'unknown')} indexed packages; package manager {capabilities['package_manager']} |",
    ]
    for provider, status in sorted(statuses.items()):
        detail = status.get("reason") or status.get("upstream_release") or "assets verified"
        rows.append(f"| {provider} | {capabilities['target_series']} | {status['status']} | {detail} |")
    return "\n".join(rows) + "\n"


def append_migration_report(path: Path, report: str) -> None:
    marker = "<!-- thirdparty-compatibility -->"
    existing = path.read_text(encoding="utf-8") if path.exists() else "# ImmortalWrt migration report\n"
    if marker in existing:
        existing = existing.split(marker, 1)[0].rstrip() + "\n"
    path.write_text(existing + f"\n{marker}\n\n" + report, encoding="utf-8")


def strict_exit_code(
    selected: set[str], statuses: dict[str, dict[str, Any]], strict: bool
) -> int:
    """Return failure only when strict mode sees a requested degraded provider."""
    degraded = any(
        statuses.get(provider, {}).get("status") != "compatible"
        for provider in selected
    )
    return 1 if strict and degraded else 0


def compatible_status(
    provider: str,
    cfg: dict[str, Any],
    capabilities: dict[str, Any],
    release: dict[str, Any],
    asset_records: list[dict[str, Any]],
    apk_checks: list[dict[str, Any]],
    official_index_digest: str,
    warnings: list[str],
) -> dict[str, Any]:
    required_dependencies = sorted(set(cfg.get("official_dependencies", [])))
    status: dict[str, Any] = {
        "status": "compatible",
        "provider": provider,
        "rule_version": cfg["rule_version"],
        "repository": cfg["repository"],
        "packages": sorted(cfg.get("packages", [])),
        "target": {
            "distribution": capabilities.get("distribution"),
            "version": capabilities.get("target_version"),
            "target": capabilities.get("target"),
            "profile": capabilities.get("profile"),
            "architecture": capabilities.get("arch"),
            "package_manager": capabilities.get("package_manager"),
            "resolution_digest": capabilities.get("resolution_digest"),
            "official_index_digest": official_index_digest,
        },
        "upstream_release": release.get("tag_name", ""),
        "assets": asset_records,
        "apk_checks": apk_checks,
        "official_dependencies": {
            "required": required_dependencies,
            "missing": [],
            "index_digest": official_index_digest,
        },
        "warnings": warnings,
    }
    status["evidence_digest"] = canonical_digest(status)
    return status


def unknown_provider_statuses(
    selected: set[str], configured: set[str]
) -> dict[str, dict[str, Any]]:
    return {
        provider: {
            "status": "unresolved",
            "provider": provider,
            "reason": "selected provider has no trusted versioned rule",
        }
        for provider in sorted(selected - configured)
    }


def load_official_index(
    path: Path, capabilities: dict[str, Any], *, required: bool
) -> tuple[dict[str, Any], str]:
    if required and not path.exists():
        raise ProviderError(
            "unresolved", "official package index is required for third-party dependency validation"
        )
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderError("unresolved", f"invalid official package index: {exc}") from exc
    if required and (not isinstance(value, dict) or not value):
        raise ProviderError("unresolved", "official package index is empty or invalid")
    digest = canonical_digest(value)
    if required and capabilities.get("official_index_digest") != digest:
        raise ProviderError(
            "unresolved", "official package index digest does not match release capabilities"
        )
    return value, digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("config/thirdparty.yml"))
    parser.add_argument("--selection", type=Path, default=Path("generated/packages-thirdparty.txt"))
    parser.add_argument("--destination", type=Path, default=Path("files/root/thirdparty"))
    parser.add_argument("--metadata", type=Path, default=Path("generated/thirdparty-assets.json"))
    parser.add_argument("--capabilities", type=Path, default=Path("generated/release-capabilities.json"))
    parser.add_argument("--status", type=Path, default=Path("generated/thirdparty-status.json"))
    parser.add_argument("--compatibility-report", type=Path, default=Path("generated/compatibility-report.md"))
    parser.add_argument("--migration-report", type=Path, default=Path("generated/migration-report.md"))
    parser.add_argument("--version", default="25.12.2")
    parser.add_argument("--openclash-version", default="0.48.002")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    try:
        info = parse_version(args.version)
    except ReleaseValidationError as exc:
        print(f"::error::{exc}")
        return 2
    if not args.capabilities.exists():
        print(f"::error::release capability file is missing: {args.capabilities}")
        return 2
    capabilities = json.loads(args.capabilities.read_text(encoding="utf-8"))
    if capabilities.get("target_version") != info.target_version:
        print("::error::release capabilities do not match the requested target version")
        return 2
    if capabilities.get("package_manager") != "apk":
        print(
            f"::error::Unsupported target package manager detected: {capabilities.get('package_manager', 'unknown')}. "
            "Repository logic currently supports APK targets only."
        )
        return 2

    raw_config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    try:
        config = validate_provider_config(raw_config)
    except ProviderError as exc:
        print(f"::error::{exc.reason}")
        return 2
    selected = selected_providers(args.selection)
    args.destination.mkdir(parents=True, exist_ok=True)
    for stale in args.destination.glob("*.apk"):
        stale.unlink()
    stale_manifest = args.destination / "SHA256SUMS"
    if stale_manifest.exists():
        stale_manifest.unlink()
    records: list[dict[str, Any]] = []
    statuses: dict[str, dict[str, Any]] = {}
    values = template_values(args.version, capabilities, args.openclash_version)
    official_index = args.capabilities.parent / "official-package-index.json"
    try:
        official_index_data, official_index_digest = load_official_index(
            official_index, capabilities, required=bool(selected)
        )
    except ProviderError as exc:
        print(f"::error::{exc.reason}")
        return 2
    official_packages = set(official_index_data)

    unknown_statuses = unknown_provider_statuses(selected, set(config))
    statuses.update(unknown_statuses)
    for provider in unknown_statuses:
        print(f"::warning title={provider} unresolved::selected provider has no trusted versioned rule")

    with tempfile.TemporaryDirectory(prefix="thirdparty-") as temp_name:
        temp = Path(temp_name)
        for provider, cfg in sorted(config.items()):
            if provider not in selected:
                statuses[provider] = {"status": "disabled", "reason": "provider was not requested by the resolved manifest"}
                continue
            try:
                supported_managers = cfg.get("supported_package_managers", [])
                if capabilities["package_manager"] not in supported_managers:
                    raise ProviderError(
                        "incompatible",
                        f"provider supports {supported_managers}, target uses {capabilities['package_manager']}",
                    )
                if capabilities.get("distribution") not in cfg.get("supported_distributions", ["immortalwrt"]):
                    raise ProviderError(
                        "incompatible", f"provider does not support distribution {capabilities.get('distribution')}"
                    )
                supported_arches = cfg.get("supported_architectures", [])
                if capabilities["arch"] not in supported_arches and "all" not in supported_arches:
                    raise ProviderError(
                        "incompatible", f"provider does not support target architecture {capabilities['arch']}"
                    )
                absent_dependencies = sorted(set(cfg.get("official_dependencies", [])) - official_packages)
                if absent_dependencies:
                    raise ProviderError(
                        "incompatible",
                        "target official feeds lack provider dependencies: " + ", ".join(absent_dependencies),
                    )

                release = release_metadata(provider, cfg, values)
                assets = match_assets(provider, cfg, release, values, info.target_series)
                provider_dir = temp / provider
                provider_dir.mkdir()
                provider_records: list[dict[str, Any]] = []
                output_apks: list[Path] = []
                for asset in assets:
                    validate_asset_url(provider, cfg, asset)
                    target = provider_dir / asset["name"]
                    actual = download(asset["browser_download_url"], target)
                    verify_digest(asset, actual, bool(cfg.get("require_digest")))
                    provider_records.append({
                        "provider": provider,
                        "release": release.get("tag_name", ""),
                        "asset": asset["name"],
                        "sha256": actual,
                        "url": asset["browser_download_url"],
                    })
                    if target.name.endswith(".tar.gz"):
                        archive_patterns = [
                            re.compile(format_template(pattern, values))
                            for pattern in cfg.get("archive_member_patterns", [])
                        ]
                        output_apks.extend(copy_archive_members(target, archive_patterns, provider_dir))
                    elif target.name.endswith(".apk"):
                        output_apks.append(target)
                    else:
                        raise ProviderError("incompatible", f"unsupported asset type: {target.name}")
                if not output_apks:
                    raise ProviderError("unresolved", f"{provider}: no APK was produced")

                apk_checks: list[dict[str, Any]] = []
                warnings: list[str] = []
                for path in output_apks:
                    with path.open("rb") as package_file:
                        magic = package_file.read(3)
                    if path.stat().st_size < 4 or magic != b"ADB":
                        raise ProviderError("incompatible", f"downloaded file is not an APK v3 package: {path.name}")
                    metadata, warning = inspect_apk_metadata(path)
                    apk_check: dict[str, Any] = {
                        "file": path.name,
                        "sha256": sha256_file(path),
                        "magic_verified": True,
                        "metadata_status": "verified" if metadata else "unavailable",
                        "architecture": "unknown",
                    }
                    if metadata:
                        arch = metadata.get("arch")
                        if arch and arch not in {"all", "noarch", capabilities["arch"]}:
                            raise ProviderError(
                                "incompatible", f"APK {path.name} architecture {arch} conflicts with {capabilities['arch']}"
                            )
                        apk_check["architecture"] = arch or "unknown"
                        apk_check["package"] = metadata.get("name")
                        apk_check["version"] = metadata.get("version")
                        apk_check["dependencies"] = metadata.get("dependencies", [])
                    if warning and warning not in warnings:
                        warnings.append(warning)
                    destination = args.destination / path.name
                    if destination.exists():
                        raise ProviderError("unresolved", f"duplicate third-party APK filename: {path.name}")
                    shutil.copy2(path, destination)
                    apk_checks.append(apk_check)
                records.extend(provider_records)
                statuses[provider] = compatible_status(
                    provider, cfg, capabilities, release, provider_records,
                    apk_checks, official_index_digest,
                    warnings,
                )
            except ProviderError as exc:
                statuses[provider] = {"status": exc.status, "reason": exc.reason}
                print(f"::warning title={provider} {exc.status}::{exc.reason}")

    apk_files = sorted(args.destination.glob("*.apk"))
    sums = [f"{sha256_file(path)}  {path.name}" for path in apk_files]
    (args.metadata.parent / "thirdparty-sha256sums").write_text(
        "\n".join(sums) + ("\n" if sums else ""), encoding="utf-8"
    )
    if sums:
        manifest = args.destination / "SHA256SUMS"
        manifest.write_text("\n".join(sums) + "\n", encoding="utf-8")
        manifest.chmod(0o600)
    args.metadata.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.status.write_text(json.dumps(statuses, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = render_compatibility_report(capabilities, statuses)
    args.compatibility_report.write_text(report, encoding="utf-8")
    append_migration_report(args.migration_report, report)

    degraded = any(
        provider in selected and status["status"] != "compatible"
        for provider, status in statuses.items()
    )
    print("Third-party compatibility:")
    for provider, status in sorted(statuses.items()):
        print(f"  {provider}: {status['status']} - {status.get('reason') or status.get('upstream_release', '')}")
    print("Third-party APK files:")
    for path in apk_files:
        print(f"  {path.name}")
    if strict_exit_code(selected, statuses, args.strict):
        print("::error::strict mode rejects unresolved or incompatible requested third-party providers")
        return 1
    if degraded:
        print("::warning title=DEGRADED MIGRATION::Building without unresolved/incompatible third-party providers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
