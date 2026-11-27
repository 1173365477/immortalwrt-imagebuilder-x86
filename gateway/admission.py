"""Verify authenticated collector records and restrict remotely retained Snapshot data."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.migration_plan import APK_COMPARISON_PATTERN

from .targets import SHA_PATTERN, strict_json

ROOT = Path(__file__).resolve().parents[1]
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
DEFAULT_SNAPSHOT_TTL = 24 * 3600
GENERATION = re.compile(r"[a-f0-9]{64}-[1-9][0-9]{0,11}-[1-9][0-9]{0,9}")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+@~-]{0,127}")
PACKAGE_NAME = r"[A-Za-z0-9][A-Za-z0-9_.+@-]*"
APK_ATOM = re.compile(
    rf"(?P<conflict>!)?(?:(?:so|cmd|pc|virtual):)?(?P<name>{PACKAGE_NAME})"
    rf"(?:(?:<~|>~|~|{APK_COMPARISON_PATTERN})(?P<version>[0-9][A-Za-z0-9_.+~-]*))?"
)
OPKG_ATOM = re.compile(
    rf"(?P<name>{PACKAGE_NAME})(?:[ \t]*\([ \t]*(?:<<|>>|{APK_COMPARISON_PATTERN})[ \t]*"
    r"(?P<version>(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9_.+~-]*)[ \t]*\))?"
)
CREDENTIAL_KEYS = {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
SCANNER_NAME = re.compile(PACKAGE_NAME)
SCANNER_OPERATOR = re.compile(rf"{APK_COMPARISON_PATTERN}|~")
SENSITIVE_TOKEN = re.compile(
    r"(?:(?:authorization\s*:|\b(?:bearer|basic)\s+[A-Za-z0-9_.+~-]+)|gh[pousr]_|github_pat_|AKIA[A-Z0-9]{16}|xox[baprs]-|sk_(?:live|test)_|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|"
    r"(?:[a-zA-Z0-9_.+-]+)@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|"
    r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:password|passwd|secret|token)\s*[=:])",
    re.IGNORECASE,
)
PACKAGE_PROOFS = {
    "firmware-rom-baseline", "opkg-auto-installed:true", "opkg-auto-installed:false",
    "apk-world-candidate", "apk-world", "apk-installed-db", "opkg-status-installed",
    "operator-confirmed",
}
WARNINGS = {
    "top-level provenance is not authoritative; retain unknown packages for manual review",
    "boot/profile and mount inspection may be incomplete",
    "package database unavailable; services cannot be classified",
    "package inventory truncated at 4096 records",
}
IDENTITY_ERRORS = {"target_uname_arch_mismatch", "release_package_arch_mismatch"}
STORAGE_ERRORS = {
    "mountinfo_missing", "mountinfo_truncated", "mountinfo_parse_error",
    "block_topology_unknown", "docker_daemon_permission_denied",
    "docker_container_query_failed", "docker_containers_truncated",
    "docker_container_inspect_failed", "docker_volume_query_failed",
    "docker_volumes_truncated", "docker_volume_name_invalid", "docker_volume_inspect_failed",
    "docker_volume_mountpoint_invalid",
}
RECORD_KEYS = {"version", "device_id", "snapshot_id", "snapshot_sha256", "scan_generation",
               "collected_at", "mac"}
SCHEMA = Draft202012Validator(json.loads((ROOT / "schemas/system-snapshot-v1.json").read_bytes()))


def validate_limits(value) -> None:
    stack = [(value, 0)]
    count = 0
    while stack:
        row, depth = stack.pop()
        count += 1
        if depth > 12 or count > 150_000:
            raise ValueError("snapshot structure exceeds limits")
        if isinstance(row, dict):
            stack.extend((child, depth + 1) for child in row.values())
        elif isinstance(row, list):
            if len(row) > 4096:
                raise ValueError("snapshot list exceeds limit")
            stack.extend((child, depth + 1) for child in row)


def restricted(value: str | None, pattern=IDENTIFIER) -> None:
    if value is not None and (not pattern.fullmatch(value) or SENSITIVE_TOKEN.search(value)):
        raise ValueError("snapshot value violates remote privacy policy")


def dependency_clauses(raw: str | None, manager: str, *, provides: bool = False) -> list[str]:
    if raw is None:
        return []
    if SENSITIVE_TOKEN.search(raw) or any(ord(char) < 32 and char != "\t" for char in raw):
        raise ValueError("snapshot dependency violates remote privacy policy")
    if manager == "apk":
        clauses = re.split(r"[ \t]+", raw.strip(" \t"))
        pattern = APK_ATOM
    elif manager == "opkg":
        clauses = [clause.strip(" \t") for clause in raw.split(",")]
        pattern = OPKG_ATOM
    else:
        raise ValueError("dependencies require a recognized package manager")

    for clause in clauses:
        alternatives = clause.split("|") if manager == "opkg" else [clause]
        if provides and len(alternatives) != 1:
            raise ValueError("invalid OPKG dependency or provide")
        for expression in alternatives:
            atom = pattern.fullmatch(expression.strip(" \t"))
            if atom is None or (provides and manager == "apk" and atom["conflict"]):
                raise ValueError(f"invalid {manager.upper()} dependency or provide")
            if atom["version"] is not None and atom["name"].lower() in CREDENTIAL_KEYS:
                raise ValueError("snapshot dependency violates remote privacy policy")
    return clauses


def validate_dependency_rows(rows: list[dict], clauses: list[str]) -> None:
    if [row["raw"] for row in rows] != clauses:
        raise ValueError("structured dependencies do not match raw evidence")
    for row in rows:
        text = row["raw"]
        relation = "package"
        if text.startswith("so:"):
            relation, text = "soname", text[3:]
        elif text.startswith("virtual:"):
            relation, text = "virtual", text[8:]
        name = SCANNER_NAME.match(text)
        remainder = text[name.end():] if name else ""
        operator = SCANNER_OPERATOR.match(remainder)
        # Compare with the existing scanner projection. OPKG parenthesized
        # constraints and APK namespaces remain in the validated raw evidence.
        expected = (
            relation, name[0] if name else None, operator[0] if operator else None,
            (remainder[operator.end():] or None) if operator else None,
            None if name else "unrecognized-dependency-expression",
        )
        if tuple(row.get(key) for key in ("relation", "name", "operator", "version", "parse_error")) != expected:
            raise ValueError("invalid structured dependency evidence")


def validate_snapshot(raw: bytes) -> dict:
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError("snapshot exceeds byte limit")
    snapshot = strict_json(raw)
    validate_limits(snapshot)
    if not SCHEMA.is_valid(snapshot):
        raise ValueError("invalid snapshot schema")
    if (any(key.startswith("x-") for key in snapshot) or snapshot["privacy_mode"] != "redacted"
            or snapshot["digest"]["canonicalization"] != "evidence-sha256-v2"
            or snapshot["snapshot_id"] != f"urn:sha256:{snapshot['digest']['value']}"):
        raise ValueError("snapshot does not satisfy remote identity and privacy rules")
    system = snapshot["system"]
    if (system["distribution"].lower() not in {"openwrt", "immortalwrt", "unknown"}
            or set(system["identity_errors"]) - IDENTITY_ERRORS
            or set(snapshot["warnings"]) - WARNINGS or snapshot["errors"]):
        raise ValueError("unsupported remote snapshot diagnostics")
    for key in ("version", "profile", "architecture", "package_architecture",
                "kernel_architecture", "rootfs_type", "firmware_image_type"):
        restricted(system[key])
    restricted(system["target"], re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|unknown"))
    installed = snapshot["packages"]["installed"]
    if len({package["name"] for package in installed}) != len(installed):
        raise ValueError("duplicate package identity")
    for name in snapshot["packages"]["top_level"] + snapshot["packages"]["intent_candidates"]:
        restricted(name)
    for package in installed:
        restricted(package["name"])
        restricted(package["version"])
        clauses = dependency_clauses(package["dependencies_raw"], system["package_manager"])
        dependency_clauses(package["provides_raw"], system["package_manager"], provides=True)
        validate_dependency_rows(package["depends"], clauses)
        for proof in package["evidence"]:
            if proof not in PACKAGE_PROOFS and not re.fullmatch(
                r"rom-package-origin-manifest:sha256:[a-f0-9]{64}", proof
            ):
                raise ValueError("unsupported package provenance evidence")
    storage = snapshot["storage"]
    if set(storage["errors"]) - STORAGE_ERRORS:
        raise ValueError("unsupported remote storage diagnostic")
    ids = {mount["id"] for mount in storage["mount_inventory"]["entries"]}
    for mount in storage["mount_inventory"]["entries"]:
        restricted(mount["filesystem"])
    for target in storage["targets"]:
        if target["mount_id"] is not None and target["mount_id"] not in ids:
            raise ValueError("mount reference is not in the redacted inventory")
    return snapshot


def verify_collector_record(raw: bytes, record_bytes: bytes, key: bytes) -> dict:
    if len(key) != 32:
        raise ValueError("collector requires a 32-byte private key")
    record = strict_json(record_bytes)
    if (not isinstance(record, dict) or set(record) != RECORD_KEYS or type(record["version"]) is not int
            or record["version"] != 1 or type(record["collected_at"]) is not int
            or record["collected_at"] <= 0 or not isinstance(record["device_id"], str)
            or not IDENTIFIER.fullmatch(record["device_id"])
            or not all(isinstance(record[field], str) for field in
                       ("snapshot_id", "snapshot_sha256", "scan_generation", "mac"))
            or not GENERATION.fullmatch(record["scan_generation"])
            or not SHA_PATTERN.fullmatch(record["mac"])):
        raise ValueError("invalid collector record")
    claims = {name: value for name, value in record.items() if name != "mac"}
    encoded = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.digest(key, b"smart-upgrade/collector/v1\0" + encoded, "sha256").hex()
    if not hmac.compare_digest(record["mac"], expected):
        raise ValueError("untrusted collector record")
    if record["snapshot_sha256"] != hashlib.sha256(raw).hexdigest():
        raise ValueError("collector record does not match snapshot bytes")
    snapshot = validate_snapshot(raw)
    if (snapshot["snapshot_id"] != record["snapshot_id"]
            or not record["scan_generation"].startswith(snapshot["digest"]["value"] + "-")):
        raise ValueError("collector record does not match the snapshot identity")
    return claims
