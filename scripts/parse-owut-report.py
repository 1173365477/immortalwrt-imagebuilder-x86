#!/usr/bin/env python3
"""Parse an owut migration report without depending on fixed line numbers."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.@-]*$")
VERSION_RE = re.compile(r"^(?:v?\d|r\d|[0-9a-f]{7,})(?:[A-Za-z0-9+_.:~^-]*-?)*$")
REPORT_VERSION_RE = re.compile(
    r"^(?P<version>\d{1,3}\.\d{1,3}(?:\.\d{1,3})?)"
    r"(?:\s+r\d+-[A-Za-z0-9]{7,40})?"
    r"(?:\s+\(kernel\s+\d{1,3}\.\d{1,3}(?:\.\d{1,3})?[A-Za-z0-9+_.~-]*\))?$"
)
METADATA_VALUE_RE = {
    "target": re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,63}/[a-z0-9][a-z0-9+_.-]{0,63}$"),
    "profile": re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}$"),
    "package_arch": re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.-]{0,63}$"),
    "rootfs_type": re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,31}$"),
    "sys_type": re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,63}$"),
}
PROFILE_LINE_RE = re.compile(
    r"^(?P<profile>[A-Za-z0-9][A-Za-z0-9+_.-]{0,127})"
    r"(?:\s+\([a-z0-9][a-z0-9+_.-]{0,63}/[a-z0-9][a-z0-9+_.-]{0,63}\))?$"
)
META_KEYS = {
    "version-from": "source_version",
    "version-to": "target_version",
    "target": "target",
    "profile": "profile",
    "package-arch": "package_arch",
    "root-fs-type": "rootfs_type",
    "sys-type": "sys_type",
    "image-type": "sys_type",
}
SECTION_NAMES = {
    "installed packages": "installed_packages",
    "top-level packages": "top_level_packages",
    "top level packages": "top_level_packages",
    "user-installed packages": "user_installed_packages",
    "user installed packages": "user_installed_packages",
}
SENSITIVE_RE = re.compile(
    r"(?i)(TEST_SECRET_DO_NOT_UPLOAD_[A-Z0-9_]*|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:token|password|passwd|secret|subscription)\s*[:=]|https?://[^\s]+@)"
)
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_PACKAGE_EXPORT_BYTES = 16 * 1024 * 1024


def read_bounded_utf8(path: Path, limit: int) -> str:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds {limit} byte limit: {path}")
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"input is not valid UTF-8: {path}: {exc}") from exc


def validate_metadata(field: str, value: str) -> str | None:
    """Return a normalized allow-listed value without copying rejected input."""
    if not value or len(value) > 256 or re.search(r"[\x00-\x1f\x7f]", value):
        return None
    if SENSITIVE_RE.search(value):
        return None
    if field in {"source_version", "target_version"}:
        match = REPORT_VERSION_RE.fullmatch(value)
        return match.group("version") if match else None
    if field == "profile":
        match = PROFILE_LINE_RE.fullmatch(value)
        return match.group("profile") if match else None
    validator = METADATA_VALUE_RE.get(field)
    return value if validator and validator.fullmatch(value) else None


def redact(value: str) -> str:
    if SENSITIVE_RE.search(value):
        return "[redacted: report line looked sensitive]"
    value = re.sub(r"https?://\S+", "[url]", value)
    value = re.sub(r"[\x00-\x1f\x7f]", " ", value)
    return value[:500]


def package_tokens(value: str) -> list[str]:
    value = re.sub(r"\([^)]*\)", " ", value)
    tokens = re.split(r"[\s,]+", value.strip())
    return [
        token for token in tokens
        if PACKAGE_RE.fullmatch(token) and re.search(r"[A-Za-z]", token)
    ]


def parse_installed_file(path: Path | None) -> tuple[dict[str, str | None], set[str], dict[str, dict[str, Any]]]:
    packages: dict[str, str | None] = {}
    user_installed: set[str] = set()
    evidence: dict[str, dict[str, Any]] = {}
    if path is None or not path.exists():
        return packages, user_installed, evidence
    text = read_bounded_utf8(path, MAX_PACKAGE_EXPORT_BYTES)
    # opkg list-installed output.
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9+_.@-]*)\s+-\s+(\S+)\s*$", line)
        if match:
            packages[match.group(1)] = match.group(2)
            evidence[match.group(1)] = {
                "installed": True,
                "install_reason": "unknown",
                "evidence": ["opkg-list-installed"],
                "confidence": "low",
            }
    # /usr/lib/opkg/status paragraphs. Fields vary, so only Package/Version/Status
    # are used and the optional user-installed marker is treated as best effort.
    for block in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip().lower()] = value.strip()
        name = fields.get("package")
        if name and PACKAGE_RE.fullmatch(name):
            status = fields.get("status", "")
            # OPKG status databases may retain non-installed records.  Only the
            # canonical installed state (or a paragraph with no Status field,
            # for compatibility with exported minimal fixtures) is inventory.
            if status and " installed" not in f" {status.lower()}":
                continue
            packages[name] = fields.get("version")
            status_blob = " ".join(
                fields.get(key, "")
                for key in ("status", "user-installed", "auto-installed", "flags")
            ).lower()
            auto = fields.get("auto-installed", "").lower()
            explicit_user = fields.get("user-installed", "").lower() in {"yes", "true", "1"}
            reason = "unknown"
            confidence = "low"
            proof = ["opkg-status-installed"]
            if explicit_user or "user installed" in status_blob:
                user_installed.add(name)
                reason, confidence = "manual", "high"
                proof.append("opkg-user-installed")
            elif auto in {"yes", "true", "1"}:
                reason, confidence = "dependency", "high"
                proof.append("opkg-auto-installed:true")
            elif auto in {"no", "false", "0"}:
                # Auto-Installed:no is positive evidence that OPKG did not
                # mark the package automatic; it is not proof of repository
                # origin, but is accepted as manual install intent.
                reason, confidence = "manual", "medium"
                user_installed.add(name)
                proof.append("opkg-auto-installed:false")
            evidence[name] = {
                "installed": True,
                "install_reason": reason,
                "evidence": proof,
                "confidence": confidence,
            }
    return packages, user_installed, evidence


def parse_package_change(line: str) -> tuple[str, dict[str, Any]] | None:
    stripped = line.strip()
    missing = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9+_.@-]*)\s+(\S+)\s+missing\s+to-version\b",
        stripped,
        re.IGNORECASE,
    )
    if missing:
        return missing.group(1), {"from": missing.group(2), "to": None, "status": "missing"}

    arrow = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9+_.@-]*)(?:\s+\S+)?\s+(?:->|=>|replaced\s+by)\s+([A-Za-z0-9][A-Za-z0-9+_.@-]*)",
        stripped,
        re.IGNORECASE,
    )
    if arrow:
        return arrow.group(1), {"from": None, "to": arrow.group(2), "status": "replacement"}

    table = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9+_.@-]*)\s+(\S+)\s+(\S+)\s+\((upgrade|downgrade|replacement|removed|same|unchanged|indeterminate)\)\s*$",
        stripped,
        re.IGNORECASE,
    )
    if table:
        name, old, new, status = table.groups()
        status = status.lower()
        if status == "unchanged":
            status = "same"
        return name, {"from": old, "to": None if status == "removed" else new, "status": status}

    # Some owut versions print two version columns without an annotation. Only
    # accept this while both fields look version-like to avoid parsing log prose.
    columns = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9+_.@-]*)\s{2,}(\S+)\s{2,}(\S+)\s*$", stripped
    )
    if columns and VERSION_RE.match(columns.group(2)) and VERSION_RE.match(columns.group(3)):
        return columns.group(1), {
            "from": columns.group(2),
            "to": columns.group(3),
            "status": "change",
        }
    return None


def parse_report(report_path: Path, installed_path: Path | None, top_level_path: Path | None) -> dict[str, Any]:
    text = read_bounded_utf8(report_path, MAX_REPORT_BYTES)
    lines = text.splitlines()
    analysis: dict[str, Any] = {
        "source_version": None,
        "target_version": None,
        "target": None,
        "profile": None,
        "package_arch": None,
        "rootfs_type": None,
        "sys_type": None,
        "installed_count": 0,
        "top_level_count": 0,
        "user_installed_count": 0,
        "installed_packages": [],
        "top_level_packages": [],
        "user_installed_packages": [],
        "packages": {},
        "warnings": [],
        "errors": [],
        "sensitive_input_warning": bool(SENSITIVE_RE.search(text)),
        "parser_notes": [],
        "top_level_manifest": {"state": "missing", "evidence": []},
        "package_evidence": {},
    }

    list_sets = {name: set() for name in SECTION_NAMES.values()}
    current_section: str | None = None
    replacement_section = False
    for raw_line in lines:
        line = raw_line.rstrip()
        meta = re.match(r"^\s*([A-Za-z][A-Za-z0-9 -]*?)\s{2,}(.+?)\s*$", line)
        if not meta:
            meta = re.match(r"^\s*([A-Za-z][A-Za-z0-9 -]*?)\s*:\s*(.+?)\s*$", line)
        if meta:
            normalized = re.sub(r"\s+", "-", meta.group(1).strip().lower())
            if normalized in META_KEYS:
                field = META_KEYS[normalized]
                value = meta.group(2).strip()
                safe_value = validate_metadata(field, value)
                if safe_value is None:
                    error_code = f"metadata_invalid:{field}"
                    if error_code not in analysis["errors"]:
                        analysis["errors"].append(error_code)
                else:
                    analysis[field] = safe_value

        header = re.match(r"^\s*([A-Za-z -]+packages)\s*(?:\((?:example )?subset\))?\s*:\s*(.*)$", line, re.IGNORECASE)
        if header:
            label = re.sub(r"\s+", " ", header.group(1).strip().lower())
            current_section = SECTION_NAMES.get(label)
            if current_section:
                list_sets[current_section].update(package_tokens(header.group(2)))
                if current_section in {"top_level_packages", "user_installed_packages"}:
                    analysis["top_level_manifest"] = {
                        "state": "empty" if not package_tokens(header.group(2)) else "partial",
                        "evidence": ["owut-report-list"],
                    }
            continue
        if current_section:
            if not line.strip():
                current_section = None
            elif raw_line[:1].isspace():
                list_sets[current_section].update(package_tokens(line))
                continue
            else:
                current_section = None

        if re.match(r"^\s*Automatic package replacements/removals:\s*$", line, re.IGNORECASE):
            replacement_section = True
            continue
        if replacement_section:
            if not line.strip() or line.lstrip().startswith("Details at"):
                replacement_section = False
            else:
                replacement = re.match(
                    r"^\s+([A-Za-z0-9][A-Za-z0-9+_.@-]*)\s{2,}([A-Za-z0-9][A-Za-z0-9+_.@-]*|removed)\s*$",
                    line,
                    re.IGNORECASE,
                )
                if replacement and replacement.group(1).lower() != "package":
                    target = replacement.group(2)
                    analysis["packages"][replacement.group(1)] = {
                        "from": None,
                        "to": None if target.lower() == "removed" else target,
                        "status": "removed" if target.lower() == "removed" else "replacement",
                    }
                    continue

        change = parse_package_change(line)
        if change:
            name, details = change
            analysis["packages"][name] = details

        lower = line.lower()
        if re.search(r"\bwarning\b", lower):
            analysis["warnings"].append(redact(line.strip()))
        if re.search(r"\b(error|failed|failure)\b", lower):
            analysis["errors"].append(redact(line.strip()))

        count_patterns = (
            ("installed_count", r"^\s*(?:installed\s+(\d+)|(\d+)\s+installed)\s+packages?\b"),
            ("top_level_count", r"^\s*(?:top[- ]level\s+(\d+)|(\d+)\s+top[- ]level)\s+packages?\b"),
            ("user_installed_count", r"^\s*(?:user[- ]installed\s+(\d+)|(\d+)\s+user[- ]installed)\s+packages?\b"),
        )
        for field, pattern in count_patterns:
            count = re.search(pattern, lower)
            if count:
                analysis[field] = int(next(value for value in count.groups() if value is not None))

    supplemental, status_user, supplemental_evidence = parse_installed_file(installed_path)
    list_sets["installed_packages"].update(supplemental)
    list_sets["user_installed_packages"].update(status_user)
    if top_level_path and top_level_path.exists():
        top_level_text = read_bounded_utf8(top_level_path, MAX_PACKAGE_EXPORT_BYTES)
        exported = {
            token
            for line in top_level_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
            for token in package_tokens(line)
        }
        list_sets["top_level_packages"].update(exported)
        list_sets["user_installed_packages"].update(exported)
        analysis["top_level_manifest"] = {
            "state": "empty" if not exported else "partial",
            "evidence": ["explicit-top-level-file"],
        }
    for name, version in supplemental.items():
        if name not in analysis["packages"]:
            analysis["packages"][name] = {"from": version, "to": None, "status": "installed"}
        elif not analysis["packages"][name].get("from"):
            analysis["packages"][name]["from"] = version
        analysis["package_evidence"][name] = supplemental_evidence[name]

    # Every package with an old version is known to be installed even if owut did
    # not emit a dedicated Installed packages list.
    for name, details in analysis["packages"].items():
        if details.get("from"):
            list_sets["installed_packages"].add(name)

    for field, values in list_sets.items():
        analysis[field] = sorted(values)
    if not analysis["installed_count"]:
        analysis["installed_count"] = len(analysis["installed_packages"])
    if not analysis["top_level_count"]:
        analysis["top_level_count"] = len(analysis["top_level_packages"])
    if not analysis["user_installed_count"]:
        analysis["user_installed_count"] = len(analysis["user_installed_packages"])

    if analysis["top_level_manifest"]["state"] == "missing" and (
        analysis["top_level_packages"] or analysis["user_installed_packages"]
    ):
        analysis["top_level_manifest"] = {
            "state": "partial",
            "evidence": ["owut-report-list"],
        }

    known_reason = {
        name for name, item in analysis["package_evidence"].items()
        if item.get("install_reason") in {"manual", "dependency", "system_default"}
    }
    covered = set(analysis["top_level_packages"]) | set(analysis["user_installed_packages"]) | known_reason
    installed_set = set(analysis["installed_packages"])
    manifest = analysis["top_level_manifest"]
    manifest["unclassified_packages"] = sorted(installed_set - covered)
    if analysis["top_level_count"] > len(analysis["top_level_packages"]):
        manifest["evidence"].append("reported-count-exceeds-captured-list")
    if manifest["state"] == "partial" and not manifest["unclassified_packages"]:
        manifest["state"] = "complete"

    if not analysis["top_level_packages"] and not analysis["user_installed_packages"]:
        analysis["parser_notes"].append(
            "No complete top-level/user-installed list was found; strict migration must block unclassified packages."
        )
    return analysis


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--installed", type=Path)
    parser.add_argument("--top-level", type=Path)
    parser.add_argument("--output", type=Path, default=Path("generated/system-analysis.json"))
    args = parser.parse_args()
    if not args.report.is_file():
        parser.error(f"report does not exist: {args.report}")
    analysis = parse_report(args.report, args.installed, args.top_level)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Parsed {args.report}: {analysis['installed_count']} installed, "
          f"{analysis['top_level_count']} top-level, {analysis['user_installed_count']} user-installed")
    if analysis["sensitive_input_warning"]:
        print("::warning::The report appears to contain sensitive text; review it before committing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

