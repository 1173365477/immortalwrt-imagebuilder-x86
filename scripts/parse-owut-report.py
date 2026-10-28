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
    r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:token|password|passwd|secret|subscription)\s*[:=]|https?://[^\s]+@)"
)


def clean_version(value: str) -> str:
    match = re.search(r"\b(\d+\.\d+(?:\.\d+)?(?:[-+~][^\s]+)?)\b", value)
    return match.group(1) if match else value.strip()


def redact(value: str) -> str:
    if SENSITIVE_RE.search(value):
        return "[redacted: report line looked sensitive]"
    value = re.sub(r"https?://\S+", "[url]", value)
    return value[:500]


def package_tokens(value: str) -> list[str]:
    value = re.sub(r"\([^)]*\)", " ", value)
    tokens = re.split(r"[\s,]+", value.strip())
    return [
        token for token in tokens
        if PACKAGE_RE.fullmatch(token) and re.search(r"[A-Za-z]", token)
    ]


def parse_installed_file(path: Path | None) -> tuple[dict[str, str | None], set[str]]:
    packages: dict[str, str | None] = {}
    user_installed: set[str] = set()
    if path is None or not path.exists():
        return packages, user_installed
    text = path.read_text(encoding="utf-8", errors="replace")
    # opkg list-installed output.
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9+_.@-]*)\s+-\s+(\S+)\s*$", line)
        if match:
            packages[match.group(1)] = match.group(2)
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
            packages[name] = fields.get("version")
            status_blob = " ".join(
                fields.get(key, "")
                for key in ("status", "user-installed", "auto-installed", "flags")
            ).lower()
            if "user installed" in status_blob or fields.get("user-installed", "").lower() in {"yes", "true", "1"}:
                user_installed.add(name)
    return packages, user_installed


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
    text = report_path.read_text(encoding="utf-8", errors="replace")
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
                analysis[field] = clean_version(value) if field.endswith("version") else value.split()[0]

        header = re.match(r"^\s*([A-Za-z -]+packages)\s*(?:\((?:example )?subset\))?\s*:\s*(.*)$", line, re.IGNORECASE)
        if header:
            label = re.sub(r"\s+", " ", header.group(1).strip().lower())
            current_section = SECTION_NAMES.get(label)
            if current_section:
                list_sets[current_section].update(package_tokens(header.group(2)))
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

    supplemental, status_user = parse_installed_file(installed_path)
    list_sets["installed_packages"].update(supplemental)
    list_sets["user_installed_packages"].update(status_user)
    if top_level_path and top_level_path.exists():
        top_level_text = top_level_path.read_text(encoding="utf-8", errors="replace")
        exported = {
            token
            for line in top_level_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
            for token in package_tokens(line)
        }
        list_sets["top_level_packages"].update(exported)
        list_sets["user_installed_packages"].update(exported)
    for name, version in supplemental.items():
        if name not in analysis["packages"]:
            analysis["packages"][name] = {"from": version, "to": None, "status": "installed"}
        elif not analysis["packages"][name].get("from"):
            analysis["packages"][name]["from"] = version

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

    if not analysis["top_level_packages"] and not analysis["user_installed_packages"]:
        analysis["parser_notes"].append(
            "No explicit top-level/user-installed list was found; resolver will use functional triggers only."
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

