#!/usr/bin/env python3
"""Conservative target/image compatibility checks for a system snapshot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def evaluate(snapshot: dict[str, Any], *, target: str, profile: str, architecture: str, image_type: str) -> dict[str, Any]:
    system = snapshot.get("system", {})
    blockers: list[str] = []
    unknown: list[str] = []
    evidence: list[str] = []
    for field, requested in (("target", target), ("profile", profile), ("package_architecture", architecture)):
        actual = system.get(field)
        if actual in (None, "", "unknown"):
            unknown.append(f"{field} is unknown")
        elif actual != requested:
            blockers.append(f"{field} mismatch: device={actual}, requested={requested}")
        else:
            evidence.append(f"{field}:{actual}")

    boot = system.get("boot_mode", "unknown")
    if image_type.endswith("-efi"):
        if boot == "bios":
            blockers.append(f"EFI image {image_type} conflicts with confirmed BIOS boot")
        elif boot == "unknown":
            unknown.append("boot mode unknown; EFI image cannot be selected automatically")
        else:
            evidence.append("boot_mode:efi")
    elif image_type in {"combined", "legacy"}:
        if boot == "efi":
            blockers.append(f"legacy image {image_type} conflicts with confirmed EFI boot")
        elif boot == "unknown":
            unknown.append("boot mode unknown; legacy image cannot be selected automatically")
        else:
            evidence.append("boot_mode:bios")
    else:
        unknown.append(f"unrecognized firmware image type: {image_type}")

    status = "incompatible" if blockers else ("unknown" if unknown else "compatible")
    return {"status": status, "blockers": blockers, "unknown": unknown, "evidence": evidence}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--image-type", required=True)
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    result = evaluate(snapshot, target=args.target, profile=args.profile, architecture=args.architecture, image_type=args.image_type)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "compatible" else 1


if __name__ == "__main__":
    raise SystemExit(main())
