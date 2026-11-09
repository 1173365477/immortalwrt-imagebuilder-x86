#!/usr/bin/env python3
"""Create provenance from a revalidated build input and the actual firmware bytes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from build_evidence import (
    EvidenceError, canonical_digest, load_json, safe_path, sha256_file,
    validate_schema, verify_build_input, write_json,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        context = verify_build_input(
            args.input, args.repo_root, expected_repository=args.repository,
            expected_commit=args.commit, revalidate_upstream=False,
        )
        firmware = args.firmware.resolve(strict=True)
        if not firmware.is_file() or firmware.is_symlink() or firmware.stat().st_size <= 0:
            raise EvidenceError("firmware artifact is missing, empty, or a symlink")
        build_input = load_json(args.input)
        assets = [
            {"provider": provider["provider"], "release_id": provider["release_id"],
             "asset_id": asset["asset_id"], "sha256": asset["sha256"]}
            for provider in build_input["thirdparty"] for asset in provider["assets"]
        ]
        value = {
            "schema_version": "1.0.0", "provenance_id": "", "digest": "",
            "request_id": context["request_id"],
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "build_input_id": context["build_input_id"],
            "build_input_digest": context["build_input_digest"],
            "snapshot_id": context["snapshot_id"], "snapshot_digest": context["snapshot_digest"],
            "plan_id": context["plan_id"], "plan_digest": context["plan_digest"],
            "target": context["target"],
            "resolution_digest": context["release"]["resolution_digest"],
            "official_index_digest": context["release"]["official_index_digest"],
            "provider_assets": assets,
            "trace": {"repository": args.repository, "commit_sha": context["runtime_commit_sha"],
                      "workflow_run_id": args.run_id, "workflow_run_attempt": args.run_attempt},
            "imagebuilder": {"url": context["release"]["imagebuilder_url"],
                             "filename": context["release"]["imagebuilder_filename"],
                             "sha256": context["release"]["imagebuilder_sha256"]},
            "artifact": {"filename": firmware.name, "sha256": sha256_file(firmware),
                         "size_bytes": firmware.stat().st_size},
            "build_status": "succeeded", "verification_status": "verified",
            # A successful build verifies evidence and bytes; it is not firmware compatibility testing.
            "compatibility_validated": False, "build_allowed": True, "flash_ready": False,
        }
        digest = canonical_digest(value, ("provenance_id", "digest"))
        value["digest"] = digest
        value["provenance_id"] = f"urn:sha256:{digest}"
        validate_schema(value, args.repo_root / "schemas/build-provenance-v1.json", "build provenance")
        write_json(args.output, value)
    except (EvidenceError, OSError) as exc:
        print(f"::error::PROVENANCE BLOCKED: {exc}")
        return 2
    print(f"Wrote verified provenance for {args.firmware.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
