#!/usr/bin/env python3
"""Offline target refresh, authenticated Snapshot import and evidence retention."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.admission import DEFAULT_SNAPSHOT_TTL, MAX_SNAPSHOT_BYTES
from gateway.app import GatewaySettings
from gateway.database import GatewayStore
from gateway.errors import GatewayError
from gateway.targets import DEFAULT_TTL, private_file, refresh_catalog


def main() -> int:
    defaults = GatewaySettings.from_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=defaults.database_path)
    commands = parser.add_subparsers(dest="command", required=True)
    refresh = commands.add_parser("refresh-targets")
    refresh.add_argument("--catalog", type=Path, default=defaults.target_catalog_path)
    refresh.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL)
    refresh.add_argument("--timeout-seconds", type=int, default=90)
    admit = commands.add_parser("admit-snapshot")
    admit.add_argument("--snapshot", type=Path, required=True)
    admit.add_argument("--collector-record", type=Path, required=True)
    admit.add_argument("--ttl-seconds", type=int, default=DEFAULT_SNAPSHOT_TTL)
    commands.add_parser("purge-expired")
    args = parser.parse_args()
    try:
        if args.command == "refresh-targets":
            refresh_catalog(
                args.catalog or args.database.parent / "target-catalog.json",
                ttl=args.ttl_seconds, timeout=args.timeout_seconds,
            )
            print("Target catalog verified and published.")
            return 0
        store = GatewayStore(args.database)
        store.initialize()
        if args.command == "admit-snapshot":
            key_file = os.environ.get("GATEWAY_COLLECTOR_KEY_FILE")
            if not key_file:
                raise ValueError("trusted collector key is not configured")
            print(store.admit_snapshot(
                private_file(args.snapshot, MAX_SNAPSHOT_BYTES),
                private_file(args.collector_record, 4096),
                private_file(Path(key_file), 32),
                ttl=args.ttl_seconds,
            ))
        else:
            snapshots = store.purge_expired_snapshots()
            analyses = store.purge_expired_analysis()
            print(f"expired_snapshot_payloads={snapshots} expired_analysis_receipts={analyses}")
    except GatewayError as exc:
        print(exc.code.value, file=sys.stderr)
        return 1
    except (ValueError, OSError, RecursionError):
        print("The administrative operation could not be completed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
