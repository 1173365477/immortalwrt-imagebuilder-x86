#!/usr/bin/env python3
"""Offline administrator utility for issuing and revoking device credentials."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.database import GatewayStore


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    issue = subparsers.add_parser("issue", help="issue a device-scoped bearer credential")
    issue.add_argument("--device-id", required=True)
    issue.add_argument("--ttl-seconds", type=int, default=90 * 24 * 60 * 60)
    revoke = subparsers.add_parser("revoke", help="revoke a credential by its public ID")
    revoke.add_argument("--credential-id", required=True)
    revoke_device = subparsers.add_parser(
        "revoke-device", help="revoke every active credential for a device"
    )
    revoke_device.add_argument("--device-id", required=True)
    args = parser.parse_args()

    store = GatewayStore(args.database)
    store.initialize()
    if args.command == "issue":
        token = store.issue_credential(args.device_id, ttl_seconds=args.ttl_seconds)
        credential_id = token.split(".", 1)[0]
        print(f"credential_id={credential_id}")
        print(f"token={token}")
        print("Store the token once over an out-of-band secure channel; it cannot be recovered.")
    elif args.command == "revoke":
        store.revoke_credential(args.credential_id)
        print(f"revoked={args.credential_id}")
    else:
        count = store.revoke_device_credentials(args.device_id)
        print(f"revoked_device={args.device_id}")
        print(f"revoked_count={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
