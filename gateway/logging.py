"""Structured allowlist logging that never serializes raw requests or secrets."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any


LOGGER = logging.getLogger("smart_upgrade.gateway")


def device_fingerprint(device_id: str) -> str:
    return hashlib.sha256(device_id.encode("utf-8")).hexdigest()[:16]


def audit(event: str, **fields: Any) -> None:
    allowed = {
        "request_id", "internal_task_id", "device", "status", "duration_ms",
        "error_code", "commit", "idempotent", "endpoint",
    }
    payload = {"event": event}
    payload.update({key: value for key, value in fields.items() if key in allowed and value is not None})
    LOGGER.info(json.dumps(payload, sort_keys=True, separators=(",", ":")))
