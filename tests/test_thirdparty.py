from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location("fetch_thirdparty", "scripts/fetch-thirdparty.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_nikki_future_series_does_not_reuse_25_12_asset() -> None:
    release = json.loads(Path("tests/fixtures/thirdparty-29.0.json").read_text(encoding="utf-8"))
    cfg = {
        "asset_patterns": [r"^nikki_{arch}-openwrt-{target_series}\.tar\.gz$"],
        "strict_compatibility": True,
    }
    values = MODULE.template_values(
        "29.0.1", {"arch": "x86_64", "profile": "generic"}, "0.48.002"
    )
    with pytest.raises(MODULE.ProviderError, match="no release asset matching target series 29.0"):
        MODULE.match_assets("nikki", cfg, release, values, "29.0")


def test_strict_and_non_strict_degraded_behavior() -> None:
    selected = {"nikki"}
    statuses = {"nikki": {"status": "unresolved", "reason": "synthetic future asset missing"}}
    assert MODULE.strict_exit_code(selected, statuses, strict=True) == 1
    assert MODULE.strict_exit_code(selected, statuses, strict=False) == 0

