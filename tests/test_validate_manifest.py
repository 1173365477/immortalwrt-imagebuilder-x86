from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from validate_manifest import validate


def write_generated(root: Path, target_version: str) -> None:
    root.mkdir()
    (root / "packages-official.txt").write_text("-dnsmasq\ndnsmasq-full\n", encoding="utf-8")
    (root / "packages-thirdparty.txt").write_text("", encoding="utf-8")
    (root / "packages-missing.txt").write_text("", encoding="utf-8")
    (root / "system-analysis.json").write_text(
        json.dumps({
            "target": "x86/64",
            "profile": "generic",
            "rootfs_type": "ext4",
            "target_version": target_version,
        }),
        encoding="utf-8",
    )


def test_report_and_requested_version_must_match(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    write_generated(generated, "25.12.2")
    args = SimpleNamespace(
        generated=generated,
        thirdparty=Path("config/thirdparty.yml"),
        version="29.0.1",
        strict=False,
        online=False,
    )
    errors = validate(args)
    assert any("does not match requested build version" in error for error in errors)

