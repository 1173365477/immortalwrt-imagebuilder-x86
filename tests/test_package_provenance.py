import argparse
import json
from pathlib import Path

from parse_owut_report import parse_report
from resolve_packages import resolve
import pytest


ROOT = Path(__file__).resolve().parents[1]


def _parse(tmp_path: Path, status_text: str, top_level: str | None):
    report = tmp_path / "report.txt"
    report.write_text(
        "Version-from  24.10.4\nVersion-to  25.12.2\nTarget  x86/64\n"
        "Profile  generic\nRoot-FS-type  ext4\nSys-type  combined-efi\n",
        encoding="utf-8",
    )
    status = tmp_path / "status"
    status.write_text(status_text, encoding="utf-8")
    top = None
    if top_level is not None:
        top = tmp_path / "top-level.txt"
        top.write_text(top_level, encoding="utf-8")
    return parse_report(report, status, top)


def _resolve(tmp_path: Path, analysis: dict):
    analysis_path = tmp_path / "analysis.json"
    analysis_path.write_text(json.dumps(analysis), encoding="utf-8")
    args = argparse.Namespace(
        analysis=analysis_path,
        rules=ROOT / "config/package-rules.yml",
        thirdparty=ROOT / "config/thirdparty.yml",
        base=ROOT / "config/base-packages.txt",
        output_dir=tmp_path / "out",
        include_openclash=None,
        include_nikki=None,
        include_lucky=None,
    )
    args.output_dir.mkdir()
    return resolve(args)


def test_partial_top_level_blocks_each_unclassified_package(tmp_path):
    analysis = _parse(
        tmp_path,
        "Package: manual-a\nVersion: 1\nStatus: install ok installed\nAuto-Installed: no\n\n"
        "Package: mystery-b\nVersion: 1\nStatus: install ok installed\n\n",
        "manual-a\n",
    )
    assert analysis["top_level_manifest"]["state"] == "partial"
    assert analysis["top_level_manifest"]["unclassified_packages"] == ["mystery-b"]
    result = _resolve(tmp_path, analysis)
    assert result["decisions"]["manual-a"]["decision"] == "keep"
    assert result["decisions"]["mystery-b"]["decision"] == "review"
    assert any(row.startswith("mystery-b\t") for row in result["missing"])


def test_empty_top_level_blocks_unknown_but_allows_proven_dependency(tmp_path):
    analysis = _parse(
        tmp_path,
        "Package: auto-lib\nVersion: 1\nStatus: install ok installed\nAuto-Installed: yes\n\n"
        "Package: mystery\nVersion: 1\nStatus: install ok installed\n\n",
        "",
    )
    assert analysis["top_level_manifest"]["state"] == "empty"
    result = _resolve(tmp_path, analysis)
    assert result["decisions"]["auto-lib"]["decision"] == "skip"
    assert result["decisions"]["mystery"]["decision"] == "review"


def test_complete_manifest_requires_evidence_for_every_installed_package(tmp_path):
    analysis = _parse(
        tmp_path,
        "Package: app\nVersion: 1\nStatus: install ok installed\nAuto-Installed: no\n\n"
        "Package: lib\nVersion: 1\nStatus: install ok installed\nAuto-Installed: yes\n\n",
        "app\n",
    )
    assert analysis["top_level_manifest"]["state"] == "complete"
    result = _resolve(tmp_path, analysis)
    assert not any(row.startswith("unknown-provenance\t") for row in result["missing"])
    assert result["decisions"]["lib"]["decision"] == "skip"


def test_non_installed_opkg_paragraph_is_excluded(tmp_path):
    analysis = _parse(
        tmp_path,
        "Package: stale\nVersion: 1\nStatus: deinstall ok config-files\nAuto-Installed: no\n\n",
        "",
    )
    assert "stale" not in analysis["installed_packages"]


def test_invalid_utf8_is_explicit_parse_failure(tmp_path):
    report = tmp_path / "report.txt"
    report.write_bytes(b"Version-to  25.12.2\n\xff")
    with pytest.raises(ValueError, match="valid UTF-8"):
        parse_report(report, None, None)


def test_oversized_report_is_rejected_before_parse(tmp_path):
    report = tmp_path / "report.txt"
    report.write_bytes(b"x" * (8 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="byte limit"):
        parse_report(report, None, None)

