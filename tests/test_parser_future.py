from pathlib import Path

from parse_owut_report import parse_report


def test_synthetic_29_report_parses_without_release_hardcoding() -> None:
    analysis = parse_report(Path("tests/fixtures/owut-29.0.txt"), None, None)
    assert analysis["source_version"] == "28.4.3"
    assert analysis["target_version"] == "29.0.1"
    assert analysis["target"] == "x86/64"
    assert analysis["packages"]["future-tool"]["status"] == "upgrade"
    assert analysis["packages"]["future-missing"]["status"] == "missing"

