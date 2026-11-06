import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
MARKER = "TEST_SECRET_DO_NOT_UPLOAD_123456"


def run_python(*args):
    return subprocess.run(
        [PYTHON, *map(str, args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_parser_and_artifact_gate_never_emit_injected_secret(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text(
        "\n".join(
            [
                f"Version-from  password={MARKER}",
                f"Version-to  {MARKER}",
                f"Target  {MARKER}",
                f"Profile  {MARKER}",
                f"Package-arch  {MARKER}",
                f"Root-FS-type  {MARKER}",
                f"Sys-type  {MARKER}",
                f"ERROR password={MARKER}",
                "Installed packages: busybox",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    generated = tmp_path / "generated"
    analysis = generated / "system-analysis.json"
    parsed = run_python("scripts/parse-owut-report.py", "--report", report, "--output", analysis)
    assert parsed.returncode == 0

    resolved = run_python(
        "scripts/resolve-packages.py",
        "--analysis",
        analysis,
        "--output-dir",
        generated,
    )
    assert resolved.returncode == 0
    checked = run_python("scripts/validate-artifacts.py", "--path", generated)
    assert checked.returncode == 0, checked.stdout + checked.stderr

    emitted = parsed.stdout + parsed.stderr + resolved.stdout + resolved.stderr + checked.stdout + checked.stderr
    emitted += "".join(
        path.read_text(encoding="utf-8")
        for path in generated.rglob("*")
        if path.is_file()
    )
    assert MARKER not in emitted
    data = json.loads(analysis.read_text(encoding="utf-8"))
    assert data["source_version"] is None
    assert data["target_version"] is None
    assert "metadata_invalid:source_version" in data["errors"]
    assert all(MARKER not in item for item in data["errors"])


def test_artifact_gate_blocks_secret_without_echoing_it(tmp_path):
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "unsafe.json").write_text(
        json.dumps({"diagnostic": f"token={MARKER}"}), encoding="utf-8"
    )
    checked = run_python("scripts/validate-artifacts.py", "--path", generated)
    assert checked.returncode == 1
    assert "sensitive_value" in checked.stdout
    assert MARKER not in checked.stdout + checked.stderr
