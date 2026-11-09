from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def test_build_version_is_taken_from_dispatch_input_not_self_reference():
    text = (ROOT / ".github/workflows/build.yml").read_text()
    assert "TARGET_VERSION: ${{ inputs.target_version }}" in text
    assert "$(jq -r '.target.version'" in text
    assert "resolve_version.py" not in text


def test_existing_build_inputs_and_artifact_names_remain_compatible():
    data = workflow("build.yml")
    inputs = data[True]["workflow_dispatch"]["inputs"]
    for name in ("immortalwrt_version", "report_path", "include_openclash", "openclash_version", "include_nikki", "include_lucky", "rootfs_size", "create_release", "strict_mode"):
        assert name in inputs
    for name in ("request_id", "snapshot_ref", "target_version"):
        assert name in inputs
    text = (ROOT / ".github/workflows/build.yml").read_text()
    assert "generated/firmware/" in text
    assert "Legacy reports must first use analyze.yml" in text
    assert "permissions:\n  contents: read" in text
    assert "gh release create" not in text


def test_ci_runs_actionlint_and_all_scanner_shellcheck_targets():
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "actionlint" in text
    assert "scripts/smart-upgrade-agent.sh scripts/smart-upgrade-storage.sh" in text


def test_artifact_uploads_require_successful_safety_gate():
    for name in ("analyze.yml", "build.yml"):
        data = workflow(name)
        job = next(iter(data["jobs"].values()))
        safety = next(step for step in job["steps"] if step.get("id") == "artifact_safety")
        assert safety["if"] == "always()"
        assert "validate-artifacts.py" in safety["run"]
        assert "generated" in safety["run"]
        uploads = [step for step in job["steps"] if step.get("uses") == "actions/upload-artifact@v4"]
        assert uploads
        assert all("steps.artifact_safety.outcome == 'success'" in step["if"] for step in uploads)


def test_build_workflow_has_no_strict_mode_or_legacy_build_bypass():
    text = (ROOT / ".github/workflows/build.yml").read_text()
    assert "verify-build-input.py" in text
    assert "scripts/build-image.sh" in text
    assert "--offline-recheck" in text
    assert "--offline-recheck" not in (ROOT / "scripts/build-image.sh").read_text()
    assert "STRICT_MODE" not in text
    assert "validate-manifest.py" not in text
    assert "fetch-thirdparty.py" not in text
    assert "cancel-in-progress: false" in text

