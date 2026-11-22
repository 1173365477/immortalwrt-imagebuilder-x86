import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "luci-app-smart-upgrade"
RPC = APP / "root/usr/libexec/rpcd/smart_upgrade"
MODEL = APP / "htdocs/luci-static/resources/smart-upgrade/model.js"
VIEW = APP / "htdocs/luci-static/resources/view/smart-upgrade/overview.js"
ACL = APP / "root/usr/share/rpcd/acl.d/luci-app-smart-upgrade.json"
MENU = APP / "root/usr/share/luci/menu.d/luci-app-smart-upgrade.json"
HEX = "a" * 64
URN = f"urn:sha256:{HEX}"


def snapshot(*, manager="opkg", boot="unknown", status="partial", packages=None):
    return {
        "schema_version": "1.0.0",
        "snapshot_id": URN,
        "digest": {
            "algorithm": "sha256",
            "canonicalization": "evidence-sha256-v2",
            "value": HEX,
        },
        "status": status,
        "privacy_mode": "redacted",
        "system": {
            "distribution": "ImmortalWrt",
            "version": "25.12.2",
            "target": "x86/64",
            "profile": "generic",
            "architecture": "x86_64",
            "package_architecture": "x86_64",
            "kernel_architecture": "x86_64",
            "boot_mode": boot,
            "boot_evidence": "no_affirmative_evidence",
            "rootfs_type": "overlay",
            "firmware_image_type": "unknown",
            "package_manager": manager,
            "identity_status": "consistent" if manager != "unknown" else "unknown",
            "identity_errors": [],
        },
        "packages": {
            "installed": packages or [],
            "top_level": [],
            "intent_candidates": [],
            "classification_status": "unknown",
            "truncated": False,
        },
        "services": {
            name: {
                "package_detected": None,
                "executable_exists": None,
                "service_definition_exists": None,
                "running": "unknown",
            }
            for name in ("openclash", "lucky", "adguardhome", "docker")
        },
        "storage": {
            "status": "partial",
            "scan_completeness": {
                "containers": "unavailable",
                "volumes": "unavailable",
                "mounts": "partial",
                "container_scope": "unknown",
                "volume_scope": "unknown",
            },
            "docker": {
                "installed": True,
                "daemon_state": "unavailable",
                "root": None,
                "configured_root": None,
                "root_source": "none",
                "verified": False,
                "config_mismatch": False,
            },
            "mount_inventory": {"state": "partial", "truncated": False, "entries": []},
            "targets": [],
            "errors": ["docker_mounts_unavailable"],
        },
        "warnings": ["classification incomplete"],
        "errors": [],
    }


def plan(snapshot_id=URN, *, flash_ready=False):
    return {
        "schema_version": "1.0.0",
        "plan_id": f"urn:sha256:{'b' * 64}",
        "digest": "b" * 64,
        "source_snapshot_id": snapshot_id,
        "source_snapshot_digest": snapshot_id.removeprefix("urn:sha256:"),
        "privacy_mode": "redacted",
        "status": "blocked",
        "target": {
            "distribution": "immortalwrt",
            "version": "29.0.1",
            "target": "x86/64",
            "profile": "generic",
            "architecture": "x86_64",
            "package_manager": "apk",
            "compatibility": "unknown",
        },
        "build_allowed": False,
        "flash_ready": flash_ready,
        "decisions": [
            {
                "package": "mystery", "decision": "review", "target_package": None,
                "replacements": [], "reason": "official package missing", "compatible": None,
            },
            {
                "package": "old-addon", "decision": "replace", "target_package": "new-addon",
                "replacements": ["new-addon"], "reason": "renamed", "compatible": True,
            },
        ],
        "blockers": ["boot mode unknown"],
        "warnings": ["storage scan partial"],
        "errors": [],
    }


def make_rpc_tools(tmp_path):
    helper = tmp_path / "jshn_helper.py"
    helper.write_text(
        """#!/usr/bin/env python3
import json, sys
path, op, context, key = sys.argv[1:5]
value = sys.argv[5] if len(sys.argv) > 5 else None
try:
    data = json.loads(open(path, encoding='utf-8').read())
except Exception:
    data = {}
if op == 'array':
    data[key] = []
elif op == 'string':
    if context:
        data[context].append(value)
    else:
        data[key] = value
elif op == 'boolean':
    data[key] = value in ('1', 'true')
open(path, 'w', encoding='utf-8').write(json.dumps(data, ensure_ascii=False))
""",
        encoding="utf-8",
    )
    helper.chmod(0o755)
    jshn_data = tmp_path / "jshn.json"
    jshn = tmp_path / "jshn.sh"
    jshn.write_text(
        f"""JSHN_CONTEXT=
JSHN_DATA={shlex.quote(str(jshn_data))}
JSHN_HELPER={shlex.quote(str(helper))}
json_init() {{ printf '%s' '{{}}' > "$JSHN_DATA"; JSHN_CONTEXT=; }}
json_add_string() {{ "$JSHN_HELPER" "$JSHN_DATA" string "$JSHN_CONTEXT" "$1" "$2"; }}
json_add_boolean() {{ "$JSHN_HELPER" "$JSHN_DATA" boolean "$JSHN_CONTEXT" "$1" "$2"; }}
json_add_array() {{ "$JSHN_HELPER" "$JSHN_DATA" array "" "$1"; JSHN_CONTEXT=$1; }}
json_close_array() {{ JSHN_CONTEXT=; }}
json_dump() {{ cat "$JSHN_DATA"; }}
""",
        encoding="utf-8",
    )
    jsonfilter = tmp_path / "jsonfilter"
    jsonfilter.write_text(
        """#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
path = args[args.index('-i') + 1]
expr = args[args.index('-e') + 1]
try:
    value = json.load(open(path, encoding='utf-8'))
    parts = expr.removeprefix('@.').split('.')
    expand = parts[-1].endswith('[*]')
    if expand:
        parts[-1] = parts[-1][:-3]
    for part in parts:
        value = value[part]
    values = value if expand else [value]
    for item in values:
        if isinstance(item, bool):
            print('true' if item else 'false')
        elif item is not None:
            print(item)
except Exception:
    raise SystemExit(1)
""",
        encoding="utf-8",
    )
    jsonfilter.chmod(0o755)
    return jshn, jsonfilter


@pytest.fixture
def rpc_harness(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    jshn, jsonfilter = make_rpc_tools(tmp_path)
    snapshot_file = tmp_path / "agent-snapshot.json"
    snapshot_file.write_text(json.dumps(snapshot()), encoding="utf-8")
    args_log = tmp_path / "agent-args"
    agent = tmp_path / "agent"
    agent.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$*\" > {shlex.quote(str(args_log))}\n"
        f"cat {shlex.quote(str(snapshot_file))}\n",
        encoding="utf-8",
    )
    agent.chmod(0o755)
    env = os.environ.copy()
    env.update(
        SMART_UPGRADE_STATE_DIR=str(state),
        SMART_UPGRADE_AGENT=str(agent),
        SMART_UPGRADE_JSONFILTER=str(jsonfilter),
        SMART_UPGRADE_JSHN_LIBRARY=str(jshn),
    )

    def invoke(method, payload="{}"):
        result = subprocess.run(
            ["sh", str(RPC), "call", method], input=payload,
            capture_output=True, text=True, env=env, timeout=10,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    return state, snapshot_file, args_log, agent, env, invoke


def node_model(method, *args):
    source = MODEL.read_text(encoding="utf-8")
    program = (
        "const fs=require('fs');"
        f"const model=(new Function({json.dumps(source)}))();"
        "const args=JSON.parse(fs.readFileSync(0,'utf8'));"
        f"process.stdout.write(JSON.stringify(model[{json.dumps(method)}](...args)));"
    )
    result = subprocess.run(
        ["node", "-e", program], input=json.dumps(args),
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_rpc_lists_only_fixed_read_only_contract():
    result = subprocess.run(
        ["sh", str(RPC), "list"], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == {
        "status": {}, "scan": {}, "snapshot": {}, "plan": {}, "report": {}
    }


def test_rpc_scan_is_fixed_redacted_and_preserves_partial_result(rpc_harness):
    state, _, args_log, _, _, invoke = rpc_harness
    forbidden = state.parent / "forbidden"
    result = invoke("scan", json.dumps({"command": f"touch {forbidden}", "root": "/etc"}))
    assert result["scan_status"] == "partial"
    assert result["snapshot_id"] == URN
    assert result["completed_at"].endswith("Z")
    assert result["dispatch_allowed"] is False
    assert result["flash_ready"] is False
    assert args_log.read_text().strip() == "--privacy redacted"
    envelope = invoke("snapshot")
    assert envelope["available"] is True
    assert envelope["snapshot"]["snapshot_id"] == URN
    assert (state / "system-snapshot-v1.json").is_file()
    assert not forbidden.exists()


def test_rpc_scan_failure_is_explicit_and_keeps_safety_false(rpc_harness):
    _, _, _, agent, _, invoke = rpc_harness
    agent.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
    agent.chmod(0o755)
    result = invoke("scan")
    assert result["scan_status"] == "failed"
    assert result["error_code"] == "SCAN_FAILED"
    assert result["dispatch_allowed"] is False
    assert result["flash_ready"] is False


def test_report_requires_real_files_and_rejects_unsafe_plan(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    assert invoke("report")["error_code"] == "REPORT_MISSING"
    (state / "migration-report.md").write_text("# report\n", encoding="utf-8")
    (state / "migration-plan-v1.json").write_text("not-json", encoding="utf-8")
    assert invoke("report")["error_code"] == "REPORT_INVALID"
    (state / "migration-plan-v1.json").write_text(
        json.dumps(plan(flash_ready=True)), encoding="utf-8"
    )
    result = invoke("report")
    assert result["error_code"] == "REPORT_INVALID"
    assert result["flash_ready"] is False


def test_report_binds_snapshot_and_exposes_server_blockers(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("scan")
    (state / "migration-plan-v1.json").write_text(json.dumps(plan()), encoding="utf-8")
    (state / "migration-report.md").write_text("# Migration\nBlocked.\n", encoding="utf-8")
    report = invoke("report")
    assert report["available"] is True
    assert report["integrity_status"] == "matched"
    assert report["snapshot_id"] == URN
    assert report["target_version"] == "29.0.1"
    assert report["blockers"] == ["boot mode unknown"]
    assert report["build_allowed"] is False
    assert report["dispatch_allowed"] is False
    assert report["flash_ready"] is False
    plan_envelope = invoke("plan")
    assert plan_envelope["dispatch_allowed"] is False
    assert plan_envelope["flash_ready"] is False
    assert plan_envelope["plan"]["source_snapshot_id"] == URN
    assert plan_envelope["plan"]["decisions"][1]["target_package"] == "new-addon"


def test_report_snapshot_mismatch_is_not_silently_trusted(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("scan")
    other = f"urn:sha256:{'c' * 64}"
    (state / "migration-plan-v1.json").write_text(json.dumps(plan(other)), encoding="utf-8")
    (state / "migration-report.md").write_text("# stale\n", encoding="utf-8")
    assert invoke("report")["integrity_status"] == "mismatch"
    assert invoke("plan")["error_code"] == "REPORT_SNAPSHOT_MISMATCH"


@pytest.mark.parametrize("manager", ["opkg", "apk"])
def test_model_displays_package_manager_without_inference(manager):
    value = node_model("overview", snapshot(manager=manager), None)
    assert value["current_package_manager"] == manager.upper()
    assert value["target_version"] == "Unknown"


def test_model_preserves_unknown_identity_and_boot_mode():
    value = node_model("overview", snapshot(manager="unknown", boot="unknown"), None)
    assert value["current_package_manager"] == "UNKNOWN"
    assert value["boot_mode"] == "Unknown"
    assert value["target_version"] == "Unknown"


def test_empty_top_level_keeps_every_package_and_unknown_origin():
    packages = [
        {
            "name": "vendor-addon", "version": "1", "origin": "third_party",
            "install_reason": "manual", "confidence": "high",
            "evidence": ["signed vendor manifest"], "depends": [],
        },
        {
            "name": "mystery", "version": None, "origin": "unproven",
            "install_reason": "unknown", "confidence": "low",
            "evidence": ["apk-installed-db"], "depends": [{"raw": "libc>=1"}],
        },
    ]
    rows = node_model("packages", snapshot(manager="apk", packages=packages), None)
    assert [row["name"] for row in rows] == ["vendor-addon", "mystery"]
    assert rows[0]["origin"] == "third_party"
    assert rows[1]["origin"] == "unknown"
    assert rows[1]["dependencies"] == "libc>=1"


def test_storage_special_mount_and_partial_docker_remain_visible():
    value = snapshot()
    value["storage"]["mount_inventory"]["entries"] = [{
        "mountpoint": None, "device": None, "filesystem": "overlay",
        "size_bytes": None, "risk": "special_mount",
    }]
    value["storage"]["targets"] = [{
        "kind": "bind", "source": None, "persistence": "unknown",
        "firmware_overwrite_risk": "unknown", "verified": False,
    }]
    rendered = node_model("storage", value)
    assert rendered["status"] == "partial"
    assert rendered["mounts"][0]["risk"] == "special_mount"
    assert rendered["targets"][0]["firmware_overwrite_risk"] == "unknown"
    assert rendered["errors"] == ["docker_mounts_unavailable"]


def test_target_version_requires_snapshot_matched_report():
    report = {"available": True, "integrity_status": "mismatch", "target_version": "29.0.1"}
    assert node_model("overview", snapshot(), report)["target_version"] == "Unknown"
    report["integrity_status"] = "matched"
    assert node_model("overview", snapshot(), report)["target_version"] == "29.0.1"


def test_matched_report_supplies_target_identity_without_browser_inference():
    report = {
        "available": True, "integrity_status": "matched", "target_version": "29.0.1",
        "target": "x86/64", "profile": "generic", "architecture": "x86_64",
        "package_manager": "apk",
    }
    value = node_model("overview", snapshot(manager="opkg"), report)
    assert value["current_package_manager"] == "OPKG"
    assert value["target_package_manager"] == "APK"
    assert value["target_target"] == "x86/64"
    assert value["target_profile"] == "generic"


def test_model_displays_server_package_decisions_without_reclassifying():
    rows = node_model("decisions", plan())
    assert rows[0] == {
        "package": "mystery", "decision": "review", "target_package": "Unknown",
        "replacements": "Unknown", "reason": "official package missing",
        "compatible": "Unknown",
    }
    assert rows[1]["target_package"] == "new-addon"
    assert rows[1]["replacements"] == "new-addon"


def test_acl_separates_read_methods_from_scan_permission():
    acl = json.loads(ACL.read_text(encoding="utf-8"))["luci-app-smart-upgrade"]
    assert acl["read"]["ubus"]["smart_upgrade"] == ["status", "snapshot", "plan", "report"]
    assert acl["write"]["ubus"]["smart_upgrade"] == ["scan"]


def test_package_and_menu_use_native_luci_install_contract():
    makefile = (APP / "Makefile").read_text(encoding="utf-8")
    assert "+luci-base +rpcd +jsonfilter" in makefile
    assert "$(TOPDIR)/feeds/luci/luci.mk" in makefile
    assert "scripts/smart-upgrade-agent.sh" in makefile
    menu = json.loads(MENU.read_text(encoding="utf-8"))["admin/system/smart-upgrade"]
    assert menu["action"] == {"type": "view", "path": "smart-upgrade/overview"}
    assert menu["depends"]["acl"] == ["luci-app-smart-upgrade"]


def test_frontend_has_no_device_mutation_or_build_dispatch_rpc():
    text = VIEW.read_text(encoding="utf-8")
    for method in ("status", "scan", "snapshot", "plan", "report"):
        assert f"method: '{method}'" in text
    for forbidden in ("sysupgrade", "reboot", "uci.set", "opkg", "apk add", "workflow_dispatch"):
        assert forbidden not in text.lower()
    assert "new Blob" in text
    assert "flash_ready: false" in text
    assert "dispatch_allowed: false" in text


def test_frontend_surfaces_rpc_permission_and_transport_errors():
    text = VIEW.read_text(encoding="utf-8")
    assert "Permission denied or RPC unavailable" in text
    assert "callStatus().catch(rpcFallback)" in text
    assert "callScan().then" in text
    assert "Read-only scan failed" in text


def test_luci_javascript_is_syntax_valid():
    for path in (MODEL, VIEW):
        result = subprocess.run(
            ["node", "--check", str(path)], capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, result.stderr
