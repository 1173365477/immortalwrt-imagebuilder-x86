import json
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from luci_evidence import create_bundle, publish_bundle
APP = ROOT / "luci-app-smart-upgrade"
RPC = APP / "root/usr/libexec/rpcd/smart_upgrade"
RPC_SHELL = shlex.split(os.environ.get("T15_RPC_SHELL", "sh"))
MODEL = APP / "htdocs/luci-static/resources/smart-upgrade/model.js"
VIEW = APP / "htdocs/luci-static/resources/view/smart-upgrade/overview.js"
ACL = APP / "root/usr/share/rpcd/acl.d/luci-app-smart-upgrade.json"
MENU = APP / "root/usr/share/luci/menu.d/luci-app-smart-upgrade.json"
HEX = "a" * 64
URN = f"urn:sha256:{HEX}"
BOOT_ID = "12345678-1234-4234-9234-123456789abc"


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
            "evidence_digest": HEX,
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
    value = {
        "schema_version": "1.0.0",
        "plan_id": "",
        "digest": "",
        "source_snapshot_id": snapshot_id,
        "source_snapshot_digest": snapshot_id.removeprefix("urn:sha256:"),
        "privacy_mode": "redacted",
        "status": "blocked",
        "source": {
            "distribution": "ImmortalWrt", "version": "25.12.2",
            "target": "x86/64", "profile": "generic", "architecture": "x86_64",
            "package_manager": "opkg", "boot_mode": "unknown",
        },
        "target": {
            "distribution": "immortalwrt",
            "version": "29.0.1",
            "target": "x86/64",
            "profile": "generic",
            "architecture": "x86_64",
            "package_manager": "apk",
            "boot_mode": "unknown", "image_type": None,
            "image_name": None, "image_sha256": None,
            "compatibility": "unknown",
        },
        "release": {
            "channel": "release", "resolution_digest": HEX,
            "profiles_url": "https://example.invalid/profiles.json", "profiles_sha256": HEX,
            "official_index_digest": HEX,
            "package_index_sources": [{
                "url": "https://example.invalid/packages.json", "sha256": HEX,
                "checksum_manifest_url": "https://example.invalid/sha256sums",
                "checksum_manifest_sha256": HEX, "checksum_entry": "packages.json",
            }],
            "imagebuilder_url": "https://example.invalid/imagebuilder.tar.zst",
            "imagebuilder_sha256": HEX,
        },
        "package_summary": {"installed": 2, "keep": 0, "replace": 1, "skip": 0, "review": 1, "block": 0},
        "storage_risk": {
            "status": "partial", "docker_present": True,
            "firmware_overwrite_risks": ["unknown"], "flash_blockers": ["storage unknown"],
        },
        "explicit_exclusions": [],
        "strict_mode": True,
        "build_allowed": False,
        "build_status": "not_started",
        "compatibility_validated": False,
        "flash_ready": flash_ready,
        "decisions": [
            {
                "package": "mystery", "source_version": None, "origin": "unknown",
                "install_reason": "unknown", "decision": "review", "target_package": None,
                "match_type": "unresolved", "provider": None,
                "replacements": [], "conflicts": [], "dependencies": [],
                "reason": "official package missing", "compatible": None,
                "evidence": ["snapshot:unknown"],
            },
            {
                "package": "old-addon", "source_version": "1", "origin": "official",
                "install_reason": "manual", "decision": "replace", "target_package": "new-addon",
                "match_type": "replacement", "provider": None,
                "replacements": ["new-addon"], "conflicts": [], "dependencies": [],
                "reason": "renamed", "compatible": True, "evidence": ["rule:test"],
            },
        ],
        "blockers": ["boot mode unknown"],
        "warnings": ["storage scan partial"],
        "errors": [],
    }
    identity = dict(value)
    identity.pop("plan_id")
    identity.pop("digest")
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    value["digest"] = digest
    value["plan_id"] = f"urn:sha256:{digest}"
    return value


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
JSHN_DATA={shlex.quote(str(jshn_data))}.$$
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
type_only = '-t' in args
expr = args[args.index('-t' if type_only else '-e') + 1]
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
        if type_only:
            if isinstance(item, bool): print('boolean')
            elif isinstance(item, str): print('string')
            elif isinstance(item, (int, float)): print('number')
            elif isinstance(item, list): print('array')
            elif isinstance(item, dict): print('object')
            elif item is None: print('null')
        elif isinstance(item, bool):
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
    state.chmod(0o700)
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
    boot_id = tmp_path / "boot-id"
    boot_id.write_text(BOOT_ID + "\n", encoding="ascii")
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    setsid = tmp_path / "setsid"
    setsid.write_text(
        "#!/usr/bin/env python3\nimport os,sys\nos.setsid()\nos.execvp(sys.argv[1], sys.argv[1:])\n",
        encoding="utf-8",
    )
    setsid.chmod(0o755)
    flock = shutil.which("flock")
    if not flock:
        flock = tmp_path / "flock"
        flock.write_text(
            "#!/usr/bin/env python3\nimport fcntl, sys\n"
            "try: fcntl.flock(int(sys.argv[2]), fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "except BlockingIOError: raise SystemExit(1)\n",
            encoding="utf-8",
        )
        flock.chmod(0o755)
    env = os.environ.copy()
    env.update(
        SMART_UPGRADE_STATE_DIR=str(state),
        SMART_UPGRADE_AGENT=str(agent),
        SMART_UPGRADE_JSONFILTER=str(jsonfilter),
        SMART_UPGRADE_JSHN_LIBRARY=str(jshn),
        SMART_UPGRADE_EXPECTED_UID=str(os.getuid()),
        SMART_UPGRADE_BOOT_ID_FILE=str(boot_id),
        SMART_UPGRADE_PROC_ROOT=str(proc_root),
        SMART_UPGRADE_SELF_START_TICKS="12345",
        SMART_UPGRADE_SETSID=os.environ.get("T15_SETSID", shutil.which("setsid") or str(setsid)),
        SMART_UPGRADE_FLOCK=os.environ.get("T15_FLOCK", str(flock)),
    )

    def invoke(method, payload="{}"):
        result = subprocess.run(
            [*RPC_SHELL, str(RPC), "call", method], input=payload,
            capture_output=True, text=True, env=env, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    return state, snapshot_file, args_log, agent, env, invoke


def published_snapshot(state):
    generation = (state / "current-snapshot").read_text(encoding="ascii").split()[0]
    return state / "snapshots" / generation / "system-snapshot-v1.json"


def publish_analysis(state, tmp_path, value=None, report="# Migration\nBlocked.\n"):
    bundle = tmp_path / "analysis-source"
    bundle.mkdir(exist_ok=True)
    plan_path = bundle / "migration-plan-v1.json"
    report_path = bundle / "migration-report.md"
    plan_path.write_text(json.dumps(value or plan()), encoding="utf-8")
    report_path.write_text(report, encoding="utf-8")
    create_bundle(
        published_snapshot(state), plan_path, report_path, bundle, ROOT,
        producer_commit="d" * 40,
    )
    return publish_bundle(bundle, state, ROOT)


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
    assert envelope["integrity_status"] == "verified"
    assert envelope["snapshot"]["snapshot_id"] == URN
    assert published_snapshot(state).is_file()
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
    assert invoke("report")["error_code"] == "EVIDENCE_UNVERIFIED"
    (state / "migration-report.md").write_text("# report\n", encoding="utf-8")
    (state / "migration-plan-v1.json").write_text("not-json", encoding="utf-8")
    assert invoke("report")["error_code"] == "EVIDENCE_UNVERIFIED"
    (state / "migration-plan-v1.json").write_text(
        json.dumps(plan(flash_ready=True)), encoding="utf-8"
    )
    result = invoke("report")
    assert result["error_code"] == "EVIDENCE_UNVERIFIED"
    assert result["flash_ready"] is False


def test_report_binds_snapshot_and_exposes_server_blockers(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("scan")
    publish_analysis(state, state.parent)
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
    state, snapshot_file, _, _, _, invoke = rpc_harness
    invoke("scan")
    publish_analysis(state, state.parent)
    changed = snapshot()
    changed["digest"]["value"] = "c" * 64
    changed["snapshot_id"] = f"urn:sha256:{'c' * 64}"
    snapshot_file.write_text(json.dumps(changed), encoding="utf-8")
    invoke("scan")
    report = invoke("report")
    assert report["available"] is False
    assert report["error_code"] == "EVIDENCE_UNVERIFIED"
    assert "target_version" not in report
    assert invoke("plan")["error_code"] == "EVIDENCE_UNVERIFIED"


def test_state_directory_symlink_is_rejected_without_changing_target(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    state.rmdir()
    victim = state.parent / "victim"
    victim.mkdir(mode=0o755)
    state.symlink_to(victim, target_is_directory=True)
    result = invoke("status")
    assert result["error_code"] == "STATE_DIRECTORY_UNSAFE"
    assert victim.stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize("kind", ["file", "fifo"])
def test_non_directory_state_object_is_rejected(rpc_harness, kind):
    state, _, _, _, _, invoke = rpc_harness
    state.rmdir()
    if kind == "file":
        state.write_text("not a directory", encoding="utf-8")
    else:
        os.mkfifo(state)
    result = invoke("status")
    assert result["error_code"] == "STATE_DIRECTORY_UNSAFE"


def test_state_directory_owner_and_permissions_fail_closed(rpc_harness):
    state, _, _, _, env, invoke = rpc_harness
    state.chmod(0o777)
    assert invoke("status")["error_code"] == "STATE_DIRECTORY_UNSAFE"
    state.chmod(0o700)
    env["SMART_UPGRADE_EXPECTED_UID"] = str(os.getuid() + 1)
    assert invoke("status")["error_code"] in {"STATE_PARENT_UNSAFE", "STATE_DIRECTORY_UNSAFE"}


def test_concurrent_first_state_creation_is_atomic(rpc_harness):
    state, _, _, _, env, _ = rpc_harness
    state.rmdir()
    environments = []
    for index in range(2):
        tools_dir = state.parent / f"worker-{index}"
        tools_dir.mkdir()
        jshn, jsonfilter = make_rpc_tools(tools_dir)
        worker = env.copy()
        worker["SMART_UPGRADE_JSHN_LIBRARY"] = str(jshn)
        worker["SMART_UPGRADE_JSONFILTER"] = str(jsonfilter)
        environments.append(worker)

    def call(worker):
        result = subprocess.run(
            ["sh", str(RPC), "call", "status"], input="{}", text=True,
            capture_output=True, env=worker, timeout=30, check=True,
        )
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(call, environments))
    assert [row["scan_status"] for row in results] == ["idle", "idle"]
    assert state.stat().st_mode & 0o777 == 0o700


def test_status_is_rebuilt_and_ignores_forged_safety_fields(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("status")
    status_path = state / "scan-state.json"
    status_path.write_text(json.dumps({
        "scan_status": "completed", "started_at": "2026-11-24T00:00:00Z",
        "completed_at": "2026-11-24T00:00:01Z", "snapshot_id": URN,
        "snapshot_status": "partial", "error_code": "", "error_message": "",
        "dispatch_allowed": True, "flash_ready": True, "unknown": "ignored",
    }), encoding="utf-8")
    status_path.chmod(0o600)
    result = invoke("status")
    assert result["scan_status"] == "completed"
    assert result["dispatch_allowed"] is False
    assert result["flash_ready"] is False
    assert "unknown" not in result


@pytest.mark.parametrize("payload", [
    "not-json",
    json.dumps({"scan_status": "unsafe"}),
    json.dumps({
        "scan_status": "failed", "started_at": "bad-time", "completed_at": "",
        "snapshot_id": "", "snapshot_status": "failed", "error_code": "E",
        "error_message": "x",
    }),
])
def test_invalid_status_fails_closed(rpc_harness, payload):
    state, _, _, _, _, invoke = rpc_harness
    invoke("status")
    status_path = state / "scan-state.json"
    status_path.write_text(payload, encoding="utf-8")
    status_path.chmod(0o600)
    result = invoke("status")
    assert result["available"] is False
    assert result["error_code"] == "STATUS_INVALID"
    assert result["dispatch_allowed"] is False
    assert result["flash_ready"] is False


def test_status_symlink_and_oversize_are_rejected(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("status")
    target = state.parent / "external-status"
    target.write_text("{}", encoding="utf-8")
    (state / "scan-state.json").symlink_to(target)
    assert invoke("status")["error_code"] == "STATUS_UNSAFE"
    (state / "scan-state.json").unlink()
    (state / "scan-state.json").write_text("x" * 65537, encoding="ascii")
    (state / "scan-state.json").chmod(0o600)
    assert invoke("status")["error_code"] == "STATUS_UNSAFE"


def owner_payload(*, boot=BOOT_ID, pid="123", ticks="999", created_at="2026-11-24T00:00:00Z"):
    return {
        "schema_version": "1.0.0", "pid": pid, "boot_id": boot,
        "process_start_ticks": ticks, "created_at": created_at,
    }


def write_lock(state, *, boot=BOOT_ID, pid="123", ticks="999", valid=True, payload=None):
    lock = state / "scan.lock"
    lock.mkdir(mode=0o700)
    owner = lock / "owner.json"
    owner.write_text(json.dumps(payload or owner_payload(boot=boot, pid=pid, ticks=ticks)) if valid else "broken", encoding="utf-8")
    owner.chmod(0o600)


def write_gate(state, *, boot=BOOT_ID, pid="123", ticks="999", valid=True, payload=None, owner=True):
    gate = state / "scan.acquire"
    gate.mkdir(mode=0o700)
    if owner:
        owner_path = gate / "owner.json"
        owner_path.write_text(json.dumps(payload or owner_payload(boot=boot, pid=pid, ticks=ticks)) if valid else "broken", encoding="utf-8")
        owner_path.chmod(0o600)


def write_proc_stat(proc_root, pid="123", ticks="999"):
    directory = proc_root / pid
    directory.mkdir(parents=True, exist_ok=True)
    # After the closing parenthesis, process start time is Linux /proc stat field 22,
    # which is the twentieth whitespace field consumed by the provider.
    fields = ["S"] + ["0"] * 18 + [ticks] + ["0"] * 4
    (directory / "stat").write_text(f"{pid} (scanner) " + " ".join(fields) + "\n", encoding="ascii")


def test_live_scan_lock_remains_busy(rpc_harness):
    state, _, _, _, env, invoke = rpc_harness
    invoke("status")
    write_lock(state)
    write_proc_stat(Path(env["SMART_UPGRADE_PROC_ROOT"]))
    assert invoke("scan")["error_code"] == "SCAN_BUSY"
    assert (state / "scan.lock").is_dir()


def test_present_process_with_unreadable_identity_does_not_recover_lock(rpc_harness):
    state, _, _, _, env, invoke = rpc_harness
    invoke("status")
    write_lock(state)
    (Path(env["SMART_UPGRADE_PROC_ROOT"]) / "123").mkdir()
    assert invoke("scan")["error_code"] == "LOCK_UNVERIFIABLE"
    assert (state / "scan.lock").is_dir()


@pytest.mark.parametrize("mode", ["missing-process", "pid-reuse", "new-boot"])
def test_proven_stale_lock_is_isolated_and_requires_retry(rpc_harness, mode):
    state, _, _, _, env, invoke = rpc_harness
    invoke("status")
    write_lock(state, boot="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" if mode == "new-boot" else BOOT_ID)
    if mode == "pid-reuse":
        write_proc_stat(Path(env["SMART_UPGRADE_PROC_ROOT"]), ticks="1000")
    result = invoke("scan")
    assert result["error_code"] == "LOCK_RECOVERED"
    assert not (state / "scan.lock").exists()
    assert any((state / "recovered-locks").iterdir())
    # Recovery never starts the scan; a new explicit request is required.
    assert invoke("scan")["scan_status"] == "partial"


def test_corrupt_or_symlink_lock_is_not_removed(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("status")
    write_lock(state, valid=False)
    assert invoke("scan")["error_code"] == "LOCK_UNVERIFIABLE"
    assert (state / "scan.lock").is_dir()
    (state / "scan.lock/owner.json").unlink()
    (state / "scan.lock").rmdir()
    target = state.parent / "lock-target"
    target.mkdir()
    (state / "scan.lock").symlink_to(target, target_is_directory=True)
    assert invoke("scan")["error_code"] == "LOCK_UNVERIFIABLE"
    assert target.is_dir()


@pytest.mark.parametrize("mutation", [
    "empty-pid", "empty-ticks", "empty-boot", "invalid-boot",
    "missing-schema", "numeric-pid", "numeric-ticks", "missing-created-at",
])
def test_incomplete_or_wrong_type_lock_owner_is_unverifiable(rpc_harness, mutation):
    state, _, _, _, _, invoke = rpc_harness
    invoke("status")
    payload = owner_payload()
    if mutation == "empty-pid": payload["pid"] = ""
    elif mutation == "empty-ticks": payload["process_start_ticks"] = ""
    elif mutation == "empty-boot": payload["boot_id"] = ""
    elif mutation == "invalid-boot": payload["boot_id"] = "not-a-linux-boot-id"
    elif mutation == "missing-schema": payload.pop("schema_version")
    elif mutation == "numeric-pid": payload["pid"] = 123
    elif mutation == "numeric-ticks": payload["process_start_ticks"] = 999
    elif mutation == "missing-created-at": payload.pop("created_at")
    write_lock(state, payload=payload)
    result = invoke("scan")
    assert result["error_code"] == "LOCK_UNVERIFIABLE"
    assert (state / "scan.lock").is_dir()


def test_active_acquisition_gate_remains_busy(rpc_harness):
    state, _, _, _, env, invoke = rpc_harness
    invoke("status")
    write_gate(state)
    write_proc_stat(Path(env["SMART_UPGRADE_PROC_ROOT"]))
    assert invoke("scan")["error_code"] == "SCAN_BUSY"
    assert (state / "scan.acquire").is_dir()


@pytest.mark.parametrize("mode", ["missing-process", "pid-reuse", "new-boot"])
def test_proven_stale_acquisition_gate_is_isolated_without_scanning(rpc_harness, mode):
    state, _, _, _, env, invoke = rpc_harness
    invoke("status")
    write_gate(state, boot="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" if mode == "new-boot" else BOOT_ID)
    if mode == "pid-reuse":
        write_proc_stat(Path(env["SMART_UPGRADE_PROC_ROOT"]), ticks="1000")
    result = invoke("scan")
    assert result["error_code"] == "LOCK_RECOVERED"
    assert not (state / "scan.acquire").exists()
    assert any(path.name.startswith("acquire-") for path in (state / "recovered-locks").iterdir())
    assert not (state / "current-snapshot").exists()


@pytest.mark.parametrize("owner_kind", ["missing", "corrupt"])
def test_crash_window_acquisition_gate_is_unverifiable_not_deleted(rpc_harness, owner_kind):
    state, _, _, _, _, invoke = rpc_harness
    invoke("status")
    write_gate(state, owner=owner_kind != "missing", valid=owner_kind != "corrupt")
    result = invoke("scan")
    assert result["error_code"] == "LOCK_UNVERIFIABLE"
    assert (state / "scan.acquire").is_dir()


def test_concurrent_acquisition_gate_recovery_is_atomic(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("status")
    write_gate(state)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: invoke("scan"), range(2)))
    codes = {result.get("error_code", "") for result in results}
    assert "LOCK_RECOVERED" in codes
    assert codes <= {"LOCK_RECOVERED", "SCAN_BUSY", ""}
    recovered = list((state / "recovered-locks").glob("acquire-*"))
    assert len(recovered) == 1


def test_acquisition_mutex_released_when_holder_is_killed(rpc_harness):
    state, _, args_log, _, env, invoke = rpc_harness
    ready = state.parent / "mutex-ready"
    holder = subprocess.Popen(
        [
            "sh", "-c",
            'umask 077; exec 9>>"$1"; "$2" -n 9 || exit 1; : >"$3"; kill -STOP "$$"',
            "mutex-holder", str(state / "scan.acquire.mutex"),
            env["SMART_UPGRADE_FLOCK"], str(ready),
        ],
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.exists()
        assert invoke("scan")["error_code"] == "SCAN_BUSY"
        assert not args_log.exists()
    finally:
        holder.kill()
        holder.wait(timeout=5)
    assert invoke("scan")["scan_status"] == "partial"


def test_two_simultaneous_scan_requests_never_run_two_agents(rpc_harness):
    state, _, _, agent, env, _ = rpc_harness
    counter = state.parent / "agent-counter"
    release = state.parent / "agent-release"
    agent.write_text(
        "#!/bin/sh\nprintf 'run\\n' >> \"$AGENT_COUNTER\"\n"
        "while [ ! -f \"$AGENT_RELEASE\" ]; do sleep 1; done\ncat \"$SNAPSHOT_FILE\"\n",
        encoding="utf-8",
    )
    agent.chmod(0o755)
    env["AGENT_COUNTER"] = str(counter)
    env["AGENT_RELEASE"] = str(release)
    env["SNAPSHOT_FILE"] = str(state.parent / "agent-snapshot.json")

    first = subprocess.Popen(
        [*RPC_SHELL, str(RPC), "call", "scan"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    )
    assert first.stdin
    first.stdin.write("{}")
    first.stdin.close()
    owner_path = state / "scan.lock/owner.json"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not owner_path.exists():
        time.sleep(0.02)
    assert owner_path.exists()
    while time.monotonic() < deadline and (state / "scan.acquire").exists():
        time.sleep(0.02)
    assert not (state / "scan.acquire").exists()
    owner = json.loads(owner_path.read_text())
    write_proc_stat(Path(env["SMART_UPGRADE_PROC_ROOT"]), owner["pid"], owner["process_start_ticks"])
    second = subprocess.run(
        ["sh", str(RPC), "call", "scan"], input="{}", capture_output=True,
        text=True, env=env, timeout=30,
    )
    release.write_text("continue\n", encoding="ascii")
    first.wait(timeout=15)
    assert first.stdout and first.stderr
    first_stdout = first.stdout.read()
    first_stderr = first.stderr.read()
    assert first.returncode == 0, first_stderr
    assert second.returncode == 0, second.stderr
    payloads = [json.loads(first_stdout), json.loads(second.stdout)]
    assert sum(payload.get("error_code") == "SCAN_BUSY" for payload in payloads) == 1, payloads
    assert counter.read_text().splitlines() == ["run"]


def test_overall_timeout_kills_process_group_and_releases_lock(rpc_harness):
    state, _, _, agent, env, invoke = rpc_harness
    child_pid = state.parent / "child-pid"
    agent.write_text(
        "#!/bin/sh\n(trap '' TERM; sleep 20 & printf '%s\\n' \"$!\" > \"$CHILD_PID.grandchild\"; wait) &\n"
        "printf '%s\\n' \"$!\" > \"$CHILD_PID\"\nwait\n",
        encoding="utf-8",
    )
    agent.chmod(0o755)
    env["CHILD_PID"] = str(child_pid)
    env["SMART_UPGRADE_SCAN_TIMEOUT"] = "1"
    result = invoke("scan")
    assert result["scan_status"] == "failed"
    assert result["error_code"] == "SCAN_TIMEOUT"
    assert result["dispatch_allowed"] is False
    assert result["flash_ready"] is False
    assert not (state / "scan.lock").exists()
    pid = int(child_pid.read_text().strip())
    assert_process_stopped(pid)
    assert_process_stopped(int(child_pid.with_suffix(".grandchild").read_text()))


def process_stopped(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    # Linux can retain an orphan as a zombie until PID 1 reaps it.
    stat = Path(f"/proc/{pid}/stat")
    if sys.platform.startswith("linux"):
        try:
            return stat.read_text().rsplit(") ", 1)[1].startswith("Z ")
        except FileNotFoundError:
            return True
    return False


def assert_process_stopped(pid):
    assert process_stopped(pid), f"scanner descendant {pid} is still running"


@pytest.mark.parametrize("runtime", ["missing", "failed"])
def test_supervisor_unavailable_releases_lock_and_allows_retry(rpc_harness, runtime):
    state, _, args_log, _, env, invoke = rpc_harness
    normal = env["SMART_UPGRADE_SETSID"]
    env["SMART_UPGRADE_SETSID"] = (
        str(state.parent / "missing-setsid") if runtime == "missing" else "/usr/bin/false"
    )
    assert invoke("scan")["error_code"] == "SCAN_RUNTIME_UNAVAILABLE"
    assert not args_log.exists()
    assert not (state / "scan.lock").exists()
    env["SMART_UPGRADE_SETSID"] = normal
    assert invoke("scan")["scan_status"] == "partial"


def test_term_during_scan_kills_children_and_releases_lock(rpc_harness):
    state, _, _, agent, env, _ = rpc_harness
    child_pid = state.parent / "term-child-pid"
    agent.write_text(
        "#!/bin/sh\nsleep 20 &\nprintf '%s\\n' \"$!\" > \"$CHILD_PID\"\nwait\n",
        encoding="utf-8",
    )
    agent.chmod(0o755)
    env["CHILD_PID"] = str(child_pid)
    process = subprocess.Popen(
        [*RPC_SHELL, str(RPC), "call", "scan"], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    )
    assert process.stdin
    process.stdin.write("{}")
    process.stdin.close()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not child_pid.exists():
        time.sleep(0.05)
    assert child_pid.exists()
    pid = int(child_pid.read_text().strip())
    process.terminate()
    process.wait(timeout=10)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process_stopped(pid):
            break
        time.sleep(0.05)
    else:
        pytest.fail("scanner child remained alive after TERM")
    assert not (state / "scan.lock").exists()


def test_rpc_rejects_any_changed_published_evidence_bytes(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("scan")
    generation = publish_analysis(state, state.parent)
    analysis = state / "analyses" / generation
    for name in (
        "system-snapshot-v1.json", "migration-plan-v1.json",
        "migration-report.md", "luci-evidence-bundle-v1.json",
    ):
        path = analysis / name
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        result = invoke("report")
        assert result["available"] is False, name
        assert result["error_code"] == "EVIDENCE_UNVERIFIED", name
        assert result.get("build_allowed", False) is False
        assert result["flash_ready"] is False
        path.write_bytes(original)


def test_rpc_rejects_changed_snapshot_bytes(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    invoke("scan")
    path = published_snapshot(state)
    original = path.read_bytes()
    path.write_bytes(original + b" ")
    result = invoke("snapshot")
    assert result["available"] is False
    assert result["error_code"] == "SNAPSHOT_UNVERIFIED"
    assert result["flash_ready"] is False
    path.unlink()
    external = state.parent / "external-snapshot.json"
    external.write_bytes(original)
    external.chmod(0o600)
    path.symlink_to(external)
    assert invoke("snapshot")["error_code"] == "SNAPSHOT_UNVERIFIED"


def test_analysis_with_same_snapshot_id_but_different_bytes_is_unavailable(rpc_harness):
    state, _, _, _, _, invoke = rpc_harness
    assert invoke("scan")["scan_status"] == "partial"
    source = state.parent / "alternate-snapshot.json"
    source.write_bytes(published_snapshot(state).read_bytes() + b"\n")
    plan_path = state.parent / "alternate-plan.json"
    plan_path.write_text(json.dumps(plan()))
    report = state.parent / "alternate-report.md"
    report.write_text("# Alternate report\n")
    bundle = state.parent / "alternate-bundle"
    create_bundle(source, plan_path, report, bundle, ROOT, producer_commit="d" * 40)
    publish_bundle(bundle, state, ROOT)
    for method in ("plan", "report"):
        result = invoke(method)
        assert result["error_code"] == "EVIDENCE_UNVERIFIED"
        assert "target_version" not in result and "build_allowed" not in result


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
