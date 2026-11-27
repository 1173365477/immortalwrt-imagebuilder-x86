"""T16 server transport and LuCI result binding without a device or live Gateway."""

import importlib.machinery
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "luci-app-smart-upgrade"
CLIENT = APP / "root/usr/libexec/smart-upgrade/gateway-client"
MODEL = APP / "htdocs/luci-static/resources/smart-upgrade/remote.js"
VIEW = APP / "htdocs/luci-static/resources/view/smart-upgrade/overview.js"
BEARER = "d" * 32 + "." + "s" * 43
REF = "e" * 48
TARGET = "a" * 48
RESOLUTION = "b" * 64
SUBJECT = {
    "snapshot_id": "urn:sha256:" + "c" * 64,
    "scan_generation": "c" * 64 + "-1700000000-19",
    "snapshot_sha256": "f" * 64,
}
FLAGS = {"dispatch_allowed": False, "flash_ready": False}


@pytest.fixture
def client():
    loader = importlib.machinery.SourceFileLoader("luci_gateway_client", str(CLIENT))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def write_private(path, obj):
    path.write_text(json.dumps(obj))
    path.chmod(0o600)


@pytest.fixture
def https_gateway(tmp_path, client):
    key, certificate = tmp_path / "key.pem", tmp_path / "certificate.pem"
    config = tmp_path / "openssl.cnf"
    config.write_text(
        "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
        "[dn]\nCN=localhost\n[extensions]\nsubjectAltName=DNS:localhost\nbasicConstraints=CA:TRUE\n"
    )
    subprocess.run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-config", str(config), "-keyout", str(key), "-out", str(certificate)],
                   check=True, capture_output=True, timeout=10)
    calls = []
    reply = {"status": 200, "content_type": "application/json", "body": b"{}"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def request(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append((self.command, self.path, self.headers.get("Authorization"), raw))
            self.send_response(reply["status"])
            self.send_header("Content-Type", reply["content_type"])
            if reply.get("redirect"):
                self.send_header("Location", reply["redirect"])
            if not reply.get("unframed"):
                self.send_header("Content-Length", str(len(reply["body"])))
            self.end_headers()
            try:
                if reply.get("drip"):
                    for byte in reply["body"]:
                        self.wfile.write(bytes([byte]))
                        time.sleep(reply["drip"])
                else:
                    self.wfile.write(reply["body"])
            except OSError:
                pass

        do_GET = do_POST = request

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certificate, key)
    server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    write_private(directory / "gateway.json", {
        "url": f"https://localhost:{server.server_port}", "device_id": "device-test", "bearer": BEARER,
    })
    write_private(directory / "snapshot-ref.json", {
        "device_id": "device-test", "snapshot_ref": REF, **SUBJECT, "expires_at": int(time.time()) + 360,
    })
    client.CA_BUNDLE = str(certificate)
    try:
        yield directory, calls, reply, server.server_port
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def targets(now):
    return {**FLAGS, "targets": [{
        "target_ref": TARGET, "resolution_digest": RESOLUTION, "distribution": "immortalwrt",
        "version": "25.12.2", "target": "x86/64", "profile": "generic",
        "filesystem": "ext4", "image_type": "combined-efi", "architecture": "x86_64",
        "package_manager": "apk", "verified_at": now - 1, "expires_at": now + 300,
        "private": BEARER,
    }]}


def analysis(now):
    return {
        **FLAGS, **SUBJECT, "resolution_digest": RESOLUTION, "status": "blocked",
        "blockers": ["BOOT_MODE_UNVERIFIED"], "expires_at": now + 150,
        "package_summary": {"installed": 3, "keep": 1, "replace": 0, "skip": 1, "review": 0, "block": 1},
        "storage_risk": {"status": "partial", "docker_present": True,
                         "firmware_overwrite_risks": ["unknown"], "private": BEARER},
        "private": {"token": BEARER, "ref": REF},
    }


def requested(**overrides):
    return json.dumps({"target_ref": TARGET, **SUBJECT, "ubus_rpc_session": "1" * 32,
                       **overrides}).encode()


def test_fixed_tls_calls_and_sanitized_analysis(client, https_gateway, capsys):
    directory, calls, reply, _ = https_gateway
    now = int(time.time())
    reply["body"] = json.dumps(targets(now)).encode()
    catalog = client.invoke("targets", {}, b'{"ubus_rpc_session":"11111111111111111111111111111111"}', directory)
    assert catalog["available"] and catalog["targets"][0]["target_ref"] == TARGET
    assert calls == [("GET", "/targets", "Bearer " + BEARER, b"")]
    reply["body"] = json.dumps(analysis(now)).encode()
    result = client.invoke("analyze", SUBJECT, requested(), directory)
    assert result["available"] and result["status"] == "blocked"
    assert result["blockers"] == ["BOOT_MODE_UNVERIFIED"]
    assert result["snapshot_sha256"] == SUBJECT["snapshot_sha256"]
    assert result["flash_ready"] is result["dispatch_allowed"] is False
    assert calls[-1][:3] == ("POST", "/analysis", "Bearer " + BEARER)
    assert json.loads(calls[-1][3]) == {"snapshot_ref": REF, "target_ref": TARGET}
    assert BEARER not in json.dumps([catalog, result]) and REF not in json.dumps(result)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("defect", ["missing", "expired", "device", "id", "generation", "bytes", "file_mode", "symlink"])
def test_reference_denied_before_network(client, https_gateway, defect):
    directory, calls, _, _ = https_gateway
    path = directory / "snapshot-ref.json"
    binding = json.loads(path.read_text())
    if defect == "missing":
        path.unlink()
    elif defect == "file_mode":
        path.chmod(0o644)
    elif defect == "symlink":
        path.rename(directory / "old-ref")
        path.symlink_to("old-ref")
    else:
        key = {"expired": "expires_at", "device": "device_id", "id": "snapshot_id",
               "generation": "scan_generation", "bytes": "snapshot_sha256"}[defect]
        binding[key] = 1 if defect == "expired" else "other"
        write_private(path, binding)
    with pytest.raises(client.Unavailable, match="SNAPSHOT_REFERENCE_UNAVAILABLE"):
        client.invoke("analyze", SUBJECT, requested(), directory)
    assert not calls


@pytest.mark.parametrize("field", ["endpoint", "bearer", "snapshot_ref", "raw_body", "path"])
def test_rpc_arguments_cannot_control_gateway_request(client, https_gateway, field):
    directory, calls, _, _ = https_gateway
    with pytest.raises(client.Unavailable, match="INVALID_REQUEST"):
        client.invoke("analyze", SUBJECT, requested(**{field: "synthetic"}), directory)
    assert not calls


@pytest.mark.parametrize("fault,code", [
    ("unavailable", "GATEWAY_UNAVAILABLE"), ("redirect", "GATEWAY_UNAVAILABLE"),
    ("oversize_declared", "GATEWAY_RESPONSE_INVALID"), ("oversize_unframed", "GATEWAY_RESPONSE_INVALID"),
    ("bad_json", "GATEWAY_RESPONSE_INVALID"), ("wrong_type", "GATEWAY_RESPONSE_INVALID"),
    ("wrong_scan", "TARGET_EVIDENCE_UNAVAILABLE"), ("unsafe_flags", "GATEWAY_RESPONSE_INVALID"),
])
def test_failed_gateway_responses_are_not_relayed(client, https_gateway, fault, code):
    directory, calls, reply, port = https_gateway
    body = analysis(int(time.time()))
    if fault == "unavailable":
        reply["status"] = 503
    elif fault == "redirect":
        reply.update(status=307, redirect=f"https://localhost:{port}/elsewhere")
    elif fault.startswith("oversize"):
        reply.update(body=b"x" * (client.MAX_REPLY + 1), unframed=fault.endswith("unframed"))
    elif fault == "bad_json":
        reply["body"] = b'{"available":true,"available":false}'
    elif fault == "wrong_type":
        reply.update(content_type="text/plain", body=json.dumps(body).encode())
    else:
        if fault == "wrong_scan":
            body["snapshot_sha256"] = "0" * 64
        else:
            body["dispatch_allowed"] = True
        reply["body"] = json.dumps(body).encode()
    with pytest.raises(client.Unavailable, match=code) as error:
        client.invoke("analyze", SUBJECT, requested(), directory)
    assert BEARER not in str(error.value) and REF not in str(error.value)
    assert len(calls) == 1


def test_hostname_mismatch_rejects_tls_before_sending_bearer(client, https_gateway):
    directory, calls, _, port = https_gateway
    settings = json.loads((directory / "gateway.json").read_text())
    settings["url"] = f"https://127.0.0.1:{port}"
    write_private(directory / "gateway.json", settings)
    with pytest.raises(ssl.SSLCertVerificationError):
        client.invoke("targets", {}, b"{}", directory)
    assert calls == []


def test_changed_local_scan_is_rejected_before_network(client, https_gateway):
    directory, calls, _, _ = https_gateway
    with pytest.raises(client.Unavailable, match="SNAPSHOT_REFERENCE_UNAVAILABLE"):
        client.invoke("analyze", SUBJECT, requested(scan_generation="b" * 64 + "-1700000000-19"), directory)
    assert not calls


def test_wall_clock_budget_includes_slow_continuous_response(client, https_gateway):
    directory, calls, reply, _ = https_gateway
    reply.update(drip=0.04, body=b" " * 60)
    code = (
        "import runpy,sys;"
        "p=runpy.run_path(sys.argv[1]);m=p['main'];"
        "m.__globals__.update(DIRECTORY=sys.argv[2],CA_BUNDLE=sys.argv[3],DEADLINE=0.7);"
        "sys.argv=['gateway-client','targets'];m()"
    )
    run = subprocess.run([sys.executable, "-I", "-c", code, str(CLIENT), str(directory), client.CA_BUNDLE],
                         input="{}", capture_output=True, text=True, check=True, timeout=2)
    output = json.loads(run.stdout)
    assert output["error_code"] == "GATEWAY_UNAVAILABLE"
    assert BEARER not in run.stdout + run.stderr and REF not in run.stdout + run.stderr
    assert len(calls) == 1


def run_node(program, payload):
    result = subprocess.run(["node", "-e", program, str(MODEL), str(VIEW)], input=json.dumps(payload),
                            capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("event", ["match", "new_scan", "same_id_new_bytes", "target", "refresh",
                                   "out_of_order", "expired_response", "expired_display", "revoked"])
def test_luci_result_binding(event):
    program = r"""
const fs = require('fs'), assert = require('node:assert/strict');
const { event, scan, catalog, analysis } = JSON.parse(fs.readFileSync(0));
const { AnalysisDisplay } = new Function('baseclass', fs.readFileSync(process.argv[1], 'utf8'))({extend:x=>x});
const state = new AnalysisDisplay(), target = catalog.targets[0], now = 1700000000;
state.select(target);
const ticket = state.capture(state.begin(), scan, now);
assert(ticket);
let current = scan, response = analysis;
if (event === 'new_scan')
  current = {...scan, scan_generation: scan.scan_generation + '1'};
else if (event === 'same_id_new_bytes')
  current = {...scan, snapshot_sha256: '0'.repeat(64)};
else if (event === 'target')
  state.select({...target, target_ref:'1'.repeat(48)});
else if (event === 'refresh')
  state.select(null);
else if (event === 'revoked')
  response = {available:false,error_code:'RPC_UNAVAILABLE'};
else if (event === 'out_of_order') {
  const latest = state.capture(state.begin(), scan, now);
  assert.equal(state.accept(latest, {...analysis, status:'eligible'}, scan, now), true);
  assert.equal(state.accept(ticket, analysis, scan, now), false);
  process.stdout.write(JSON.stringify(state.result.status));
  return;
} else if (event === 'expired_response')
  response = {...analysis, expires_at:now};
const accepted = state.accept(ticket, response, current, now);
if (event === 'expired_display') {
  assert.equal(accepted, true);
  assert.equal(state.expire(response.expires_at), true);
}
process.stdout.write(JSON.stringify(state.result && state.result.status));
"""
    assert run_node(f"(function(){{{program}}})();", {
        "event": event, "scan": {**SUBJECT, "available": True, "integrity_status": "verified"},
        "catalog": targets(1700000000), "analysis": {**analysis(1700000000), "available": True},
    }) == {"match": "blocked", "out_of_order": "eligible"}.get(event)


@pytest.mark.parametrize("denied", [False, True])
def test_panel_shows_bound_result_and_reports_rpc_denial(denied):
    program = r"""
const fs = require('fs'), assert = require('node:assert/strict');
const { denied, scan, catalog, analysis } = JSON.parse(fs.readFileSync(0));
const remote = new Function('baseclass', fs.readFileSync(process.argv[1], 'utf8'))({extend:x=>x});
const original = fs.readFileSync(process.argv[2], 'utf8');
const rpcCalls = [];
const rpc = { declare: spec => (...args) => {
  rpcCalls.push({method: spec.method, args});
  if (spec.method === 'targets') return Promise.resolve({available:true,...catalog});
  if (spec.method === 'snapshot_identity') return Promise.resolve(scan);
  if (spec.method === 'analyze') return denied ? Promise.reject(new Error('Access denied')) : Promise.resolve(analysis);
  throw new Error('Unexpected RPC method');
}};
const elements = [];
function E(tag, attributes, children) {
  const el = {
    tag, attributes, children: Array.isArray(children) ? children : children == null ? [] : [children],
    events: {}, value: '', textContent: '',
    appendChild(child) { this.children.push(child); },
    replaceChildren(...children) { this.children = children; this.textContent = ''; },
    addEventListener(event, fn) { this.events[event] = fn; },
  };
  elements.push(el);
  return el;
}
const window = { clearTimeout() {}, setTimeout() {} };
const panel = new Function('rpc','model','remote','E','_','window',
  original.substring(0, original.indexOf('\nreturn view.extend')) + '\nreturn remotePanel();'
)(rpc,{display:String},remote,E,x=>x,window);
(async function() {
  await new Promise(resolve => setImmediate(resolve));
  const select = elements.find(el => el.tag === 'select'), buttons = elements.filter(el => el.tag === 'button');
  select.value = catalog.targets[0].target_ref;
  select.events.change();
  assert.equal(buttons[1].disabled, false);
  await buttons[1].events.click();
  const calls = rpcCalls.filter(call => call.method === 'analyze');
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].args, [select.value, scan.snapshot_id, scan.scan_generation, scan.snapshot_sha256]);
  const result = elements.find(el => el.attributes.role === 'status');
  process.stdout.write(JSON.stringify(denied ? result.textContent : result.children[0].children[0]));
})().catch(e => { console.error(e); process.exit(1); });
"""
    now = int(time.time())
    result = run_node(program, {
        "denied": denied, "scan": {**SUBJECT, "available": True, "integrity_status": "verified"},
        "catalog": targets(now), "analysis": {**analysis(now), "available": True},
    })
    assert result == ("Unavailable — check Gateway access and permissions." if denied else "Blocked")
