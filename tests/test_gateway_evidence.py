from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from gateway.database import GatewayStore
from gateway.errors import ErrorCode, GatewayError
from gateway.evidence import RejectingEvidenceVerifier, SubprocessT13Verifier
from gateway.models import BuildRequest


REPOSITORY = "1173365477/immortalwrt-imagebuilder-x86"
DIGEST = "a" * 64


def make_checkout(tmp_path: Path, verifier_exit: int = 0):
    checkout = tmp_path / "checkout"
    (checkout / "scripts").mkdir(parents=True)
    (checkout / "scripts/verify-build-input.py").write_text(
        "import sys\nraise SystemExit(%d)\n" % verifier_exit
    )
    (checkout / "evidence/requests/request-001").mkdir(parents=True)
    (checkout / "evidence/requests/request-001/build-input-v1.json").write_text("{}")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=checkout, check=True)
    subprocess.run(["git", "config", "user.name", "Gateway Test"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "."], cwd=checkout, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=checkout, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=checkout, text=True, capture_output=True, check=True
    ).stdout.strip()
    return checkout, commit


def request(commit: str):
    return BuildRequest(
        request_id="request-001",
        build_input_id=f"urn:sha256:{DIGEST}",
        build_input_digest=DIGEST,
        repository=REPOSITORY,
        evidence_commit_sha=commit,
    )


def test_rejecting_verifier_never_treats_schema_as_trust():
    verdict = RejectingEvidenceVerifier().verify(request("b" * 40))
    assert verdict.trusted is False
    assert verdict.failure_code == ErrorCode.EVIDENCE_UNVERIFIED


def test_controlled_t13_adapter_binds_exact_checkout_commit_and_path(tmp_path):
    checkout, commit = make_checkout(tmp_path)
    verifier = SubprocessT13Verifier(checkout, REPOSITORY)
    assert verifier.verify(request(commit)).trusted is True

    wrong = verifier.verify(request("b" * 40))
    assert wrong.trusted is False
    assert wrong.failure_code == ErrorCode.EVIDENCE_NOT_FOUND


def test_controlled_t13_adapter_rejects_symlink_and_verifier_failure(tmp_path):
    checkout, commit = make_checkout(tmp_path, verifier_exit=2)
    verifier = SubprocessT13Verifier(checkout, REPOSITORY)
    blocked = verifier.verify(request(commit))
    assert blocked.trusted is False
    assert blocked.failure_code == ErrorCode.BUILD_BLOCKED

    evidence = checkout / "evidence/requests/request-001/build-input-v1.json"
    evidence.unlink()
    evidence.symlink_to("../../../../scripts/verify-build-input.py")
    missing = verifier.verify(request(commit))
    assert missing.trusted is False
    assert missing.failure_code == ErrorCode.EVIDENCE_NOT_FOUND


def test_credential_admin_cli_issues_once_and_revokes(tmp_path):
    database = tmp_path / "gateway.db"
    result = subprocess.run(
        [
            sys.executable, "scripts/gateway-credentials.py", "--database", str(database),
            "issue", "--device-id", "router-a", "--ttl-seconds", "3600",
        ],
        text=True, capture_output=True, check=True,
    )
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    token = values["token"]
    credential_id = values["credential_id"]
    store = GatewayStore(database)
    assert store.authenticate(token).device_id == "router-a"

    subprocess.run(
        [
            sys.executable, "scripts/gateway-credentials.py", "--database", str(database),
            "revoke", "--credential-id", credential_id,
        ],
        text=True, capture_output=True, check=True,
    )
    with pytest.raises(GatewayError) as raised:
        store.authenticate(token)
    assert raised.value.code == ErrorCode.AUTH_INVALID
