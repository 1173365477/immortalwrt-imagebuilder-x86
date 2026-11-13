# Sprint 2B / T14-A Acceptance

## Scope and status

T14-A provides a persistent, fail-closed foundation for authenticated build
requests. It deliberately cannot dispatch GitHub Actions, produce firmware, or
declare an image safe to flash. Every public task response fixes
`dispatch_allowed` and `flash_ready` to `false`.

Branch: `feature/smart-upgrade-sprint2b-t14a`

Base: `beda3d175545df4abb6a920af9460284e7af1cee`

Issue #16 remains open. The pull request must remain Draft pending independent
review.

## Acceptance matrix

| Requirement | Result | Evidence |
| --- | --- | --- |
| Threat model and trust boundaries | PASS | `docs/t14-gateway-threat-model.md` covers entry points, impact, mitigations, negative tests, and residual risk. |
| Per-device authentication | PASS | Random bearer credentials are stored only as salted scrypt hashes; expiry, rotation, single-credential revocation, and device-wide revocation are supported. |
| HTTPS production prerequisite | PASS | HTTP is rejected by default; proxy forwarding headers are not trusted to override the observed scheme. |
| Fixed immutable request identity | PASS | Strict Pydantic models bind build input ID to digest and accept only the configured repository and a full 40-character commit. |
| T13 verifier reuse | PASS | A controlled-checkout adapter calls `verify-build-input.py`; the production-safe default rejects all evidence when no trusted adapter is configured. |
| Persistent idempotency | PASS | SQLite unique constraint plus `BEGIN IMMEDIATE` makes `(device_id, request_id)` atomic across processes using the same database. Immutable-field conflicts return 409. |
| State machine | PASS | Legal T14-A transitions are enforced and persisted with a transition journal. Restarted incomplete validations fail closed. |
| Device isolation | PASS | Device identity comes only from the authenticated credential and scopes all task reads and idempotency keys. |
| Resource controls | PASS | Persistent per-device rate limits, task quota, body-size limit, request limits, validation timeout, and task expiry are enforced. |
| Storage failure handling | PASS | Lock, write, initialization, integrity, and permission failures are mapped to a fail-closed storage error. |
| Safe logging and errors | PASS | Audit logs use an allowlist and hashed device identifier. Public errors omit paths, tracebacks, raw requests, and credentials. |
| GitHub App design | PASS (design only) | The API document defines repository scoping, minimum permissions, short-lived installation tokens, and server-only key handling. No GitHub credential or API call is implemented. |
| T14-B endpoints | NOT IMPLEMENTED (expected) | Targets, analysis, dispatch, artifacts, and logs are contract-only and return no false success response. |
| Firmware build and router integration | NOT IMPLEMENTED (expected) | Explicitly outside T14-A. No firmware workflow, router, package installation, reboot, flash, or partition action is performed. |

## Security regression coverage

The Gateway tests cover anonymous, invalid, expired, and revoked credentials;
cross-device reads; forged device and state fields; arbitrary repositories,
URLs, paths, and mutable refs; exact replay and identity conflicts; ten-way
concurrent replay; restart persistence; illegal and concurrent transitions;
database locks, corruption, write rollback, and restart recovery; persistent
rate limiting and quota; request-size and validation timeouts; credential and
log redaction; and controlled T13 adapter success and failure.

The existing T13 and earlier Sprint suites remain part of the unchanged CI
test command. CI also compiles the `gateway` package and scripts before pytest.

## Database and deployment boundary

SQLite is a persistent single-instance MVP. WAL, foreign keys, full synchronous
writes, database integrity checks, file mode `0600`, unique constraints, and
write transactions are enabled. Multiple workers sharing the same local file
can serialize writes, but uncoordinated replicas, a network filesystem, and
multi-region deployment are not supported. T14-B must adopt an appropriately
coordinated data store before claiming those deployment modes.

Expired request identifiers remain reserved and cannot be rebound to different
evidence. Rate-limit counters and task identities survive process restart. A
crash during evidence validation is recovered to `FAILED`; T14-B will require
reconciliation for partial GitHub-side success.

## T14-B integration contract

T14-B may add dispatch only after a task is `VALIDATED`. It must:

1. retrieve and freeze evidence through a server-controlled repository path;
2. rerun the T13 verifier against the exact commit and build input digest;
3. obtain a short-lived installation token for the one configured repository;
4. atomically reserve dispatch before calling GitHub and reconcile ambiguous
   outcomes without creating a second run;
5. persist and validate `run_id` plus `run_attempt` against the request identity;
6. verify artifact provenance and bytes before exposing an artifact result;
7. proxy only allowlisted, redacted log fields; and
8. keep build success, compatibility validation, and flash safety separate.

Client-supplied URLs, repositories, workflow names, package lists, run IDs,
states, and GitHub credentials remain forbidden. T14-B must add no transition
that can make `flash_ready=true`.

## Known limitations

- No real GitHub App, installation token, repository write, workflow dispatch,
  polling, artifact retrieval, or provenance query exists yet.
- The default evidence verifier intentionally blocks every request. Deployment
  must explicitly supply a trusted evidence adapter.
- There is no LuCI or real-router integration.
- Credential issuance is an offline administrator operation; recovery means
  revoking the old credential and issuing a new one over a separate trusted
  channel.
- SQLite is not presented as an uncoordinated multi-replica solution.
- `flash_ready=false` is permanent for this MVP.

