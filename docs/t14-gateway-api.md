# T14 secure build gateway

## Status and boundary

T14-A established the authenticated persistent request registry and evidence
validation state machine. T14-B adds a production-disabled GitHub REST mapping,
durable Dispatch Intent, run reconciliation, artifact verification and bounded
log proxy using injected transports and test substitutes. No production GitHub
App, key, network transport or evidence admission process is configured, and
the test suite never dispatches the real workflow. Firmware is never made
flash-ready.

The implementation uses FastAPI/Pydantic for strict HTTP validation and the
Python `sqlite3` module for a small single-instance transactional store. API
tests use HTTPX2, the maintained continuation selected by the current FastAPI
test client. This matches the repository's Python stack without adding an ORM,
message queue, container platform, or in-memory source of truth.

## Local project structure

```text
gateway/
  app.py          FastAPI routes, HTTPS/body/rate boundaries and safe responses
  database.py     credentials, SQLite schema, transactions and persistent quotas
  evidence.py     default-deny and controlled T13 verifier adapters
  resolver.py     fixed-repository immutable checkout boundary
  github.py       GitHub App and versioned REST mapping boundaries
  service.py      durable dispatch/reconciliation orchestration
  artifacts.py    bounded ZIP, provenance and firmware verification
  errors.py       stable public error codes
  logging.py      structured allowlist audit logging
  models.py       strict request/response models
  state.py        server-owned T14-A/T14-B state machine
  main.py         uvicorn entry point
scripts/
  gateway-credentials.py  offline issue/revoke administrator utility
```

## Authentication

Every protected request uses:

```http
Authorization: Bearer <credential-id>.<random-secret>
```

The server derives `device_id` from its credential table. A JSON field, query
parameter, forwarded header, or IP address cannot select a device identity.
The database contains a random salt and scrypt hash, never the original token.
Credentials have an expiry and revocation timestamp.

Issue a test or enrolled-device credential from a trusted administrator host:

```sh
python scripts/gateway-credentials.py \
  --database work/gateway/gateway.db \
  issue --device-id router-001 --ttl-seconds 7776000
```

The token is printed once and must be delivered out of band. Rotate by issuing
a replacement and then revoking the public credential ID:

```sh
python scripts/gateway-credentials.py \
  --database work/gateway/gateway.db \
  revoke --credential-id <32-hex-character-id>
```

If a device credential is lost, revoke all credentials associated with that
device before enrolling a replacement:

```sh
python scripts/gateway-credentials.py \
  --database work/gateway/gateway.db \
  revoke-device --device-id router-001
```

Production requires HTTPS. The
`GATEWAY_ALLOW_HTTP=true` switch exists only for controlled local testing and
does not trust `X-Forwarded-For` or `X-Forwarded-Proto`.

## POST /builds

The only accepted JSON fields are:

```json
{
  "request_id": "request-001",
  "build_input_id": "urn:sha256:<64-lowercase-hex>",
  "build_input_digest": "<64-lowercase-hex>",
  "repository": "1173365477/immortalwrt-imagebuilder-x86",
  "evidence_commit_sha": "<40-lowercase-hex>"
}
```

`build_input_id` must contain the exact supplied digest. The repository must
equal the server-configured repository. The evidence identity must be a full
commit SHA, not `main`, a tag, an abbreviation, a URL, or a local path. Extra
fields are rejected, including client-selected packages, status, `device_id`,
download URLs, and GitHub credentials.

A new request returns HTTP 201. An exact idempotent replay returns HTTP 200 and
the original `internal_task_id`. Reuse of the same `(device_id, request_id)`
with any changed immutable field returns HTTP 409 `IDEMPOTENCY_CONFLICT`.

The response distinguishes every security stage:

```json
{
  "request_id": "request-001",
  "internal_task_id": "<uuid>",
  "status": "BLOCKED",
  "build_input_id": "urn:sha256:<digest>",
  "build_input_digest": "<digest>",
  "repository": "1173365477/immortalwrt-imagebuilder-x86",
  "evidence_commit_sha": "<sha>",
  "created_at": "<UTC timestamp>",
  "updated_at": "<UTC timestamp>",
  "expires_at": "<UTC timestamp>",
  "failure_code": "EVIDENCE_UNVERIFIED",
  "evidence_verified": false,
  "dispatch_allowed": false,
  "flash_ready": false,
  "idempotent_replay": false
}
```

T14-A's default verifier always produces `BLOCKED/EVIDENCE_UNVERIFIED`. A
controlled adapter may produce `VALIDATED` only after the T13 verifier succeeds
against exact local checkout bytes. Even then `dispatch_allowed` and
`flash_ready` remain false.

## GET /builds/{request_id}

The authenticated device may read only its own request namespace. A task that
belongs to another device is returned as `EVIDENCE_NOT_FOUND`, preventing
cross-device enumeration. Responses omit credential hashes, raw failure
details, GitHub credentials, and database-only fields.

T14-B adds device-scoped artifact and log reads as described below.

## Error contract

Errors always use:

```json
{"error":{"code":"INVALID_REQUEST","message":"The request is invalid."}}
```

Stable codes are `AUTH_REQUIRED`, `AUTH_INVALID`, `AUTH_EXPIRED`,
`ACCESS_DENIED`, `INVALID_REQUEST`, `INVALID_REPOSITORY`, `INVALID_COMMIT`,
`IDEMPOTENCY_CONFLICT`, `EVIDENCE_NOT_FOUND`, `EVIDENCE_UNVERIFIED`,
`BUILD_BLOCKED`, `RATE_LIMITED`, `REQUEST_EXPIRED`, `STORAGE_UNAVAILABLE`,
`INTERNAL_ERROR`, `TLS_REQUIRED`, and `REQUEST_TOO_LARGE`. Public responses do
not contain stack traces, local paths, raw exceptions, or secrets.

## Database schema and transaction boundary

SQLite stores:

- `device_credentials`: public credential ID, device ID, salt/hash, expiry and revocation;
- `build_tasks`: immutable identity, status, timestamps, failure classification,
  and reserved GitHub run fields;
- `task_transitions`: append-only state transition audit;
- `rate_limits`: persistent per-device fixed-window counters;
- `dispatch_intents`: immutable dispatch identity, claim/reconciliation state,
  run binding, target and evidence digests;
- `verified_artifacts`: allowlisted metadata only after byte/provenance checks;
- `gateway_meta`: schema version.

`UNIQUE(device_id, request_id)` is the authoritative idempotency constraint.
Creation uses `BEGIN IMMEDIATE`, compares every immutable field inside the
transaction, and rolls back on conflict/failure. State changes use the same
transaction discipline plus a versioned compare-and-swap. WAL, foreign keys,
full synchronous writes, bounded busy timeout, and startup integrity checks are
enabled. Lock timeouts, corruption, unwritable storage, and transaction errors
fail closed as `STORAGE_UNAVAILABLE`.

Expired request IDs remain reserved and return `REQUEST_EXPIRED`; expiry never
silently creates a second logical task. Startup converts interrupted
`RECEIVED/VALIDATING` records to `FAILED`. T14-B additionally claims a
never-started `DISPATCH_PENDING` intent once, converts interrupted
`DISPATCHING` to `DISPATCH_UNKNOWN`, and reconciles unknown/bound external work
without blind dispatch retry.

## State machine

```text
RECEIVED -> VALIDATING -> VALIDATED
                    \-> BLOCKED
                    \-> FAILED
RECEIVED ----------------> BLOCKED / FAILED
```

Duplicate same-state writes are idempotent. T14-A treats `VALIDATED`, `BLOCKED`,
and `FAILED` as terminal and rejects transitions to `DISPATCH_PENDING`,
`RUNNING`, `SUCCEEDED`, or any other T14-B state. Clients have no status-update
endpoint.

## Limits and deployment

Defaults are a 16 KiB request body, 30 requests per device per 60 seconds, 100
unexpired tasks per device, seven-day task expiry, 30-second verification
timeout, and one-second SQLite lock timeout. Rate counters and task quota are
database-backed; client IP and forwarded headers are not security identities.

SQLite is supported only for one coordinated Gateway instance using a durable
local volume. It is not multi-replica coordination and must not be placed on an
unsafe network filesystem. Production additionally needs filesystem
permissions, backups, monitoring, trusted TLS termination, and a reverse proxy
whose forwarded-header policy is explicitly configured.

Run locally after installing dependencies:

```sh
python -m pip install -r requirements.txt
GATEWAY_DATABASE=work/gateway/gateway.db \
  uvicorn gateway.main:app --host 127.0.0.1 --port 8000
```

Do not set `GATEWAY_ALLOW_HTTP=true` outside a controlled local test.

## GitHub App design for T14-B

No GitHub App or production key exists in T14-A. T14-B should install one App
only on the configured repository and mint short-lived installation tokens in
server memory. Initial minimum permissions are:

| Permission | Level | Purpose |
|---|---|---|
| Metadata | Read | Required repository identity metadata. |
| Contents | Read | Fetch the exact evidence/code commit for verification. |
| Actions | Write | Dispatch the single allowlisted workflow; also permits required Actions reads. |

Administration, repository hooks, secrets, deployments, releases, packages,
issues, pull requests, and contents write are not required for dispatch and
must remain disabled. If T14-B decides the Gateway itself must create evidence
commits, that is a separate security design requiring a narrowly controlled
contents-write boundary and review; it is not authorized by T14-A.

The private key belongs only in server secret storage. Installation tokens must
never be returned to routers, written to task rows, or printed in logs. API
requests cannot select another repository or installation.

## T13 reuse and T14-B integration contract

`SubprocessT13Verifier` demonstrates the required adapter boundary:

1. use a server-controlled checkout;
2. require its exact HEAD to equal `evidence_commit_sha`;
3. derive `evidence/requests/<validated-request-id>/build-input-v1.json`
   internally;
4. invoke `scripts/verify-build-input.py` with the fixed repository and commit;
5. before deleting the temporary output, strictly parse `context.json`, reject
   duplicate keys, and bind `request_id`, `build_input_id`,
   `build_input_digest`, `runtime_commit_sha`, and `repository` to the request
   and server configuration; and
6. treat any missing, malformed, oversized, incomplete, timed-out, nonzero, or
   mismatched result as untrusted.

A zero exit status alone is never a trust result. Python cannot forcibly cancel
a verifier thread that is already running, so the Gateway uses a dedicated,
bounded validation executor. A timed-out call retains its slot until the worker
actually exits; later calls cannot create an unbounded validation queue. The
subprocess adapter also enforces a child-process timeout. Future trusted
adapters must retain a finite internal timeout and must not spawn detached work.

T14-B must add immutable evidence retrieval, GitHub App token acquisition,
dispatch intent, `request_id -> run_id -> run_attempt`, run polling, artifact
and provenance verification, and ambiguous-side-effect recovery. It must not
reimplement `build_allowed`, rewrite Snapshot/Plan data, accept arbitrary URLs,
or dispatch before this adapter records a trusted verification result.

## T14-B mock integration contract

T14-B retains the `POST /builds` request body unchanged. Dispatch is enabled
only by the server-side `GATEWAY_DISPATCH_ENABLED` switch and injected trusted
adapters. The client cannot select a GitHub installation, token, workflow,
repository, ref, run, URL, target version, strictness, or task state.

The public task response may additionally contain `trusted_code_commit_sha`,
`github_run_id`, and `github_run_attempt`. Its state can advance through
`DISPATCH_PENDING`, `DISPATCHING`, `DISPATCH_UNKNOWN`, `QUEUED`, `RUNNING`,
`VERIFYING_ARTIFACT`, `SUCCEEDED`, `BUILD_FAILED`, and `ARTIFACT_FAILED`.
GitHub success alone stops at `VERIFYING_ARTIFACT`; only a verified provenance
and firmware byte stream can reach `SUCCEEDED`.

`GET /builds/{request_id}/artifacts` returns only allowlisted metadata for an
already verified artifact: request, filename, recomputed SHA256/size, run ID,
attempt, `verified=true`, and `flash_ready=false`. It does not expose an
unverified archive or router filesystem path. `GET /builds/{request_id}/logs`
returns bounded, control-character-cleaned, redacted lines and a truncation
flag. Both routes use the authenticated device namespace.

The production GitHub transport, App private-key issuer, TLS/reverse-proxy
deployment, and protected evidence-ref admission process are deployment
dependencies. The checked-in implementation uses protocols and controlled
test substitutes; dispatch remains disabled unless an operator supplies all
dependencies. No route performs flash, reboot, partition, or router
configuration operations.

## Target catalog and offline analysis

Both routes use TLS and the existing device Bearer credential, per-route
device rate limits and the Gateway error envelope. Successful responses have
`Cache-Control: no-store`, `dispatch_allowed: false` and `flash_ready: false`.
The optional `GATEWAY_ANALYSIS_ENABLED=false` policy disables both routes.
Keep Gateway and reverse-proxy access logs from recording headers, query
strings and bodies. Use Uvicorn's `--no-access-log` if no sanitized access log
is configured.

### GET /targets

Send an empty request with no query. The response has a `targets` array.
Each entry contains an opaque `target_ref`, `distribution`, `version`,
`target`, `profile`, `filesystem`, `image_type`, `architecture`,
`package_manager`, `resolution_digest`, `verified_at` and `expires_at`.
Timestamps are Unix seconds. Initial server policy permits ImmortalWrt
25.12.2, x86/64, generic, ext4 and combined-efi. A catalog entry represents
verified release evidence. The analysis route determines device compatibility.

Outside the HTTP process, schedule `python scripts/gateway-analysis.py
refresh-targets` to run more frequently than the default one-hour catalog
TTL. Configure the location with `GATEWAY_TARGET_CATALOG` or use
`target-catalog.json` beside the Gateway database. `--ttl-seconds` sets the TTL.
One refresh process per catalog holds an OS lock. A 90-second default
worker wall-clock limit, 64 requests, at most three redirects per resource
and 64 MiB of aggregate metadata constrain refresh. TLS uses system CAs
and every redirect stays on the fixed official host and release paths.
The resolver verifies profiles and index bytes against the official
`sha256sums` fetched over HTTPS, checks the image and ImageBuilder digest
entries and requires successful nonempty HTTPS HEAD responses for those
artifacts. Refresh does not download their bodies or verify signatures.
The manifest is trusted via HTTPS. Any eventual firmware consumption still
requires verification of actual bytes under the build controls.

Successful refresh atomically replaces the private catalog and rotates
`target_ref`. Failed refresh leaves a still-fresh prior entry usable until
its original deadline. No fresh verified catalog results in 503. After an
entry is replaced, clients must fetch the new catalog and repeat analysis
with its new reference.

### Trusted Snapshot admission

There is no HTTP upload. A trusted collector must independently bind the
enrolled device, observe collection completion with a trusted clock, and
sign the exact redacted Snapshot bytes and scan generation. Configure the
operator CLI with `GATEWAY_COLLECTOR_KEY_FILE`, an owner-only regular file
containing exactly 32 raw key bytes provisioned out of band. Then invoke
`python scripts/gateway-analysis.py admit-snapshot --snapshot SNAPSHOT
--collector-record RECORD`. It returns an opaque `snapshot_ref`. Without a
configured key and valid record, admission is unavailable. A production
collector, key provisioning and authenticated device-to-collector transport
are deployment prerequisites.

The record has exactly `version` (integer 1), `device_id`, `snapshot_id`,
`snapshot_sha256` (SHA256 of the actual file bytes), `scan_generation`,
`collected_at` (integer Unix seconds from the collector) and `mac`. The
MAC is lowercase HMAC-SHA256 over the bytes
`smart-upgrade/collector/v1` followed by a NUL byte and the other fields
encoded as UTF-8 JSON with sorted keys and no separator whitespace.
`scan_generation` uses LuCI's digest-epoch-PID form. Its digest prefix
must match the Snapshot identity, and its embedded time alone carries no
freshness authority. The collector must sign only device-bound observations
that it verified, never caller-declared metadata or arbitrary uploads.

Admission enforces Snapshot v1 Schema, the `evidence-sha256-v2` identity
format, a 2 MiB limit, bounded structure and the remote value allowlists.
The remote subset rejects local mode, extension fields, arbitrary
diagnostics, non-redacted storage and unsafe values. Some otherwise valid
local Snapshots require a future collector-side privacy policy revision.
Current partial scanner evidence remains admissible where its fields fit
the remote policy and produces a blocked strict analysis.

Expiry is enforced from trusted collection time (default at most 24 hours,
`admit-snapshot --ttl-seconds`). An identical repeat returns the original
reference and expiry. Same-device reuse of bytes or scan generation with
different claims conflicts. A distinct generation and byte digest can
share the same Snapshot ID, so clients must compare all three identities.
Schedule `python scripts/gateway-analysis.py purge-expired` to remove
expired payloads and receipts while retaining permanent reference, digest
and generation tombstones. Cleanup is logical deletion. Protect SQLite,
its WAL and backups as evidence storage and preserve tombstones across
restore. The service requires a reliable clock and persistent database.

### POST /analysis

Send `Content-Type: application/json` and exactly
`{"snapshot_ref":"…","target_ref":"…"}`. There is no query. Both references
are opaque 48-character lowercase hexadecimal values. The 16 KiB request
limit applies. Extra and duplicate keys are rejected.

Analysis uses the admitted Snapshot and frozen target capabilities and
index with fixed checkout rules, calling the strict planner offline.
The response includes `analysis_id`, `status` (`eligible` or `blocked`),
`blockers` (stable codes), `package_summary` (counts),
`storage_risk` (status, Docker presence and overwrite risk enums),
`snapshot_id`, `snapshot_sha256`, `scan_generation`, `resolution_digest`,
`plan_id`, `plan_digest` and `expires_at`. Internal receipts additionally
bind the device, references, index, exact rule bytes and analyzer digest.
The lifetime is the earliest of Snapshot expiry, target expiry and one
hour from analysis start by default (`GATEWAY_ANALYSIS_TTL_SECONDS`).

| HTTP | Meaning |
|---|---|
| 200 | Trusted evidence was analyzed. `blocked` includes incompatible or incomplete evidence. |
| 401 | Missing, expired, invalid or revoked credentials. |
| 403 | TLS or server policy denied the request. |
| 404 | An unknown or other device's Snapshot reference, or an unknown target reference. |
| 409 | Owned evidence bytes and identity differ from the admitted evidence. |
| 410 | Owned Snapshot or current target evidence has expired. |
| 413, 422, 429 | Body limit, invalid request envelope or device rate limit. |
| 503 | Catalog, storage or analysis capacity unavailable. |

Blocker codes include `STRICT_PLAN_BLOCKED`, `SNAPSHOT_INCOMPLETE`,
`SYSTEM_IDENTITY_UNVERIFIED`, `BOOT_MODE_UNVERIFIED`,
`TARGET_COMPATIBILITY_UNVERIFIED`, `PACKAGE_EVIDENCE_UNVERIFIED` and
`THIRDPARTY_EVIDENCE_UNVERIFIED`. No trusted third-party binary evidence is
admitted through this interface. Package names, paths, raw planner
diagnostics and Snapshot contents stay inside the service. At most two
catalog or analysis jobs run simultaneously by default, with a ten-second
HTTP deadline and capacity held until the worker returns.

`eligible` is a migration analysis outcome. It creates no build task,
dispatch intent, T13 Build Input or GitHub state. Existing `POST /builds`
and T13 gates still apply independently. In T16, capture Snapshot ID,
generation and byte SHA256 before requesting analysis. Display a response
only if all three still match the active scan and the response is fresh.
Discard a delayed reply after a scan or target change. Implement read-only
display first. Device-bound immutable build evidence admission, explicit
dispatch authorization, task recovery, logs and verified artifact delivery
are separate steps.
