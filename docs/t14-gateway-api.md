# T14-A secure build gateway foundation

## Status and boundary

T14-A is an authenticated, persistent request registry and evidence-validation
state machine. It deliberately has no GitHub API client and cannot upload
evidence, dispatch Actions, report a build as running/succeeded, download an
artifact, or make firmware flash-ready. T14-B must extend this foundation
without bypassing the T13 verifier.

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
  errors.py       stable public error codes
  logging.py      structured allowlist audit logging
  models.py       strict request/response models
  state.py        server-owned T14-A state machine
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

The following future routes are documented but intentionally return 404 in
T14-A; there is no fake successful implementation:

- `GET /targets`
- `POST /analysis`
- `GET /builds/{request_id}/artifacts`
- `GET /builds/{request_id}/logs`

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
`RECEIVED/VALIDATING` records to `FAILED`. T14-B must replace this simple
fail-closed recovery with GitHub-side reconciliation for dispatch states.

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
