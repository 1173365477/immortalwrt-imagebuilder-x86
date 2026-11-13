# T14 secure build gateway threat model

## Scope and security objective

T14-A accepts authenticated, immutable build requests and records their
validation state. It does **not** upload evidence to GitHub, acquire a GitHub
token, dispatch a workflow, build firmware, or claim that an image is safe to
flash. A request is never dispatchable until the existing T13 verifier has
produced a trusted success result. `flash_ready` remains `false`.

The protected data flow is:

```text
OpenWrt Router Agent -> Build Gateway -> Trusted Evidence -> GitHub Actions
                              |
                         Gateway Database

Future LuCI -> Router Agent
Build Gateway -> GitHub App -> GitHub Repository / Actions
GitHub Actions -> Artifact + Provenance -> Build Gateway
```

The Router Agent, future LuCI, all client input, HTTP headers, network peers,
and mutable Git refs are untrusted. The Gateway process, its configured device
credential hashes, fixed repository identity, SQLite database, T13 verifier
code, and locally controlled evidence adapter are inside the T14-A trust
boundary. GitHub, Actions, and artifact storage are external trusted services
whose identity and returned evidence must still be verified.

## Components and trust boundaries

| Component | Trust and responsibility |
|---|---|
| OpenWrt Router Agent | Holds only a device-scoped Gateway bearer credential; never a GitHub credential. |
| LuCI (future) | Untrusted presentation layer; no direct Gateway or GitHub authority in T14-A. |
| Build Gateway | Authenticates devices, validates the request envelope, invokes the T13 verification adapter, applies the state machine, and persists atomically. |
| Gateway Database | Durable SQLite identity, idempotency, rate-limit, credential, and task state for one coordinated Gateway instance. |
| Immutable Evidence Storage | T14-A uses only a controlled local test adapter. T14-B must bind repository bytes to an immutable commit before dispatch. |
| GitHub App | T14-B only. Server-held private key mints short-lived, repository-scoped installation tokens. |
| GitHub Repository | Fixed by server configuration. Arbitrary client repositories and mutable refs are forbidden. |
| GitHub Actions | T14-B only. Must execute T13 verification and bind run identity to the accepted task. |
| Artifact / Provenance | T14-B only. Untrusted until digest, run, commit, request, and provenance bindings verify. |

## Threat analysis

| Threat | Attack entry and impact | Required mitigation | Negative test | Residual risk |
|---|---|---|---|---|
| Anonymous Gateway call | Missing credentials create or enumerate tasks. | Protected routes require an Authorization bearer credential; use a uniform external authentication error. | POST/GET without Authorization returns `AUTH_REQUIRED`. | Availability endpoints may remain public only if explicitly designated later. |
| Forged device identity | Client JSON or header claims another `device_id`. | Device identity is derived only from a server-side credential record; request models reject extra fields. | Submit `device_id` in JSON and query another device's request. | A stolen valid device credential acts as that device until revoked. |
| Gateway token leakage | Token in URL, logs, tracebacks, or database task rows permits impersonation. | Authorization is header-only; store salted scrypt hashes, redact logs, never serialize credentials in task responses. | Send a canary token through failures and assert it is absent from logs and DB task rows. | Process memory contains a presented token briefly. Host hardening remains required. |
| Replay | Captured POST creates repeated builds. | Persistent `(device_id, request_id)` uniqueness and immutable identity comparison make exact repeats idempotent. | Ten concurrent identical POSTs create one task. | T14-A creates no external build; T14-B needs dispatch-side idempotency and recovery. |
| Request parameter tampering | Digest, commit, repository, URL, package list, or status is changed to authorize other evidence. | Strict request model allows only four immutable identity fields plus `request_id`; repository is server-fixed; no URL, package list, status, or device fields exist. | Extra URL/path/status/repository and malformed digest/ref tests fail. | A syntactically valid request is not evidence of trust. |
| `request_id` collision | Same device reuses an ID for different evidence and overwrites history. | Unique constraint plus transactionally compared identity fields; conflicts return `IDEMPOTENCY_CONFLICT`. | Same ID with different digest, commit, repository, or build-input ID returns 409. | Different devices have independent namespaces by design. |
| Concurrent duplicate submission | Check-then-insert race creates multiple tasks. | `BEGIN IMMEDIATE`, database unique constraint, bounded busy timeout, and conflict re-read inside the transaction. | Ten threads submit the same request and receive one `internal_task_id`. | SQLite serializes writers and limits throughput. Multi-replica deployment is unsupported. |
| SQLite transaction race or partial write | Lock contention, disk failure, or exception leaves an incomplete task or quota record. | Atomic transactions, rollback on every exception, WAL, foreign keys, integrity errors mapped fail-closed. | Forced write failure and lock-timeout tests show no partial task. | Disk corruption requires restore from protected backup; T14-A does not provide HA. |
| Evidence commit replacement | Mutable branch/ref or wrong repository points to different bytes. | Accept exactly 40 lowercase hex SHA, fixed repository only, no ref names; T14-B must fetch by SHA and verify ancestry/content. | `main`, tags, abbreviated SHA, uppercase SHA, and arbitrary repository are rejected. | GitHub repository compromise remains an administrative trust risk. |
| Snapshot/Plan mismatch | A valid-looking envelope references internally inconsistent evidence. | Envelope validation cannot authorize a build. Only a successful T13 `verify-build-input.py` adapter result can reach `VALIDATED`. | Adapter reports mismatch/unverified and task becomes `BLOCKED`. | T14-A local adapter is not GitHub provenance; production adapter is T14-B work. |
| Untrusted URL or local path injection | Client causes SSRF or reads server files. | Build request schema contains no URL/path; extra keys are forbidden; T14-A performs no client-directed I/O. | URL and `../../` extra fields return `INVALID_REQUEST`. | T14-B evidence fetcher requires its own fixed-host and commit-bound controls. |
| Excess GitHub permission | Compromised Gateway writes code/releases or accesses other repositories. | T14-B GitHub App design: one installation, repository allowlist, metadata/contents read and Actions write only if dispatch requires it; no administration, secrets, releases, or package write. | Configuration review and permission assertion test before enabling the adapter. | GitHub Actions write can start workflows; workflow and ref policy remain critical. |
| GitHub private key or installation token leakage | Attacker gains repository API authority. | Private key only in server secret storage; short-lived installation token kept in memory, never returned, logged, or written to task records. | Canary secret log/response/database scan. | Host compromise can access in-memory credentials. Rotation and incident response are required. |
| Log leakage | Exceptions expose bearer tokens, private paths, environment data, or evidence content. | Structured allowlist logger, safe device fingerprint, stable public errors, no raw request/header/exception serialization. | Invalid auth, validation, DB failure, and conflict logs contain no canary secret. | Host runtime or reverse-proxy logs must follow the same policy. |
| Cross-device task access | One router reads another router's task status. | Every lookup is scoped by authenticated `device_id`; use indistinguishable `EVIDENCE_NOT_FOUND` externally. | Device B cannot GET device A's request. | Gateway administrators can access the database and require operational controls. |
| Restart loses state | Memory-only tasks or quotas allow replay and identity changes after restart. | SQLite stores credentials, tasks, transitions, and rate events; startup performs schema/integrity checks. | Recreate the app on the same DB and repeat POST/GET. | Ephemeral/container storage is invalid production deployment. |
| Gateway/GitHub partial success | Evidence commit succeeds but dispatch or DB update fails, causing duplicate runs. | T14-A never calls GitHub. T14-B must persist intent before each side effect, reconcile by idempotency key, and recover `DISPATCHING` records. | T14-B fault-injection around commit/dispatch boundaries. | GitHub API ambiguity requires reconciliation, not blind retry. |
| Illegal state transition | Client or race changes `FAILED` to `SUCCEEDED`, regresses status, or dispatches unverified evidence. | Server-only transition table, compare-and-swap update, immutable transition audit; T14-A states stop at `VALIDATED`, `BLOCKED`, or `FAILED`. | Illegal, repeated, concurrent, terminal, and fake client-status tests. | T14-B must extend the same transition table rather than bypass it. |
| Build success confused with flash safety | UI/API presents accepted or successful build as safe to install. | Responses explicitly expose `build_authorized=false` until verification and always `flash_ready=false`; documentation separates acceptance, validation, dispatch, build, and flash safety. | Every T14-A response asserts `flash_ready` is false and no running/succeeded state exists. | Human operators may still ignore warnings; future UI must preserve the distinction. |
| Resource exhaustion | Large bodies, rapid requests, long locks, huge identifiers, or timed-out verifier threads consume memory/DB/worker time. | ASGI body-size middleware, Pydantic length limits, persistent per-device fixed-window quota, SQLite busy timeout, child-process timeout, and a dedicated bounded validation pool whose slot is retained until the worker really exits. | Oversize, rate-limit, quota, lock-timeout, and blocking-adapter tests prove later requests cannot create an unbounded verification queue. | Python cannot kill a hung thread; a permanently hung trusted adapter can consume its bounded pool and requires operator recovery. |
| Proxy spoofing | Attacker supplies `X-Forwarded-For` to evade controls or forge audit origin. | Authorization and rate limiting are device-based. T14-A does not use forwarded headers for trust decisions; production proxy allowlist is deployment work. | Spoofed forwarded headers do not change identity or quota. | Network-layer abuse still needs a trusted reverse proxy/WAF. |
| Expired or revoked credential | Old token continues to create/read tasks. | Credential rows include expiry and revocation; both are checked on every protected request. | Expired and revoked token tests return uniform auth failure. | Clock integrity matters; production hosts require reliable time. |
| Expired task resubmission | Reusing an old request silently creates a second task. | Task identity remains reserved after expiry; repeat returns `REQUEST_EXPIRED`, never a new task. | Expire a row, restart, and repeat POST. | Retention/purge policy must archive identity tombstones before deleting details. |

## Authentication lifecycle

Each router receives a random high-entropy Gateway bearer token over an
out-of-band enrollment channel. The Gateway stores only a credential ID,
device ID, random salt, scrypt hash, expiry, and revocation time.
Rotation creates a new credential, overlaps it briefly if policy permits, and
then revokes the old credential. Loss recovery revokes every credential for the
device before issuing a replacement. Production requires HTTPS; the app refuses
to treat forwarded headers as proof that TLS was used.

The GitHub App is a separate server identity. T14-B may mint a short-lived
installation token only for the configured repository. The private key belongs
in a server secret manager or protected file descriptor. Neither the key nor
the installation token may enter HTTP responses, SQLite task records, router
storage, or logs.

## Evidence and recovery boundary

T14-A's evidence adapter accepts only a locally controlled test verdict and
invokes the existing T13 verification interface. Request schema validity alone
leaves the task unverified. In production, T14-B must:

1. persist the request and intent;
2. create or locate immutable evidence at the fixed repository and commit;
3. fetch by full commit SHA, never a branch;
4. execute T13 verification against those exact bytes and trusted code;
5. persist the verifier result atomically;
6. persist dispatch intent before calling GitHub;
7. reconcile ambiguous GitHub responses by the durable idempotency key.

If a GitHub commit exists but workflow dispatch has not happened, recovery must
reuse that exact commit and task. It must not create new evidence or silently
select a newer ref.

## Deployment limitations

SQLite is a durable single-instance MVP, not a coordinated multi-replica data
store. WAL improves local concurrency but does not make network filesystems or
multiple independent Gateway replicas safe. Production deployment needs a
persistent local volume, backups, file permissions, integrity monitoring,
trusted TLS termination, and exactly one coordinated writer instance. A later
multi-replica design must move uniqueness, quotas, and state transitions to a
shared transactional database.
