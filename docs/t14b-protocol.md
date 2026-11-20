# T14-B immutable dispatch protocol

## Status and deployment gate

This protocol is implemented against test substitutes. Production dispatch
remains disabled until the repository owner provisions the GitHub App and the
immutable evidence-ref policy below. `flash_ready` is always `false`.

## Four commit identities

- `trusted_code_commit_sha` is the reviewed code containing the workflow and
  T13 verifier. `build-input-v1.json` stores it as `build.git_commit_sha`.
- `evidence_commit_sha` is the later immutable commit containing the request
  evidence. It must descend from the trusted code commit and may change only
  `evidence/requests/<request_id>/` relative to that ancestor.
- `gateway_task_id` is a globally unique, server-generated identifier derived
  from the internal task UUID. It is independent of the device-controlled
  `request_id` and is persisted before dispatch.
- `dispatch_ref` is a server-controlled dedicated ref named from
  `gateway_task_id` that must resolve exactly
  to the evidence commit immediately before dispatch. Clients cannot provide it.
- `workflow_runtime_sha` is the run's `head_sha` and must equal the evidence
  commit.

This avoids an impossible self-reference: evidence does not contain its own
commit SHA. The Build Input binds an already-existing reviewed code commit; the
Gateway separately binds the later evidence commit and proves that all
non-evidence code bytes are unchanged.

Before dispatch the resolver proves both commits exist in the fixed repository,
ancestry is correct, every changed path is below the request directory, the
isolated workspace contains no unsafe paths/types or excessive data, and T13
validates the exact request using the trusted code commit. The workflow repeats
the ancestry/protected-tree check before T13 or ImageBuilder.

After dispatch the correlator validates repository, workflow ID,
`workflow_dispatch` event, run ID, attempt, head SHA, ref, Gateway task ID, and
Build Input digest. Run ID is globally unique in the fixed repository and may
bind only one intent. Ref movement or ambiguous candidates becomes `DISPATCH_UNKNOWN`;
it is never automatically redispatched.

## Evidence admission and owner deployment condition

The Gateway has no Contents Write permission. Evidence must enter through a
separately reviewed process on a dedicated `evidence/<request_id>` ref.
Deployment requires an owner-managed ruleset that prevents force-push/deletion,
restricts updates to the evidence automation identity, requires an approved
code ancestor, and rejects changes outside the request evidence directory.

Automatic evidence publication or Contents Write requires a separate threat
review and explicit owner approval; it is not part of T14-B.

## GitHub App permissions

The configured installation and repository are fixed server-side. Permissions
are exactly Metadata Read, Contents Read, and Actions Write. No Contents Write,
Workflows Write, Administration, Secrets, Releases, Packages, Deployments,
Pull Requests Write, or Issues Write is used. The private key remains in server
secret storage. Short-lived installation tokens are refreshed before expiry,
held only in memory, and never stored, returned, or logged.

## Durable dispatch and recovery

SQLite stores one intent per task before any GitHub call. Immutable identity
includes the server Gateway task ID plus request/digest/evidence/code/workflow/ref.
The Gateway task ID flows through the dispatch Ref, Workflow input, Run Name,
concurrency group, artifact name, and provenance. States are `PENDING`,
`DISPATCHING`, `UNKNOWN`, `BOUND`, and `FAILED`. A worker claims an intent
atomically; another worker cannot dispatch it.

Task expiry is part of the same `BEGIN IMMEDIATE` transaction that creates an
intent or changes `PENDING` to `DISPATCHING`; `now >= expires_at` fails closed.
After token acquisition and Ref resolution, the Gateway performs one final
transactional deadline authorization immediately before calling GitHub. No
queue wait, token operation, network read, or other blocking operation occurs
between that authorization and the Dispatch invocation. A task proven expired
at this point is atomically recorded as task `FAILED` and intent `FAILED` with
`REQUEST_EXPIRED`, preserving its immutable evidence and audit history without
calling GitHub or returning to `PENDING`.

Timeout, connection loss, an ambiguous dispatch response, or a local failure
after the external call becomes `UNKNOWN`. Dispatch itself is never retried.
Read-only operations use bounded exponential backoff and `Retry-After` for 429;
exhaustion preserves the current durable state. Reconciliation accepts only one
exact candidate. Zero or multiple matches require manual review and never cause
a blind retry. On startup a never-claimed `PENDING` intent may be claimed once;
an interrupted `DISPATCHING` intent first becomes `UNKNOWN`. Unknown and bound
runs are then reconciled without creating another workflow run. Synchronous
GitHub adapters run outside the event loop in a bounded executor. If an HTTP
deadline expires, the worker slot remains reserved until the underlying call
finishes; Python cannot forcibly cancel that thread, so production transports
must also enforce finite socket timeouts.

Startup recovery handles each intent independently. It may read an expired
task through an internal audit-only database path, but expiry remains enforced
for every client API. An expired record is neither claimed nor polled and can
never cause automatic redispatch; its task, intent, external identity, Run
binding, timestamps, and failure state remain durable for manual reconciliation.
A corrupt record is deferred without preventing later records from recovering.

## Run, artifact, and log trust

The REST mapping is pinned to GitHub API version `2026-03-10`. Dispatch accepts
the documented `200` response with `workflow_run_id`; the compatibility path
also treats an older `204` response as identity-unknown and performs exact
correlation. The injected transport must send
`Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2026-03-10`.
It must enforce TLS, finite timeouts, bounded bodies, and redirect host policy.
Those requirements are exercised through a fake transport; no production
network transport or real dispatch is enabled in this sprint.

GitHub `success` moves a task to `VERIFYING_ARTIFACT`, not `SUCCEEDED`. Artifact
ZIP inspection rejects traversal, duplicate names, symlinks, special files,
excessive member/byte/ratio limits, missing provenance, and extra firmware.
The verifier validates provenance schema and digest and recomputes firmware
SHA256/size while binding repository, runtime SHA, request, Build Input,
Snapshot, Plan, Gateway task ID, run ID, and attempt. Artifact bytes are spooled
with a hard download bound, firmware hashing is streamed, and verification is
bounded globally and mutually exclusive per task. The per-task lock registry
counts active callers and waiters under one registry guard; an entry is removed
only when its reference count reaches zero, so a newly arriving verifier cannot
create a second lock while an older waiter still exists.

Project provenance is an internal evidence record, not a GitHub cryptographic
Artifact Attestation. This implementation does not claim independent signature
verification. Verified artifacts remain `flash_ready=false`.

Artifact download adapters must return repository, run ID, attempt, expiry,
size, and a seekable bounded stream. The Gateway rejects expired or mismatched envelopes before opening the
ZIP, then applies archive limits and verifies `build-provenance-v2.json` plus
the firmware bytes. A failed integrity check is terminal `ARTIFACT_FAILED`.

Logs are fetched from GitHub's attempt-specific ZIP endpoint only after exact
Run/attempt identity validation. Archive, member, expansion, compression ratio,
line and output limits apply; only safe UTF-8 `.txt` members are accepted.
Control characters, secret fields and standalone GitHub token patterns are
redacted. Raw archives, environment dumps and arbitrary binary output are not
exposed.

## API boundary

`POST /builds` keeps the T14-A schema. Server-side dispatch additionally needs
an explicit switch and configured adapters. Exact replay returns the existing
task and never creates another intent. Task, artifact, and log reads remain
device-scoped. Clients cannot provide repository URLs, refs, workflows, GitHub
tokens, package lists, run IDs, state, or dispatch inputs.

