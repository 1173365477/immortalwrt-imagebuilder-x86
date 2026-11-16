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
- `dispatch_ref` is a server-configured dedicated ref that must resolve exactly
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
`workflow_dispatch` event, run ID, attempt, head SHA, ref, request ID, and Build
Input digest. Ref movement or ambiguous candidates becomes `DISPATCH_UNKNOWN`;
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
includes request/digest/evidence/code/workflow/ref. States are `PENDING`,
`DISPATCHING`, `UNKNOWN`, `BOUND`, and `FAILED`. A worker claims an intent
atomically; another worker cannot dispatch it.

Timeout, connection loss, 429, 5xx, missing run details, or a local failure
after the external call becomes `UNKNOWN`. Reconciliation accepts only one
exact candidate. Zero or multiple matches require manual review and never cause
a blind retry. Startup preserves externally ambiguous states for reconciliation.

## Run, artifact, and log trust

GitHub `success` moves a task to `VERIFYING_ARTIFACT`, not `SUCCEEDED`. Artifact
ZIP inspection rejects traversal, duplicate names, symlinks, special files,
excessive member/byte/ratio limits, missing provenance, and extra firmware.
The verifier validates provenance schema and digest and recomputes firmware
SHA256/size while binding repository, runtime SHA, request, Build Input,
Snapshot, Plan, run ID, and attempt.

Project provenance is an internal evidence record, not a GitHub cryptographic
Artifact Attestation. This implementation does not claim independent signature
verification. Verified artifacts remain `flash_ready=false`.

Logs are device-scoped, bounded UTF-8 text produced through a field/line
allowlist with control characters removed. Raw archives, environment dumps,
tokens, and arbitrary binary output are not exposed.

## API boundary

`POST /builds` keeps the T14-A schema. Server-side dispatch additionally needs
an explicit switch and configured adapters. Exact replay returns the existing
task and never creates another intent. Task, artifact, and log reads remain
device-scoped. Clients cannot provide repository URLs, refs, workflows, GitHub
tokens, package lists, run IDs, state, or dispatch inputs.

