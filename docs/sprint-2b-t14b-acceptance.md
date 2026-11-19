# Sprint 2B T14-B acceptance report

## Scope and result

T14-B implements the testable Secure GitHub Actions Build Integration on
`feature/smart-upgrade-sprint2b-t14b`. It uses a Mock GitHub API, local Git
fixtures, SQLite, and synthetic artifacts only. It does not create a production
GitHub App, dispatch the repository workflow, build firmware, access a router,
or claim flash safety. `flash_ready=false` remains invariant.

## Acceptance matrix

| Item | Status | Evidence |
|---|---|---|
| B01 commit/ref protocol and threat model | PASS | Four distinct identities, ancestry and protected-tree checks are documented and exercised by a two-commit fixture. |
| B02 GitHub App least privilege | PASS (adapter) | Fixed installation/repository, exact Metadata Read / Contents Read / Actions Write permission set, expiry refresh, memory-only token and canary scans. Production issuer is intentionally not configured. |
| B03 immutable evidence resolver | PASS (controlled fetcher) | Full commit checkout, fixed repository, bounded files/bytes, unsafe type rejection, duplicate-safe JSON, T13 output identity binding. |
| B04 durable dispatch intent | PASS | SQLite unique intent, server-generated globally unique `gateway_task_id`, transaction-before-side-effect, atomic worker claim, globally unique GitHub Run binding, persistent identity, transition audit, concurrent replay tests. |
| B05 workflow dispatch and run binding | PASS (Mock API) | The Gateway identity is bound through Ref, Workflow input, Run Name, concurrency group, artifact name and provenance. Exact repository/workflow/event/ref/SHA/Gateway identity/digest/attempt checks prevent cross-device Run reuse for both explicit and legacy dispatch responses. No production dispatch occurred. |
| B06 state and recovery | PASS | Fail-closed transition table; startup distinguishes never-claimed `PENDING` from ambiguous `DISPATCHING`; unknown dispatch is reconciled without redispatch. Recovery isolates each record, retains expired task/intent audit identity without network activity or redispatch, and continues after expired or corrupt records. |
| B07 run polling | PASS | Queued/running/terminal mapping, attempt pinning, no state regression, bounded read retry/backoff, persisted reconciliation time and request quotas. |
| B08 artifact/provenance | PASS (synthetic ZIP) | Bounded streamed download and firmware hashing, reference-counted per-task lock entries and bounded verification concurrency; expiry/envelope, ZIP traversal/type/duplicate/size/ratio, v2 schema/digest, Gateway/run/request/Snapshot/Plan identity, firmware SHA256/size and `flash_ready=false` checks. |
| B09 API | PASS | Idempotent POST and device-scoped task/artifact/log GET routes. `/targets` and `/analysis` remain documented as not implemented. |
| B10 log safety | PASS | Attempt-specific GitHub log ZIP handling; archive/member/expanded/output bounds; path, type, duplicate, binary and UTF-8 checks; control removal plus secret-field and standalone GitHub-token redaction. Raw archives are not returned. |
| B11 regression | PASS | 304 tests collected after final remediation. Linux CI: 303 passed and 1 skipped; the separate pinned real apk-tools integration passed. actionlint, ShellCheck, YAML/Python/Schema checks, online index validation and strict negative gates passed. Local non-platform-specific regression: 263 passed and 1 skipped; macOS-only BSD `awk` failures remain an existing Linux-targeted fixture limitation. |

Final re-review remediation CI evidence: <https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/44464449591>.

## Security proofs covered by tests

1. An untrusted T13 verdict cannot create an intent or dispatch.
2. Replayed and twenty concurrent identical POST requests produce one task,
   one intent, and at most one dispatch call.
3. A lost dispatch response enters `DISPATCH_UNKNOWN`; the call is not retried.
4. Another device cannot read task, artifact, or log data.
5. Run ID and attempt are bound to the fixed repository, workflow, ref,
   evidence/runtime commit, request, and Build Input digest.
6. Success is withheld until the downloaded firmware and v2 provenance are
   independently checked.
7. Installation-token canaries do not enter SQLite or API responses.
8. API and provenance schemas require `flash_ready=false`.
9. Tests inject only mocks and local fixtures; there is no production side
   effect path enabled by default.
10. The commit-bound resolver invokes the existing T13 verifier and binds its
    structured output; exit code zero alone is insufficient.
11. Two devices using the same `request_id`, with equal or different Build
    Input digests, receive different server-generated Gateway identities and
    cannot bind the same GitHub Run under either 200 or legacy 204 responses.
12. Slow synchronous GitHub adapters execute in a bounded worker pool. A timed
    out call keeps its capacity reservation until the underlying operation
    ends, and durable dispatch claiming prevents replay from redispatching it.
13. An expired recoverable task cannot abort startup recovery or trigger a new
    dispatch. Its durable task and intent identities remain stored for audit,
    while later corrupt and healthy records are independently deferred or
    recovered across service restarts.
14. Every active Artifact verifier and waiter registers against one
    reference-counted lock entry before waiting. Cleanup occurs only after the
    last registered user exits, including a failed verifier followed by two
    concurrent waiters; all callers observe one terminal task state.

## Workflow and provenance compatibility

The existing workflow inputs remain present. T14-B adds the server-generated
`gateway_task_id` without re-enabling legacy build bypasses. Runtime code is the evidence
commit, while the Build Input binds its reviewed code ancestor; the workflow
repeats ancestry and changed-path checks. Provenance v1 is not silently changed:
new builds emit the separately versioned `build-provenance-v2.json` schema with
Gateway task, trusted-code, evidence, runtime, run, and attempt identities.

## Deployment conditions and remaining risk

Before production enablement, the repository owner must:

- provision a repository-scoped GitHub App with exactly Metadata Read,
  Contents Read, and Actions Write;
- provide a secret-manager-backed App JWT/installation-token issuer;
- create an owner-controlled, non-force-push, non-deletable evidence-ref
  admission process that permits changes only below the request directory;
- supply a production GitHub REST transport with finite request timeouts and
  validate the selected API version;
- deploy one coordinated Gateway writer on durable local SQLite storage behind
  trusted TLS termination, backups, monitoring, and credential rotation; and
- decide whether GitHub Artifact Attestations are required. T14-B verifies
  internal project provenance, not an independent GitHub cryptographic
  attestation.

The synchronous adapter boundary is isolated from the application event loop
by a bounded executor and timeout/capacity gate. Python threads cannot be
forcibly cancelled; after an HTTP timeout the underlying bounded operation may
finish in the background while its slot remains occupied and durable intent
state prevents redispatch. A production transport must still provide finite
socket/connect/read timeouts so shutdown latency is bounded. Evidence publication,
Contents Write, multi-replica coordination, T14-C, automatic flashing, reboot,
partitioning, and router configuration are outside this sprint.

Issue #16 must remain open and the pull request must remain Draft until an
independent security review confirms these boundaries.
