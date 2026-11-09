# Sprint 2B / T13 acceptance

## Baseline audit

Baseline `8933c5d0272162e8a2c88ef98d8b9722669f9e66` allowed `build.yml` to
re-run legacy parsing and resolve mutable `latest`, indexes and Provider assets.
With `strict_mode=false`, unresolved packages/providers could continue to
`build-image.sh`. That script consumed mutable `generated/final-packages.txt`
and `files/` and called ImageBuilder without reading a System Snapshot or
Migration Plan. The workflow had `contents: write` and could publish a Release.

T13 removes those build paths. Legacy inputs remain present, but a request
without repository-bound immutable evidence fails before any download.

## Acceptance matrix

| Requirement | Status | Evidence |
|---|---|---|
| Immutable versioned Build Input | PASS | Schema, creator, canonical digest and file/tree digests |
| Snapshot/Plan/Release/index binding | PASS | Independent schema, ID, canonical digest and byte checks |
| Provider/APK binding | PASS | Versioned rule, target, status digest, asset set, APK metadata and bytes |
| Trusted code identity | PASS | Frozen ancestor commit plus protected-tree no-change proof |
| Package-list authorization | PASS | Exact keep/replace + baseline equality; extras and omissions fail |
| Strict unified build gate | PASS | Workflow preflight and `build-image.sh`; legacy/non-strict bypass removed |
| TOCTOU resistance | PASS | Private staged bytes and immediate pre-make re-hash |
| Provenance | PASS | Actual firmware SHA/size and complete evidence/run trace |
| Real apk-tools semantics | PASS | Pinned Alpine 3.22.8 rootfs, apk-tools 2.14.12 integration test |
| No-flash boundary | PASS | Schemas and provenance require `flash_ready=false` |
| Durable cross-run idempotency | OUT OF SCOPE | T14 Gateway responsibility; concurrency alone is documented as insufficient |

## Validation record

The new focused suite covers positive verification/provenance plus wrong commit,
strict false, Plan/Snapshot/index/package/files tampering, unsafe paths, storage
unknown, wrong comparator policy and proof that an invalid request cannot reach
network or make. CI additionally runs actionlint, ShellCheck, all schemas, the
full existing pytest suite and a real apk-tools comparator.

No firmware build, router access, flash, reboot, partition change, Issue closure
or merge is part of this implementation. This report must be updated with final
HEAD, test count, CI links and any remaining blocker before review handoff.
