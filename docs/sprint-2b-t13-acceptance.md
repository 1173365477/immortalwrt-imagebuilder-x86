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
| Real apk-tools semantics | PASS | Pinned Alpine 3.23.8 rootfs, apk-tools 3.0.9 version and APKv3 metadata integration test |
| No-flash boundary | PASS | Schemas and provenance require `flash_ready=false` |
| Durable cross-run idempotency | OUT OF SCOPE | T14 Gateway responsibility; concurrency alone is documented as insufficient |

## Validation record

The new focused suite covers positive verification/provenance plus wrong commit,
strict false, Plan/Snapshot/index/package/files tampering, unsafe paths, storage
unknown, wrong comparator policy and proof that an invalid request cannot reach
network or make. CI additionally runs actionlint, ShellCheck, all schemas, the
full existing pytest suite and a real apk-tools comparator.

No firmware build, router access, flash, reboot, partition change, Issue closure
or merge is part of this implementation.

## Review handoff (2026-11-09)

- Branch: `feature/smart-upgrade-sprint2b-t13`
- Draft PR: [#23](https://github.com/1173365477/immortalwrt-imagebuilder-x86/pull/23)
- Validated implementation HEAD: `73878df1775cc975e94d3d78d3e865254d225558`
- Push CI: [42587624604](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42587624604) — SUCCESS
- PR CI: [42587633021](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42587633021) — SUCCESS
- pytest: 187 passed, 1 real-apk case skipped in the ordinary suite; the pinned
  Alpine/apk-tools job then ran that case against the real binary: 1 passed.
- actionlint 1.7.7, ShellCheck, Python/YAML syntax, existing fixture regression,
  official 25.12.2 online index validation, version-mismatch rejection and
  strict unresolved-package rejection all passed.

Remaining review condition: independent review of PR #23. Durable cross-run
idempotency remains explicitly assigned to T14 and is not represented as a T13
PASS. There is no unresolved T13 HIGH blocker in the worker validation.

Worker conclusion: **READY FOR INDEPENDENT REVIEW**. Keep the PR Draft until an
independent reviewer accepts the final HEAD. Do not merge or close Issue #15.

## Independent review remediation

Review baseline: `8c37669873a5684ad221b35fee0777fd727a7f3f`.

### A — chroot APK metadata access

Confirmed. The original wrapper forwarded a host absolute path unchanged to
`chroot`, where that path does not exist. The Linux integration test records
`Original unmapped chroot path correctly failed`. A restricted wrapper now
copies only a regular, non-symlink, size-limited APK from configured roots into
a private chroot ingress, permits only version comparison and JSON `adbdump`,
and cleans the ingress. The integration runs pinned apk-tools 3.0.9 (the first
pinned runtime in this workflow that actually provides `adbdump`), creates a
valid APKv3 fixture with the real `apk mkpkg`, and requires
`inspect_apk_metadata()` to obtain its exact name, x86_64 architecture, version
and `musl` dependency. apk-tools 2.14 was rejected as a test runtime because it
does not implement `adbdump` and therefore cannot validate APKv3 metadata.

### B — third-party Provider completeness

Confirmed. A canonical, schema-valid Plan with a third-party OpenClash `keep`,
an empty Build Input Provider list and no bundled APK returned:

```text
ORIGINAL RESULT: ACCEPTED 2c0380d735d7d889cf910dbadac407bbf57c0613e1649ed97b7e7fdeb339e5f2
thirdparty declarations: 0
bundled APKs: []
```

The gate now requires exact Plan/Build-Input Provider-set equality, exact Plan
evidence-digest binding, a bound APK for every retained third-party target
package, and exact declared/bundled APK-byte equality. The negative test also
invokes the real `build-image.sh` entry and proves neither curl nor make runs.

### C — trusted base packages

Confirmed. Adding official-index package `nano`, declaring it in
`build.base_packages`, and recomputing every affected digest returned:

```text
ORIGINAL RESULT: ACCEPTED ee2995ed46b8d1708c8724f0cdc69cea385838382334c0192add06b905a5b8cb
untrusted base_packages: ['nano']
```

The verifier now requires exact ordered equality with the protected,
version-controlled `config/base-packages.txt`. The request creator refuses an
alternate base-package file. The negative test passes self-consistent modified
index, capabilities, Plan, package-list, config and Build Input digests through
the real build entry and proves the gate stops before network or make.

Post-remediation focused local result: 54 passed, 1 real-apk CI test skipped.

Final Linux validation at remediation HEAD
`311f8ea0bd3b30505f555d014fbe3e583a382ea4`:

- Push CI [42746129555](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42746129555) — SUCCESS.
- PR CI [42746134953](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42746134953) — SUCCESS.
- Ordinary suite: 190 passed, 1 real-apk case skipped; the separate pinned
  Alpine 3.23.8 / apk-tools 3.0.9 integration then passed that case.
- actionlint 1.7.7, ShellCheck, Python/YAML/JSON syntax and schemas, official
  25.12.2 index validation, target-version mismatch rejection and strict
  unresolved-package rejection passed.

This record is superseded only by the documentation-only final evidence commit
and its matching successful Push/PR runs. PR #23 remains Draft; Issue #15
remains open. No firmware build or router operation was performed.
