# T13 immutable build protocol

## Trust and digest model

`build-input-v1.json` is the only supported firmware build request. JSON digests
use UTF-8, recursively sorted keys and separators `,` and `:` with no
insignificant whitespace. `build_input_id` and `digest` are excluded from their
own digest. This is the same canonical JSON convention used by Migration Plan.

Snapshot retains its existing evidence digest semantics. The Build Input binds
both the Snapshot ID/evidence digest and SHA-256 of the exact JSON file. A
Migration Plan is schema-validated and its canonical digest is recomputed. The
official index is bound by canonical digest and file SHA-256. The files tree is
the canonical digest of sorted `{path, sha256}` rows; symlinks are forbidden.

SHA-256 proves byte integrity, not origin. Trust roots are: reviewed repository
history; the frozen build-code commit; official HTTPS Release/index checksum
evidence produced by the Release Resolver; versioned provider rules; GitHub
Release/Asset identities authenticated by `fetch-thirdparty.py`; and the APK
metadata and dependency evidence stored by that flow. Build-time verification
does not turn an arbitrary self-consistent status file into trusted evidence.
For every selected Provider it re-fetches the frozen Release ID and complete
policy-matched asset set (it never reselects `latest`), verifies upstream asset
digests, re-extracts and inspects APK metadata, and compares those bytes with
the bundled APKs. Network, metadata or dependency uncertainty fails closed.

## Creating a request

`scripts/create-build-input.py` copies, but never edits or completes, the
reviewed Snapshot, Plan and indexes into a new request directory. It derives the
package list only from keep/replace decisions plus the versioned baseline and
records the exact overlay tree. It refuses to overwrite an existing request.

The `git_commit_sha` is the reviewed T13 build-code commit that exists before
the evidence-only request commit. This avoids an impossible self-referential
commit hash. At runtime the verifier requires that code commit to be an ancestor
of `GITHUB_SHA` and proves that scripts, schemas, config, build workflow and
requirements did not change between them. The evidence-only commit is recorded
as the runtime commit in provenance.

Example (does not build firmware):

```sh
python scripts/create-build-input.py \
  --request-id request-001 \
  --snapshot generated/system-snapshot-v1.json \
  --plan generated/migration-plan-v1.json \
  --release-capabilities generated/release-capabilities.json \
  --official-index generated/official-package-index.json \
  --thirdparty-status generated/thirdparty-status.json \
  --files files --filesystem ext4 \
  --repository 1173365477/immortalwrt-imagebuilder-x86 \
  --commit "$(git rev-parse HEAD)" \
  --created-at 2026-11-09T00:00:00Z \
  --output evidence/requests/request-001
```

Commit that new directory without changing protected build code, then dispatch
with `request_id`, the exact `snapshot_ref`, and frozen `target_version`.

## Gate and TOCTOU controls

GitHub limits a dispatch form to 10 inputs, so the original nine inputs remain
unchanged in `build-legacy.yml`; that compatibility entry is read-only guidance
and has no checkout, verifier, network or ImageBuilder step. The T13 workflow
has `contents: read`, checks out exactly `github.sha` without
persisted credentials, rejects legacy-only requests and disables Release
publishing. `verify-build-input.py` validates every identity, digest and safety
binding. Package and files inputs are copied into a private temporary stage and
re-hashed immediately before `make image`. ImageBuilder is downloaded from the
frozen official HTTPS URL and checked against its pinned SHA-256. Failed gates
never invoke curl or make and never upload firmware.

The workflow performs an early offline structural preflight. The only supported
ImageBuilder entry, `build-image.sh`, always performs the full frozen-upstream
Provider revalidation before its first ImageBuilder download. The explicit
offline mode is only a duplicate integrity recheck and is not a build authority.

Concurrency groups reduce duplicate simultaneous runs. They are not durable
cross-run idempotency; T14 must implement persistent request/digest conflict
handling.

The pinned comparator and APKv3 metadata inspector are apk-tools 3.0.9 from
Alpine 3.23.8. CI verifies the
official minirootfs SHA-256 and executes real `apk version -t` cases. A Build
Input with another comparator version is rejected.

The apk-tools process runs in that pinned Alpine chroot. Host paths are not
visible inside a chroot, so `apk-chroot-wrapper.sh` accepts only the two version
commands and JSON `adbdump`. For `adbdump`, it resolves a regular non-symlink
APK under an explicit allowed root, enforces a 512 MiB limit, copies it into a
per-call mode-0700 ingress directory, makes the copy read-only and passes only
the chroot-local path to apk. The ingress is deleted after inspection. CI first
proves the original unmapped host path fails, then uses the pinned real
`apk mkpkg` implementation to create a valid APKv3 fixture and inspects it
through this mapping. Production revalidation also fixes
`TMPDIR` to a dedicated runner directory and permits only that directory plus
the checked-out immutable evidence tree; it does not expose general host paths.

The verifier also enforces bidirectional package completeness. Every Migration
Plan third-party keep/replace decision must name exactly one declared Provider,
bind that Provider evidence digest, and have its target package among the
actual frozen APKs. Extra Providers, missing Providers/APKs and orphan bundled
APKs fail. `build.base_packages` must exactly equal the reviewed
`config/base-packages.txt`; being present in the official index is not authority
to extend the baseline.

## Provenance and safety states

After the expected image exists, `generate-build-provenance.py` re-runs the
input verifier and hashes the actual artifact bytes. Provenance records request,
Snapshot, Plan, input, Release/index, Provider assets, runtime commit, workflow
run/attempt, ImageBuilder and firmware identity.

`build_allowed=true` means the evidence permits GitHub to run ImageBuilder.
`build_status=succeeded` means ImageBuilder produced the expected file.
`compatibility_validated=false` remains false because a build is not device or
firmware compatibility testing. `flash_ready=false` is permanent in MVP v1.

## T14 interface

The future Gateway accepts only `{request_id, build_input_id,
build_input_digest, repository, evidence_commit_sha}`. It must authenticate,
rate-limit and apply a persistent idempotency key over request ID plus digest;
the same request with a different digest is a conflict. It may return workflow
run state and artifact/provenance identities, but must not accept arbitrary
URLs, package lists, refs or GitHub write tokens from a router. It never flashes,
reboots or changes partitions.
