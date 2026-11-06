# Sprint 2A acceptance report

Branch: `feature/smart-upgrade-sprint2a`  
Base: `main` at `97259ea688ff911bf2c8e86d32b77826e7732b24`  
Draft PR: <https://github.com/1173365477/immortalwrt-imagebuilder-x86/pull/22>

## Acceptance matrix

| Task | Result | Evidence |
|---|---|---|
| T10 / #12 | PASS | Distribution-separated stable release discovery; authenticated profile, image, ImageBuilder and official indexes; frozen version/source/digests; size/time limits and TTL cache; future-version and negative fixtures. |
| T11 / #13 | PASS | Versioned OpenClash/Lucky/Nikki rules; exact upstream, format, architecture, dependency and digest evidence; unsafe archive/URL rejection; build and first-boot hash checks; unknown providers unresolved. |
| T12 / #14 | PASS | Direct snapshot input; explicit blocked legacy adapter; every installed package receives keep/replace/skip/review/block; strict identity/package/dependency/conflict/digest gates; legacy outputs preserved; storage remains a flash-stage risk; `flash_ready=false`. |

## Safety properties and blockers

- Release and package data are read-only HTTPS metadata. A missing release,
  ImageBuilder, target/profile/image, checksum entry or matching architecture
  blocks the plan.
- A same-name OPKG/APK package is not treated as migration compatibility.
- Incomplete top-level intent, unknown origin, unresolved required third-party
  assets, missing dependencies, conflicts, and stale snapshot/release/index
  digests block the build gate.
- Build permission, build execution status, compatibility validation and flash
  readiness are separate fields. No firmware build is started by Sprint 2A.
- Docker/storage uncertainty is retained in `storage_risk.flash_blockers` and
  never converted into disk-upgrade safety.
- Bundled third-party APKs are still installed with `--allow-untrusted` because
  this project does not own upstream signing keys. The mitigated path requires
  a GitHub-provided asset digest, records extracted APK digests, and verifies
  the exact manifest again at first boot. A locally signed repository remains
  a future hardening option; the limitation is not hidden.

## Compatibility outputs

The new generator writes `migration-plan-v1.json` and continues to write
`packages-official.txt`, `packages-thirdparty.txt`, `packages-missing.txt`,
`packages-replaced.txt`, `packages-skipped.txt`, `package-decisions.json` and
`migration-report.md`. Existing ImageBuilder CLI and `workflow_dispatch`
inputs are unchanged.

## Sprint 2B interfaces (T13–T14)

T13 should accept only a schema-valid plan whose `plan_id`, `digest`, frozen
release `resolution_digest`, official `official_index_digest`, exact source
Snapshot identity, and `build_allowed=true` all verify. It should pin repository
Commit SHA, workflow run/attempt, ImageBuilder digest, package manifests and
firmware Artifact digest into `build-result-v1`; it must not reinterpret the
plan or resolve `latest` again.

T14's gateway should accept a plan ID/digest and immutable repository ref,
verify strict gate state before dispatch, and return a request ID without
holding router credentials. It must distinguish request acceptance,
`build_status`, `compatibility_validated`, and permanent `flash_ready=false`.
No token belongs on the router and no gateway may trigger flashing.

## Verification

The repository CI runs Python compilation, YAML parsing, actionlint,
ShellCheck, all historical tests, new positive/negative tests, the full offline
Snapshot-to-gate fixture, Artifact safety checks and the existing read-only
25.12.2 online index check. Final test count and latest CI run are recorded in
the PR and handoff after the Draft branch CI completes.
