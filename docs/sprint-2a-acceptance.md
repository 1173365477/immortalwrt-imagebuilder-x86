# Sprint 2A acceptance report

Branch: `feature/smart-upgrade-sprint2a`  
Base: `main` at `97259ea688ff911bf2c8e86d32b77826e7732b24`  
Draft PR: <https://github.com/1173365477/immortalwrt-imagebuilder-x86/pull/22>

## Acceptance matrix

| Task | Result | Evidence |
|---|---|---|
| T10 / #12 | PASS | Distribution-separated stable release discovery; authenticated profile, image, ImageBuilder and official indexes; frozen version/source/digests; size/time limits and TTL cache; future-version and negative fixtures. |
| T11 / #13 | PASS | Versioned OpenClash/Lucky/Nikki rules; exact upstream, format, architecture, dependency and digest evidence; target-bound compatibility status; unsafe archive/URL rejection; build and first-boot hash checks; unknown providers unresolved. |
| T12 / #14 | PASS | Direct snapshot input; explicit blocked legacy adapter; every installed package receives exactly one keep/replace/skip/review/block decision; third-party checks precede dependency omission; policy-proven exclusions only; strict identity/package/dependency/conflict/digest gates; legacy outputs preserved; storage remains a flash-stage risk; `flash_ready=false`. |

## Independent re-review findings and remediation

The review at `579f7cd7cb60d05874c47bab112d5e73d5014b94`
reproduced four fail-open paths. They were not waived:

1. Third-party packages marked as dependencies/defaults could be skipped before
   provider verification. Third-party origin is now evaluated first. A
   third-party dependency is kept only with complete target-bound evidence;
   otherwise it is blocked.
2. A bare external `status=compatible` could authorize a third-party package.
   Compatible evidence now binds provider/rule/repository, target distribution,
   exact release, target/profile/architecture/package manager, frozen release
   and official-index digests, upstream asset URLs and SHA-256 values, APK
   format/hash/architecture checks, the hashes of the APK files actually
   bundled into the image, and official dependency resolution. The evidence
   object has its own canonical digest and cannot be reused for a different
   target.
3. Selected unknown providers and a missing official index could evade checks.
   Unknown selections now produce explicit `unresolved` states and fail strict
   mode. A selected provider requires a non-empty official index whose digest
   matches the frozen release; dependency absence is always checked.
4. User input `optional=true` was sufficient for exclusion. Exclusions now
   require a versioned `optional_exclusions` policy entry, reject system/network
   protected packages and third-party plugins, and reject removal when another
   installed package depends on it. Snapshot digest and source-version binding
   remain mandatory.

The final trust-boundary review also reproduced three additional weaknesses:

- A multi-APK provider could publish its first APK before a later APK failed.
  Provider output is now validated completely in same-filesystem staging and
  committed as one provider directory rename. A failed provider contributes no
  file to the image or `SHA256SUMS`, in strict and non-strict modes alike.
- Missing/failed `apk adbdump`, or missing package name, architecture, version
  or dependency metadata, could still result in compatible status. Such cases
  now resolve to `unresolved`; APK magic and SHA-256 alone do not establish
  target compatibility.
- A self-consistent evidence digest proved integrity but not origin. Before a
  compatible status can authorize a Migration Plan, the consumer now re-fetches
  the pinned GitHub release/assets, verifies GitHub asset IDs and digests,
  reproduces archive extraction when applicable, and compares the result with
  the APK bytes actually bundled. Statuses not authenticated by that trusted
  path remain blocked.

The final evidence-closure review at `ae2db7271daa3dc57784780c3566bc45137209c6`
reproduced two further validation gaps and closed both in the real Migration
Plan CLI path:

- Re-fetching a frozen GitHub Release authenticated its repository, release ID,
  asset ID and digest, but did not re-apply the versioned provider policy. The
  consumer now validates an exact configured tag when required, or retains the
  initially frozen `latest` identity, then rechecks the target-series
  declaration, architecture/series asset patterns and the complete required
  asset set. A genuine asset with the wrong provider version or pattern is
  blocked.
- Upstream SHA-256 authenticated bytes but did not prove the internal APK
  identity. Both producer and consumer now require parseable APK name,
  architecture, version and dependency metadata. The package set must exactly
  match the provider rule, architecture must match the target or be explicit
  `all`/`noarch`, and status metadata must equal the consumer's fresh parse.
  `metadata_status=unavailable` and `architecture=unknown` cannot authorize a
  build.

The dependency-constraint audit at
`5e324209054c13fd39ea99fb878355bdc66c4fbf` reproduced one final fail-open:
an APK dependency such as `libexample>=3.0` was reduced to the package name, so
an official `libexample` version `2.0` incorrectly allowed the build. Versioned
APK dependencies now retain their operator and required version. Relational
constraints are evaluated by the target `apk version -t` implementation, not
by generic string or Python-package comparison. Missing target versions,
unavailable/failed comparison, conflicts, fuzzy constraints and other
unsupported expressions remain unresolved and block strict builds. Structured
`apk adbdump --format json` parsing also prevents malformed or unrecognized
dependency metadata from silently becoming an empty dependency list.

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

## Cross-package-manager boundary

Sprint 2A does **not** implement a general OPKG-to-APK migration. Same-name
official or third-party packages are not sufficient evidence. When source and
target package managers differ, a package needs an explicit versioned
replacement/binary compatibility mapping; without it the decision is
`review`/`block` and `build_allowed=false`. This is a verified safety gate, not
a claim that cross-manager migration is implemented.

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
