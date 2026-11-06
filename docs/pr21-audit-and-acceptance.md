# PR #21 audit and Sprint 0–1 acceptance

Audit baseline: `862473c19e0ffd9c517eef8f167c8fdcb53592b9`  
Audited branch: `feature/smart-upgrade-sprint0-1`  
Safety boundary: no router connection, package mutation, source refresh, service restart, image build, `sysupgrade`, reboot, partition operation, main merge or force-push was performed.

## Outcome

The baseline HEAD had not changed when remediation began. The changes are incremental and retain the existing Actions inputs, analyzer CLI flags, report names and firmware build entry point. Unknown evidence remains unknown or becomes an explicit review/block decision. The latest implementation CI is green; `flash_ready` is unconditionally false in the v1 protocol.

## Original findings and remediation

| Finding | Remediation | Evidence |
|---|---|---|
| Empty-only provenance check missed partial top-level lists | Parser distinguishes missing/empty/partial/complete manifests. Resolver emits a decision for every installed package and blocks every unclassified package. Explicit user packages cannot be dropped by dependency ignore rules. | `scripts/parse-owut-report.py`, `scripts/resolve-packages.py`, `tests/test_package_provenance.py` |
| Package `source` mixed repository origin and install reason | Separate `origin`, `install_reason`, `confidence` and `evidence`. Non-installed OPKG paragraphs are excluded. APK world is only an intent candidate. Raw constraints and virtual/soname relations are retained. | `scripts/smart-upgrade-agent.sh`, realistic APK/OPKG fixtures, system snapshot Schema |
| Docker Root Dir was configuration-only | Runtime `docker info` wins; UCI/daemon.json is unverified fallback. Fixed Docker inspect templates extract only mount type/source/destination/name. Mountinfo longest-prefix resolution classifies Docker root, volumes and binds. | `scripts/smart-upgrade-storage.sh`, storage tests in `tests/test_smart_upgrade_agent.py` |
| Storage conclusion used no block evidence | Mount records retain filesystem, device, major:minor, sysfs-backed capacity and resolution state. Missing/truncated/permission states remain unknown/partial. Redacted mode retains only anonymous `mount-N` relationships and risk. | storage module, system snapshot Schema, block-capacity test |
| x86_64 could be confused with EFI | EFI, BIOS and unknown require evidence. Release, os-release, ubus board, uname, package architecture, rootfs and image type are recorded and checked for conflicts. Image compatibility never selects EFI from architecture alone. | `scripts/identity-compat.py`, identity tests |
| Service package presence implied service health | Package, executable, init definition and runtime state are independent fields. Unknown runtime is not converted to running. | scanner service model and service-state test |
| Schemas allowed dangerous combinations | All three v1 Schemas require trace identities and status fields. Unknown/incompatible targets cannot set `build_allowed`; `flash_ready` is always false; redacted paths must be null; failed results require errors. | `schemas/*.json`, `docs/schema-v1-protocol.md`, `tests/test_schema_contracts.py` |
| Parser tolerated invalid UTF-8 and unbounded files | Strict UTF-8, input byte limits, control-character sanitization, bounded package/mount/dependency output and explicit parse failures were added. | parser and adversarial tests |
| CI checked YAML only as generic YAML | actionlint 1.7.7, both scanner shell files in ShellCheck, workflow input regression assertions and new safety fixtures were added. | `.github/workflows/ci.yml`, `tests/test_workflows.py` |

## T01–T09 acceptance matrix

| Task | Code / key location | Tests | Result | Known limits | Status |
|---|---|---|---|---|---|
| T01 repository audit | `docs/sprint-0-audit.md`; this report | full suite and diff review | Baseline and safety boundaries recorded; issues mapped to fixes | Audit is scoped to PR and relevant pre-existing build path | PASS |
| T02 target version parsing | `.github/workflows/build.yml` release step; `scripts/resolve_version.py` | `test_build_version_is_taken_from_dispatch_input_not_self_reference`; existing release tests | Dispatch input is consumed before the step output exists; downstream output name retained | Online release metadata remains time-dependent | PASS |
| T03 three v1 Schemas | `schemas/*.json`; `docs/schema-v1-protocol.md` | positive/negative cases in `test_schema_contracts.py`, including incomplete Docker scans and invalid safety states | Required trace, status, privacy, blocker and MVP no-flash semantics enforced. Snapshot canonicalization v2 binds dynamic storage/device evidence | Historical `system-analysis.json` intentionally remains a separate legacy artifact | PASS |
| T04 CI baseline | `.github/workflows/ci.yml` | 80 pytest cases; actionlint; ShellCheck; workflow regressions | Local suite and GitHub-hosted online validation pass | Online release metadata remains external and time-dependent | PASS |
| T05 identity and package manager | scanner; `identity-compat.py` | realistic OPKG/APK, non-installed, EFI/BIOS/unknown, DMI negative regression and architecture conflict tests | All uncertain values remain explicit; DMI vendor presence is not treated as Legacy BIOS proof | Hardware-specific ubus/sysfs variants beyond fixtures remain possible and must return unknown | PASS |
| T06 origin/install reason | scanner ROM baselines and optional read-only ROM origin manifest | official/third-party/unknown, manual/dependency/default/unknown tests | Origin is independent from intent; no feed origin is guessed | Existing devices without ROM origin evidence classify non-default origin as unknown | PASS |
| T07 top-level fallback | parser/resolver and `package-decisions.json` | missing, empty, partial, complete and explicit-ignore conflict tests | Every installed package receives keep/replace/skip/block/review evidence; strict mode sees unresolved rows | A complete list still depends on truthful package-manager metadata | PASS |
| T08 services and storage | scanner plus storage module | daemon mismatch, same-disk/different-disk partitions, stopped-container bind, unused volume, 64-container truncation, query/inspect failures, nested mount, symlink, no Docker and missing mountinfo | Persistence and whole-disk overwrite exposure are independent. All containers and volumes are enumerated; incomplete scans are partial | Scanner observes its mount namespace; inaccessible daemon/sysfs or ambiguous firmware disk remains unknown. Docker socket must never be delegated to LuCI/RPC users | PASS |
| T09 privacy/minimum privilege/errors | redacted default, bounded parser, fixed command templates, Schema privacy condition | secret non-leak, invalid UTF-8, oversize input, local/redacted path and stable-redaction snapshot-ID tests | No config secret, Docker environment or complete inspect object is read; anonymous disk/mount relationships survive redaction | Local mode contains paths by design and must stay local; root Docker inspection remains a privileged helper boundary | PASS |

## Verification

- `pytest -q`: **80 passed**.
- ShellCheck 0.10.0: passed for `smart-upgrade-agent.sh`, `smart-upgrade-storage.sh`, existing build script and first-boot script.
- actionlint 1.7.7: passed for all workflows.
- `git diff --check`: passed.
- GitHub Actions implementation run: [Project self-test #47](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42008119694) — all steps passed.

No firmware build was executed as part of this acceptance. The existing online index validation remains in GitHub CI and does not certify a produced image for flashing.

## Commits after the audit baseline

1. `9ba69b2` — block incomplete package intent evidence.
2. `2d0d63c` — conservative identity, package, service and storage evidence.
3. `443fc6f` — constrained schemas and workflow regressions.
4. `0ee4dad` — realistic package formats, dependency relations and user-intent safeguards.
5. `2ca284f` — block-device resolution and capacity evidence.
6. `5da3438` — acceptance report, evidence digest and ROM origin support.
7. `1416641` — satisfy actionlint workflow shell checking without lowering rules.
8. `7663717` — harden Docker enumeration, physical-disk risk, snapshot evidence and boot detection.
9. `50796a2` — satisfy ShellCheck without suppressing the volume-fixture guard.

## Targeted follow-up review at PR HEAD

The follow-up started from remote HEAD `b3ed1aec30b0cad8edfcc6ae9b4a1798434238c6`; the earlier T01–T09 implementation was retained and reviewed only where the four reported gaps intersected it.

| Area | Code evidence | Regression evidence | Known limit | Re-acceptance |
|---|---|---|---|---|
| T03 snapshot contract | `schemas/system-snapshot-v1.json:53,64-87`; `docs/schema-v1-protocol.md:7`; `scripts/smart-upgrade-agent.sh:55-78,265` | `tests/test_smart_upgrade_agent.py:386-402` (`test_snapshot_id_changes_with_dynamic_storage_and_identity_evidence`); `tests/test_schema_contracts.py:63-82` (`test_storage_contract_rejects_implicit_upgrade_safety_or_missing_completeness`) | v2 is evidence canonicalization, not RFC 8785 JSON canonicalization | PASS |
| T05 boot identity | `scripts/smart-upgrade-agent.sh:93-128` | `tests/test_smart_upgrade_agent.py:405-421` (`test_dmi_vendor_is_not_legacy_bios_evidence`); existing `test_identity_uses_injected_read_only_evidence` | Legacy BIOS remains unknown unless an audited adapter supplies affirmative evidence | PASS |
| T08 Docker/storage | `scripts/smart-upgrade-storage.sh:66-186,198-243,244-304` | `tests/test_smart_upgrade_agent.py:295-383` (`test_separate_partition_does_not_imply_firmware_overwrite_safety`, `test_all_container_states_and_unused_volumes_are_in_scan_scope`, incomplete-enumeration parameter cases and symlink regression) | A different physical disk is lower exposure to whole-firmware-disk overwrite, not a claim that upgrade/partition tooling is safe | PASS |
| T09 conservative failure/privacy | `scripts/smart-upgrade-storage.sh:67-68,171-186,287-303`; `schemas/system-snapshot-v1.json:74-87` | `tests/test_smart_upgrade_agent.py:348-402`; `tests/test_schema_contracts.py:56-82` | Docker metadata queries require privileged local access and must not be exposed through generic LuCI/RPC | PASS |

Targeted implementation CI: [Project self-test #53](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42024934027) — all steps passed.

## First-boot third-party installer audit

`files/etc/uci-defaults/99-install-thirdparty` is **not** part of the local read-only scanner. It executes later, as root, on first boot of a generated image and runs `apk add --allow-untrusted` for every bundled `/root/thirdparty/*.apk`.

- Build stage: `fetch-thirdparty.py` requires GitHub API SHA-256 digests for all enabled providers, checks target package manager/architecture/dependencies, verifies APK v3 magic/metadata, records asset and APK hashes, and embeds the selected files. The firmware image receives its own SHA-256 after build.
- Signature model: `--allow-untrusted` bypasses APK repository-signature trust at first boot. The boot script itself does not re-check `thirdparty-sha256sums`; integrity therefore depends on the verified build inputs and validation of the final firmware image before use.
- Privilege/dependencies: installation runs with root filesystem/package-manager privileges and may execute package scripts or enable files supplied by the APK. Dependency resolution may install or reject additional packages according to the image repositories.
- Failure/retry: on failure, APKs and the uci-defaults script remain, so installation is retried on a later boot. On success, `/root/thirdparty` is recursively removed.

This is a distinct future mutation boundary: (1) local scanner is read-only, (2) GitHub build downloads and assembles artifacts, and (3) first boot performs privileged installation. They do not share the same read-only guarantee. Sprint 2 should either verify embedded APK hashes again before installation and pin a trust key, or remove `--allow-untrusted` by producing a signed local repository.

## Sprint 2 interface recommendations

1. Emit migration-plan and build-result documents from the existing v1 Schemas; bind them by ID/digest and reject stale snapshots.
2. Generate `/rom/usr/share/smart-upgrade/package-origins.tsv` from verified build metadata so future scans can prove third-party origin without package-name heuristics.
3. Put privileged daemon inspection behind a narrowly scoped root helper that returns only the storage sub-document. Do not expose `/var/run/docker.sock` through LuCI or generic ubus RPC.
4. Add a signed, hash-verifying first-boot APK repository/install flow and record the exact package-script privilege boundary.
5. Freeze official and third-party metadata identities in the build request; emit run ID, attempt, Commit and Artifact digests in build-result.
6. Keep automatic flash, reboot, partition changes and rollback outside scope until storage blockers, image identity and backup/restore evidence have independent acceptance.

## Ready-for-review decision

The code-level Sprint 0–1 criteria and current CI satisfy the conditions for **Ready for Review**. This task leaves the PR in Draft so the repository owner can make the explicit state transition after reading the security boundary and first-boot risk section. Any future P0 regression, unknown-to-compatible coercion, or first-boot trust change returns the decision to blocked. Ready for Review would not authorize merge, image flashing or router mutation.

