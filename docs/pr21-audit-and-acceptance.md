# PR #21 audit and Sprint 0–1 acceptance

Audit baseline: `862473c19e0ffd9c517eef8f167c8fdcb53592b9`  
Audited branch: `feature/smart-upgrade-sprint0-1`  
Safety boundary: no router connection, package mutation, source refresh, service restart, image build, `sysupgrade`, reboot, partition operation, main merge or force-push was performed.

## Outcome

The baseline HEAD had not changed when remediation began. The changes are incremental and retain the existing Actions inputs, analyzer CLI flags, report names and firmware build entry point. Unknown evidence remains unknown or becomes an explicit review/block decision. The four findings from the final review of `a43f3ecbf19a80579444082d357e51c629330cd1` were remediated at implementation HEAD `4fa7b7ad38ba828a7d042414ad22d4ee7660a4b1`; [Project self-test #57](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42156307171) passed on that exact tree. `flash_ready` remains unconditionally false in the v1 protocol.

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
| T04 CI baseline | `.github/workflows/ci.yml` | 107 pytest cases; actionlint; ShellCheck; workflow regressions; Artifact safety integration | Local suite and GitHub-hosted online validation pass | Online release metadata remains external and time-dependent | PASS |
| T05 identity and package manager | scanner; `identity-compat.py` | realistic OPKG/APK, EFI sysfs positive case, DMI/config/absence negative cases and architecture conflicts | EFI has affirmative kernel evidence; no reliable universal Legacy BIOS affirmative adapter was identified, so uncertainty remains unknown and blocks image selection | Legacy BIOS detection completeness remains limited by the Linux evidence boundary | PARTIAL |
| T06 origin/install reason | scanner ROM baselines and optional read-only ROM origin manifest | official/third-party/unknown, manual/dependency/default/unknown tests | Origin is independent from intent; no feed origin is guessed | Existing devices without ROM origin evidence classify non-default origin as unknown | PASS |
| T07 top-level fallback | parser/resolver and `package-decisions.json` | missing, empty, partial, complete and explicit-ignore conflict tests | Every installed package receives keep/replace/skip/block/review evidence; strict mode sees unresolved rows | A complete list still depends on truthful package-manager metadata | PASS |
| T08 services and storage | scanner plus storage module | daemon mismatch, same-disk/different-disk partitions, stopped-container bind, unused volume, 64-container truncation, query/inspect failures, nested mount, symlink, no Docker and missing mountinfo | Persistence and whole-disk overwrite exposure are independent. All containers and volumes are enumerated; incomplete scans are partial | Scanner observes its mount namespace; inaccessible daemon/sysfs or ambiguous firmware disk remains unknown. Docker socket must never be delegated to LuCI/RPC users | PASS |
| T09 privacy/minimum privilege/errors | redacted default, bounded parser, fixed command templates, Schema privacy condition | secret non-leak, invalid UTF-8, oversize input, local/redacted path and stable-redaction snapshot-ID tests | No config secret, Docker environment or complete inspect object is read; anonymous disk/mount relationships survive redaction | Local mode contains paths by design and must stay local; root Docker inspection remains a privileged helper boundary | PASS |

## Verification

- `pytest -q`: **107 passed**.
- ShellCheck 0.10.0: passed for `smart-upgrade-agent.sh`, `smart-upgrade-storage.sh`, existing build script and first-boot script.
- actionlint 1.7.7: passed for all workflows.
- `git diff --check`: passed.
- GitHub Actions implementation run: [Project self-test #57](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42156307171) at `4fa7b7ad38ba828a7d042414ad22d4ee7660a4b1` — actionlint, syntax/YAML, ShellCheck, 107 pytest cases, fixture analysis, official 25.12.2 indexes, version mismatch rejection and strict-mode rejection all passed.

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
10. `4287ab3` — fail closed when a build result is partial, blocked, failed or unknown.
11. `245865b` — validate metadata and gate every Artifact upload on a clean output scan.
12. `a5ed8aa` — recursively resolve dm/md slaves to complete physical-disk sets.
13. `4fa7b7a` — record affirmative EFI evidence while keeping unsupported BIOS conclusions unknown.

## Targeted follow-up review at PR HEAD

The follow-up started from remote HEAD `b3ed1aec30b0cad8edfcc6ae9b4a1798434238c6`; the earlier T01–T09 implementation was retained and reviewed only where the four reported gaps intersected it.

| Area | Code evidence | Regression evidence | Known limit | Re-acceptance |
|---|---|---|---|---|
| T03 snapshot contract | `schemas/system-snapshot-v1.json:53,64-87`; `docs/schema-v1-protocol.md:7`; `scripts/smart-upgrade-agent.sh:55-78,265` | `tests/test_smart_upgrade_agent.py:386-402` (`test_snapshot_id_changes_with_dynamic_storage_and_identity_evidence`); `tests/test_schema_contracts.py:63-82` (`test_storage_contract_rejects_implicit_upgrade_safety_or_missing_completeness`) | v2 is evidence canonicalization, not RFC 8785 JSON canonicalization | PASS |
| T05 boot identity | `scripts/smart-upgrade-agent.sh` identity adapter | `test_dmi_vendor_is_not_legacy_bios_evidence`; `test_linux_efi_sysfs_is_affirmative_read_only_evidence`; `test_efi_capable_kernel_without_efi_sysfs_does_not_prove_legacy_bios` | Legacy BIOS remains unknown unless an audited adapter supplies affirmative evidence | PARTIAL |
| T08 Docker/storage | `scripts/smart-upgrade-storage.sh:66-186,198-243,244-304` | `tests/test_smart_upgrade_agent.py:295-383` (`test_separate_partition_does_not_imply_firmware_overwrite_safety`, `test_all_container_states_and_unused_volumes_are_in_scan_scope`, incomplete-enumeration parameter cases and symlink regression) | A different physical disk is lower exposure to whole-firmware-disk overwrite, not a claim that upgrade/partition tooling is safe | PASS |
| T09 conservative failure/privacy | `scripts/smart-upgrade-storage.sh:67-68,171-186,287-303`; `schemas/system-snapshot-v1.json:74-87` | `tests/test_smart_upgrade_agent.py:348-402`; `tests/test_schema_contracts.py:56-82` | Docker metadata queries require privileged local access and must not be exposed through generic LuCI/RPC | PASS |

Targeted implementation CI: [Project self-test #53](https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/42024934027) — all steps passed.

## Final blocking-review remediation

Review source: [CHANGES REQUIRED on `a43f3ec`](https://github.com/1173365477/immortalwrt-imagebuilder-x86/pull/21#issuecomment-6675669414).

| Finding | Before | Remediation / Commit | Reproducible regression evidence | After |
|---|---|---|---|---|
| Partial build result remained build-allowed | Draft 2020-12 validator accepted `partial + build_allowed=true` | Status condition now forces false for every non-ok state; migration-plan was cross-checked (`4287ab3`) | `test_incomplete_build_result_cannot_allow_build`; `test_partial_build_result_is_valid_only_when_fail_closed`; `test_successful_build_requires_artifact_and_valid_plan_link` | Invalid combinations are rejected; complete fail-closed partial sample validates |
| Sensitive owut metadata reached an uploaded JSON | `Version-from  password=TEST_SECRET...` survived as `source_version` | Strict field grammars, safe error codes, bounded output scanner and upload dependency gate (`245865b`) | `test_parser_and_artifact_gate_never_emit_injected_secret`; `test_artifact_gate_blocks_secret_without_echoing_it`; `test_artifact_uploads_require_successful_safety_gate` | Marker is absent from JSON, Markdown, package outputs and diagnostics; unsafe output prevents upload |
| dm/md names were treated as physical disks | dm-0 root plus dm-1 data could report `different_physical_disk` | Recursive sysfs slave resolution, deduplicated physical sets, cycle/depth guards and anonymous redacted relationships (`a5ed8aa`) | `test_dm_devices_compare_recursive_physical_disk_sets`; `test_multi_slave_virtual_device_retains_all_physical_parents`; `test_nested_dm_md_chain_resolves_recursively`; `test_incomplete_or_invalid_virtual_topology_is_unknown`; ordinary NVMe and all-target consistency cases | Intersection means same-disk exposure; proven disjoint sets mean different disk; incomplete sets remain unknown |
| No real-device affirmative Legacy BIOS adapter | Only a test override could produce BIOS | Kernel EFI sysfs is recorded as positive EFI evidence; absence, DMI, architecture, partition table and kernel capability remain inconclusive (`4fa7b7a`) | EFI positive test plus DMI and EFI-capable-kernel/absent-sysfs negative tests | T05 remains PARTIAL; unknown still blocks both EFI and legacy automatic image selection |

## Legacy BIOS evidence decision

Linux provides affirmative EFI evidence through `/sys/firmware/efi`: the upstream
EFI subsystem creates that sysfs interface after EFI boot information is accepted,
and its `systab` ABI exposes EFI configuration tables.  Upstream does not provide
the inverse guarantee that an absent directory proves a Legacy BIOS boot.  Kernel
configuration, EFI disabling, registration failure, and namespace/sysfs visibility
can all make absence inconclusive.  See the Linux kernel
[`drivers/firmware/efi/efi.c`](https://github.com/torvalds/linux/blob/master/drivers/firmware/efi/efi.c)
and [`sysfs-firmware-efi` ABI](https://www.kernel.org/doc/html/latest/admin-guide/abi-testing-files.html#abi-file-testing-sysfs-firmware-efi).

The scanner therefore records `linux_efi_sysfs` as affirmative EFI evidence but
keeps Legacy BIOS as `unknown` unless an audited adapter is added in a future
change. DMI vendor strings, x86_64, GPT/MBR, `CONFIG_EFI=y`, and EFI-sysfs absence
are not promoted to BIOS evidence. Unknown boot mode continues to block automatic
EFI or legacy image selection. T05 remains **PARTIAL** for detection completeness,
without creating a false-compatible or false-safe state.

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

## Final re-review decision

All HIGH findings from the final blocking review have code fixes, positive/negative regressions and a successful GitHub Runner result. T03, T04, T08 and T09 are PASS. T05 remains PARTIAL only for affirmative Legacy BIOS detection completeness: this does not create an unsafe compatibility claim because `unknown` is preserved and both EFI and legacy automatic image selection remain blocked. It is therefore not a remaining HIGH merge blocker for the read-only Sprint 0–1 scanner, but it must not be relabeled PASS without new audited evidence.

The author-side implementation status is **READY FOR FINAL RE-REVIEW**. This is not an approval or merge authorization. PR #21 must remain unmerged until an independent final review accepts the new HEAD and the repository owner explicitly authorizes merge. No firmware build, flash, router access, Issue closure or main-branch modification was performed.

