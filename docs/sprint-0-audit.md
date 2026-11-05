# Sprint 0 audit and compatibility plan

Baseline: main at `f255e46e4a4d91c879e411aedd41c5a82e19efd7` (2026-11-05).

## Confirmed defects

- `.github/workflows/build.yml` step `release` consumes `steps.release.outputs.version` before it exists. Resolve from `inputs.immortalwrt_version`; preserve downstream `steps.release.outputs.version`.
- `.github/workflows/ci.yml` exercises `reports/*.txt.example` files which are absent. Main run 41964793113 failed at that step; the 32 preexisting pytest cases passed.
- `reports/top-level-packages.txt` is tracked but empty. Parser records a note, while `resolve-packages.py` selects primarily top-level and fixed feature rules; arbitrary manually installed packages can be excluded silently. This is a migration blocker, not evidence that a package may be deleted.
- Existing `system-analysis.json` is an owut analyzer output, **not** the new `system-snapshot-v1` contract. Keep old CLI and artifact names unchanged.
- `validate-manifest.py --online` fetches current upstream indexes (non-reproducible unless frozen). Offline acceptance should not imply target-package compatibility; unavailable or inconsistent metadata must block a strict build.
- `thirdparty.yml`: OpenClash `strict_compatibility: false`; third-party release checks require independent target-series and architecture evidence. Unknown remains a blocker, not approval.
- `build-image.sh` currently supports validated APK targets only, x86/64 generic and ext4. Do not claim universal OpenWrt target support.
- `files/etc/uci-defaults/99-install-thirdparty` is a boot-time installer in generated firmware. It is not part of the read-only scanner; any end-to-end firmware safety claim must assess it separately.
- `analyze.yml` uploads generated artifacts even on failure; ensure no private report is included and failures remain clearly visible.
- GitHub Actions checkout/setup-python v4/v5 emit Node 20 deprecation warnings; these are warnings rather than the observed main CI failure.

## Compatibility boundaries

1. Retain `parse-owut-report.py`, `resolve-packages.py`, `validate-manifest.py`, `build-image.sh` CLI flags and historical artifact filenames.
2. Introduce versioned schemas as sidecar contracts; never silently repurpose old `system-analysis.json`.
3. Device probe is a read-only utility, not executed from firmware installation or GitHub Actions by default. Device footprint: POSIX shell + awk; no Python.
4. `unknown` provenance, boot mode, target metadata or mounted Docker persistence must remain explicit. No auto-deletion or automatic upgrade decisions.
5. Future Sprint 2 must introduce tested adapters for exact APK world/manual package tracking, validated firmware identity/boot source, Docker inspect/mount mapping, and immutable version/package indexes before strict end-to-end migration.
6. Redacted reports must not include raw UCI configuration, subscription links, private keys, Docker environment values, or shell execution of untrusted strings. Local/full mode must be kept local and must never be auto-uploaded.
7. Build Actions can still produce a full-disk image. Even if no automatic flashing exists, a manual flash can overwrite an unusual partition layout. Treat this as an explicit human review blocker.

## Current first-round scope and incomplete acceptance

Implemented: build version input fix, restored CI fixture paths, new schemas, conservative opkg/apk read-only inventory and initial tests. Not yet implemented: confident default/manual classification, full Docker Root Dir and persistent mount identification, complete target/boot/profile adaptation, immutable snapshots, end-to-end migration-plan/build-result emitters. Those remain **blockers**, not silently accepted features.

No router commands, service restarts, package installation, disk writes or flashing are authorized.
