# Sprint 3 T15 acceptance report

## Result and dependency status

T15 implements the Draft-only `luci-app-smart-upgrade` Overview, Scanner,
Package Evidence, Service/Storage Risk, and Migration Report UI. The baseline is
main `8c9e394befa98b7879327a74df64f300fef3df10` after PR #25 and main CI #132.

T03, T06, T07, T08, and T09 are closed. T05 / Issue #7 remains open because a
reliable affirmative Legacy BIOS detector is not available. This work preserves
`boot_mode=unknown`, does not mark T05 PASS, and must remain Draft unless the
repository owner separately waives that dependency.

## Acceptance matrix

| Item | Status | Evidence |
|---|---|---|
| Native LuCI JS, no CDN/framework | PASS | LuCI `view`, `rpc`, `ui`, and `poll` modules only; local CSS/model |
| System and target overview | PASS | Snapshot fields are direct; target fields require a Snapshot-matched Plan |
| Read-only scanner | PASS | Fixed rpcd method invokes only the installed agent with `--privacy redacted` |
| Scan state/error handling | PASS | idle/running/completed/partial/failed, timestamps and stable errors |
| OPKG/APK/unknown identity | PASS | Existing scanner fixtures plus T15 presentation tests |
| Package evidence | PASS | All installed records retained; official/third-party/unknown kept distinct |
| Empty top-level handling | PASS | Explicit warning and no package omission |
| Services, Docker and storage | PASS | Runtime, completeness, mounts, capacity and overwrite risk shown without safe inference |
| Migration Report | PASS | Immutable Evidence Bundle, complete producer-side Schema/canonical-digest validation, byte hashes, atomic publication and fail-closed browser export |
| ACL | PASS | status/snapshot/plan/report are read; scan is separate write permission |
| No client shell execution | PASS | RPC accepts no parameters and consumes request JSON without interpolation |
| Safety invariants | PASS | `dispatch_allowed=false`, `flash_ready=false`; no reboot/flash/package/UCI/disk operation |
| State filesystem boundary | PASS | Atomic 0700 creation; owner/type/mode/size checks; links, FIFOs and unsafe objects rejected |
| Scan lock and deadline | PASS | PID + start ticks + boot ID; audited stale isolation; 180-second process-group deadline |
| Responsive UI | PASS | LuCI tables plus local mobile CSS; wide evidence tables scroll rather than truncate |
| T14 `/targets` and `/analysis` gap | DOCUMENTED | Target stays Unknown without a real Snapshot-matched Plan; no Gateway/build UI |
| T05 dependency | OPEN / DRAFT BLOCKER | Issue #7 remains open; unknown boot mode blocks automatic image choice |

## Test coverage

The remediation additionally covers:

- OPKG and APK display;
- unknown system identity and boot mode;
- empty top-level inventory without losing installed packages;
- third-party and unknown origins;
- dependencies and evidence confidence;
- Docker unavailable/partial evidence, special mounts and overwrite risk;
- scanner failure and partial results;
- read/write ACL separation and permission-error presentation;
- missing, unsafe, stale, and Snapshot-mismatched reports;
- JavaScript syntax;
- absence of device mutation, build dispatch, reboot, or flash calls;
- actual Make callback execution and IPK-format staging contents;
- Snapshot/Plan/Report/manifest byte tampering and full Schema validation;
- symlink, FIFO, owner, mode, size and concurrent state creation failures;
- status field allow-listing and forged safety flags;
- active, stale, reused-PID, old-boot and corrupt scan locks; and
- timeout/TERM descendant cleanup and lock release.

Historical verification before the follow-up to F3, F6 and F7:

- Ubuntu full suite: **373 passed, 1 skipped**;
- pinned real apk-tools/APKv3 integration: **1 passed**;
- actionlint, ShellCheck, Python/YAML/JSON Schema, online index validation and
  strict negative gates: **passed**; and
- push CI: <https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/45381474807>;
- PR CI: <https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/45381486644>.

Validation layers are explicitly separated:

- Python performs full Snapshot, Plan and Evidence Bundle Schema validation and
  canonical Plan digest verification in the trusted producer/publisher path;
- rpcd verifies safe filesystem ownership/types, the atomic pointer seal, all
  file byte hashes, identities, bindings and safety constants;
- the package test performs reproducible staging and IPK archive inspection;
- no complete OpenWrt SDK/IPK compile, real rpcd/ubus session or browser engine
  is claimed by the host tests.

On macOS, the unchanged storage scanner's GNU/BusyBox awk expressions remain
incompatible with BSD awk. The final Linux GitHub Actions run remains the
authoritative scanner validation. No test was deleted, skipped, or weakened.

## Remaining limitations

The follow-up verifies Prepare and Install using the pinned OpenWrt LuCI
`openwrt-25.12` rules at `cb87fe60e1e2e052af36a93647f2264577829e0a` with a
minimal buildroot harness. CI exercises the process group with the BusyBox ash
and setsid from the checksum-pinned Alpine rootfs on Linux. Full target SDK
packaging and actual OpenWrt rpcd/ubus runtime remain unverified. The current
PR checks are available on [PR #26](https://github.com/1173365477/immortalwrt-imagebuilder-x86/pull/26/checks).

- No affirmative Legacy BIOS evidence: Issue #7 remains open.
- No live router/browser screenshot is produced in this sprint; source-level DOM,
  responsive CSS and executable model/RPC tests are the reviewable UI evidence.
- Report files require the trusted bundle generator and publisher. With no such
  producer installed on the router, Plan and Report deliberately remain unavailable.
- Reproducible package staging is verified; a full target SDK IPK compile remains
  an independent environment validation item.
- T14 `/targets` and `/analysis` are not available, so the page cannot discover
  targets or start analysis through the Gateway.
- No T16 remote build controls are present.
