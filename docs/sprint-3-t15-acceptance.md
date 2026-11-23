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
| Migration Report | PASS | Fixed local files, size/identity/safety checks, blockers, Plan decisions, Snapshot binding and browser export |
| ACL | PASS | status/snapshot/plan/report are read; scan is separate write permission |
| No client shell execution | PASS | RPC accepts no parameters and consumes request JSON without interpolation |
| Safety invariants | PASS | `dispatch_allowed=false`, `flash_ready=false`; no reboot/flash/package/UCI/disk operation |
| Responsive UI | PASS | LuCI tables plus local mobile CSS; wide evidence tables scroll rather than truncate |
| T14 `/targets` and `/analysis` gap | DOCUMENTED | Target stays Unknown without a real Snapshot-matched Plan; no Gateway/build UI |
| T05 dependency | OPEN / DRAFT BLOCKER | Issue #7 remains open; unknown boot mode blocks automatic image choice |

## Test coverage

Targeted T15 tests cover:

- OPKG and APK display;
- unknown system identity and boot mode;
- empty top-level inventory without losing installed packages;
- third-party and unknown origins;
- dependencies and evidence confidence;
- Docker unavailable/partial evidence, special mounts and overwrite risk;
- scanner failure and partial results;
- read/write ACL separation and permission-error presentation;
- missing, unsafe, stale, and Snapshot-mismatched reports;
- JavaScript syntax; and
- absence of device mutation, build dispatch, reboot, or flash calls.

Verification on the functional implementation HEAD:

- T15-specific tests: **19 passed**;
- T15 plus workflow contract tests: **24 passed**;
- Ubuntu full suite: **334 passed, 1 skipped** (335 collected);
- actionlint, ShellCheck (including the rpcd provider), Python/YAML/JSON Schema,
  pinned real apk-tools/APKv3, online index validation, and strict negative
  gates: **passed**; and
- Draft PR CI: <https://github.com/1173365477/immortalwrt-imagebuilder-x86/actions/runs/44976938054>.

On macOS, the unchanged storage scanner's GNU/BusyBox awk expressions remain
incompatible with BSD awk. The platform-independent suite completed with 294
passed and 1 skipped; authoritative scanner coverage is the successful Ubuntu
CI above. No test was deleted, skipped, or weakened for T15.

## Remaining limitations

- No affirmative Legacy BIOS evidence: Issue #7 remains open.
- No live router/browser screenshot is produced in this sprint; source-level DOM,
  responsive CSS and executable model/RPC tests are the reviewable UI evidence.
- Report files require a trusted local analysis producer; T15 never fabricates them.
- T14 `/targets` and `/analysis` are not available, so the page cannot discover
  targets or start analysis through the Gateway.
- No T16 remote build controls are present.
