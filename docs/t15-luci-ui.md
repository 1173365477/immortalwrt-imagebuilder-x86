# T15 LuCI read-only UI and rpcd contract

## Scope

`luci-app-smart-upgrade` is a native LuCI JavaScript page for evidence already
produced by the router-side scanner and the migration analysis pipeline. T15
does not implement the T16 build-operation UI, publish evidence, call the
Gateway, dispatch GitHub Actions, build firmware, or perform any device change.

The page has five sections:

1. current system and trusted target overview;
2. read-only scan state and errors;
3. package origin, intent, confidence, evidence, and dependency data;
4. service, Docker, mount, and physical-disk risk evidence; and
5. a Snapshot-bound Migration Report viewer and local browser export.

Unknown and partial data are displayed explicitly. The page never derives
compatibility, build permission, image selection, or flash safety.

## Components

| Component | Responsibility |
|---|---|
| `htdocs/luci-static/resources/view/smart-upgrade/overview.js` | LuCI page, RPC error presentation, scan action, report export |
| `htdocs/luci-static/resources/smart-upgrade/model.js` | Presentation-only normalization; retains every installed package and maps invalid origins to `unknown` |
| `root/usr/libexec/rpcd/smart_upgrade` | Fixed-method rpcd provider, secure state/bundle consumer, bounded scan supervisor |
| `root/usr/share/rpcd/acl.d/luci-app-smart-upgrade.json` | Read ACL for evidence; separate write ACL only for starting the read-only scan |
| `scripts/smart-upgrade-agent.sh` | Existing read-only `system-snapshot-v1` producer installed by the package |
| `scripts/smart-upgrade-storage.sh` | Existing bounded storage and Docker evidence helper installed by the package |

There is no CDN, third-party browser dependency, SPA framework, UCI mutation,
package operation, service operation, disk operation, or shell parameter
forwarding.

## ubus/rpcd v1 contract

Object: `smart_upgrade`

| Method | ACL | Client parameters | Result |
|---|---|---|---|
| `status` | read | none | `scan_status`, timestamps, Snapshot identity/status, stable error, and false safety flags |
| `scan` | write | none | Runs only the fixed agent with `--privacy redacted`; returns the updated status |
| `snapshot` | read | none | Validated scanner envelope containing the complete Snapshot |
| `plan` | read | none | Matched Plan only after immutable Bundle seal, byte hashes, identities, binding and safety checks |
| `report` | read | none | Matched Report only from the same verified Bundle; otherwise unavailable |

Every response produced by the provider keeps `dispatch_allowed=false` and
`flash_ready=false`. The input JSON is consumed but is never interpolated into
a path or command. In particular, the RPC surface accepts no package, service,
device, root, report path, URL, or shell command argument.

Runtime state is stored below `/tmp/smart-upgrade`. The provider atomically
creates the directory with mode `0700`, requires the configured root UID, and
rejects links, FIFOs, devices, unsafe modes, unsafe owners and unexpected file
types before reading or changing them. It never `chmod`s an unverified path.

- `scan-state.json` is parsed and reconstructed from a field allow-list;
- `snapshots/<generation>/` contains an immutable Snapshot and byte-integrity
  manifest selected through the atomically replaced `current-snapshot` file;
- `analyses/<bundle-digest>/` contains an immutable Snapshot, Plan, Report and
  `luci-evidence-bundle-v1.json`, selected through `current-analysis`; and
- `recovered-locks/` retains proven stale lock ownership evidence for audit.

The scanner writes a complete generation in a private directory, binds its
actual file SHA256 to the existing `evidence-sha256-v2` identity, then publishes
only an atomic pointer. The evidence identity is not redefined as a JSON file
hash. A scan has a fixed 180-second deadline, is launched in an isolated process
group, and TERM/timeout stops its descendants. Scanner stderr is private and is
never returned to LuCI.

The lock owner record binds PID, Linux process start ticks and boot ID. A live
owner returns `SCAN_BUSY`. A provably exited/reused PID or old boot is atomically
isolated and returns `LOCK_RECOVERED`; the recovery request never starts a scan.
Damaged or unverifiable ownership returns `LOCK_UNVERIFIABLE`. For a legacy
`scan.acquire` without valid owner evidence, a local administrator should
quiesce new scans, independently confirm that the scanner and its descendants
have stopped, and preserve the directory for investigation before retrying.
The provider serializes acquisition and recovery with kernel `flock` on a
stable private inode. The kernel releases the lock when its last descriptor
closes. The scan lock directory and complete owner record are published together
by rename.

`generate-migration-plan.py` performs the complete existing Snapshot and Plan
JSON Schema validation and verifies the Plan canonical digest before generating
a versioned LuCI Evidence Bundle. `publish-luci-evidence.py` revalidates every
file and atomically publishes a new immutable analysis generation while keeping
the previous generation and pointer on failure. The router package does not
install or expose that Python publisher; when no trusted local producer exists,
Plan and Report RPCs remain unavailable.

The rpcd consumer checks root ownership, regular-file type, size, immutable
manifest seal, every file SHA256, producer/version fields, Snapshot identity,
Plan identity, Snapshot/Plan binding, privacy and false safety flags before
returning data. Any missing, mixed, stale or changed byte makes Plan and Report
unavailable; target, compatibility and build permission are not returned.
Report export creates a browser-side Markdown Blob from a matched response and
performs no router write.

The privileged publisher and its private directories form the trust boundary.
The publisher verifies existing generations before reusing them and refuses
unsafe directories or files. The Snapshot evidence ID identifies the scanner's
evidence, and its separate byte hash binds the analysis to the exact current
Snapshot bytes. The Plan canonical digest binds its normalized JSON content.
The producer name and Git commit are provenance labels supplied by the trusted
execution environment. The commit can come from `SMART_UPGRADE_PRODUCER_COMMIT`.
Hashes and commit labels provide neither a digital signature nor proof that an
arbitrary bundle came from the trusted generator. A privileged operator must
restrict publication to output from that generator.

## Evidence Bundle v1

`schemas/luci-evidence-bundle-v1.json` binds:

- the actual SHA256 of Snapshot, Plan and Markdown Report files;
- the unchanged `evidence-sha256-v2` Snapshot ID;
- the existing canonical Migration Plan digest and Plan ID;
- Snapshot/Plan source identity;
- full producer-side Schema validation results;
- producer name, version and Git commit; and
- `dispatch_allowed=false` and `flash_ready=false`.

The manifest itself has canonical bytes, a canonical bundle digest and an
actual byte SHA256 sealed into the atomic current-generation pointer.

## Identity and T05 limitation

Issue #7 remains open. The existing agent has affirmative Linux EFI sysfs
evidence for EFI, but does not have an equivalent affirmative Legacy BIOS
signal. Missing EFI sysfs, x86 CPU architecture, DMI vendor, or firmware image
names are not treated as BIOS evidence. `boot_mode=unknown` is displayed as
Unknown and remains an automatic image-selection blocker in downstream plans.

T15 does not change this policy or claim T05 completion.

## T14 interface gap

The T14 Gateway still documents `/targets` and `/analysis` as unimplemented.
Consequences for T15 are deliberate and fail closed:

- the page does not query the Gateway;
- target version and compatibility remain Unknown until a real local Migration
  Plan matching the current Snapshot is present;
- the page cannot request a build and never displays Gateway dispatch controls;
- a missing or unverified Plan/Report is explicit `EVIDENCE_UNVERIFIED`, not an empty or safe
  report.

T16 may add authenticated remote-operation UX only after those server
interfaces and their authorization model are independently implemented.

## Reviewable UI evidence

The page layout and all displayed fields are reviewable without a router in:

- `overview.js` for the complete LuCI DOM structure;
- `model.js` for presentation-only transformations; and
- `tests/test_luci_smart_upgrade.py` for OPKG/APK, Unknown identity and boot,
  empty top-level lists, third-party/unknown packages, Docker and storage risk,
  partial/failure states, permission separation, corrupt reports, Snapshot
  mismatch, and forbidden mutation/dispatch actions.

The tests execute the JavaScript model with Node and exercise the real rpcd
shell entry through fake `jshn`/`jsonfilter` and controlled agents. They cover
filesystem object types, owner/mode checks, concurrent creation, bundle byte
tampering, status reconstruction, PID/boot/start-time lock recovery, timeout and
TERM process-group cleanup. A dynamic Make harness exercises the real package
Makefile callback and inspects an IPK-format `data.tar.gz` staging archive.

These remain mocked host-side integration tests: no real OpenWrt rpcd/ubus
session or browser engine is claimed, and the staging harness is not a complete
OpenWrt SDK build.
