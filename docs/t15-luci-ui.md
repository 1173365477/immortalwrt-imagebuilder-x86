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
| `root/usr/libexec/rpcd/smart_upgrade` | Fixed-method rpcd provider with no client-controlled path or command |
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
| `plan` | read | none | Safety envelope with a bounded Plan only after server-side Snapshot identity and `flash_ready=false` checks |
| `report` | read | none | Fixed local Plan/Report envelope, Snapshot binding state, server-supplied blockers and target data |

Every response produced by the provider keeps `dispatch_allowed=false` and
`flash_ready=false`. The input JSON is consumed but is never interpolated into
a path or command. In particular, the RPC surface accepts no package, service,
device, root, report path, URL, or shell command argument.

Runtime state is stored with mode `0700` below `/tmp/smart-upgrade`:

- `scan-state.json`;
- `system-snapshot-v1.json`;
- `migration-plan-v1.json` (optional, supplied by the trusted analysis path);
- `migration-report.md` (optional, supplied with the Plan).

The scanner writes to a private temporary file, verifies the schema version,
redacted privacy mode, status, Snapshot ID/digest binding and size, then uses an
atomic rename. A lock directory rejects concurrent scans. Scanner stderr is not
returned to LuCI.

The Report endpoint requires both fixed files, bounded sizes, Plan schema and
identity fields, and `flash_ready=false`. A Plan whose `source_snapshot_id`
does not equal the current Snapshot is returned with `integrity_status=mismatch`;
the overview therefore keeps target fields Unknown. Report export creates a
browser-side Markdown Blob from the exact server response and performs no
router write.

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
- a missing Plan/Report is an explicit `REPORT_MISSING`, not an empty or safe
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
shell entry through fake `jshn`/`jsonfilter` and a fixed fake agent. They do not
connect to a router or GitHub Actions.
