# T16 read-only Gateway display

The Smart Upgrade page displays the verified Gateway target catalog and
migration analysis alongside T15's local evidence. `eligible` is a migration
analysis outcome. Both safety flags stay false. Local scan, plan, report and
report export retain their T15 behavior.

## Server configuration and operator handoff

Install the LuCI package with `python3-urllib`, `python3-openssl` and
`ca-bundle`. The helper reads the system CA bundle at
`/etc/ssl/certs/ca-certificates.crt`. It accepts an operator-configured
`https://host[:port]` origin and calls only fixed `/targets` and `/analysis`
paths. It validates the TLS hostname and certificate, bypasses proxy
configuration, never follows redirects, and uses a 15-second wall-clock budget
and a 32 KiB response limit. It returns stable public errors and selected
response fields. The device Bearer is taken from a protected file and used
only in the server-side request header. It is never passed as a command
argument, browser field, RPC result or log field.

Provision the following root-owned files under `/etc/smart-upgrade`. Set the
directory to mode 0700 and the files to 0600 or 0400. Use atomic replacement
for updates. Neither file is created by the package or exposed to LuCI.

| File | Exact JSON keys |
|---|---|
| `gateway.json` | `url`, `device_id`, `bearer` |
| `snapshot-ref.json` | `device_id`, `snapshot_ref`, `snapshot_id`, `scan_generation`, `snapshot_sha256`, `expires_at` |

1. Provision a Gateway device credential through the operator interface. Pair
   its Bearer with the same enrolled device ID in `gateway.json`.
2. Use the trusted collector and T14 administrative Snapshot admission flow
   to obtain the opaque `snapshot_ref` for the currently published redacted
   Snapshot. Obtain the collector's verified device, scan generation, byte
   SHA256 and expiry from the same admission. Copy those exact values into
   `snapshot-ref.json`. `expires_at` is Unix seconds and must be no later than
   Gateway admission expiry. Configure synchronized device and server clocks.
3. When a scan changes, repeat trusted admission and replace the handoff file.
   Missing, unsafe, expired or mismatched handoff evidence prevents the
   router from posting analysis. Setting a local expiry cannot extend
   Gateway admission.

The current release provides a protected handoff contract. Production
collector provisioning, authentication between device and collector, and
operator installation on the target runtime require deployment verification.
No Snapshot upload or collector signer is exposed by these RPC methods.

## RPC and display

- `smart_upgrade.targets` has no client parameters and uses the existing
  display group's read ACL.
- `smart_upgrade.snapshot_identity` uses the same read ACL. It returns the
  Snapshot ID, scan generation and SHA256 from the verified original file,
  without returning its JSON body. A scan lock or unverifiable evidence
  makes the identity unavailable.
- `smart_upgrade.analyze` needs the separate
  `luci-app-smart-upgrade-analysis` write grant because Gateway analysis
  records a receipt. Grant this explicitly to the operator alongside the view
  ACL. The existing `scan` write grant is independent. The analysis method takes
  the selected target reference and the expected Snapshot triple only.
  Router-side code independently checks the triple before posting and
  checks the published generation and bytes again after the response.

The browser captures the triple, target reference, resolution digest and a
request sequence. It re-reads the current verified identity before displaying
a result. Scan changes, target selection, catalog refresh and expiry
invalidate previous results. An older response cannot replace the current
one. Results received after expiry, with mixed provenance, or with either
safety flag set are unavailable. The result panel distinguishes strict
`blocked` from missing or unavailable evidence.

The test suite uses local TLS, a disposable RPC state directory and Node
view fixtures. Native LuCI packaging is tested using the pinned v25.12
LuCI rules. Full target SDK installation, real rpcd/ubus permissions and
production Gateway/collector integration remain deployment checks.

See the [T14 Gateway API](t14-gateway-api.md) and [T15 LuCI contract](t15-luci-ui.md).
The dependency layout is documented in the
[ImmortalWrt TLS package rules](https://github.com/immortalwrt/packages/blob/openwrt-25.12/lang/python/python3/files/python3-package-openssl.mk)
and [OpenWrt CA bundle rules](https://github.com/openwrt/openwrt/blob/openwrt-25.12/package/system/ca-certificates/Makefile).
