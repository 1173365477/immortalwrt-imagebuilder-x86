# Release resolver and trusted-source policy

The resolver treats `OpenWrt` and `ImmortalWrt` as separate trust domains. It
accepts only the selected distribution's HTTPS download root and the
`releases/<version>/` channel; snapshots are never substituted for a release.
`latest` is resolved once from direct, three-component stable release
directories and the resulting exact version is written to the build evidence.

For every request, `profiles.json` must be authenticated by the target
`sha256sums`. The selected profile, target/subtarget, package architecture,
package manager, image type and ImageBuilder archive must all exist. Each
official JSON package index must also be authenticated by the `sha256sums` in
its own directory. The emitted capability document records every URL, content
digest, checksum-manifest URL and checksum-manifest digest, then hashes the
frozen resolution. Duplicate package records that disagree are rejected.

Network errors, malformed JSON/UTF-8, missing checksum entries, checksum
mismatches and inconsistent metadata fail closed. Requests are limited to 30
seconds and 64 MiB per metadata response. The optional local cache has an
explicit TTL and never uses stale data as a successful resolution. Cache keys
cannot contain path separators.

The current firmware workflow is implemented only for `x86/64`, profile
`generic`. Metadata for another platform may be inspected, but its support
status remains `unknown` and must not be represented as a generally supported
build. OPKG and APK are detected from target metadata; detection alone is not
proof that a package with the same name is migration-compatible.

Offline tests use a synthetic `29.0.1` fixture solely to prove future-version
discovery. It is not listed as or treated as an actual published release.
