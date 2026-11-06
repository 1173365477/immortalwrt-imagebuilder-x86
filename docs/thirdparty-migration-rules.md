# Third-party migration and trust rules

`config/thirdparty.yml` is a versioned, fail-closed rule set. Every provider
identifies one GitHub Release repository, the ImageBuilder binary path, APK as
the package format, supported architectures and distributions, official
dependencies, exact asset matching, required upstream SHA-256 evidence and the
reason compatibility is believed. SDK source builds are a separate path and
are not implemented by these rules.

OpenClash is selected by an exact user-pinned tag and exact APK asset. Nikki's
release archive must encode both target series and architecture. Lucky's
release notes must name the target series and every APK must encode x86_64.
All three require GitHub's asset SHA-256 digest, APK v3 magic, and—when the
local APK metadata tool can fully parse it—package name, architecture, version
and dependency validation. If that tool is absent, fails, or returns incomplete
metadata, compatibility is unresolved rather than inferred from magic and
SHA-256. Official
dependencies are checked against the frozen release index. A same-name OPKG
and APK is never compatibility evidence by itself.

`thirdparty-status.json` is evidence, not an assertion flag. A compatible row
binds the provider and rule version to the exact target release-resolution and
official-index digests, architecture, package manager, upstream release/assets,
asset SHA-256 values, extracted APK checks and official dependency result. Its
canonical evidence digest is revalidated by the Migration Plan generator, which
also re-fetches the pinned GitHub release and asset metadata, verifies GitHub
asset IDs/digests, repeats archive extraction when applicable, and hashes the
APK files actually present in `files/root/thirdparty`. A bare or stale
`status: compatible`, a self-consistent locally fabricated status, evidence
copied from another target, or a status without the matching bundled APK fails
closed. The evidence digest supplies integrity; the upstream revalidation
supplies source authenticity.

Consumer revalidation never re-resolves a provider configured as `latest`.
It re-fetches the status's frozen tag and requires the same release ID, then
re-applies the current versioned provider rule to that frozen release. Exact-tag
providers must still match the configured version; latest-tag providers must
still satisfy target-series declarations, architecture/filename patterns and
the complete required asset set. Every re-downloaded APK is parsed again, and
its package name, architecture, version and dependencies must match both the
provider rule and the recorded evidence.

Unknown providers, missing assets, wrong architecture/package manager,
untrusted URLs, absent digests, missing official dependencies, ambiguous
matches, unsafe archives and malformed APKs resolve to `unresolved` or
`incompatible`. No upstream installation script is downloaded or executed.
Selecting a provider without a configured rule emits an explicit unresolved
row and fails strict mode. Selecting any provider also requires a non-empty,
digest-matching official index; dependency validation is never skipped.

The downloaded artifact digest is verified during preparation. Each extracted
APK receives a second recorded SHA-256, and the exact `SHA256SUMS` file is
bundled beside the APKs. A provider with multiple APKs is fully validated in a
same-filesystem staging directory and published by one directory rename only
after every APK passes; a failed provider publishes nothing. On first boot, the
UCI default script checks that the
manifest and APK set match exactly and runs `sha256sum -c` before invoking
`apk add --allow-untrusted`. This prevents post-build substitution but does not
turn the packages into a locally signed APK repository; the remaining signing
limitation is explicit and must be considered when reviewing the plan.
