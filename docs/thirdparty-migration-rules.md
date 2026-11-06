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
local tool supports it—package metadata architecture validation. Official
dependencies are checked against the frozen release index. A same-name OPKG
and APK is never compatibility evidence by itself.

Unknown providers, missing assets, wrong architecture/package manager,
untrusted URLs, absent digests, missing official dependencies, ambiguous
matches, unsafe archives and malformed APKs resolve to `unresolved` or
`incompatible`. No upstream installation script is downloaded or executed.

The downloaded artifact digest is verified during preparation. Each extracted
APK receives a second recorded SHA-256, and the exact `SHA256SUMS` file is
bundled beside the APKs. On first boot, the UCI default script checks that the
manifest and APK set match exactly and runs `sha256sum -c` before invoking
`apk add --allow-untrusted`. This prevents post-build substitution but does not
turn the packages into a locally signed APK repository; the remaining signing
limitation is explicit and must be considered when reviewing the plan.
