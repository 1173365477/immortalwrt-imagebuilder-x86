# T13 build-path audit

Baseline: `8933c5d0272162e8a2c88ef98d8b9722669f9e66`.

## Baseline call chain and findings

`workflow_dispatch → resolve_version.py → parse-owut-report.py →
resolve-packages.py → validate-manifest.py → fetch-thirdparty.py →
build-image.sh → make image`

The build entry did not consume `system-snapshot-v1.json` or
`migration-plan-v1.json`. It accepted mutable generated files and the repository
overlay, resolved `latest` and external metadata within the build run, and
allowed non-strict unresolved state to continue. The workflow had write
permission and a release-publishing branch. These were direct gate bypass,
provenance, TOCTOU and misleading-artifact risks.

## T13 supported call chain

`workflow_dispatch(request_id, snapshot_ref, target_version) → exact checkout →
immutable request/path validation → verify-build-input.py → private stage →
build-image.sh (same verifier) → frozen ImageBuilder SHA check → pre-make stage
recheck → make image → generate-build-provenance.py (same verifier) → artifact
safety → upload`

There is one supported `make image` call and it follows the shared verifier.
Legacy dispatch fields remain visible but are never passed into analysis,
resolution, Provider selection or ImageBuilder. `create_release=true` is
rejected and the workflow has only `contents: read`.

## Threat decisions

- Mutable latest/ref/URL: absent from the build decision path; frozen Release
  and asset identities are revalidated without choosing a newer release.
- Arbitrary local path/traversal/symlink: rejected before reading evidence.
- Self-consistent forged Provider JSON: insufficient; frozen upstream identity,
  full asset set, APK metadata/dependencies and bundled bytes are revalidated.
- Request/code commit self-reference: avoided with a frozen ancestor code
  commit plus an exact protected-tree diff to the evidence commit.
- Tampering after validation: package and overlay bytes are staged privately
  and re-hashed immediately before ImageBuilder.
- Failed/degraded build artifact: upload requires success and artifact-safety;
  no degraded/non-strict build state exists.
- Build success mistaken for upgrade safety: provenance keeps
  `compatibility_validated=false` and `flash_ready=false`.

No alternate CLI is supported without `BUILD_INPUT`, trusted repository and
runtime commit. Direct invocation fails before network access.
