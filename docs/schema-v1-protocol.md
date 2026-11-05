# Smart Upgrade v1 protocol

The three Draft 2020-12 schemas are sidecar contracts. They do not replace the historical `system-analysis.json` CLI output or its file name.

## Identity and digest

`system-snapshot-v1` uses `snapshot_id = urn:sha256:<digest>`. `evidence-sha256-v1` means: for each allow-listed evidence slot in the documented order, emit `logical_name:<lowercase sha256>` or `logical_name:missing`, separated by LF, then SHA-256 that byte stream. Host paths, secrets and report presentation are not part of the digest. This is an evidence-set identity, not RFC 8785 canonical JSON.

Migration plans carry both `source_snapshot_id` and `source_snapshot_digest`. Build results carry both `source_plan_id` and `source_plan_digest`, plus the GitHub repository, exact 40-character Commit SHA, workflow run ID and run attempt. Consumers must reject a digest or ID mismatch instead of silently rebasing a plan.

## Status and safety semantics

- `ok`: required evidence is complete and internally consistent for that artifact.
- `partial`: useful output exists, but at least one non-fatal evidence set is incomplete.
- `blocked`: a known condition prevents the requested next step.
- `failed`: generation or validation failed; `errors` must explain why.
- `unknown`: the artifact cannot establish a more specific state.

`build_allowed` only permits a GitHub firmware build request. It never permits flashing. In MVP v1, `flash_ready` is unconditionally `false` in both migration plan and build result. Unknown target, image, package intent or compatibility evidence cannot become `compatible`.

Package `origin` (`official`, `third_party`, `unknown`) is independent from `install_reason` (`system_default`, `manual`, `dependency`, `unknown`). APK world membership is an intent candidate, not automatic proof of a manual install. Dependency strings and virtual provides are retained as raw expressions; parsed names never replace the raw evidence.

## Privacy and extensions

`redacted` is the default upload-safe representation. Storage paths, devices, Docker mount names and destinations are null while anonymous `mount-N` relationships and risk classes remain. `local` may contain paths and must not be uploaded automatically.

Core objects reject unknown fields. Compatible extensions must use a top-level `x-<name>` key. Any incompatible semantic change requires a new schema version rather than changing the meaning of v1.

