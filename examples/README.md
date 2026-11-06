# Reproducible Sprint 2A example

The sanitized example snapshot is
`tests/fixtures/system-snapshot-sprint2a.json`. It contains no device paths,
addresses, tokens or real configuration. The corresponding positive strict
plan is `examples/migration-plan-v1.example.json`; its release hashes and URLs
are deterministic fixture evidence, not a claim about a newly published
release.

The integration test builds the same flow entirely offline:

```text
system-snapshot-v1
  -> frozen release capabilities and verified package index fixture
  -> per-package official/third-party compatibility
  -> migration-plan-v1
  -> strict build gate
```

The positive plan permits only a future GitHub firmware build request. Its
`build_status` is `not_started`, `compatibility_validated` is false, and
`flash_ready` is permanently false.
