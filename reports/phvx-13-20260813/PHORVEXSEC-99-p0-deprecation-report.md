# PHORVEXSEC-99 — PHVX-13 P0 deprecation and audit-versioning report

Date: 2026-08-13
Branch: `fix/phvx-13-deprecate-p0`
Base: synchronized with `origin/main` at `303e897` (`v0.4.18`)

## Result

The four release-scoped requirements are satisfied without deleting P0 or changing its CLI contract.

| requirement | result |
|---|---|
| Warn when `--engine=p0` is selected | Added the exact requested deprecation message before constructing `NewEngine()` |
| Preserve NaN safety on `CoverageEngine` | Already present on `main`; `nan_property_test.go` tests finite output and selection neutrality directly on `CoverageEngine` |
| Prove ablation is not P0-vs-P1 | Added `TestAblationNeverReferencesDeprecatedP0Engine`; it fails if `ablation.go` mentions `NewEngine` |
| Version and replay the audit contract | Added `schemaVersion`, current `phorvex.audit.v1`, explicit legacy `phorvex.audit.v0`, and a replay test over every shipped audit JSONL |

## Audit compatibility

Newly marshalled records always contain:

```json
{"schemaVersion":"phorvex.audit.v1","kind":"phorvex.decision"}
```

The repository currently ships 10 matching audit JSONL files: 9 contain 1,196 records in total and 1
is intentionally empty. Every non-empty line is decoded by `TestReplayEveryShippedAuditJSONL`, which
also asserts that every stable legacy contract key is physically present. Historical records predate
the field, so the decoder assigns them
`phorvex.audit.v0` explicitly rather than confusing an absent version with the current contract.

The current-record test also verifies the stable required key set, including `risk`, `residual`,
`threatPosture`, `belief`, and `r6Counterfactual`. No field was renamed or removed in this change.

## Scope boundaries kept

- `engine.go`, `engine_test.go`, `internal/physics`, and `internal/belief` remain intact.
- The `--engine=p0` flag still works; it now warns.
- `Risk` was not renamed.
- `threatPosture` remains in the audit record.
- P0 deletion remains next-release work, exactly as the ticket requires.

## Verification

- `go build ./...`
- `go vet ./...`
- `go test -count=1 ./internal/audit`
- `go test -count=1 ./internal/decision -run 'Test(AblationNeverReferencesDeprecatedP0Engine|DecideNeverEmitsNonFiniteCost|DecideStaysSelectableUnderPoisonedTelemetry)$'`
- `go test -count=1 ./...`
- `go test -count=1 ./...` in `build/test-harness`
- `git diff --check`

PHORVEXSEC-123 / PR #21 is now merged into `main`; the formerly missing scenarios-export output
directory is present, so the unfiltered suite is part of this branch's final verification.

## Review note

This change creates the schema/replay prerequisite consumed by PHORVEXSEC-122 (PHVX-27). That follow-up
must stack after this branch and own vocabulary translation; it must not be folded into this deprecation
change.
