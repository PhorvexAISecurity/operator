# PHORVEXSEC-122 — PHVX-27 versioned audit-contract report

Date: 2026-08-13

Branch: `feat/phvx-27-audit-contract`

Base: `fix/phvx-13-deprecate-p0` at `a1dd77b` (PHORVEXSEC-99 / PR #37), synchronized with `main` v0.4.18

## Result

The task is no longer blocked: PHORVEXSEC-99 supplies the required
`schemaVersion` and corpus replay test. This branch consumes that prerequisite,
bumps the public audit contract to `phorvex.audit.v2`, and adds an actual
old-to-new translation path rather than only accepting old JSON.

Every new record is written as v2. Records with no version are classified as v0;
v0 and v1 records are translated into the canonical v2 in-memory form on read.
Unknown versions fail instead of being guessed.

## Published v1 to v2 migration map

| Category | Old | Canonical v2 | Result |
|---|---|---|---|
| fact kind | `modelFingerprint` | `modelIdentity` | attribution is renamed at the audit boundary |
| fact kind | `session` | `session` | same token, now explicitly scoped to ephemeral in-process KV/agent-session state |
| fact kind | `nodePlacement` | `retired:nodePlacement` | historical contribution is preserved without presenting it as current cover |
| decision field | `risk` | `coverageValue` | P1 recon coverage has an unambiguous name |
| decision field | `risk` under deprecated P0 | `threatRisk` | legacy threat-weighted value is preserved separately, so `coverageValue` never has two meanings |
| decision field | `belief` | `pHold` | one authoritative probability; an explicitly present old `pHold` wins |
| decision field | `threatPosture` | unchanged | retained and labelled observational under default P1 selection |
| decision field | `residual` | unchanged | retained and labelled observational under default P1 selection |

The map is available both in code through `V1ToV2Migrations()` and in
`phorvex/AUDIT-CONTRACT.md`.

## Translation behavior

Direction: **old to new on read**. There is no new-to-old writer.

- Re-serializing a translated record always writes v2.
- `cover:modelFingerprint` becomes `cover:modelIdentity`.
- `cover:nodePlacement` becomes `retired:nodePlacement`; its numeric contribution
  is retained, not silently discarded.
- Old P1 `risk` becomes `coverageValue`; old P0 `risk` becomes `threatRisk`.
- `belief` is used only when old `pHold` is physically absent.
- A v2 record containing retired `risk`, `belief`, `cover:modelFingerprint`, or
  `cover:nodePlacement` is rejected.

The compatibility shim expires when `phorvex.audit.v4` becomes current. At that
version it must be removed or renewed by an explicit schema decision and tests;
it cannot become an unbounded permanent shim.

## GPU taxonomy intentionally held

No `sideChannel` migration is published. I checked the audited taxonomy stack
`#12 → #28 → #29 → #31 → #13`. PR #31 itself records that the required
`PX_Reports_V1/coversets/COVERSETS-DECISION.md` authority is absent from this
repository, while the task explicitly forbids choosing between
`gpuCoresidency` and `gpuContentionChannel` before that cross-link exists.

Accordingly, the map excludes both proposed GPU targets, the test fails if either
appears, and old `cover:sideChannel` is preserved byte-for-byte. This is the
required hold, not an omitted implementation.

## Tests

- the inherited PHORVEXSEC-99 replay test still decodes every shipped JSONL line,
  and now verifies v0/v1 source versions translate into v2;
- a concrete v1 record proves field and fact-kind translation, including retired
  `nodePlacement` and authoritative `pHold`;
- a legacy P0 record proves threat risk is not relabelled as coverage;
- the new writer proves only canonical v2 names are emitted;
- v2 rejects retired field and fact tokens;
- the migration-map guard proves every settled item is listed, no GPU mapping is
  published, and the read shim has a fixed v4 expiry;
- P0 and P1 engine tests prove their primary value fields never mix.

## Verification

- `go test -race -count=1 ./internal/audit`
- `go test -count=1 ./...`
- `go build ./...`
- `go vet ./...`
- `go test -count=1 ./...` in `build/test-harness`
- `git diff --check`

PHORVEXSEC-123 / PR #21 is now merged into `main`, so the scenarios-export fixture
path is present and the unfiltered Phorvex suite is part of final verification.

## Scope and merge order

1. PR #37 — PHORVEXSEC-99 / PHVX-13: schema v1 and replay prerequisite
2. This branch — PHORVEXSEC-122 / PHVX-27: v2 migration contract and read shim

The existing replay test was extended rather than duplicated. The production
taxonomy cleanup remains in its owning PR stack; this change controls the public
audit boundary and changes no cover weights, action feasibility, optimizer
selection, or actuator behavior.
