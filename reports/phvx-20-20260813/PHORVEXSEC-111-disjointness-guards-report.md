# PHORVEXSEC-111 — PHVX-20 disjointness-guard report

Date: 2026-08-13
Branch: `fix/phvx-20-disjointness-guards`
Base: `origin/main` at `89a027e`

## Result

The production path now fails closed at startup if a registered recon profile emits a
cover key outside its owning pod block. The check runs once before the ticker starts;
no validation work was added to `Decide()` or the per-tick path.

| Requirement | Result |
|---|---|
| G1 — static block-prefix guard | `recon.ValidateRegistryCoverKeys` checks every registered profile and every branch probe; every cover key must start with `<namespace>/<pod>\|` |
| G2 — adversarial topology | Eight GPU/MIG pods share two nodes and one `ModelID`; every mutating action is enabled and the production `coversDisjoint` checker must stay green |
| G3 — generator collision failure | Owned by PHORVEXSEC-112 / PHVX-21, stacked immediately after this branch so collision recording and tick rejection remain one coherent change |
| G4 — registry-wide coverage | Both startup validation and adversarial testing iterate `recon.Registry.All()`; no profile name is hardcoded |
| Production startup | `runner.Manager.Start` returns an error before creating the ticker when validation fails |

## Mutation proof

The tests introduce `shared-block|podIdentity` and `shared-block|gpuColocation` deliberately.
The first is rejected by the block-prefix validator, the second makes the production
`coversDisjoint` checker report a cross-asset collision, and an invalid registered profile
prevents `Manager.Start` from starting even when its context is already cancelled.

The `gpuColocation` condition remains represented as a per-pod fact. Although the measured
co-residency multiplier comes from a node condition, every emitted fact key is still owned by
the pod decision block. No node block or non-pod decision type was introduced.

## Scope and sequencing

This branch establishes the invariant before any taxonomy edits to `profile.go`. It does not
change the objective, greedy selection, fact taxonomy, cover grants, action generation, or CI
workflows. PHORVEXSEC-112 is intentionally a separate stacked change because it owns the
`ActionSet` collision contract, metrics/logging, startup rejection, and per-tick rejection.

Merge order:

1. PHORVEXSEC-111 / PHVX-20
2. PHORVEXSEC-112 / PHVX-21
3. Cover withdrawals and later taxonomy work

## Verification

- `go test -count=1 ./internal/recon ./internal/runner`
- `go test -count=1 ./internal/decision -run 'Test(AdversarialTopologyStaysDisjoint|GreedyIsExactOnShippedFleets|SelfCheckFiresOnSharedKey)$'`
- `go test -count=1 -skip TestScenariosExport ./...`
- `go build ./...`
- `go vet ./...`
- `go test -count=1 ./...` in `build/test-harness`
- `git diff --check`

The unfiltered decision suite still encounters the pre-existing
`TestScenariosExport` missing `bin/scenarios-instances.jsonl` failure on `origin/main`.
PHORVEXSEC-123 / PR #21 owns that fixture issue; this branch does not alter it.
