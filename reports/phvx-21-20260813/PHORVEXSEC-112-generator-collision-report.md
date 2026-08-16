# PHORVEXSEC-112 — PHVX-21 generator collision report

Date: 2026-08-13
Branch: `fix/phvx-21-generator-collisions`
Base: `fix/phvx-20-disjointness-guards` at `05a41e7` (PR #38)

## Result

The action-set generator no longer silently max-merges a recon key claimed by two
pod decision blocks. Same-pod overlap remains legal; cross-block overlap rejects the
entire tick before selection, learning, decision emission, or actuation.

| Requirement | Result |
|---|---|
| Distinguish collision types | The generator tracks the owning pod block for every fact and every declared cover key |
| Within-pod overlap | Repeated use by actions in the same block remains legal; the existing maximum-weight merge is retained only within that owner |
| Cross-block collision | `ActionSet.Rejected` is set, `CrossBlockCollisions` records the key and both owners, and all partially generated candidates are removed |
| Hard error | `ActionSet.CollisionError()` propagates through `CoverageEngine.DecideChecked`; the rejected tick returns no decisions |
| Metric | `phorvex_action_set_rejections_total{tenant,reason="cross-block-collision"}` increments |
| Log | `runner.Manager` logs the error with tenant and optimizer and explicitly suppresses decisions and actuation |
| Startup | The parent PHORVEXSEC-111 change validates every registered profile before the ticker starts and refuses startup on a cross-block key |

The generator scans all `CoverByAction` entries, including actions disabled by the
current policy. A taxonomy collision is therefore treated as a structural violation,
not as something that becomes safe merely because one tenant has not enabled the action.

## Failure behavior

On the first cross-block collision, generation stops and returns an `ActionSet` with:

- `Rejected = true`
- one `CrossBlockCollision` containing the key, existing block, and conflicting block
- zero selectable candidates
- a non-nil `CollisionError()`

The production runner uses the checked optimizer seam. It does not fall back to the
legacy unchecked `Decide` method after an error, does not emit decisions, and does not
actuate. The failed tenant tick is timestamped normally so the controller retries on
the configured policy cadence instead of creating a tight retry loop.

## Tests

- `TestWithinPodOverlapDoesNotRejectActionSet` — two actions cover one same-pod fact without error
- `TestCrossBlockCollisionRejectsActionSet` — a shared key records both blocks, rejects the set, and leaves zero candidates
- `TestCoverageEngineRejectsCrossBlockCollision` — checked optimization returns an error and no decisions
- `TestTickUsesCheckedOptimizerAndRejectsCollision` — the runner never falls back to unchecked selection
- Parent guard tests retain startup refusal and the adversarial multi-pod topology proof

## Verification

- Focused collision tests in `internal/actionset`, `internal/decision`, and `internal/runner`
- `go test -count=1 -skip TestScenariosExport ./...`
- `go build ./...`
- `go vet ./...`
- `go test -count=1 ./...` in `build/test-harness`
- `git diff --check`

The unfiltered decision suite still encounters the pre-existing
`TestScenariosExport` missing `bin/scenarios-instances.jsonl` failure on `origin/main`.
PHORVEXSEC-123 / PR #21 owns that fixture issue; this branch does not alter it.

## Merge order

1. PR #38 — PHORVEXSEC-111 / PHVX-20 startup and topology guards
2. This branch — PHORVEXSEC-112 / PHVX-21 generator and tick rejection
3. Cover withdrawals and later PHVX-30 taxonomy work
