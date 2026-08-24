# PHORVEXSEC-125 (PHVX-30) — P-COVERSETS taxonomy report

Updated: 2026-08-24 · Branch `feat/phorvexsec-125-cover-taxonomy`

## Disposition

Implemented originally as a stacked change on `feat/phorvexsec-91-cost-model` because PHVX-9b's
non-zero extended-action cost model is a hard prerequisite. PR #64 is now merged. Current `main`
was merged into this branch without conflict on 2026-08-24, so PR #67 can be reviewed and tested
independently against `main`.

The existing PHVX-9e false-cover withdrawals, PHVX-20 block guards, PHVX-21 fail-loud collision
handling, PHVX-26a GPU split, dead `nodePlacement` removal, and the corrected
`kv-migrate-invalidate → session` mapping were retained. The older ticket text predates those
changes; they were verified rather than reimplemented.

## Implementation

- Added explicit `pod`, `node`, `model`, and `service` fact scopes.
- Changed fact identity to `scope|asset|kind[|edge]`.
- Kept every selectable fact pod-owned. `gpuColocation` is documented as workload-level exposure
  even though its input is node-derived.
- Kept lateral edges origin-owned and documented the resulting conservative under-crediting.
- Added Tier-2 audit facts:
  - `nodeFoothold` at node scope;
  - `modelIdentity` at model scope; and
  - `guardrailVariant` at the declared route-service scope.
- Added Tier-3 pod-attributed CANNOT-HELP facts: `credential`, `retrievalState`,
  `artifactProvenance`, and `controlPlanePersistence`.
- Gave every Tier-2/3 fact zero action cover.
- Projected objective weights and collision ownership only through keys referenced by an action
  cover. Shared audit keys therefore cannot affect marginal gain, candidate generation,
  feasibility, cost, normalization, or cross-block rejection.
- Updated attribution parsing and the exactness/self-check wording for scope-prefixed keys.
- Did not add node/model decision blocks, alter the partition, restore withdrawn cover grants, or
  loosen any disjointness/exactness assertion.

## Mathematical checks

The attached math ruling is implemented directly:

- Q1: selectable facts retain one pod owning block; GPU exposure and lateral-edge caveats are
  documented.
- Q2: a regression injects shared and pod audit facts with weight `1e12`; candidates, objective
  weights, exclusions, feasibility/cost path, and collision result remain byte-equivalent.
- Q3: a paired exact-arm test compares the full taxonomy with the identical profile after removing
  only Tier-2/3 facts.

Identical six-asset fixture, before and after:

| Measurement | Before | After |
|---|---:|---:|
| Selected | `crown1/quarantine`, `crown2/quarantine` | same |
| Greedy objective | 7.157000000000 | 7.157000000000 |
| Exact objective | 7.157000000000 | 7.157000000000 |
| Optimality ratio | 1.000000000000 | 1.000000000000 |
| Disjoint | true | true |
| Exact skipped | false | false |

The exact arm on this branch is governed by the newer PHVX-23 work-budget guard rather than the
obsolete flat 18-asset cap described in the original ticket. This fixture was admitted and actually
ran; no skipped result was presented as a ratio.

## Verification

- `go test ./...` — pass
- `go vet ./...` — pass
- `go build ./...` — pass
- `go test -race ./internal/recon ./internal/actionset ./internal/decision -count=1` — pass
- required taxonomy, orphan-cover, block-prefix, adversarial-disjointness, identical-cover,
  shared-key mutation, and greedy/exact tests — pass
- `git diff --check` — pass

## Final PR gate

PR #64 has landed and this branch now contains current `main`. Retarget PR #67 to `main`, require
its independent CI to pass, and only then move PHORVEXSEC-125 to `Test`.
