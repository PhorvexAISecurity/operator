# Proposal (PHORVEXSEC-289): make `crm-refund-revoke` comparable in the cost-v1 (REVISED / 281-287) objective

**Status: PROPOSAL — comparison-enabling, needs team sign-off. DO NOT MERGE / DO NOT DEPLOY.**
Reviewer: @hamihoriyat · Assignee: @Milad93R

## Why
Zeinab's review point: `crm-refund-revoke` is **not** in the cost-v1 admission action vocabulary, so an
OLD-vs-REVISED comparison on CRM is not apples-to-apples — REVISED can never pick the action OLD uses to
defend the cross-record refund abuse. This proposal makes the comparison fair and reports what REVISED
*actually* does once it can pick the action.

## Scope / provenance
The cost-v1 "revised objective" (EvaluateV1 / `NOT_IN_V1` / SecurityCandidatesV1) is **not present in
operator-refactored** on any branch — it lives only on the pinned reference lineage
`github.com/phorvex/phorvex @ 4d9ec284`. So this PR carries the change as a reviewable **patch** against that
lineage plus the measured decision evidence; it adds **no** code to the deployed tree. Apply target when
cost-v1 is ported: `internal/cost/v1admission.go`, `internal/decision/v1_candidates.go`.

## The change (minimal, reversible) — see `phvx-289-crm-refund-revoke-costv1.patch`
1. **Vocabulary** (`internal/cost/v1admission.go:219`): add `crm-refund-revoke` to the admitted set
   `{rotate, request-drain, quarantine, kv-reset}` so the candidate is no longer dropped `NOT_IN_V1:ACTION`.
2. **Value wiring** (`internal/decision/v1_candidates.go`, `v1SecurityValueProjection`): a *bound* CRM refund
   observation is **live-corroborated** evidence (`bindCRMRefundObservation` validates guard/Service/policy/
   target-Pod identities), not a bare label declaration, so preserve the policy's label-derived business asset
   value (`data-class`) for such pods instead of flooring it to `minimumHeldAssetWeight` (0.001). This is
   consistent with the I3 rationale ("declarations alone are not corroborated security evidence"). Reversible:
   delete the block to restore the pure I3 floor.

## Measured result on the SAME frozen CRM input as the v6 report (sha256 `2c4e64b3…`, target pod `…m8brj`, `data-class:restricted`, bound trusted refund observation)

| arm / state | selected | crm-refund-revoke | defends refund abuse? |
|---|---|---|---|
| **OLD (p1-coverage, deployed)** | `crm-refund-revoke` | CoverageValue **1.6579844**, Net 1.60 | **YES** |
| REVISED cost-v1 — *v6 baseline* (vocab-excluded) | hygiene `rotate` (V 0.00199) | V 0.001658, `NOT_IN_V1:ACTION` | no |
| REVISED cost-v1 — **+vocab** | hygiene `rotate` (V 0.00199) | V 0.001658, `MAX_MOVES` | no |
| REVISED cost-v1 — **+vocab +value** | hygiene `rotate` (V **1.9895813**) | V **1.6579844** (== OLD), `MAX_MOVES` | no |

**Conclusion.** The vocabulary was *necessary but not sufficient*. With the business value restored,
`crm-refund-revoke` is valued **byte-identically to OLD** (1.6579844183443524 vs 1.6579844183443522), yet
REVISED still selects the event-lifted **hygiene rotate** and blocks `crm-refund-revoke` only on `MAX_MOVES`
(one move per pod/tick). The deciding gate is **not** the vocabulary: cost-v1 removed the SLO cost-ceiling
that the deployed OLD engine uses to EXCLUDE that rotate (`conformal-slo: worst-case cost 1.60 > ceiling
1.20`), which is exactly why OLD selects `crm-refund-revoke`. `crm-refund-revoke`'s sole non-selection reason
is `MAX_MOVES` (it passed vocab/worth/floor/quorum/budget) → it is selectable, and would be selected and
**defend** if the revised objective re-introduced cost-aware suppression of the competing rotate.

So making CRM apples-to-apples needs more than this patch: it needs a decision about rotate-suppression in the
revised 281/287 objective. **That is why this is a proposal, not a merge.** The decision comparison above
proves the point without deploying anything.

## Verification
`go build ./...`, `go vet ./internal/cost/ ./internal/decision/`, and `go test ./internal/cost/
./internal/decision/` are **GREEN** with go1.26.1 (see `evidence/build/go-build-test.log`). The OLD/coverage
arm is a separate engine and is byte-for-byte unaffected by this patch.
