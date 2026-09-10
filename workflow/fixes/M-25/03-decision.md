# M-25 · 03 Decision (claude) — BELIEF max-consequence stage merge

Base `62d6f48`. Commit `ddea288` on `t1/belief-m025-max-consequence-stage-merge` (pushed). Roles: K3 owed proposer (T1-C debt) → I proposed the FAST path in bus 329 (I implement/run Go; K3 blind-derives §A + P3 + L3, keeps the proposer seat for the next ticket). Awaiting K3 §A + P3.

## Decisions
- **Merge rule = max-consequence over the EXISTING `consequence()` ordinal.** Rank is not invented (P-ORDER): both the event and AI chains are the same `Stage` enum. Crucial: `consequence()` is NOT ordinal-monotonic — the AI chain interleaves (gpu-side-channel ordinal 5 = 0.15, below persist ordinal 2 = 0.6) — so the merge compares consequence(), not the raw ordinal. `maxByConsequence(a,b)` returns the higher consequence, ties keep `a` (the event-incorporating current stage). NO INSUFFICIENT-EVIDENCE tag and NO AI-ENGINEER ordering decision were needed (the order pre-exists in consequence(), not the Sojourn maps — K3 B.2 phrasing fix); AI-ENGINEER functional review (task #5) still confirms "max is never semantically wrong for any pair."
- **Merge only, not the M-26 gate (P2).** Arm (1) still fires on physics; M-25 only stops it lowering a stage. HasEvidence/prov/cadence/event-trust untouched. consequence()/ordinal/Sojourn maps unchanged.
- **Record (P4):** `StageAI` + `StageMergeRule="max-consequence"` added to the Assessment, the decision, and the audit record, beside the existing `StageEvent`(event) + `Stage`(merged).
- **aiClassified stays true when the AI stage LOSES the max (B.3):** the fix changes only the merged `stage`, not `aiClassified`; a workload the AI arm matched is still flagged AI-classified even when its stage didn't win. Verified not to worsen M-26 (that ticket gates arm (1)'s HasEvidence contribution separately). 
- **The T1-A pin flip is IN 04 (B.2):** `leakage_gate_test.go` `..._DeclaredDowngrade`→`..._NoDowngrade` is part of commit ddea288 (my 01 test-list omitted it; the diff carries it). It is the empirical proof against the numeric-ordinal no-op reading K3 flagged.
- **Escalation preserved (P-BELIEF):** an AI stage above the event stage still wins (recon + model-theft → model-theft). The detector-derived stage is a floor, never a ceiling.

## Parallel-safety (the user's constraint)
Independent of the two open PRs. Depends only on T0-D (landed) + soft T1-A (landed @0.4.74). Branched off origin/main (NOT stacked on T1-B/T1-C). hazard.go overlap is additive: T1-C @ ~:292 (disjoint), T1-B @ :356+ StageClock.Observe (adjacent to the :354-355 merge — one small additive rebase), M-25 @ :354-355. Second/third to merge rebases. All three deploy + live-test together; M-25 does NOT require the two merged first.

## Deliberate test change (evidence-discipline)
`leakage_gate_test.go`'s `..._DeclaredDowngrade` pin was authored during T1-A to DOCUMENT the M-25 downgrade (asserted gpu-side-channel) and its own comment says "when M-25 lands, its diff flips exactly this assertion." Flipped to assert `StagePersist` and renamed `..._NoDowngrade`. RED proof (evidence/RED_downgrade.txt): the original pin passes asserting gpu-side-channel on base 62d6f48; the fix returns persist. Strictly the sanctioned change breaking a documented-old-behavior assumption — not a green-wash.
