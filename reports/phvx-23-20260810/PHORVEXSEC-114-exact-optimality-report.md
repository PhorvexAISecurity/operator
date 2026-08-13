# PHORVEXSEC-114 (PHVX-23) — items 1, 2 and 4 — report

Date: 2026-08-10 · Branch `fix/phvx-23-exact-skipped` · Commits `df6e407`, `ecfaaf9`, `f5ba9f3`
Item 3 (bounding the gap) belongs to the ticket's math owner and is **not** covered here — but its
premise has moved; see §5.

## Headline

The exactness claim is now **measured at production scale**: 76 assets at the live move budget,
`ratio = 1.000000000000, gap = 0`. The ticket's central complaint — *"your central technical claim has
never been verified at production scale"* — is answered by measurement rather than by argument.

That became possible because item 2 turned out not to be a tuning exercise. The cap was on the wrong
variable.

## 1. Item 1 — a skipped solve rendered as a perfect score

The ticket predicted `ratio = 0` being mistaken for a measured zero. There are two code paths, and the
live one was worse than that.

| path | behaviour above the cap |
|---|---|
| `computeOptimality` (ablation) | correct — sets `ExactSkipped`, leaves ratios at 0 |
| `probeArm` (optimizer probe) | **discarded the flag** |

`probeArm` dropped `skipped`, so the resulting `exObj = 0` fell into the branch meaning *"the exact
solve ran and correctly selected nothing, so the ratio is 1"* — and the arm reported
`greedyRatio = swapRatio = 1.0000`. The dashboard rendered that green. A computation that never ran
was displayed as a perfect score, which is the *"stale 1.0 with no signal"* the ticket warns about and
is worse than a bare 0: a 0 at least looks wrong.

**Root cause:** `exObj == 0` carries two meanings that were conflated —

- *skipped* → nothing was measured;
- *not skipped* → the solve ran and correctly selected nothing, where 1 is genuinely right.

Now separate branches. `TestZeroObjectiveIsNotConfusedWithSkipped` pins the second so the fix cannot
silently swallow a real measurement.

`OptimizerProbeArm` carries `ExactSkipped`; the dashboard's `ProbeArm` renders `n/a` instead of a
number, matching what the ablation table at `bench.tsx:239` already did.

**Reachability, stated honestly:** the shipped probe fixtures hold 4 assets against a cap of 18, so
this did not fire in production. It was latent. The ticket flags item 1 as a prerequisite for PHVX-28
precisely because promoting node/model to their own blocks raises the block count.

The regression test fails against **both** pre-fix shapes — flag discarded, and flag kept with the old
ratio logic.

## 2. Item 2 — the cap was on the wrong variable

`exactBruteForceAssetCap = 18` had no recorded derivation. Measuring the runtime curve
(k = candidate actions per asset):

| n | k | B | exact solve |
|---|---|---|---|
| 76 | 6 | 1 | **0.98 ms** |
| 600 | 6 | 1 | 28.7 ms |
| 76 | 6 | 2 | 102 ms |
| 300 | 6 | 2 | 4.7 s |
| 76 | 6 | 3 | 20.3 s |
| 18 | 6 | 4 | 2.8 s |

Cost is driven by the **move budget B**, not fleet size. So a flat asset cap was wrong in both
directions:

- **too strict** — every live tenant policy sets `maxMovesPerTick = 1`, and at B=1 the solve reaches a
  600-asset fleet in 29 ms. The cap refused at 19. *This is the concrete reason the claim had never
  been measured at production scale.*
- **too loose** — at B=4, 18 assets is "under the cap" and takes 2.8 s.

The guard now estimates the work the enumeration will actually do — `Σ_{j≤B} C(n,j)·k^j` candidate
sets — and skips above 200 000, roughly 0.2–0.6 s worst case at the measured 1–3 µs per set. It sits
on the on-demand ablation/console path, not the per-tick decision loop. Overflow returns `+Inf`, so a
huge fleet always skips rather than wrapping to a small number.

`TestWorkBudgetReachesTheLiveFleet` pins each measured point against the guard, so the derivation
cannot drift away from the numbers it was built from.

## 3. The measurement this unlocked

`TestGreedyIsExactAtProductionScale`, direct brute force at the live budget:

```
18 assets, B=1: ratio=1.000000000000 gap=0 disjoint=true
40 assets, B=1: ratio=1.000000000000 gap=0 disjoint=true
76 assets, B=1: ratio=1.000000000000 gap=0 disjoint=true
```

This is a real brute-force comparison, not a bound and not an extrapolation.

## 4. Item 4 — the claim, restated

The proof is the strong part and is scale-free; the measurement was the weak part and was being quoted
as though it were not. Every surface now states both:

> Exact optimality is **proven structurally** — with block-ownership plus the partition constraint the
> objective is modular over a truncated partition matroid, so the greedy is exact by Rado–Edmonds, and
> that does not depend on fleet size. The empirical check is separate and bounded, and is measured at
> **76 assets, B=1: 1.000000000000, gap 0**.

Swept: `P5-FINAL-REPORT.md` (headline, evidence table, claim list), `P-OPTIMIZE-RATIO-DECISION.md`,
`PROJECT-LOG.md`, `NEXT-SESSION.md`, and the dashboard bench tooltip.

Statements of the form *"asset-disjoint ⇒ modular ⇒ provably optimal"* were **left unchanged** — they
are claims about the proof and were already correct. The dashboard tooltip now also says `n/a` means
*not measured*, never a score.

## 5. Effect on item 3 (not mine — flagging only)

Item 3 reads *"Brute force won't reach 76. Choose a bounding method (LP relaxation, randomized upper
bound…)"*. At the live budget it **does** reach 76, in under a millisecond, and the measured ratio is
exactly 1. So the falsification test item 3 asks for can be run directly rather than relaxed — at
least for B=1. A bound is still the right tool for larger B (B=3 at 76 assets is 20 s), so the item is
not obsolete, only narrowed. That call belongs to the ticket's math owner.

## 6. Not claimed

- Not that the exact arm is tractable in general. It is bounded, and the bound is now honest.
- Not that the 76-asset fixture is the live fleet. It mirrors the shipped fixture's shape at live
  scale; the live pods are not replayed here.
- The dashboard change was **not typechecked** — `node_modules` is not installed in this environment.
  The edit adds one required field to an interface fed only by the API; no mock constructs it.
