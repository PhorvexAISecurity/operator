# PHORVEXSEC-128 (PHVX-72) — completion report: the threshold, measured

Date: 2026-08-09 · Branch `fix/phvx-72-threshold-sweep` · Commit `0104406`
Follows the threshold analysis attached to this ticket (`phorvexsec-128-threshold-analysis.md`).

## Verdict: the analysis's **first branch** applies — a scalar threshold exists, and it works

`U_competitive = 0.0502–0.0504 < 0.075`, so the interval in §4 is non-empty and §7's first branch
holds. The threshold is implemented, and for the first time in this ticket the defence is shown to
**change a selection** rather than merely to be reachable.

Two limits were found that the analysis could not have predicted from the code, and both are now
asserted by tests rather than described in prose.

## 1. Answering §6 — the fine-grained sweep

Swept an evidence-less candidate against a genuine, nearly-overdue foothold through the real
`Decide()` path, one move slot.

**Finding 1 — the zero-coverage region is not a provenance effect.** Coverage is exactly 0 below
`AntiOverRotationWindow` and jumps discontinuously the moment it is cleared:

```
 295s  U=0.0546  covDecoy=  0.000   decoyWins=false
 300s  U=0.0548  covDecoy=274.618   decoyWins=true     <- AntiOverRotationWindow = 5m in the fixture
```

The cause is `feasibility/defaults.go:87` — below the window the candidate is **infeasible**, so it
has no coverage to discount. §6 asked for "the first positive coverage point"; it is not a property
of the coverage model at all, it is the feasibility gate. First positive and first
budget-competitive coincide, because coverage arrives as a step, not a ramp.

**Finding 2 — the sweep must use the LIVE policies, not the fixture.** The fixture's 5m/1h is not
what production runs:

| tenant | antiOverRotation | proactiveFloor |
|---|---|---|
| litellm, phorvex-live-demo, voice | 90s | 15m |
| nats | 60s | 15m |
| vllm | **15m** | 15m |
| mock-rag-chatbot | 90s | **15s** |

With a 60–90s window the onset urgency is **0.0502–0.0504**, not the fixture's 0.0548. That is
essentially the baseline — which is exactly why comparing against the baseline is inert.

## 2. The threshold

Both endpoints come from the consequence table; neither is tuned:

```
BaselineStageUrgency        = 0.5 * consequence(Recon)          = 0.050
LowestEvidencedStageUrgency = 0.5 * consequence(GPUSideChannel) = 0.075
ProvenanceEvidenceThreshold = midpoint                          = 0.0625
```

This is the value §5 flagged as *"may still become inactive before coverage matters"*. Measurement
resolves that concern: competitive coverage begins at 0.0502, well below 0.0625, so the threshold is
active across the whole competitive onset. Defined once in `killchain`, consumed by both
`coverage.go` and `optimality.go`.

## 3. Limit A — the window closes entirely for two live tenants

The discount is reachable only while

```
AntiOverRotationWindow <= t < ProactiveFloor        and     U(t) <= threshold
```

Below the window: infeasible. At or above the floor: `prov()` returns 1 because the asset is
genuinely due. So a tenant whose window is at or above its floor has an **empty** interval:

| tenant | window | status |
|---|---|---|
| litellm, live-demo, voice | `[90s, 495s)` | active, 405s wide |
| nats | `[60s, 495s)` | active, 435s wide |
| **vllm** | `[900s, 495s)` | **EMPTY** |
| **mock-rag-chatbot** | `[90s, 15s)` | **EMPTY** |

**`vllm` produced 1020 of the last 1025 live decisions.** On the busiest tenant on the cluster this
defence cannot act at any threshold — not because of a bug, but because its 15m/15m policy leaves no
interval in which a candidate is both selectable and not yet due. This is a **policy** finding, not a
code one, and it should not be closed silently: either the ticket accepts that the defence is scoped
to short-window tenants, or `vllm`'s window/floor are revisited.

## 4. Limit B — the discount absorbs about 2.5×, no more

`provFloor = 0.34` scaled by exposure gives 0.406 at the onset, so the discount can only reverse an
advantage below `1/0.406 ≈ 2.46×`. Measured at the onset with a genuine foothold at weight 40:

| manufactured weight | raw advantage | decoy wins raw | after discount | reversed |
|---|---|---|---|---|
| ≤ 120 | ≤ 0.80× | no | — | nothing to fix |
| 160 | 1.06× | yes | 23.8 vs 55.2 | **yes** |
| 240 | 1.59× | yes | 35.6 vs 55.2 | **yes** |
| 400 | 2.64× | yes | 59.2 vs 55.2 | no |
| 1000 | 6.59× | yes | 147.7 vs 55.2 | no |

So the defence blunts a *marginally* manufactured decoy and does not stop a *strongly* manufactured
one. Deepening `provFloor` is not free — it is the same knob that would start penalising genuine
fresh assets — so it is left as it is and the limit is recorded instead.

## 5. §8 acceptance criteria

| # | criterion | status |
|---|---|---|
| 1 | `prov() < 1` for a fresh evidence-less asset | ✅ `TestProvFloorIsReachable` |
| 2 | genuine early evidence keeps full weight | ✅ `TestThresholdPreservesWeakestGenuineEvidence` (0.0625 < 0.075) + `TestGenuineEvidenceIsNotDiscounted` |
| 3 | threshold and `provFloor` defined once, reused by both paths | ✅ `killchain.ProvenanceEvidenceThreshold`; `provFloor` deduplicated in the previous commit |
| 4 | end-to-end fixture shows the floor CHANGES selection | ✅ `TestProvenanceFloorChangesSelection` |
| 5 | the same test fails with the floor disabled / the old gate restored | ✅ **verified against both** |

Criterion 5, run explicitly:

```
gate = StageUrgency > 0                            -> FAIL  (the original tautology)
gate = StageUrgency > BaselineStageUrgency         -> FAIL  (the first fix — inert)
gate = StageUrgency > ProvenanceEvidenceThreshold  -> ok
```

§8's closing condition — *"if criterion 4 cannot be constructed, retire the floor"* — does not
trigger: it was constructed. `pHold` does not eliminate every decoy first.

## 6. Fixture correction worth flagging

The first sweep gave both candidates the same neighbour (`ns/crown`). Because they then share a recon
fact, the loser's reported `CoveredWeight` is its **marginal** value after the winner already consumed
that fact — which silently understated the competition and made the genuine foothold look weaker than
it is. All numbers above use disjoint neighbours. Any future work on this fixture should keep them
disjoint.

## 7. What is NOT claimed

- Not that the anti-decoy defence is now complete. It is bounded by §3 and §4, both measured.
- Not that it protects `vllm`. It does not, and that is the largest tenant.
- Not validated on the live cluster: this is a decision-path change proven by tests against the real
  `Decide()`, using live policy values. It has not been exercised against a real RL adversary.
