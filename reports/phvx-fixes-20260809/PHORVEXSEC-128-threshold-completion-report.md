# PHORVEXSEC-128 (PHVX-72) — completion report: the threshold, measured

Date: 2026-08-09 · Branch `fix/phvx-72-threshold-sweep` · Commit `0104406`
Follows the threshold analysis attached to this ticket (`phorvexsec-128-threshold-analysis.md`).

## Verdict: the analysis's **SECOND branch** applies — an explicit evidence gate, not a threshold

The interval in §4 does exist (`U_competitive = 0.0502–0.0504 < 0.075`), and a threshold of 0.0625
was built and shown to change a selection. **Then conditions 2 and 3 of §5 were measured, and they
hold — so that threshold had to be withdrawn.** §7's second branch says exactly this case calls for
an explicit evidence gate, and that is what shipped.

The defence now changes a selection *and* leaves genuinely-attacked pods alone. Two limits remain,
both asserted by tests rather than described in prose.

### Why the threshold was withdrawn (§5 conditions 2 and 3, measured)

`stageFromEvent` only lifts the stage above Recon for a HIGH/CRITICAL event or a recognised type, and
a neighbour event never lifts it at all. At 90s of exposure:

| asset | StageUrgency |
|---|---|
| no evidence at all (a true decoy) | 0.0504 |
| **direct LOW-severity event on the pod** | **0.0504** — identical |
| **direct MEDIUM-severity event on the pod** | **0.0504** — identical |
| **compromised NEIGHBOUR (critical)** | 0.0511 |
| direct HIGH-severity event | 0.1817 |

So any threshold able to discount a fresh decoy also discounts a genuinely-attacked pod. The 0.0625
threshold did precisely that: a pod beside a critically compromised neighbour had its gain cut to
~0.4x for six minutes — **worse than the inert gate it replaced**. Condition 1 ("evidence-less assets
stay discounted until the floor") was also unmet, since urgency lifts them out at 495s.

### The gate that shipped

`Assessment.HasEvidence` — true when a SecurityEvent targets the pod (**any** severity), a graph
neighbour is compromised, an AI kill-chain signature matches, or an adapter is poisoned. Evidence is
**presence**, not magnitude. `prov()` reads that.

Measured: a true decoy stays discounted all the way to the proactive floor (condition 1 ✅), and all
four weak-evidence shapes keep full weight (conditions 2 and 3 ✅).

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

## 2. The threshold, and why it did not survive

The midpoint construction of §7 gives 0.0625, both endpoints model-derived
(`0.5*consequence(Recon)=0.050`, `0.5*consequence(GPUSideChannel)=0.075`). It was implemented, and
§5's concern that it "may become inactive before coverage matters" turned out not to apply —
competitive coverage begins at 0.0502, well below it.

It failed on a different one of §5's conditions, and the reasoning is in the Verdict above. The
rejected constants were removed rather than left as dead code; a comment in `killchain/hazard.go`
records why, so the idea is not reintroduced, and `TestStageUrgencyCannotDiscriminateEvidence` fails
if urgency ever becomes evidence-sensitive enough to reconsider it.

## 3. Limit A — the window closes entirely for two live tenants

The discount is reachable only while

```
AntiOverRotationWindow <= t < ProactiveFloor        and     U(t) <= threshold
```

Below the window: infeasible. At or above the floor: `prov()` returns 1 because the asset is
genuinely due. So a tenant whose window is at or above its floor has an **empty** interval:

| tenant | window | status |
|---|---|---|
| litellm, live-demo, voice | `[90s, 900s)` | active, 810s wide |
| nats | `[60s, 900s)` | active, 840s wide |
| **vllm** | `[900s, 900s)` | **EMPTY** |
| **mock-rag-chatbot** | `[90s, 15s)` | **EMPTY** |

(With the evidence gate there is no urgency-based escape, so the active windows are wider than they
were under the withdrawn threshold.)

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
| 2 | genuine early evidence keeps full weight | ✅ `TestWeakGenuineEvidenceIsNotTreatedAsADecoy` (all four weak shapes) + `TestGenuineEvidenceIsNotDiscounted` |
| 3 | gate and `provFloor` defined once, reused by both paths | ✅ `Assessment.HasEvidence` computed once in `Assess`; `provFloor` deduplicated earlier |
| 4 | end-to-end fixture shows the floor CHANGES selection | ✅ `TestProvenanceFloorChangesSelection` |
| 5 | the same test fails with the floor disabled / the old gate restored | ✅ **verified against both** |

Criterion 5, run explicitly:

```
gate = StageUrgency > 0                     -> FAIL  (the original tautology)
gate = StageUrgency > BaselineStageUrgency  -> FAIL  (the first fix — inert)
gate = HasEvidence                          -> ok
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
- Not that `HasEvidence` is hard to forge. It is forgeable by anything that can emit a SecurityEvent
  or compromise a neighbour — but an attacker who can do that has already achieved more than a decoy.
  What it removes is the ability to manufacture priority from *labels and freshness alone*.
- Not that it protects `vllm`. It does not, and that is the largest tenant.
- Not validated on the live cluster: this is a decision-path change proven by tests against the real
  `Decide()`, using live policy values. It has not been exercised against a real RL adversary.
