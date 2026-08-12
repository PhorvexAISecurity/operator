# PHORVEXSEC-128 (PHVX-72) — measurement addendum

Date: 2026-08-10 · Branch `measure/phvx-72-sweep-table`
Answers the three things §6 of the threshold analysis asked for that the completion report did not
deliver. Raw test output: `sweep-and-gate-comparison.txt`.

## Why this exists

§6 asked for a fine-grained sweep recording eight quantities per point. The completion report
published **four of them at two points**, and stated the conclusions rather than the data. The sweep
itself ran in throwaway diagnostic files that were deleted, so the reasoning could not be checked.
That was the gap, and it is a fair one: a reviewer should be able to reach the verdict from the
numbers, not take it on trust.

Both tables below are now permanent tests (`provfloor_sweep_measure_test.go`), so the data cannot go
missing again.

## 1. The §6 sweep, all eight columns

Run on the **live tenant policy** (`antiOverRotationWindow=90s`, `proactiveFloor=15m`), not the
fixture's 5m/1h. Gate = the shipped `HasEvidence`.

| exposure | pHold | hazard | urgency | stage | next | rawCover | prov | provCover | feasible | decoy takes slot |
|---|---|---|---|---|---|---|---|---|---|---|
| 0s | 0.0000 | 0.0000 | 0.0500 | recon | exploit | 0.000 | 0.340 | 0.000 | no | no |
| 30s | 0.1433 | 0.0003 | 0.0500 | recon | exploit | 0.000 | 0.362 | 0.000 | no | no |
| 60s | 0.2190 | 0.0011 | 0.0502 | recon | exploit | 0.000 | 0.384 | 0.000 | no | no |
| 89s | 0.2647 | 0.0024 | 0.0504 | recon | exploit | 0.000 | 0.405 | 0.000 | no | no |
| **90s** | 0.2661 | 0.0025 | 0.0504 | recon | exploit | **58.640** | 0.406 | 23.808 | **yes** | no |
| 2m | 0.3010 | 0.0044 | 0.0508 | recon | exploit | 66.374 | 0.428 | 28.408 | yes | no |
| 3m | 0.3591 | 0.0100 | 0.0517 | recon | exploit | 79.247 | 0.472 | 37.404 | yes | no |
| 4m | 0.4132 | 0.0176 | 0.0531 | recon | exploit | 91.299 | 0.516 | 47.110 | yes | no |
| **5m** | 0.4666 | 0.0274 | **0.0548** | recon | exploit | 103.277 | 0.560 | 57.835 | yes | **YES** |
| 7m | 0.5733 | 0.0530 | 0.0593 | recon | exploit | 127.427 | 0.648 | 82.573 | yes | yes |
| 10m | 0.7333 | 0.1052 | 0.0684 | recon | exploit | 164.393 | 0.780 | 128.227 | yes | yes |
| 12m | 0.8400 | 0.1479 | 0.0759 | recon | exploit | 189.622 | 0.868 | 164.592 | yes | yes |
| 15m | 1.0000 | 0.2212 | 0.0887 | recon | exploit | 228.433 | 1.000 | 228.433 | yes | yes |
| 20m | 1.0000 | 0.3588 | 0.1128 | recon | exploit | 233.486 | 1.000 | 233.486 | yes | yes |

```
first POSITIVE coverage   : 90s   (U = 0.0504)
first BUDGET-COMPETITIVE  : 5m    (U = 0.0548)
```

### ⚠ This corrects the completion report

That report said *"first positive and first budget-competitive coincide, because coverage arrives as a
step, not a ramp."* **That was wrong.** It was an artifact of the earlier fixture — a 5-minute
anti-over-rotation window with a decoy manufactured at 25× the genuine asset, which made the first
feasible point also the first winning one.

On the live policy they are 3.5 minutes apart, and the §6 distinction the analysis drew — *"a tiny
positive coverage that cannot affect ranking should not determine the threshold"* — was exactly right.

Consequences:

- `U_competitive` is **0.0548**, not the 0.0502 the completion report used.
- §7's formula therefore gives `τ = (0.0548 + 0.075)/2 = 0.0649`, not 0.0625.
- Coverage does ramp; only *feasibility* is a step. The step at 90s is `AntiOverRotationWindow`
  (`feasibility/defaults.go:87`), not a property of the coverage model.

The verdict is unchanged — see §2 — but it now rests on the right number.

## 2. Gate comparison against the baseline

The question behind the request was *"did this approach help, or not?"*. Every candidate gate scored
on the same population, at the live policy. `prov = 1.000` means full weight; lower means the asset is
being discounted as if it were manufactured.

| asset | urg>0 | >0.0500 | >0.0625 | >0.0649 | >0.0700 | **HasEvidence** |
|---|---|---|---|---|---|---|
| decoy (fresh, no evidence) | 1.000 | 1.000 | 0.406 | 0.406 | 0.406 | **0.406** |
| decoy (5m, no evidence) | 1.000 | 1.000 | 0.560 | 0.560 | 0.560 | **0.560** |
| decoy (12m, no evidence) | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | **0.868** |
| aged, no evidence (legitimately due) | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| **GENUINE** direct low-severity | 1.000 | 1.000 | **0.406** | **0.406** | **0.406** | 1.000 |
| **GENUINE** direct medium-severity | 1.000 | 1.000 | **0.406** | **0.406** | **0.406** | 1.000 |
| **GENUINE** neighbour compromised (critical) | 1.000 | 1.000 | **0.406** | **0.406** | **0.406** | 1.000 |
| **GENUINE** direct high-severity | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

### Scorecard

| gate | decoys suppressed | false alarms | verdict |
|---|---|---|---|
| original `StageUrgency > 0` | 0 / 4 | 0 / 4 | inert |
| baseline `> 0.0500` | 0 / 4 | 0 / 4 | inert |
| `> 0.0625` | 2 / 4 | **3 / 4** | acts, but penalises real threats |
| `> 0.0649` (§7's formula on the measured value) | 2 / 4 | **3 / 4** | acts, but penalises real threats |
| `> 0.0700` (just under the weakest evidenced stage) | 2 / 4 | **3 / 4** | acts, but penalises real threats |
| **`HasEvidence` (shipped)** | **3 / 4** | **0 / 4** | acts, no false alarms |

## 3. Answering "were higher thresholds tried?"

Yes — 0.0625, 0.0649 and 0.0700, and **all three behave identically**. That is not a coincidence and
it is the useful result: no scalar threshold can do better, because `StageUrgency` does not separate
the two populations at all. A low- or medium-severity event leaves the stage at Recon, so its urgency
is *identical* to an asset that has seen nothing (0.0504 at 90s), and a compromised neighbour reaches
only 0.0511. Every threshold that catches a decoy at 0.0504 necessarily catches those too.

Raising τ further does not help either: the weakest genuinely-evidenced stage sits at 0.075
(`0.5 × consequence(GPUSideChannel)`), so anything at or above it stops acting on decoys entirely and
returns to the inert row.

`HasEvidence` also strictly dominates on the decoy side — it still discounts the 12-minute decoy
(0.868) where every threshold has already released it (1.000).

Audit correction (2026-08-12): the measurement tests originally printed these conclusions without
asserting them, so a future behavior change could leave CI green while making this report stale.
They now assert the two boundaries (90s first-positive, 5m first-competitive) and every scorecard
pair above, while leaving individual floating-point rows as measurements rather than a brittle
golden file.

## 4. What this does not settle

- The population is eight synthetic shapes, not a live incident trace. It is designed to separate
  *evidence present* from *evidence absent*, which is the property under test, and nothing more.
- The `prov` values are the ramp `0.34 + 0.66·(exposure/floor)`; the depth limit (~2.5× of
  manufactured advantage) from the completion report §4 still applies to all of them equally.
- The empty discount window on `vllm` and `mock-rag-chatbot` (completion report §3) is untouched by
  any gate choice.
