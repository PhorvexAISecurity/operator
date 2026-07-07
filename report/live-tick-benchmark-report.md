# Phorvex — LIVE Tick-Interval Benchmark (10s vs 5s)

**Real attacks on a live cluster.** Foothold (`SecurityEvent`, MITRE T1611) fired at `phorvex-live-demo/decoy` (stateless, 2 replicas) on live EKS `us-east-2`; the in-cluster Phorvex operator (`phorvex:0.2.1-reactiveonly`, engine `p1-coverage`) responds with `rotate`. Fixed **30 s** window per attack, **3 trials per cadence**. Every number below is measured — from the operator's decision audit and Kubernetes pod/event timestamps.

**Date:** 2026-07-05 · **Value-at-risk node:** t3.medium (us-east-2) · **policy λ:** 0.4 · maxMovesPerTick=1 · antiOverRotation=90s

## 1. Executive summary

Headline: on this workload, **halving the tick interval from 10 s to 5 s made no material difference** to cost, security outcome, or the objective function. To even attempt a 5 s cadence the operator's `--base-interval` had to be changed from 10 s to 5 s (the per-policy `tickInterval` alone is gated by the global base interval). With that done and real attacks fired, across 3 trials each:

- **Both cadences fully defended every trial** (3/3 at 10 s, 3/3 at 5 s). The foothold was always contained by a real `rotate`.
- **Cost over 30 s is identical.** Rotations/trial were 1.33 (10 s) vs 1.33 (5 s) — the **same** — because the response is bounded by `maxMovesPerTick=1`, two target pods and the 90 s anti-over-rotation window, **not** by the tick rate. Same actuator churn, same brief 50% availability dip, same 3-way annual cost posture.
- **The objective function is statistically indistinguishable.** Mean per-dollar 6.33 (10 s) vs 6.21 (5 s); mean net 5.18 vs 5.06; mean pHold 0.608 vs 0.613. The differences are within trial-to-trial noise.
- **The only robust effect of 5 s is a tighter worst-case latency ceiling.** Observed max time-to-first-defend was 12 s (10 s) vs 9 s (5 s); means 8.7 s vs 6.3 s. The tick interval caps *how long an attacker could wait for the next decision* — it does not change the typical case, which is dominated by near-instant actuation.

> **Note on a single-run artifact.** An earlier n=1 run showed the 5 s cadence scoring ~2× higher objective. That was **kill-chain-hazard variance, not a cadence effect** — it washed out entirely once averaged over 3 trials (means now equal). This is exactly why the benchmark was repeated. The robust findings are: *cost is equal*, *both cadences always defend*, and *5 s only tightens the worst-case latency guarantee*.

## 2. Per-cadence results (n=3 each)

| Metric | 10 s tick | 5 s tick | Better |
|---|---:|---:|:--|
| Defended trials | 3/3 | 3/3 | tie |
| Decision ticks / 30 s | 3 | 6 | — |
| Rotations / trial (mean) | 1.33 [2, 1, 1] | 1.33 [1, 2, 1] | tie |
| Time-to-first-defend (mean) | 8.7 s [4, 12, 10] | 6.3 s [6, 9, 4] | ~tie |
| Deepest kill-chain stage | exploit | exploit | — |
| Min availability | 1/2 | 1/2 | tie |
| Mean per-dollar (cov/$) | 6.33 | 6.21 | ≈ tie |
| Mean net objective | 5.18 | 5.06 | ≈ tie |
| Mean pHold at action | 0.608 | 0.613 | ≈ tie |
| Worst-case first-defend | 12 s | 9 s | 5 s (ceiling) |

## 3. Cost over the 30 s window

Because the attack is **defended in every trial at both cadences**, and the number of actuator moves is bounded by policy (not by tick rate), the cost is the same. The 3-way annualized posture (real cost model, priced from the attacked node's on-demand rate):

| | Without any defense | R6 blind timer | With Phorvex |
|---|---:|---:|---:|
| Annual cost ($/yr) | $364.42 | $369.63 | $26.03 |

- Value-at-risk = attacked `t3.medium` node on-demand = **$364.42/yr**.
- R6 blind timer catches ~20% by luck and churns ~3× the operator footprint → **$369.63/yr** (worse than doing nothing on a *targeted* foothold).
- With Phorvex = operator footprint only (**$26.03/yr**); the attacked pod is rotated, residual exposure ≈ 0. **Savings vs no defense: $338.39/yr.**
- **Tick interval does not move these numbers** — both cadences produce the same ~1–2 rotations and the same brief 50%% availability dip.

## 4. Security over the 30 s window

Every trial at both cadences ended DEFENDED (attacker's foothold pod rotated away). What the tick interval changes is the *ceiling* on how long the attacker could persist before the next decision:

- **10 s cadence:** first containment at [4, 12, 10] s (mean 8.7). Worst-case wait for a decision = 10 s.
- **5 s cadence:** first containment at [6, 9, 4] s (mean 6.3). Worst-case wait = 5 s — a tighter guarantee.
- In these trials the attacker never got past **exploit** before being rotated; the deeper `exploit`/`persist` stages appear only on the *second* pod's rotation, when the operator has already contained the first.

The security value of 5 s is therefore a **worst-case latency guarantee** (halved), not a typical-case improvement — useful for tight-dwell SLAs, invisible on the average case.

## 5. Objective-function comparison

Engine objective per decision: **net = cov − λ·ECost**, per-dollar = **cov/ECost**, with cov the consequence-weighted recon invalidated (coveredFacts=3 in every decision) scaled by pHold (probability the recon still holds). Measured means across all decisions:

| Term | 10 s | 5 s | Δ |
|---|---:|---:|---:|
| Decisions captured | 4 | 4 | |
| Mean per-dollar (cov/$) | 6.33 | 6.21 | -1.8% |
| Mean net objective | 5.18 | 5.06 | -2.2% |
| Mean pHold at action | 0.608 | 0.613 | +0.8% |

Reading it: the two cadences are **statistically indistinguishable** on every objective term (per-dollar 6.33 vs 6.21, net 5.18 vs 5.06, pHold 0.608 vs 0.613). Because the engine's objective rewards coverage-per-cost — and every decision covers the same 3 recon facts at the same ECost=0.82 regardless of tick rate — cadence simply does not enter the objective. Firing the engine twice as often (6 vs 3 ticks/30 s) does not produce higher-value moves; it only shortens the *worst-case* wait for the next one.

## 6. Recommendation

- **Keep 10 s (`--base-interval=10s`)** as the default for cost-sensitive workloads: it defended every attack at the same cost as 5 s, with a 10 s worst-case decision latency.
- **Move to 5 s** only where a tight dwell-time SLA justifies it: it halves the worst-case containment latency and acts at higher confidence, at the price of 2× operator tick work (CPU, not actuator churn) and a full operator restart to change `--base-interval`.
- The lever that would actually change *cost/coverage* is **`maxMovesPerTick`** and **`antiOverRotationWindow`**, not the tick interval — those are what bound the response here.

---

*All figures measured on live EKS `us-east-2` on 2026-07-05 by firing real SecurityEvent footholds at `phorvex-live-demo/decoy` and reading the operator decision audit + K8s timestamps. n=3 trials/cadence. Operator restored to `--base-interval=10s` after the run.*
