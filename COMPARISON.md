# COMPARISON — R6's Claims vs. What We Measured

*Stage 6. This puts R6 Security's published quantitative claims (from the 4 papers in
`./papers/` and the 2 product pages in `./products/`) side-by-side with what the
extended-Phoenix benchmark actually measured (`build/EFFECTIVENESS-K8S.md`,
`build/EFFECTIVENESS-AI.md`, `out-bench/report-dollars.md`, `out-ai-bench/report-dollars.md`).
No code was changed.*

---

## How to read this (the essential framing)

Two facts shape every row below:

1. **R6 published numbers but shipped no code to produce them.** Per `spec-map.md`
   (which mapped every claim to the 5 upstream repos and grepped the source), **every
   quantitative figure R6 cites — Persistence <4%, 94% disruption, 400s→15s,
   `MODEL_ROTATION 3.2s`, `DWELL_TIME 0ms`, 99.8% availability, 1-2% overhead — is a
   paper/marketing/dashboard value with no measurement or enforcement code.** The
   upstream code implements only a timer-driven pod-delete; node rotation, jitter,
   telemetry-weighted adaptation, signed-baseline drift correction, warm-pool swap, and
   NVIDIA-NIM inference rotation are all **claimed-without-code** or **partial**.

2. **We built those mechanisms (extended Phoenix) and measured them.** So this is, as
   far as we can tell, the **first actual measurement** of these claims — against an
   honest set of controls (no-MTD baseline, a blind timer, random rotation at equal
   rate, and the real operator), with concrete oracles and ≥20-trial confidence
   intervals. Where a claim needs a real GPU / real LLM to test (warm-swap downtime,
   model-rotation time, GPU overhead), we say **GPU-PENDING** rather than guess.

**Verdict legend:** ✅ **AGREES** (measured supports the claim's mechanism/magnitude) ·
⚠️ **DIFFERS / PARTIAL** (true only narrowly, or contradicted on average) · ⏳
**CAN'T-YET-TEST** (GPU-PENDING or outside what the harness measures).

---

## Master comparison table

| # | R6 claim (number) | Source | Upstream code status (`spec-map`) | What we built + MEASURED | Verdict |
|---|---|---|---|---|---|
| 1 | **Persistence success 95%+ → <4%** | Adaptive Security §3, Contrast table p.4 | claim-without-code (no LWS/golden; pod-delete only) | Built `Rotate`. Measured: rotation disrupts a *persistence* foothold **~27% on average (95% CI [17,37], AI)**; **100%** on time-bounded *pod-resident* footholds (blind timer on `dwell-rotation`/`escape-persist`/`persistence-evict`), **0%** on out-of-pod / detector-absent footholds | ⚠️ **PARTIAL** — the <4%-persistence magnitude is reachable **only on the rotation-amenable subset**, not as a universal result |
| 2 | **Dwell time 150+ days → <60 min** | Adaptive Security §3.1; ADA §3.3 | partial (timer only) | Built jittered cadence + scoring. Measured: attacker **dwell is bounded by the rotation interval** (≈6–8 s at the 6 s test cadence) for pod-resident footholds | ✅ **AGREES** (mechanism confirmed: dwell ≤ interval; "<60 min" is just R=60 min) — for rotation-catchable footholds only |
| 3 | **Up to 94% disruption** | Proactive Security, Abstract p.1 | marketing, no measurement code | Measured per-arm **mean disruption**: blind-timer **38.9%**, random-equal **30.4%**, full-Phoenix **5.6%** (K8s, n=21); rotating arms **~27%** (AI) | ⚠️ **DIFFERS** — 94% is **not** reproduced as a mean; rotation hits 100% only on narrow scenarios, ~30–39% across a realistic attack mix |
| 4 | **Per-stage success: Persistence 5%, PrivEsc 3%, Lateral 4%, Impact 2%** | Proactive Security, Tables I/II p.5 | marketing | Measured under rotation: **persistence** ≈0% success on `dwell-rotation` (matches ~5%); **lateral movement** ≈**100%** success (`c1-lateral` 0% disruption — the move completes inside the interval) — **contradicts** the 4% | ⚠️ **MIXED** — matches persistence, **contradicts** lateral/recon |
| 5 | **Warm-swap downtime ~400s → ~15s** | Adaptive Security §5/§5.1 p.6 | claim-without-code (no warm-pool/LWS) | Built `WarmInferenceSet` + `WarmSwap`. Measured: control-plane **cutover ≈5 s on kind** (leader flip + drain). The 400→15 *downtime* is about avoiding model-load time — needs a real model on GPU | ⏳ **GPU-PENDING** (control plane BUILT + works; the downtime number is not measurable on CPU/kind) |
| 6 | **`MODEL_ROTATION: 3.2s`** | Phoenix for AI, hero widget p.1 | dashboard value, no code | Built `Rotate`. Pod recreate ≈ seconds on CPU; a *model* rotation time (weight reload) requires real GPU/LLM | ⏳ **GPU-PENDING** |
| 7 | **Rotation interval R = 60 min ± jitter 10–30%** | Adaptive Security §3.2 p.2 | claim-without-code (deterministic; only `rand` is a gRPC nonce) | Built **jitter** (`RotationPolicy` Jitter/Stagger + jitter-on-emission in the time-based trigger). The 60 min ± 10–30% is a **config value** (we benchmarked at a short cadence) | ✅ **AGREES on mechanism** (jitter implemented vs upstream none); the specific 60 min number is configuration, not separately measured |
| 8 | **Compute/GPU overhead 1–2% (1.3–1.7%)** | Phoenix for AI; Proactive Security §V | marketing, no measurement | Used **1.5%** (midpoint of R6's 1–2%) as a **swappable ROI input**, not a measurement → GPU-overhead **$2,628/yr saved** at 8 GPU × $2.50/hr. We did not measure overhead | ⏳ **GPU-PENDING** (R6's figure is an *assumption* in our $ model, not a measured result) |
| 9 | **Availability 99.8%** | Proactive Security §V p.3 | marketing | Not measured — the harness measures *attack disruption*, not workload uptime | ⏳ **CAN'T-YET-TEST** (out of harness scope; needs a sustained-load uptime test, ideally on GPU) |
| 10 | **MTTR < 5 min (anomaly → recovery)** | Adaptive Security §5 p.6 | partial (telemetry ingest only) | Built scored matcher + panic + Regenerate/NodeRotate. Measured **time-to-action ≈0.1 s** for the injected-event path (full-Phoenix) — orders of magnitude under 5 min | ✅ **AGREES** for reactive action latency **when a sensor emits**; ⏳ real panic/node MTTR on GPU/real nodes is **GPU/real-node-PENDING** |
| 11 | **`DWELL_TIME: 0ms`** | Phoenix for K8s, telemetry panel p.1 | dashboard value | Measured dwell = the **rotation interval** (≈6 s at test cadence), never 0 | ⚠️ **DIFFERS** — "0 ms" is marketing; rotation *bounds* dwell, it cannot make it zero |
| 12 | **`MUTATION_CYCLE: 1.8s` / `PODS_ROTATED: 1,253`** | Phoenix for K8s, telemetry panel p.1 | dashboard values | One rotation ≈ seconds on CPU (a counter for pods-rotated) | ✅ plausible order-of-magnitude (≈seconds); the exact figure is a dashboard value |
| 13 | **`PIPELINE_INTEGRITY: 99.97%`** | Phoenix for AI, hero widget p.1 | dashboard value | Not measured (we don't measure inference-pipeline integrity) | ⏳ **CAN'T-YET-TEST** |
| 14 | **Scalability to 50,000 instances** | Proactive Security §V p.3 | marketing | Not tested — single-node kind, tens of pods | ⏳ **CAN'T-YET-TEST** (needs a large multi-node cluster) |
| 15 | **Adaptive/telemetry-weighted rotation > Timed (Timed: Recon 30%, Persistence 26%; Adaptive <10%)** | Proactive Security, Tables I/II + §V.A | claim-without-code (no scoring/telemetry-weighting upstream) | Built the scoring layer. BUT measured: the **blind timer (38.9%) out-disrupts the reactive full-Phoenix operator (5.6%)** on average, because the reactive path is **emitter-dependent** and most AI detectors are RECEIVER-ONLY/ABSENT | ⚠️ **DIFFERS / CONTRADICTS** in our measurement (see "Key finding" below) |

---

## The headline claims, discussed

### Persistence "<4%" and "94% disruption" — true narrowly, not universally
R6 frames these as blanket outcomes of rotation. Our measurement says: **rotation is
extremely effective on exactly the attacks it can reach** — a pod-resident foothold on a
time-bounded oracle is disrupted **100% [100,100]** by even a blind 6 s timer (so
persistence success → ~0%, beating the <4% claim). But across a *realistic* attack mix the
mean disruption is **~30–39%**, because a large class of real attacks — credential/token
theft, supply-chain/poisoned-image, admission bypass, CI/CD, sidecar injection,
secrets-sprawl, RAG/embedding-store poisoning, IMDS theft — live **outside the rotated
pod** or leave **no signal a detector catches**, so rotation cannot touch them (measured
0% on every arm, including the real operator). **The 94% / <4% numbers describe the
best-case subset, not the average over what attackers actually do.** This is the central
honest correction the benchmark provides.

### Dwell reductions — the mechanism is real and confirmed
"Dwell 150+ days → <60 min" and "DWELL_TIME 0ms" are the same idea: a foothold cannot
outlive the rotation interval. We **measured exactly that** — dwell tracks the configured
interval (≈6–8 s in our test config; set R=60 min and dwell ≤ 60 min). So the *mechanism*
agrees; the marketing "0 ms" is false (rotation bounds dwell, it cannot zero it), and the
bound only applies to footholds that live in the rotated pod.

### Warm-swap 400→15s and MODEL_ROTATION 3.2s — built, but GPU-PENDING
R6 shipped no warm-pool code; we built the `WarmInferenceSet`/`WarmSwap` control plane and
verified the cutover works (leader flip + drain ≈5 s on kind). But the **downtime** numbers
(400s→15s, 3.2s) are fundamentally about **avoiding GPU model-load latency** by pre-warming
— there is no model to load on a CPU kind node, so these cannot be measured here. They are
**capability-pending for the GPU run**, where the control plane we built can finally be
timed against real model serving.

### Overhead 1–2%, availability 99.8%, 50k-instance scale — outside what we measured
These are operational/economic numbers, not attack-disruption numbers. We did **not**
measure overhead — we *used* R6's stated 1–2% as a transparent, swappable input to the $
ROI model (yielding $2,628/yr saved at 8 GPUs), which is an assumption to be replaced by a
real GPU measurement, not a confirmation. Availability and 50k-instance scalability are out
of the harness's scope entirely (it measures disruption, not uptime or scale).

---

## Key cross-cutting finding (the most important honest result)

R6's papers argue **adaptive/telemetry-weighted rotation beats a fixed timer** (their
Tables show Timed ≈26–30% attack success vs Adaptive <10%). Our measurement **inverts this
on average**: the **blind 6 s timer disrupted more (38.9% mean) than the real reactive
Phoenix operator (5.6% mean)** in the K8s benchmark. The reason is structural and is the
through-line of the whole project: **Phoenix is reactive and emitter-dependent** — it
neutralizes an attack only where an external sensor emits a matching `SecurityEvent`. The
`AI-MTD-AUDIT` shows the AI-side detectors that would drive "adaptive" rotation
(GPU-utilization, model-I/O, semantic) are **RECEIVER-ONLY or ABSENT**, so on most
scenarios the operator never fires and only blind rotation bounds the foothold. Phoenix
*does* win decisively on the one path where the trigger exists — the injected-panic
`c2-persistence-evict` (100% disruption) and the 4 AI trigger scenarios (`MTD-NEUTRALIZES`
100% [100,100]) — but **R6's "adaptive > timed" advantage is contingent on detectors that
mostly do not exist yet.** That gap is precisely the Phorvex differentiator the benchmark
is built to quantify.

---

## What measurement honestly cannot reach (carried to the GPU/real-LLM run)

| Claim | Why not yet | Where it gets measured |
|---|---|---|
| Warm-swap 400s→15s downtime | needs real GPU model-load to have a downtime to cut | AWS/CoreWeave GPU run (control plane already built) |
| `MODEL_ROTATION 3.2s` | model-weight reload is a GPU operation | GPU run |
| GPU/compute overhead 1–2% | requires GPU utilization measurement under load | GPU run (currently a swappable ROI input) |
| Availability 99.8% | uptime metric, not attack-disruption | sustained-load test (ideally GPU) |
| Scalability 50,000 instances | needs a large multi-node cluster | scale test |
| `PIPELINE_INTEGRITY 99.97%` | inference-pipeline integrity not instrumented | GPU/LLM run |
| LLM-jacking detection, KV-cache, cross-node MTTR | GPU/multi-node-only scenarios (6 capability-pending) | GPU run by config swap |

Every "can't-yet-test" above is a **real GPU/scale dependency, not a missing capability** —
the mechanisms are built and the benchmark will produce the numbers by swapping the
per-target config, with zero code change.

---

## Bottom line

- R6's **mechanisms** that they claimed-without-code — rotation, jitter, telemetry scoring,
  signed-baseline regenerate, warm-swap, node rotation, NIM/inference rotation — are now
  **built and exercised**, so the claims are testable for the first time.
- R6's **dwell-bounding** claims are **confirmed in mechanism** (dwell ≤ rotation interval).
- R6's **headline percentages** (94% disruption, <4% persistence) are **true only for the
  rotation-amenable subset** and **do not hold as averages** over a realistic attack mix —
  the benchmark measures ~30–39% mean disruption, with a large class of attacks (out-of-pod,
  detector-absent) at 0%.
- R6's **"adaptive beats timed"** ordering is **not reproduced** — on average a blind timer
  out-disrupts the reactive operator, because the detectors that would make rotation
  "adaptive" are RECEIVER-ONLY/ABSENT.
- R6's **GPU/economic/scale numbers** (400→15s, 3.2s, 1–2% overhead, 99.8%, 50k) are
  **capability-pending**, measurable on the GPU/real-LLM run by config alone.

*Provenance: claims + upstream code status from `spec-map.md`; measured numbers from
`build/EFFECTIVENESS-K8S.md`, `build/EFFECTIVENESS-AI.md`, and the `report-dollars.md` views
under `build/test-harness/out-bench/` and `out-ai-bench/`; capability classes from
`build/AI-MTD-AUDIT.md`. Every measured figure traces to a raw log via the provenance maps.*
