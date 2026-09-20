# P-CONTEXT — Steps 2–3 report: the both-products context model, built & proven on kind

**Date:** 2026-06-06 · **Status: BUILT + PROVEN on kind (REAL).** The approved
**Predictive-Horizon** context model is implemented: the 4 AI kill-chain stages classify
live, the predictive horizon surfaces a measurable **moved-before-next-stage**, the belief
layer is sharpened (survival posterior AI-gated, hierarchical fleet prior, UCB and a typed
observed-outcome boundary), and live-β is resolved to a Tier-1 infection frontier. Scoring,
feasibility, actuation, extended Phoenix and the harness remain unchanged; selection itself no
longer supplies a persistence label. Deterministic, no LLM in the decision path. AI magnitudes
are honestly `[SP-0-PENDING]`, and no qualified live persistence-label producer is connected.

---

## 1. What was built (Step 2) — phorvex-own, additive, AI-gated/honest-absent

| Area | File | What |
|---|---|---|
| **AI kill-chain** | `internal/killchain/hazard.go` | 4 AI stages (ordinals 5–8: `gpu-side-channel→model-theft`, `llm-jacking`, `prompt-inject-persist`) + consequences (0.15/0.9/0.6/0.65) + sojourns (300/180/900/3600s, **SP-0**) + the `aiNextStage` **successor map** (fixes the `next=stage+1` defect a parallel chain can't absorb) + the `aiStageFromView` classifier (sensed off existing `Pod`/`Physics`/`Telemetry`/`SecurityEvent` fields — **never a new SecurityEvent type**) + the `Assess` edit. |
| **AI-gated belief** | `hazard.go` | Survival-form P(hold) (Weibull shape=k) **gated behind `ModelID!=''||HasGPU`** → the generic K8s path stays **byte-identical** to P1; prompt-inject-persist gets **no wipe-damping** (the KV implant survives a rotation). |
| **Predictive horizon** | `hazard.go` | Two additive `Assessment` fields: `PreemptMargin = 1−weibullCDF(exposure)` (P the stage hasn't transitioned by move-landing) + `ProjectedNextStageSec` (inverse-Weibull median lead-time) = the **moved-before-next-stage** measurable. |
| **Belief/memory** | `internal/killchain/conjugate.go` | hierarchical fleet prior (a cold tenant inherits the fleet base-rate, seeded to the old constant ⇒ byte-identical at nil-data) + UCB confidence channel (`ConfidenceK` knob, default 0 = the plain mean). |
| **Observed persistence outcomes** | `internal/decision/persistence_observation.go` | a separately trusted, operation-bound categorical `held`/`revoked` observation adds exactly one Bernoulli count; an optimizer selection and its predicted `PHold` add no count. No qualified live producer is connected in the initial delivery. |
| **Live-β Tier-1** | `internal/runner/*`, `ctxprov/sensed.go` | `InfectionFrontier ∈ [1,1+κ]`: a pod adjacent to a known-infected neighbor (high-severity TargetsPod event) gets an AssetValue lift; **zero at empty infected-set** ⇒ preserves the gates. |
| **AI identity / CLI** | `ingest/kube.go`, `cmd/main.go` | `Pod.{ModelID,EndpointPath}` from annotations; `--scan` prints the live kill-chain context. |

**Unchanged by the observed-outcome correction:** scoring/dual/conformal, the
dynamic-action-set generator, actuation, proactive engine, **extended Phoenix, and the harness.**

---

## 2. The mandatory correction (and a second the build caught)

1. **(from the decision)** the survival-form P(hold) (shape=2) is **NOT** byte-identical to the
   baseline damping (shape=1) on the generic path (+0.025 PHold at t=60s). **Applied: gated behind
   `ModelID!=''||HasGPU`** so the generic K8s belief layer is byte-identical to P1.
2. **(caught by `TestKVRecoverScale`)** the decision's proposed `RecoverScale=max(30,KVRebuildSec)`
   for prompt-injection persistence is **semantically inverted** — a *larger* recover scale means
   *more* damping at low exposure (P(hold) collapses *more*), the opposite of "the implant survives
   the wipe." **Fixed:** a prompt-inject-persisted agent gets **no wipe-damping** (`damping=1.0`), so
   its P(hold) does not collapse after a rotation.

---

## 3. Proof on kind (Step 3) — REAL

### 3a. Live kill-chain context (`phorvex --scan`, an AI-annotated NIM + a panic event + a generic pod)
```
pcontext-demo/nim-llama    stage=prompt-inject-persist [AI]  PHold=1.00 PreemptMargin=1.00 ProjNextStage=2763s infectionFrontier=1.0
pcontext-demo/web-generic  stage=recon                [generic] PHold=1.00 PreemptMargin=0.98 ProjNextStage=1264s infectionFrontier=1.5
```
- **AI kill-chain stage classified LIVE**: the model-annotated NIM + a persist-class event → `prompt-inject-persist` (successor = lateral); the generic pod stays on the generic `recon` chain.
- **Moved-before-next-stage measured LIVE**: `PreemptMargin` + `ProjectedNextStageSec` (the NIM projects ~2763s to its next stage; the generic pod ~1264s). *Decision-time form; the run-time fleet aggregate needs a harness counter the zero-change scope forbids → honestly degraded.*
- **Tier-1 live-β fired LIVE**: `web-generic` (co-located neighbor of the infected NIM) gets `infectionFrontier=1.5`; the infected NIM itself is 1.0 (no infected neighbor of its own).

### 3b. Belief/memory unit tests (deterministic)
| Test | Result |
|---|---|
| `TestAIStageClassification` | 4 AI stages classify off existing fields; non-AI pod uses the generic chain |
| `TestPredictiveHorizonFields` | PreemptMargin ∈ [0,1] falls with exposure; ProjectedNextStageSec shrinks/goes negative |
| `TestKVRecoverScale` | a KV-persisted agent retains more P(hold) after a wipe than a generic foothold |
| `TestNegativeEvidenceFallsPrior` | the low-level categorical-count primitive can lower the prior; production requires a qualified operation-bound `revoked` observation |
| `TestHierarchicalColdTenant` | a cold tenant inherits the elevated fleet base-rate, not the fixed 0.2 |

### 3c. Baseline preserved (no regression)
- **1.62× IP gate** (`TestAblationP1BeatsRandomPerDollar`) — **PASS**; UCW ties at uniform + **1.84× K8s / 1.56× AI** dispersion lift — **PASS** (the AI-gated correction holds generic byte-identity).
- **P3 with the P-CONTEXT operator**: PX dwell **5.7s** vs blind 15.2s vs no-MTD 20.5s — **matches the P3 baseline**.
- phorvex build/vet/test green; **extended Phoenix + harness build unchanged.**

---

## 4. Honest framing — preserves now; improves under conditions
- **PRESERVES (proven):** generic byte-identity (AI-gated), gates green, P3 PX 5.7s. The 1.62× +
  P3 dwell/feasibility are preserved **by construction**.
- **IMPROVES (structural now, measurable later):** the AI stages **classify live** and the horizon
  + Tier-1 frontier **measure live** — but **all AI magnitudes (300/180/900/3600s sojourns, leakage
  rates, AIRecoverScale) are `[SP-0-PENDING]`** uncalibrated knobs; the belief upgrades only diverge
  from the baseline under their trigger (thin evidence, a fleet base-rate gap, a qualified observed
  outcome, a real infected neighbor). No qualified live persistence-label producer is connected,
  so this delivery makes no learned-efficacy or calibration claim. **No AI beat number is falsifiable until a real GPU fleet
  calibrates the magnitudes.** The demonstrable deliverables today are the **structure** (4 AI stages,
  successor map, horizon fields, belief upgrades, Tier-1 frontier) + the **generic-equivalence guarantee**.
- **Deferred + flagged:** the full SIR live-β **value** (β non-falsifiable without injected-infection
  ground truth); the **run-time** moved-before-next-stage fleet aggregate (needs a forbidden harness
  counter → only the decision-time form is claimable); `plannedMoveLatencySec=0` (overstates preemption
  until sourced from the actuator); the GPU-leakage AI stages (`gpu-side-channel`/`model-theft`) need
  `HasGPU` so they stay **SP-0** on a CPU-only cluster.

---

## 5. Extensibility & reproduce
**One module = one signal/stage:** each AI stage = one entry in {classifier, sojourn, consequence,
successor map}; conditional belief terms collapse to baseline when their condition is absent, and
persistence counts change only at the typed trusted admission boundary; the horizon fields are pure
closed-form reads. Per-owner, per-platform, deterministic.
```powershell
go -C phorvex build ./... ; go -C phorvex test ./...     # green; 1.62x gate + UCW + 5 P-CONTEXT tests
go -C phorvex build -o bin/phorvex.exe ./cmd/main.go
kubectl create ns pctx; kubectl run nim --image=busybox:1.36 -n pctx --command -- sleep 3600
kubectl annotate pod nim -n pctx phorvex.ai/model-id=llama-70b phorvex.ai/endpoint=/v1/chat
# emit a panic SecurityEvent targeting pctx/nim, then:
phorvex/bin/phorvex.exe --scan --scan-namespace pctx     # -> stage=prompt-inject-persist [AI] + horizon
```

**P-CONTEXT COMPLETE (Steps 1–3).** The both-products context model completes the 4 AI kill-chain
stages (classified live on kind), surfaces a measurable moved-before-next-stage, sharpens belief
(survival posterior AI-gated, hierarchical prior and a trusted observed-outcome seam with no live
producer yet), and resolves live-β to a Tier-1 infection frontier (full SIR honestly deferred) — preserving
the 1.62× + P3 by construction, with the AI half first-class in definition and honestly SP-0-PENDING
in value, and extended Phoenix + the harness untouched.
