# AI-Side MTD Capability Audit (Stage 4 Pass B — Step 0)

> **Purpose.** Before any AI/inference attack is scored, this audit fixes *exactly*
> which AI-side moving-target-defense mechanisms the extended Phoenix operator
> actually implements — so every Group-1 "**not neutralized**" result is attributed
> correctly: a **real gap** (ABSENT), a **pending GPU detector/SLO** (GPU-PENDING),
> a **missing emitter** (RECEIVER-ONLY), or a genuine **defense failure**. It is
> never to be misread as a defense failure when the cause is a missing trigger.
>
> **Method (read-only).** Read `architecture.md` (locked design), `PHASE0..7` +
> `PHASE3B` reports, and the code under `build/phoenix-extended/` (operator) and the
> `build/*-integrator-extended/` trees. Every row cites `file:line` evidence and a
> real build/live capture where one exists. Nothing was modified.

## Classification key

| Class | Meaning |
|---|---|
| **BUILT** | implemented and exercisable on CPU/kind (the action path exists AND fires without a GPU). |
| **GPU-PENDING** | implemented, but the SLO/measurement requires a real GPU / real LLM serving. |
| **RECEIVER-ONLY** | the operator will **act** if a matching `SecurityEvent` arrives, but **no native emitter** in any of the trees produces that signal — the trigger detector is absent. |
| **ABSENT** | not implemented at all (neither detector nor receiver). |

The operator is **reactive and emitter-dependent by design**: an action fires only
when an external integrator emits a `SecurityEvent` whose `{Type,ThreatLevel,Source}`
(Exact, default) or scored clause (opt-in) matches an `AMTD.Strategy[]` rule. The
matcher default is **Exact** (`adaptivemovingtargetdefense_types.go` `MatcherMode`
`+kubebuilder:default=Exact`; `matcher.go:95`), so scored/anomaly clauses are inert
unless `matcherMode: Scored` is set.

---

## Per-mechanism classification

| # | Mechanism | Class | Evidence (file:line) | Trigger Rule `{Type/ThreatLevel/Source}` | Note |
|---|---|---|---|---|---|
| 1 | **Inference / NIM rotation** (image/env/GPU mutation + Rotate action) | **BUILT** | `api/v1beta1/adaptivemovingtargetdefense_types.go` InferenceRotationSpec (GoldenImage/EnvPatch/GPUResource); `internal/controller/rotate_executor.go` executeRotate; `nim_controller.go` (pass-through to matcher); PHASE1-REPORT live: `busybox:1.36→1.37`, `RUNTIME_MODE=SECURE`, durable template patch | `{timed, _, TimeBasedTrigger}` → Rotate; or scored `metrics.anomalyScore Gte 0.85` → Rotate | NIM timer-gate dissolved; mutation durable via owner-template patch (D3) or cold-fallback recorded as non-durable. |
| 2 | **Warm-swap / WarmInferenceSet / LeaderWorkerSet** cutover control plane | **BUILT** (control plane) · **GPU-PENDING** (downtime SLO) | `api/v1beta1/warminferenceset_types.go`; `internal/controller/swap.go` (flip→drain→retire→rewarm); `warmswap_action.go`; PHASE4 live: leader `wis-a-warm-0→wis-a-warm-1`, EndpointSlice followed, `lastSwapDurationMillis≈5122ms` | `{timed, _, TimeBasedTrigger}` → WarmSwap | Control-plane cutover works on CPU; **400s→15s downtime SLO is GPU-PENDING** (≈5s on kind is flip+drain, not model-load overhead). |
| 3 | **Endpoint / Service-selector rotation** | **BUILT** (sub-effect of WarmSwap) | `internal/controller/warmpool.go` ensureLeaderService; `swap.go` doFlip (ServiceSelectorSwap flips leader label) | part of WarmSwap action | The **external** Service endpoint name stays **stable**; only the **backend** (leader label → pod) rotates. A client holding the external endpoint is **not** invalidated — only the pod behind it changes. Important for "rotate endpoint to break persistent access." |
| 4 | **ContextMutationPolicy + panic mutation** | **BUILT** (CMP + receiver) · GatekeeperViolation trigger **RECEIVER-ONLY** | `api/v1beta1/contextmutationpolicy_types.go`; `contextmutationpolicy_controller.go` (thin status-only reconciler); `MutationApplier.Resolve`; `gatekeeper_receiver.go:20` "NO OPA-Gatekeeper-audit → SecurityEvent emitter in any of the 5 repos" | `{gatekeeper-violation, _, GatekeeperIntegrator}` → Rotate(+policyRef) | The CMP **mutation** path is built (lands via Rotate→MutationApplier). The **GatekeeperViolation trigger has no emitter** — it is receiver-only; tests must inject the event manually. |
| 5 | **Regenerate** — signed-baseline drift detect + restore-from-golden | **BUILT** | `api/v1beta1/workloadbaseline_types.go`; `baseline_verify.go` (ecdsa.VerifyASN1 / ed25519); `workloadbaseline_controller.go` (emits `Type:drift` SecurityEvent); `baseline_restorer.go` (verify-before-recreate); PHASE5 live: drift event → Regenerate restored golden digest durably | `{drift, _, FalcoIntegrator}` → Regenerate | **Signing proves provenance/integrity, NOT benignity** (a signed-but-malicious golden restores malicious state). Baseline object holds references only. |
| 6 | **Node rotation + clean-node selection + D26 trust gate** (panic-move target) | **BUILT** (control plane + gate) · **GPU/real-node-PENDING** (MTTR, true relocation) | `api/v1beta1/noderotation_types.go`; `nodedrainer.go` (Cordon/Taint/Drain via Eviction subresource, PDB-honoring; CleanNodeSelector); `node_rotate_gate.go:105` (D26: Source-allowlist + ThreatLevel-floor + human-approval-for-Delete); PHASE6 live: non-allowlisted `EvilWorkload/critical` → 0 NodeRotations (gated); allowlisted `KubeArmor/critical` → NodeRotation created, `targetCleanNode=fake-clean-1` | `{_, In[high,critical], KubeArmorIntegrator}` → NodeRotate | kind nodes are kubelet-less containers → **true cross-node relocation + MTTR are real-node/GPU-PENDING**. The "panic mutation to a clean node" target exists as NodeRotate. |
| 7 | **AnomalyScorer / EWMA / panic hysteresis** (telemetry-scoring layer) | **BUILT** (default Passthrough) | `internal/controller/scoring.go` PassthroughScorer (default; invents no math) + WeightedScorer (opt-in, no default weights); `scoring_update.go` EWMA `α=0.3`, N-consecutive-high `N=3`; PHASE3 live: score 0.2→0.6→0.9 → interval 8m12s→4m36s→1m54s, panic only after `≥0.85 & ≥3 highs` | scored: `{_, _, PrometheusIntegrator}` + `anomalyScore Gte X` | Consumes an integrator-written `Spec.AnomalyScore` as-is; **does not generate any score itself**. Panic bypasses only the min-interval floor (keeps readiness/backoff/concurrency gates). |
| 8 | **GPU-utilization detector** (LLM-jacking / shadow-compute detection) | **RECEIVER-ONLY** | repo-wide search: only `nvidia.com/gpu` *actuator* refs (DropToZero quarantine in `mutation.go:62`, `rotate_executor`); **no** DCGM/Triton exporter, **no** `gpu_util*` emitter; `warminferenceset_types.go:110` "on real GPU this is replaced by a DCGM/model-server probe" (not integrated) | future: `{_, _, PrometheusIntegrator}` + `metrics.gpu_utilization Gte X` | The operator can **zero a GPU limit** as an *action*, and `matcher.go projectField` can read `metrics.gpu_*` **if** an emitter writes them — but **no GPU-jacking detector emits that signal**. Fail-safe: no signal → no action. |
| 9 | **Model-I/O detector** (Pillar 03: agent observes model I/O → panic mutation on malicious payload) | **ABSENT** | repo-wide search: no `model.?io` / `modelInput` / `modelOutput` / inference-payload hook; no `SecurityEvent` Type with model-I/O semantics | n/a (detector); the **panic-mutation action** is testable via an injected panic event | **Neither emitter nor receiver** for model-I/O. The *panic-mutation action* (clean-node move / GPU-quarantine) is BUILT (#6/#4) and testable by injecting the event; the **I/O inspector that R6 Pillar 03 describes is not implemented**. |
| 10 | **NeMo Guardrails / semantic prompt filtering** | **ABSENT** | repo-wide search: no `NeMo` / `Guardrail` / `prompt.*filter` / `triton` | n/a | R6's product pages **explicitly defer** semantic prompt filtering to NeMo Guardrails; no hook exists in the AMTD operator (LLMOps-layer concern, out of the infra-MTD scope). |
| 11 | **KV-cache isolation / cross-session-leak control** | **ABSENT** | repo-wide search: no `kv.?cache` / cache-isolation code | n/a | No KV-cache awareness — a real KV-cache requires real LLM serving (GPU). Harness mocks it; real behavior is GPU-PENDING. |
| 12 | **Integrators emit AI-specific signals?** (Falco / Prometheus / KubeArmor) | **RECEIVER-ONLY for AI** (Phase-7 normalization **landed**, but generic-only) | `falco-integrator-extended/cmd/normalize.go` (Priority→ThreatLevel, rule→Type drift/panic), `prometheus-integrator-extended/cmd/normalize.go` (prefers real `anomaly_score` label), `kubearmor-integrator-extended/cmd/canonical.go` (Severity→ThreatLevel) | per-integrator `{Type,ThreatLevel,Source}` | Phase 7 normalization **is built** (corrects an earlier read that it was "not started"): canonical `Type ∈ {drift,panic,policy-violation,timed,disable}` and rank-aware `threatLevel`. But integrators emit **generic security signals only** — **no GPU-utilization, model-I/O, or inference-anomaly emitter exists**. |

---

## Summary breakdown

| Class | Mechanisms |
|---|---|
| **BUILT** (CPU-exercisable) | Inference/NIM rotation; WarmSwap control plane; endpoint/selector rotation; ContextMutationPolicy mutation; Regenerate (drift-detect + restore); Node rotation + D26 gate; AnomalyScorer (Passthrough+EWMA); Exact matcher; Phase-7 integrator normalization |
| **GPU-PENDING** | WarmSwap downtime SLO (400s→15s); panic MTTR (score→rotate latency); node-rotation MTTR + true cross-node relocation; KV-cache behavior; any real-LLM throughput/quality number |
| **RECEIVER-ONLY** (action wired, no emitter) | GPU-utilization detector (LLM-jacking trigger); GatekeeperViolation trigger; AI-specific integrator signals generally |
| **ABSENT** | Model-I/O detector (Pillar 03 inspector); NeMo Guardrails semantic filtering; KV-cache isolation logic |

---

## Group-1 attribution map (how to read each R6 AI-attack result)

This is the load-bearing output: for each R6-product AI attack, the **mechanism R6
cites**, its **class**, and therefore **how a "not neutralized" result must be
attributed** (so the harness never scores a missing trigger as a Phoenix loss).

| R6 attack | R6's stated mechanism | Mechanism class | Correct attribution of a "not neutralized" result | Expected MTD-effect tag |
|---|---|---|---|---|
| **LLM-Jacking** | NIM hardening; monitor GPU utilization; terminate shadow compute | action **BUILT** (rotate / GPU-zero quarantine) but **trigger RECEIVER-ONLY** (no GPU-util emitter) + measurement **GPU-PENDING** | **Missing emitter**, not a defense failure: nothing detects GPU-jacking, so no action fires on kind/today. The action path is provable only by injecting a panic event; real detection+SLO is GPU-PENDING. | MTD-BOUNDS-ONLY (with injected trigger) / MTD-CANNOT-HELP (autonomously today) |
| **Model Theft** | Rotation breaks persistent endpoint access; terminate model-scraping | rotation **BUILT**, but external endpoint stays stable (#3) and scraping-detector **ABSENT/RECEIVER-ONLY** | Rotation **bounds** a persistent *foothold* but does **not** detect scraping and **cannot un-steal** an already-extracted artifact; external endpoint persists. | MTD-BOUNDS-ONLY (foothold) / MTD-CANNOT-HELP (the extraction itself) |
| **Prompt Injection** | Pillar 01: rotate AI-request pods; invalidate session across multiple requests (semantic filtering deferred to NeMo) | pod rotation **BUILT**; semantic filter **ABSENT** (NeMo) | **SPLIT ORACLE.** (a) in-request injection: **MTD-CANNOT-HELP** (no semantic filter). (b) injected *persistence* surviving a rotation: **MTD-BOUNDS-ONLY** (rotation invalidates session-persisted state). | (a) CANNOT-HELP, (b) BOUNDS-ONLY |
| **Inference Manipulation** | Rotate API paths so static paths can't be intercepted | backend rotation **BUILT**; URL/path rotation **ABSENT** (external endpoint stable, #3) | Backend pod rotates, but the **static external path/endpoint persists** — interception of the stable path is not prevented; only the backend identity churns. | MTD-BOUNDS-ONLY / PARTIAL |
| **Pillar 03 Agentic Defense** | Security agent observes model I/O → panic mutation to a clean node on malicious payload | panic-mutation **action BUILT** (#4/#6); model-I/O **detector ABSENT** (#9) | The **action** (panic → clean-node move / GPU-quarantine) is real and testable by **injecting** the panic event; the **I/O detector is ABSENT**, so it never fires autonomously. A "not neutralized on payload" result = **absent detector**, not a defense failure. | MTD-BOUNDS-ONLY (with injected panic) / detector ABSENT |

**Consequence for scoring.** In Group 1, the `full-Phoenix` arm will **neutralize
only where the harness can supply the trigger** (e.g. inject a panic/drift/timed
`SecurityEvent`, as Pass A did for `c2-persistence-evict`). Where R6's stated
mechanism depends on a detector that is **RECEIVER-ONLY or ABSENT** (GPU-util,
model-I/O), the honest result is "**not neutralized — missing trigger**," tagged
MTD-CANNOT-HELP / detector-pending, **explicitly not** a Phoenix defense failure.
GPU-dependent numbers are reported **capability-pending** for the AWS/CoreWeave run.

---

## Capability-pending (carried into EFFECTIVENESS-AI.md)

- **GPU / real-LLM:** LLM-jacking detection + GPU-util SLO; warm-swap real downtime
  (400s→15s); KV-cache behavior; real model-extraction throughput; GPU
  side-channel / co-location. All **GPU-PENDING** on the CPU-only kind node.
- **Real-node:** node-rotation MTTR + true cross-node relocation (kind nodes are
  kubelet-less containers).
- **Detectors not built (real gaps, Phorvex differentiators):** model-I/O inspector
  (Pillar 03), GPU-utilization emitter, semantic prompt filtering (NeMo),
  KV-cache isolation.

*Compiled read-only from `architecture.md`, `PHASE0..7`+`PHASE3B` reports, and the
`phoenix-extended` + integrator trees. Every row is file:line-grounded; no code was
modified.*
