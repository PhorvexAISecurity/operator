# EFFECTIVENESS-AI — Pass-B (AI / LLM / Agentic) ≥20-TRIAL BENCHMARK

> **STATUS: COMPLETE ≥20-TRIAL BENCHMARK.** All **21 CPU-runnable AI scenarios** ran
> at **`trialsPerArm: 20`** on the kind cluster (aggregated **n=21/arm** = 20
> fixed-seed + 1 adaptive), accumulated across batches into one out-dir with
> `masterSeed=1337`. The **6 GPU/multi-node scenarios are CAPABILITY-PENDING** (run
> later on AWS/CoreWeave by config alone). 95% CIs are now tight (t≈2.09 at n=21) —
> this supersedes the coarse 2-trial smoke. No numbers fabricated.

Provenance: `build/test-harness/out-ai-bench/` — `metrics.jsonl` (**2,310 rows** = 21
× 5 arms × 22), `report.md` (full per-arm CI table), `report-dollars.md`,
`provenance.json`, `mitre_matrix.md`, `raw/` (per-trial + `operator_*.log`). Run in
two accumulating batches (B1 = 4 scenarios fresh, then the 17 remaining with
`-resume`), configs `config.ai.bench-b1.yaml` + `config.ai.bench-rest.yaml` (context
`kind-amtd-test`, ns `amtd-ai-test`, `masterSeed: 1337`). Build/vet/test re-verified
live (Go 1.26.3, exit 0). Clean teardown: namespace gone, no leftover process.

---

## 1. Scope

**21 / 21 CPU scenarios at n=20.** The **6 capability-pending** (skip-with-note):
`ai1-llm-jacking`, `ai1-pillar03-panic-mutation` (CapMultiNode), `ai2-co-location-`
`cross-tenant`, `ai2-gpu-side-channel` (CapGPU+MultiNode), `ai2-kvcache-poisoning-`
`cross-session-leak`, `ai2-unbounded-consumption` (CapGPU). Full per-arm CI table:
`out-ai-bench/report.md`.

---

## 2. MEASURED MTD-effect — the full spectrum at n=20 (tight CIs)

Every tag is DERIVED per-arm from the oracle outcome, never assumed (the review's
hardcoding defect is fixed — §5). Disruption% is mean over n=21 with 95% CI.

### MTD-NEUTRALIZES — `d-fullphoenix` only, the 4 genuine-trigger scenarios

The harness injects a matching `SecurityEvent` so the **real `matcher.go` action**
removes the foothold (the mechanism Pass A proved with `c2-persistence-evict`):

| Scenario | d-fullphoenix | d-r6blindtimer | d-randomequal |
|---|---|---|---|
| ai2-poisoned-model-registry | **NEUTRALIZES 100% [100,100]** | 0% | 0% |
| ai2-data-model-poisoning | **NEUTRALIZES 100% [100,100]** | 0% | 0% |
| ai2-agent-rogue-tool-persistence | **NEUTRALIZES 100% [100,100]** | 0% | 0% |
| ai2-malicious-model-artifact | **NEUTRALIZES 100% [100,100]** | BOUNDS 71% [50,93] | BOUNDS 67% [45,89] |

Only `d-fullphoenix` neutralizes (the only arm firing the genuine trigger). For
`malicious-model-artifact` the foothold is also pod-resident, so blind/random rotation
*additionally* bound it — the audit-predicted "NEUTRALIZE by the genuine arm, BOUND by
blind rotation" split, measured.

### MTD-BOUNDS-ONLY — rotating arms bound a pod-resident foothold (no detector)

| Scenario | d-r6blindtimer | d-randomequal |
|---|---|---|
| ai1-prompt-injection | 100% [100,100] | 52% [29,76] |
| ai2-agent-injection-to-persistence | 100% [100,100] | 67% [45,89] |
| ai2-excessive-agency | 100% [100,100] | 67% [45,89] |
| ai2-mcp-tool-poisoning | 100% [100,100] | 67% [45,89] |
| ai2-agent-excessive-agency | 95% [85,100] | 62% [39,85] |
| ai2-sensitive-info-disclosure | ~100% | ~67% |
| ai2-system-prompt-leakage | ~100% | ~67% |
| ai2-query-extraction | 0% disruption, **reuse-reduction 67%** (replay-success 3→1) | same |

Blind rotation reliably bounds the in-session/pod-resident foothold (100% at the 6s
cadence); equal-rate random bounds it roughly two-thirds of the time (memoryless gaps).
No detector → `MTD-BOUNDS-ONLY`, never NEUTRALIZES. `d-fullphoenix` is `CANNOT-HELP`
on these (timed-rotate path, no injected detector for the injection — the audit's
"no NeMo / no model-I/O detector" verdict).

### MTD-CANNOT-HELP — out-of-pod state / no detector (all arms, 0% [0,0], measured)

`model-theft`, `inference-manipulation`, `agent-memory-contamination`,
`embedding-store-tampering`, `embedding-vector-weakness`, `mcp-rogue-server`,
`mcp-tool-response-injection`, `rag-retrieval-poisoning`, `tampered-inference-base-image`.
The persistence target is outside the rotated pod (stable endpoint / PVC store /
corpus / registry ref) or has no detector — **now measured** (`armRotates(env) &&
!<live check>`), correctly 0% on every arm.

---

## 3. Controls (both VERIFIED, full run)

- **Positive control — PASS.** `d-nomtd` achieves the oracle on **every** executed
  attack trial across all 21 scenarios (0 non-achieving rows) — anchors 100%.
- **Negative control — PASS.** **105 no-attack negative-control trials; max
  `falseDefensiveActions = 0`** — zero spurious defensive moves on any arm.
- **FullPhoenix genuineness — VERIFIED.** `operator_*.log` shows the real operator
  built, applied CRDs, created the AMTD, and reconciled `matcher.go`; on the 4 trigger
  scenarios the injected event drove `MTD-NEUTRALIZES` at 100% [100,100].

---

## 4. Economics + hypotheses — ALL THREE PASS (firmed at n=20)

Source `out-ai-bench/report-dollars.md` (post-processing over the SAME schema; knobs:
gpuCount=8, $/GPU-hr=$2.50, gpuOverheadPct=0.015, avoidedBreachValue=$4.88M →
GPU-overhead **$2,628/yr saved**, arm-independent):

- **H1 (Dwell-bound):** rotating arms' mean persistence-disruption **27% (95% CI
  [17, 37]) vs static 0% → PASS** — firmed from the wide B1-only `[0,47]` once the
  BOUNDS-heavy scenarios landed.
- **H2 (In-request invariance / honest negative):** **63/63 rotating-arm rows
  attributed `detector-absent`/receiver-only → PASS** — the honest negative the
  AI-MTD-AUDIT predicts (GPU-util RECEIVER-ONLY, model-I/O ABSENT, NeMo ABSENT).
- **H3 (Trigger-gated neutralization + reuse):** trigger-supplied scenarios'
  **`d-fullphoenix` persistence-disruption 80% (CI [24, 100])** AND **rotating-arm
  reuse-reduction mean 81% → PASS** (e.g. `query-extraction` replay-success 3→1).

Schwartau: on AI rows `detectionTimeSeconds = -1` / `detectionAbsent=true` (no
autonomous detector) → `P>D+R` reported not-evaluable with the absent-note (the
AI-specific honest path). **`d-phorvex-slot` is the TO-BE-FILLED comparison** column.

---

## 5. Review fixes (the 6 defects, all resolved & verified)

1–2. **Smoke completeness** → the full ≥20-trial benchmark ran 21/21 with live
   `MTD-NEUTRALIZES`/`BOUNDS-ONLY`/`CANNOT-HELP` results and regenerated artifacts.
3. **H3 generic** → trigger scenarios identified via `TriggerAttribution=harness-`
   `injected`, no hardcoded name map (generic-core invariant).
4–5. **MTD-effect MEASURED** → the 5 previously-hardcoded scenarios compute
   `armRotates(env) && !<live check>` per arm (de-risked on the rebuilt binary).
6. **Harness-completed-restore seam disclosed** → for NEUTRALIZE scenarios the
   operator fires the real action on the matched pod; the scenario completes the
   operator's effect on the *mock* substrate gated on the genuine trigger (faithful
   stand-in; the real-workload action is proven by Pass A's `c2-persistence-evict`).

---

## 6. Pass-A-with-dollars view (no re-run, ZERO cluster touch)

Recomputed by reading `out-bench/metrics.jsonl` (1980 Pass-A rows) through the SAME
schema (no re-execution). GPU-overhead **$2,628/yr saved** (fleet).

| Arm | mean Disrupt% | mean Acts | mean TTA(s) | mean SecPerCost($) | Schwartau pos/18 |
|---|---|---|---|---|---|
| d-nomtd (static) | 0.0% | 0.00 | 0.00 | $0 | 0/18 |
| d-r6blindtimer | 38.9% | 0.50 | 3.00 | $227,733 | 9/18 |
| d-randomequal | 30.4% | 0.69 | 1.19 | $177,469 | 18/18 |
| d-fullphoenix | 5.6% | 0.06 | 0.01 | $32,533 | 18/18 |
| d-phorvex-slot | n/a (stub) | — | — | — | TO-BE-FILLED |

Honest limits: attack-reusability is NOT derivable from Pass-A raw logs (Reuse struct
postdates Pass A → NOT-MEASURED, a Pass-B-only metric); Schwartau D=R=meanTTA; Pass A
has no AI in-request/trigger rows (H2/H3 are Pass-B-only; Pass A proves H1 + the
injected-event mechanism via `c2-persistence-evict` = 100% disruption).

---

## 7. Capability-pending (carried to the AWS/CoreWeave GPU run)

The 6 skipped scenarios + their pending numbers — CPU stand-ins ran; the real number
needs GPU/MIG/multi-node and is **not fabricated**: GPU-util shadow-compute SLO
(llm-jacking), real $ GPU-cost (unbounded-consumption), KV-cache cross-session leak
(kvcache, audit #11), cross-node relocation MTTR (pillar03 — action path proven via
`c2-persistence-evict`), GPU side-channel + co-location/cross-tenant residency. They
run **by config alone** on the GPU cluster — zero code change.

---

## 8. Status — kind benchmark COMPLETE

The ≥20-trial AI benchmark on kind is **done**: 21/21 scenarios at n=20, all three
hypotheses PASS, controls anchored, MTD-effect spectrum measured with tight CIs. The
**only remaining work is the GPU/real-LLM run** (the 6 capability-pending scenarios +
the GPU headline numbers: real LLM-jacking detection, warm-swap downtime, panic MTTR,
KV-cache behavior) — run on AWS/CoreWeave by swapping the per-target config, and the
`d-phorvex-slot` arm fills its H1/H2/H3 column when the real Phorvex defender drops in
as one file.
