# PROJECT-LOG — Phoenix-Extended + Attack Harness (full engagement record)

*A durable, standalone record of the entire build-and-measure engagement. Read this to
understand the whole project state without opening anything else. Compiled 2026-06-02.
No code was changed to write this.*

---

## 1. The goal

Take **R6 Security's Phoenix** — a Kubernetes Adaptive Moving Target Defense (AMTD) operator
for AI/inference workloads — from *what the papers and product pages claim* to *something
built, faithful, and measured*. Concretely:

1. **Map** R6's claims (4 academic papers in `papers/`, 2 product pages in `products/`)
   against the 5 actual SSPL-licensed source repos (`repos/`), honestly flagging claim-vs-code.
2. **Build** the AI/inference AMTD capabilities the papers describe but the open code lacks —
   extending the operator faithfully, originals untouched.
3. **Attack** it as a world-class red team with a reusable, extensible benchmark harness, and
   **measure** with hard numbers (controls, ≥20-trial confidence intervals) what Phoenix
   actually stops.
4. **Compare** the measured results to R6's quantitative claims, and produce onboarding +
   deployment documentation.

Everything new lives under `build/`; the original repos under `repos/` were never modified.

---

## 2. The arc of the work (stage by stage)

### Stage 0 — Specification mapping (`spec-map.md`)
Mapped every claimed mechanism to exact files/lines across the 5 repos, adversarially
verified. **Headline finding:** only a *time-based trigger* and a *minimal pod-delete-and-
reschedule* are genuinely implemented upstream. The marketable mechanisms — **node rotation,
randomized/jittered intervals, telemetry-weighted adaptation, signed-baseline drift
correction, golden-image/warm-pool swap, and NVIDIA-NIM inference rotation** — are
**claimed-without-code**, and **every quantitative figure** (Persistence <4%, 94% disruption,
400s→15s, `MODEL_ROTATION 3.2s`, `DWELL_TIME 0ms`, 99.8% availability, 1-2% overhead) is a
paper/marketing/dashboard value with **no measurement or enforcement code**. All 5 repos are
**SSPL-1.0** (source-available, non-OSI copyleft).

### Stage 1 — Gap spec + locked design (`gap-spec.md`, `decisions.md`, `architecture.md`)
Wrote a precise implementation spec for everything the papers describe but the code lacked,
resolved ~36 flagged decision forks into a locked architecture, and sequenced an 8-phase
build. **The load-bearing design rule:** *every* defensive action must be invokable through
the public CRD interface — an `AMTD.Strategy[]` entry triggered by a `SecurityEvent` — and the
exact-match (`reflect.DeepEqual`) matcher was relaxed to allow a computed score/threshold to
select an action **while keeping exact-match byte-for-byte identical** (the "byte-compat
theorem"). Accuracy discipline distinguished `[PAPER-SPECIFIED]` vs `[UNDERSPECIFIED→design
decision]` vs `[R6-PAPER-ONLY]` so nothing was invented.

### Stage 2 — The 8-phase build (`build/phoenix-extended/` + `PHASE*-REPORT.md`)
Each phase was one request, built/vetted/tested, verified live on a kind cluster, with REAL
results and GPU-dependent numbers marked PENDING:

| Phase | What it added |
|---|---|
| **0** | The relaxed matcher (exact + scored, `MatcherMode` default Exact); the `AMTDAction` union extended with Rotate/WarmSwap/Regenerate/NodeRotate as type-only stubs; byte-compat proven. |
| **1** | Inference/NIM **Rotate** — image/env/GPU mutation, durable owner-template patch (the mutation-survival decision). |
| **2** | **Jittered cadence + scheduling** (`time-based-trigger-extended`) + max-concurrent-rotations. |
| **3** | **Telemetry-scoring** layer — Passthrough default (invents no math), EWMA, panic hysteresis. |
| **3b** | **ContextMutationPolicy** + panic-mutation path; the GatekeeperViolation **receiver** (no native emitter — built the receiver, did not fabricate an emitter). |
| **4** | **Warm-swap** control plane (`WarmInferenceSet` / leader→shadow cutover); 400→15s downtime marked GPU-PENDING. |
| **5** | **Regenerate** — signed-baseline drift detect + restore-from-golden (ECDSA/ed25519); "signing = provenance, not benignity" caveat carried. |
| **6** | **Node rotation** — `NodeRotation` CRD, clean-node selection, the **D26 trust gate** (Source allowlist + ThreatLevel floor + human-approval-for-Delete); real-node MTTR marked PENDING. |
| **7** | **Per-integrator normalization** + score-carrier across the falco/prometheus/kubearmor integrators (the canonical Type/ThreatLevel vocabulary). |

Result: **6 CRDs** (AdaptiveMovingTargetDefense, SecurityEvent, WarmInferenceSet,
WorkloadBaseline, NodeRotation, ContextMutationPolicy) and a **9-member `AMTDAction`** union
(legacy Disable/Delete/Quarantine/Debugger/CustomAction + new Rotate/WarmSwap/Regenerate/
NodeRotate, `MaxProperties=1`). **No stubs remain.**

### Stage 3 — End-to-end validation (`validation.md`)
Stood the operator + integrators up live on kind and exercised the whole pipeline together.
**233/233 unit tests pass across 5 trees; all 11 action paths fired end-to-end** with real
SecurityEvent/CR + operator-log evidence; **Phase-0 exact-match unregressed**; the D26 gate
**blocked both** a non-allowlisted source and a below-floor event; score flow proven on the
Falco-proxy and real-Prometheus paths. GPU/real-node items (warm-swap downtime, panic MTTR,
node MTTR, GPU-MIG preflight) correctly marked PENDING.

### Stage 4 Pass A — Kubernetes attack suite (`build/test-harness/` + `*-K8S.md`)
Built the **durable, extensible plugin harness**: every attack is a self-registering
`Scenario`, every defense a self-registering `Defender`, behind a generic runner + one metric
schema, with per-target config + required owned-ack, runtime capability detection, mocks-only
containment, and full provenance. **18 K8s scenarios** in 3 categories (classic chain incl.
CVE-2019-5736 behavior; R6-claimed; modern R6-unsupported), **5 defender arms** (no-MTD,
R6-blind-timer, random-at-equal-rate, full-Phoenix, + a reserved Phorvex slot), **MITRE
ATT&CK for Containers** coverage (38 techniques). Smoke first, then the full benchmark.

### Stage 4 Pass B — AI/inference attack suite (`*-AI.md`, `AI-MTD-AUDIT.md`)
**Step 0** produced `AI-MTD-AUDIT.md`: an honest per-mechanism classification
(BUILT/GPU-PENDING/RECEIVER-ONLY/ABSENT) used to attribute every Group-1 result correctly.
Then **27 AI scenarios** were added to the *same* harness (Group 1 = R6's 4 AI attacks +
Pillar 03; Group 2 = OWASP LLM Top 10 + MCP + agentic + model-extraction + KV-cache + AI
supply-chain + RAG), each **double-tagged** (R6-response × MTD-effect) with **split oracles**
(in-request vs persistence), plus a **metrics extension** ($ ROI, Schwartau, attack-
reusability, hypotheses H1/H2/H3) applied to the shared schema and recomputed over Pass A.
Six review defects were found and fixed (smoke truncation, an H3 scenario-name hardcode, the
MTD-effect being assumed rather than measured, and a disclosed harness-completed-restore seam).

### Stage 5 — Both ≥20-trial benchmarks
- **K8s benchmark** (`out-bench/`): 18 scenarios × 5 arms × 20 trials + controls + adaptive =
  **1,980 trials**.
- **AI benchmark** (`out-ai-bench/`): 21 CPU scenarios × 5 arms × 20 trials + controls +
  adaptive = **2,310 trials** (run in batches accumulated via a `-resume` flag into one
  out-dir, same `masterSeed=1337`). The 6 GPU/multi-node scenarios are capability-pending.

### Stage 6 — Comparison + documentation
- `COMPARISON.md` — R6's published numbers side-by-side with the measured results.
- `CODE-REPORT.md` — a single developer + founder onboarding guide to the whole codebase.
- `DEPLOY-AWS-COREWEAVE.md` — a step-by-step runbook to EKS/CoreWeave with the GPU work
  honestly split into "obtainable by config swap" vs "needs a real LLM workload (PENDING)."

---

## 3. Key decisions made (and why)

- **Public-interface-only actions + relaxed-but-compatible matcher.** Every capability is
  reachable solely through `AMTD.Strategy[]` + a `SecurityEvent`; the scored matcher is opt-in
  (`MatcherMode: Scored`) and exact-match is byte-identical to upstream. *Why:* one clean
  extension surface; existing policies behave unchanged; the harness can exercise any
  capability by emitting the right event.
- **One phase per request; originals untouched; honest stubs until each phase.** *Why:*
  reviewable increments; no scope bleed; nothing claimed before it was built.
- **Never fabricate GPU/real-node numbers — mark PENDING.** *Why:* the kind cluster is
  single-node CPU-only; honesty is the product's whole value proposition here.
- **Harness as plugins, not a monolith.** Self-registering scenarios/defenders, a generic
  runner, one comparable metric schema, mocks-only containment, config-driven portability.
  *Why:* "build once, extend forever" — add an attack or the future Phorvex arm as one file.
- **Audit-attribution rule for Group-1.** full-Phoenix neutralizes *only where the harness
  supplies the trigger*; a RECEIVER-ONLY/ABSENT detector yields "missing-trigger," **never** a
  defense failure. *Why:* otherwise a missing sensor would be misread as Phoenix losing.
- **MTD-effect measured, never assumed.** A late review caught scenarios hardcoding the effect
  tag; fixed to derive it per-arm from the live oracle outcome.
- **Batched benchmark with deterministic accumulation.** A `-resume` flag appends disjoint
  batches into one out-dir under one `masterSeed`. *Why:* run a heavy benchmark in
  limit-sized chunks while staying reproducible and comparable.

---

## 4. Key findings

### 4.1 The measured MTD-effect spectrum (AI benchmark, n=20, tight CIs)
- **MTD-NEUTRALIZES** — only `d-fullphoenix`, only the **4 genuine-trigger scenarios**
  (poisoned-model-registry, data-model-poisoning, malicious-model-artifact,
  agent-rogue-tool-persistence), all **100% [100,100]** via the real `matcher.go` injected-event
  action.
- **MTD-BOUNDS-ONLY** — rotating arms on **8 pod-resident footholds** (prompt-injection at
  blind-timer 100% / random 52%, the agentic / excessive-agency / system-prompt /
  mcp-tool-poisoning / sensitive-info / query-extraction scenarios). Blind rotation bounds the
  foothold; no detector ⇒ never neutralizes.
- **MTD-CANNOT-HELP** — **9 out-of-pod / no-detector** scenarios at **0% [0,0]** on every arm
  (model-theft, inference-manipulation, RAG, embedding-store/-vector, MCP-rogue/-response,
  memory-contamination, tampered-image) — *measured*, not assumed.

### 4.2 R6's claims vs. what we measured (from `COMPARISON.md`)
- **Dwell reduction — ✅ confirmed in mechanism:** dwell is bounded by the rotation interval
  (the "150 days → <60 min" idea). "`DWELL_TIME 0ms`" is marketing — rotation bounds dwell,
  cannot zero it.
- **"94% disruption" / "<4% persistence" — ⚠️ true only narrowly:** rotation hits **100%** on
  time-bounded pod-resident footholds, but the **measured mean disruption is ~30–39%** (K8s)
  because a large class of real attacks (credential/token theft, supply-chain, admission
  bypass, CI/CD, sidecar injection, secrets-sprawl, RAG/embedding poisoning, IMDS theft) live
  **outside the rotated pod** or trip no detector ⇒ 0% on every arm.
- **"Adaptive beats Timed" — ⚠️ inverted in our data:** the **blind 6s timer (38.9% mean)
  out-disrupted the reactive full-Phoenix operator (5.6% mean)** in K8s, because Phoenix is
  **emitter-dependent** and the AI detectors that would make rotation "adaptive" are
  RECEIVER-ONLY/ABSENT. Phoenix wins decisively only where the trigger exists.
- **GPU/economic/scale numbers (400→15s, 3.2s, 1-2% overhead, 99.8%, 50k) — ⏳ can't-yet-test:**
  capability-pending for the GPU run; the operator mechanisms are built, the real GPU
  workload is the missing input.

### 4.3 Capability status (from `AI-MTD-AUDIT.md`)
- **BUILT (CPU-exercisable):** inference/NIM rotation, warm-swap control plane, endpoint/
  selector rotation (backend-only), ContextMutationPolicy mutation, Regenerate, node rotation +
  D26 gate, AnomalyScorer (Passthrough+EWMA), Exact matcher, Phase-7 normalization.
- **GPU-PENDING:** warm-swap downtime SLO, panic MTTR, node-rotation MTTR + true cross-node
  relocation, KV-cache behavior, real-LLM numbers.
- **RECEIVER-ONLY (action wired, no native emitter):** GPU-utilization detector (the
  LLM-jacking trigger — only a GPU-*zeroing actuator* exists), GatekeeperViolation trigger.
- **ABSENT (the honest gaps / Phorvex differentiators):** model-I/O detector (Pillar 03
  inspector), NeMo Guardrails semantic filtering, KV-cache isolation.

### 4.4 Hypotheses (AI benchmark, all PASS at n=20)
- **H1 (Dwell-bound):** rotating arms 27% (95% CI [17,37]) vs static 0% → PASS.
- **H2 (In-request invariance / honest negative):** 63/63 rotating rows detector-absent → PASS.
- **H3 (Trigger-gated neutralization + reuse):** full-Phoenix 80% [24,100] on trigger
  scenarios + 81% mean replay-reuse reduction → PASS.

### 4.5 Headline benchmark numbers
- **K8s (`out-bench/`):** mean disruption — blind-timer **38.9%**, random-equal **30.4%**,
  full-Phoenix **5.6%**, no-MTD 0%. Negative control: 0 false defensive moves; positive
  control: every undefended attack succeeds.
- **AI (`out-ai-bench/`):** the spectrum + hypotheses above; 135 negative-control trials with
  0 false moves; all undefended attacks succeed.
- **$ view:** GPU-overhead **$2,628/yr saved** at 8 GPUs × $2.50/hr × 1.5% (a *swappable
  input*, not a GPU measurement); per-arm security-per-cost + Schwartau in the dollars reports.

---

## 5. Full artifact inventory (file paths)

### Analysis, design & final reports (repo root)
- `spec-map.md` — claims → upstream code map (the honest baseline).
- `gap-spec.md` — implementation spec for the missing capabilities.
- `decisions.md` — the ~36 resolved decision forks.
- `architecture.md` — the locked architecture + 8-phase plan (source of truth).
- `validation.md` — the end-to-end live validation report.
- `COMPARISON.md` — R6 claims vs. measured results.
- `CODE-REPORT.md` — developer + founder onboarding guide.
- `DEPLOY-AWS-COREWEAVE.md` — the EKS/CoreWeave GPU runbook.
- `PROJECT-LOG.md` — this record.

### Per-phase + suite reports (`build/`)
- `build/PHASE0-REPORT.md` … `PHASE7-REPORT.md`, `build/PHASE3B-REPORT.md`.
- `build/AI-MTD-AUDIT.md` — the AI-side capability classification.
- `build/ATTACKS-K8S.md`, `build/ATTACK-COVERAGE-K8S.md`, `build/EFFECTIVENESS-K8S.md`.
- `build/ATTACKS-AI.md`, `build/ATTACK-COVERAGE-AI.md`, `build/EFFECTIVENESS-AI.md`.

### Code — the extended operator (`build/phoenix-extended/`)
- `api/v1beta1/` — the 6 CRD types, `matcher.go` (the pure exact+scored predicate),
  `vocabulary.go` (canonical Type/ThreatLevel).
- `internal/controller/` — the reconcilers + action executors (securityevent_controller,
  rotate_executor, warmswap_action, regenerate_action, noderotate_action, scoring,
  node_rotate_gate, nodedrainer, mutation, swap, baseline_*, etc.).
- `internal/scheduler/` — jittered cadence. `cmd/main.go` — entrypoint.
- `config/crd/bases/` — the 6 generated CRD manifests. `charts/phoenix/` — the Helm chart.
- `README.md`, `docs/`.

### Code — the integrators / trigger (`build/`)
- `time-based-trigger-extended/` (jittered emission), `falco-integrator-extended/`,
  `prometheus-integrator-extended/`, `kubearmor-integrator-extended/` (Phase-7 normalization;
  the latter two carry the score-carrier).

### Code — the attack harness (`build/test-harness/`)
- `cmd/harness/main.go` (CLI: `-config`, `-list`, `-dry-run`, `-resume`, `-dollars-from`).
- `internal/core/` (interfaces, registry, runner, metric+economics, env, stats, logger).
- `internal/{config,capability,safety,mocks,report,kube}/`.
- `scenarios/` (18 K8s `c1_*/c2_*/c3_*` + 27 AI `ai1_*/ai2_*`, one file each).
- `defenders/` (the 5 arms, one file each). `README.md`. The `config.*.yaml` run configs.

### Benchmark outputs (`build/test-harness/`)
- **`out-bench/`** — K8s ≥20-trial benchmark (1,980 rows): `metrics.jsonl`, `report.md`,
  `report-dollars.md`, `mitre_matrix.md`, `provenance.json`, `raw/`.
- **`out-ai-bench/`** — AI ≥20-trial benchmark (2,310 rows): same set.
- **`out-ai-smoke/`** — the AI 2-trial smoke (the full-spectrum dress rehearsal).
- Intermediate evidence dirs: `out/`, `out-verify/`, `out-fpprobe/`, `out-probe/`,
  `out-ai-derisk/`, `out-ai-derisk2/`.

### Untouched originals
- `repos/` — the 5 original R6 SSPL repos, **unchanged** (the build baseline).
- `papers/` (4 PDFs), `products/` (2 PDFs) — the source claims.

---

## 6. What remains

1. **The GPU / real-LLM run** (`DEPLOY-AWS-COREWEAVE.md`). Tier A (config swap on EKS/CoreWeave)
   gives the 6 capability-pending scenarios executing + real cross-node NodeRotate/panic MTTR +
   a $ view at real GPU economics. Tier B — warm-swap 400→15s downtime, `MODEL_ROTATION 3.2s`,
   real LLM-jacking GPU-util detection, overhead %, availability %, KV-cache — needs a **real
   inference workload (NIM/vLLM/Triton) + a DCGM→Prometheus emitter** wired in; honestly PENDING.
2. **The Phorvex defender arm.** The `d-phorvex-slot` stub reserves its column; when the real
   Phorvex defense exists it drops in as one file and fills H1/H2/H3 + every report with zero
   harness changes.
3. **Closing the RECEIVER-ONLY / ABSENT detector gaps** (GPU-util emitter, model-I/O inspector,
   NeMo semantic filtering) — the gaps the benchmark already shows would change the outcome.

---

## 7. How to reproduce (one-liners)

```sh
# Operator: build/test/vet
cd build/phoenix-extended && go build ./... && go vet ./... && go test ./...

# Harness: build/test/vet + list plugins
cd build/test-harness && go build ./... && go test ./... && go run ./cmd/harness -list

# Re-run a benchmark (everything reproduces from masterSeed=1337):
go run ./cmd/harness -config config.kind.bench.yaml        # K8s, trialsPerArm>=20
go run ./cmd/harness -config config.ai.bench-b1.yaml       # AI batch 1
go run ./cmd/harness -config config.ai.bench-rest.yaml -resume   # remaining AI scenarios

# Regenerate the $ view from existing metrics (no cluster):
go run ./cmd/harness -dollars-from out-ai-bench/metrics.jsonl
```

*License note: all operator/integrator code is **SSPL-1.0** (inherited from upstream R6);
any hosted/productized offering is subject to SSPL's service-source obligations and legal
review. The attack harness is original work in this repo. No fabricated numbers appear in any
artifact above — every measured figure traces to a raw log via a `provenance.json`, and every
GPU/real-LLM number is explicitly marked PENDING.*

---

## 8. RESUMING LATER (a fresh Claude Code session: read this, then continue with zero re-explaining)

This section is written so a brand-new session can pick up the project cold. Read §1–§7 above
for context, then this for exactly how to continue.

### 8.1 Model / session settings I was using
- **Model:** **Claude Opus 4.8 (1M context)** — model ID `claude-opus-4-8[1m]`.
- **Fast mode:** ON (toggle with `/fast`; Opus output, faster — not a smaller model).
- **Working style:** high reasoning effort; long background runs are launched as **local
  processes** (free of the weekly usage limit — only my conversation turns cost the limit), and
  I report once per run. I was managing a limited weekly budget, so prefer **few, large
  batches** + background runs over chatty polling.

### 8.2 Environment setup (verified 2026-06-02 — exact)
- **OS / shell:** Windows 11; **PowerShell** is primary (use `$null` not `/dev/null`,
  `$env:VAR` not `$VAR`). Bash is available but **has no coreutils** (`grep`/`ls`/`tr` are
  missing) — use PowerShell + the dedicated Read/Grep/Glob tools instead.
- **Primary working dir:** `C:\Users\moh87733\Phorvex`. Additional working dirs: `C:\tmp`
  (workflow scripts were written here, e.g. the Pass-A/Pass-B `*.js`), and
  `C:\Users\moh87733\ieee-tsg-paper\sources`.
- **Go:** `go1.26.3 windows/amd64` (on PATH).
- **kind cluster (already running):** context **`kind-amtd-test`**, node
  **`amtd-test-control-plane`**, Kubernetes **v1.35.0**, containerd **2.2.0**, **single node,
  NO GPU**. apiserver at **`https://127.0.0.1:62067`**. Hosted by **Docker Desktop 29.5.2** (the
  kind node is a Docker container — Docker must be running).
- **Binaries / the `C:\kube` paths:** `kubectl` **v1.34.1** is on PATH; the user also keeps
  **`C:\kube\kubectl.exe`** and **`C:\kube\kind.exe`** there — **`kind` is NOT on PATH**, so to
  manage the cluster use `& C:\kube\kind.exe ...` (e.g. `& C:\kube\kind.exe get clusters`).
- **kubeconfig:** `KUBECONFIG` env is **empty** ⇒ default **`C:\Users\moh87733\.kube\config`**.
  The harness configs use `kubeconfig: ""` (default lookup) + the `context:` name.
- **helm:** **NOT installed / not on PATH** — install Helm 3 before the production Helm deploy
  in `DEPLOY-AWS-COREWEAVE.md` §5.1 (the *benchmark* path §5.2 does not need Helm).
- **`KUBEBUILDER_ASSETS`:** **unset**. The operator's envtest suite (`phoenix-extended/.../
  suite_test.go`) needs it — set it to an **envtest 1.30.3 windows/amd64** assets dir before
  `go test ./...` in `phoenix-extended` if those tests need a control plane (envtest 1.30.4 does
  not exist for windows/amd64). The harness tests and most operator unit tests need no cluster.
- **No `make` / no `controller-gen` binary:** CRD generation is done via `go run` of
  controller-gen v0.17.2. The operator builds to `bin/manager.exe`, the harness to
  `bin/harness.exe` — **rebuild `bin/harness.exe` after any harness code change** (a stale
  binary silently runs the old scenario set — this bit us once).

### 8.3 Operating gotchas a fresh session must know
- **Benchmarks run as background local processes** (`run_in_background`); they survive client
  disconnects. Check progress **read-only** (count `out-*/metrics.jsonl` rows, `Get-Process
  harness`); do not relaunch a run that is still alive (you would corrupt `metrics.jsonl`).
- **Reproducibility:** everything keys off **`masterSeed=1337`**. Use the `-resume` flag to
  accumulate disjoint scenario batches into one out-dir.
- **Discipline (non-negotiable):** never fabricate a GPU/real-node number — mark PENDING.
  Keep `repos/` (the 5 originals) untouched. Mocks-only containment in the harness, EXCEPT the
  Tier-B GPU run intentionally deploys a real model server **you own**. Follow
  `architecture.md` for any operator change; preserve the byte-compat exact matcher.

### 8.4 The three remaining tasks — exact paste-ready prompts

**(A) GPU run — Tier A (by config swap; needs an owned EKS or CoreWeave cluster):**
> Read `./PROJECT-LOG.md` and `./DEPLOY-AWS-COREWEAVE.md`. I now have an owned **[AWS EKS |
> CoreWeave]** cluster with GPU + ≥2 nodes and the NVIDIA device plugin installed; my
> kube-context is `<PASTE CONTEXT>` and apiserver `<PASTE SERVER>`. Execute **Tier A** of the
> GPU run: write `build/test-harness/config.<env>.yaml` (kubeconfig/context/namespace=
> amtd-attack-test/ownedAck=true/trialsPerArm=20/masterSeed=1337/phoenixSrcDir=../phoenix-
> extended/outDir=out-<env> + my real `gpuCount`/`dollarsPerGpuHour`/`avoidedBreachValue`),
> prove the safety guard accepts it with `-dry-run`, confirm capability detection flips the 6
> GPU/multi-node scenarios ON, then run the 18-scenario K8s suite and the full **27-scenario**
> AI suite (the 6 now execute). Capture the **real cross-node NodeRotate MTTR and panic MTTR**.
> Report REAL results and keep all **Tier-B** numbers explicitly PENDING. Do not change code.
> *(Optionally add the word "workflow" to run it as a multi-agent workflow.)*

**(B) GPU run — Tier B (the true GPU headline numbers; needs real-LLM integration):**
> Read `./PROJECT-LOG.md` and `./DEPLOY-AWS-COREWEAVE.md` §8.2. Wire the **Tier-B** real-LLM
> integration on my owned GPU cluster: deploy a real inference workload (**NVIDIA NIM / vLLM /
> Triton**) as the AMTD `PodSelector` target + the `WarmInferenceSet` pool; deploy the **DCGM
> exporter → Prometheus → the prometheus-integrator** so a real GPU-utilization spike emits a
> scored `SecurityEvent`; point the `WorkloadBaseline` at the signed model image. Then measure
> the Tier-B headline numbers and compare to R6's claims: **warm-swap 400s→15s downtime**,
> **MODEL_ROTATION time** (R6: 3.2s), **real LLM-jacking GPU-util detection**, **GPU overhead %**
> (R6: 1–2%), **availability %** (R6: 99.8%), **KV-cache** behavior. Report REAL measured numbers;
> be explicit about exactly what real workload + emitter you wired (this is beyond a config
> swap). Do not fabricate; mark anything still unreachable as PENDING with the reason.

**(C) Build the Phorvex defender arm:**
> Read `./PROJECT-LOG.md` (the reserved `d-phorvex-slot`) and `build/test-harness/README.md`
> ("how to add a new defender"). Build the real **Phorvex** defense as a new defender arm:
> create `build/test-harness/defenders/d_phorvex.go` implementing the `Defender` interface
> (`Metadata`/`Setup`/`Start`/`Stop`/`Teardown`), self-registering via `func init(){
> core.RegisterDefender(&phorvex{}) }`, with **[DESCRIBE PHORVEX'S ACTUAL DEFENSE HERE]**. It
> must drop in as just another arm with **zero core/scenario changes**. Build/vet/test green,
> rebuild `bin/harness.exe`, then re-run the K8s and AI benchmarks (same `masterSeed=1337`,
> `-resume`) so the **`d-phorvex-slot` TO-BE-FILLED column** in `EFFECTIVENESS-K8S.md`,
> `EFFECTIVENESS-AI.md`, and the `report-dollars.md` H1/H2/H3 tables fills with Phorvex's
> measured results — directly comparable to full-Phoenix. Report REAL results.

### 8.5 Sequencing suggestion
Do **(A)** first (cheapest; proves the operator + the 6 scenarios on real hardware and retires
the node/MTTR PENDINGs). Do **(C)** at any time (it is local on kind — no GPU needed). Do **(B)**
last (it needs the most real-infra integration and is where the marquee R6 numbers — 400→15s,
3.2s, overhead, availability — finally get measured). All three are independent.

---

## 9. Phorvex — the intelligence layer (the SEPARATE product: `./phorvex/`)

This is the **new product** built on top of UNMODIFIED extended Phoenix: a separate Go module
(`github.com/phorvex/phorvex`) that adds the **deterministic brain** (no LLM in the decision
path) and reuses Phoenix's **hands** over **Seam 1** (emit `SecurityEvent` + maintain an
`AdaptiveMovingTargetDefense` strategy → Phoenix runs delete|quarantine). It depends on Phoenix
ONLY via a consumer-side `replace github.com/r6security/phoenix => ../build/phoenix-extended`,
which does **not** modify Phoenix — extended Phoenix and the harness build/run unchanged after
every stage. Spec sources: `./PHORVEX_PRD.md`, `./PHORVEX_V1_MVP.md` (both are DOCX renamed
`.md`; extracted text lives in `c:\tmp\PHORVEX_*.txt`). Built/run on the same kind cluster
`amtd-test` (K8s v1.35.0), Go 1.26.3, the `C:\kube` tools.

### 9.1 P0 — platform (COMPLETE) — `phorvex/P0-REPORT.md`
The MVP skeleton: `PhorvexPolicy` CRD (`phorvex.ai/v1alpha1`, **per-tenant from line one**);
ingest (Prometheus + SecurityEvent watch + K8s graph: pods/labels/NetworkPolicy/RBAC/nodes/MIG);
blast-radius reachability graph; per-variable exposure clock; 5 swappable registries
(PhysicsProfile, FeasibilityConstraint, CostModel, BeliefEstimator, ContextProvider) +
`PhoenixActuator`/`NativeActuator` stub; dry-run audit + Prometheus + Grafana; least-privilege
RBAC (never writes pods). Live on kind: ~3 ms/tick, real blast-radius scores, the PRD lead demo
(R6 would blind-rotate all incl. stateful; Phorvex quarantines high-blast, preserves state).
Seam-1 proof: a Phorvex-emitted event made Phoenix `Delete` a pod.

### 9.2 P1 — the method (COMPLETE) — `phorvex/METHOD-DECISION.md`, `phorvex/P1-REPORT.md`
A multi-agent search (3 axes × adversarial eligibility gate, 12 candidates) chose, with
reasoning, the **submodular recon-coverage** stack over the PRD's Stackelberg default:
- **Decision:** cost-weighted submodular recon-coverage maximization over a DYNAMICALLY-
  generated feasible action set, with a Lagrangian/Whittle timing dual (λ = solved shadow-price).
- **Context:** semi-Markov kill-chain hazard (the sojourn hazard IS the predictive belief
  horizon) + Beta-Bernoulli P(hold) + per-tenant conjugate memory.
- **Cost:** RLS self-calibrating `C=λ₁C_norm+λ₂C_flow` + dual-descent λ + conformal `C_hi`
  envelope for the `[SP-0-PENDING]` GPU/KV-cache terms (never fabricated).
**IP-gate ablation (GATE #1) PASSED live on kind: 1.62×** — P1 invalidates 62% more recon-weight
per dollar than random over the identical feasible set (P1 8.78 vs random 5.41; P1 even spent
less). Dynamic action-set verified (set changes with state), predictive horizon + optimized
timing exercised, hard-constraint inviolability proven, modularity proven (one file = one impl).

### 9.3 P2 — actuation (COMPLETE) — `phorvex/P2-REPORT.md`
The submodular optimizer wired to **live actuation** over Seam 1. **Real results on kind:**
- **11 autonomous actuations** by the running active-mode operator: **3 web pods really deleted
  + respawned** by Phoenix; **stateful `state-0` quarantined** with **rotate inviolably excluded**
  (data preserved).
- **Global kill-switch PASS** — actuations frozen while engaged (the engine keeps deciding +
  logging; emits nothing). **Per-namespace dry-run PASS** — a `phorvex.ai/dry-run` namespace
  annotation suppressed actuation even with an active policy + kill-switch off.
- **Inviolability via TWO gates** — the action-set generator excludes SLO/feasibility-violating
  moves before selection, plus an emit-boundary guard; **budget B = inviolable top-B truncation**,
  λ only shapes *which* B (provably can't DoS itself).
- **Emergent firing rate** — actuation gaps **9s / 5s / 5s / 10s** (not a cron); **λ rose
  0.6 → 1.55**, dual-solved (rising risk raises the rate, λ self-throttles it).
- **139/139 decisions fully audited** — every decision carries inputs + coverage/cost math +
  SHAP-style marginal-gain attribution + the **R6 counterfactual** (action + prose note).
- **Phoenix + harness build unchanged**; **12 test files, 6,720 LOC**, build/vet/test green.

### 9.4 Next step — **P3: full attack benchmark (GATE #2)**
The remaining Phorvex stage: run the full attack/benchmark suite with the real Phorvex defender
as an arm (this is where the harness's reserved `d-phorvex-slot`, §8.4(C), and the Phorvex
product meet) — measuring Phorvex vs no-MTD / R6-blind-timer / random / full-Phoenix on
security-per-cost, dwell, the held-out-CVE / stealth-dweller scenarios, and H1/H2/H3. GATE #2 =
does the live, end-to-end defense beat the baselines on the benchmark (not just the per-dollar
recon-invalidation IP gate that P1 already passed). GPU/SP-0 numbers remain PENDING until the
owned-cluster run (§8.4 A/B).

### 9.5 Phorvex artifact inventory (`./phorvex/`)
`METHOD-DECISION.md` · `P0-REPORT.md` · `P1-REPORT.md` · `P2-REPORT.md` · `README.md` (FR1–FR9 map)
· `api/v1alpha1/` (PhorvexPolicy CRD) · `internal/{model,registry,physics,feasibility,cost,
belief,ctxprov,graph,exposure,ingest,actuator,decision,recon,killchain,actionset,metrics,audit,
runner,controller}/` · `cmd/main.go` (`--engine=p1|p0`, `--ablation`, `--integration-emit`,
`--global-kill-switch`) · `config/` (CRD + least-priv RBAC + sample) · `charts/phorvex/` (Helm)
· `grafana/phorvex-heatmap.json`. Demo manifests: `c:\tmp\phorvex-demo.yaml`,
`phorvex-policy*.yaml`.

### 9.6 P3 — full attack benchmark (GATE #2): BUILD COMPLETE + 2-trial smoke (directionally PASSED)
The real Phorvex defense is now plugged into the EXISTING attack harness as the **PX arm**
(`d-phorvex`, filling the reserved `d-phorvex-slot`) with **ZERO harness-core and ZERO
extended-Phoenix changes** — only self-registering plugin files + one plugin-test update. PX runs
genuine extended Phoenix **+** the Phorvex operator (active); the deterministic submodular brain
decides and emits SecurityEvents Phoenix actuates.

**Built (plugin files):** `defenders/d_phorvex_slot.go` (the PX arm, fills the slot),
`defenders/d_reactive_only.go` (the `d-reactive-only` H3 baseline — Phoenix reactive matcher, no
proactive timer), `defenders/d_phoenix_shared.go` (shared build/run/pin helper; FullPhoenix
untouched), `scenarios/c1_heldout_cve.go` (zero-day: NO detector event), `scenarios/c1_llm_adaptive.go`
(a **deterministic** LLM-style learner — no real LLM, seed-reproducible), `config.p3.smoke.yaml`. The
**metric extensions** live in the Phorvex module as a separate post-processor `phorvex/cmd/p3report`
→ `phorvex/EFFECTIVENESS-PHORVEX.md` (TIER 1-4 + investor/customer lenses + H1/H2/H3 + counterfactual
+ roadmap; imports nothing from the harness). Six arms total: no-MTD, R6-blind-timer, random-at-equal-
rate, reactive-only, full-Phoenix, PX. harness + phorvex `build/vet/test` green.

**Smoke result (REAL, kind; 3 detector-silent scenarios × 6 arms × (2 trials + neg control) = 54 rows):**
- **54/54 rows, 0 skips** — PX, reactive-only and full-Phoenix all ran the real operators.
- **Controls clean:** negative control **0** false defensive moves across all arms; positive control
  `d-nomtd` achieved the oracle **2/2** in every scenario.
- **THE DIFFERENTIATOR (directional):** on all 3 detector-silent scenarios (held-out-CVE / stealth-
  dweller / adaptive re-strike) **PX disrupts 100% at 0.5 moves** — its **proactive floor evicts with
  NO detector** — while **`d-reactive-only` and `d-fullphoenix` disrupt 0%** (no detector event ⇒ the
  reactive matcher never fires). **PX beats `random` on cost: 0.5 vs 1.0-2.5 moves.**
- **Honesty caveat (recorded):** `d-r6blindtimer` ALSO disrupts 100% (blind rotation covers zero-days
  *on a schedule*) — so PX's edge is **detector-independent AND cost-optimal AND consequence-targeted,
  NOT "uniquely stops zero-days".**
- **H1 PASS** (PX dwell 8.4s ≤ random 8.5s) and **H3 PASS** (stealth: PX 100% disrupt vs reactive-only
  0%), both directional at n=2.

**Two fixes pending BEFORE the heavy run** (the smoke's purpose — catch them early):
(1) **blind-timer action-accounting** — `d-r6blindtimer` logged 0 DefensiveActions yet 100% disruption
(impossible without a rotation), which invalidates the **H2** cost comparison; fix the timestamp
accounting vs the trial window. (2) **include emitting scenarios** (e.g. `c2-persistence-evict`) so
full-Phoenix's reactive path actually fires (a fair full-Phoenix comparison; in the 3 no-emit smoke
scenarios it correctly shows 0%).

**Status:** the heavy **≥20-trial** run (tight CIs, H1/H2/H3 pass/fail, the adaptive arm ON for the
learnability column, the full kind-runnable K8s+AI scenario set, stateful-work-preserved, and the
**1.62× recon-per-dollar** carried from the P1 GATE-#1 ablation) is **PENDING go-ahead**. The 6 GPU/
real-LLM scenarios stay **GPU-PENDING** — code ready, run unchanged on CoreWeave, never fabricated.
**Phoenix + harness build unchanged.** Reports: `phorvex/P3-REPORT.md` (engineering record) +
`phorvex/EFFECTIVENESS-PHORVEX.md` (investor artifact). Smoke metrics: `build/test-harness/out-p3-smoke/`.

**Update — GATE #2 PASSED (heavy run complete).** The ≥20-trial run ran clean: **792 rows, 0 skips,
controls clean** (negative=0 false moves; positive 21/21 oracle in all 6 scenarios). Both pre-run fixes
landed (root cause was a trial-isolation race: Phoenix's 30s-grace Delete left the rotated pod
terminating into the next arm — `waitPodGone` now force-deletes). Headline (real, n=20, 95% CIs):
LEAD DEMO PX **quarantine 20/20, harm 0/20** vs full-Phoenix/reactive/blind **delete → stateful-destroyed
21/21**; dwell PX **5.1–5.6s** vs blind 12–15s vs reactive/no-MTD 20s/0%; fast-attacker PX denies the
objective 21/21 while blind is **too late 21/21**; learnability PX holds 100%→100% while random collapses
40%→0%; feasibility infeasible=0/harm=0. **H1/H2/H3 PASS** (H2 reframed honestly: PX disruption ≥ blind
AND random in 6/6 at a bounded 1-move cost; blind's lower raw cost = under-acting). Schwartau presented
from measured eviction latency (the harness's interval-based metric unfairly zeroes PX's variable rate).

### 9.7 P-PHYSICS — the physics-discovery keystone: COMPLETE (both products, built + proven on kind)
The keystone that makes Phorvex truly physics-informed: a platform SCANNER that DISCOVERS per-platform
physics for BOTH the K8s and AI/inference products and RE-GROUNDS context + the recon objective, feeding
the **UNCHANGED** optimizer / proactive engine / dynamic-action-set generator / actuation through the
existing registry seams. **Zero change to extended Phoenix, the harness, or the optimizer/dual/conformal/
killchain/actuation/proactive engine** — only additive, zero-valued edits to Phorvex's own model/ingest/
runner + new self-registering modules. Deterministic, no LLM in the decision path.

**Step 1 (deep multi-agent search, both-products, PRD-grounded).** Two searches: a first K8s-centric one
(winner CapacityWitness, 22/35) was **re-scoped** when the mandate made AI/inference first-class and
mandatory and set the baseline to the **full PRD physics** (Layers A/B/C incl. the Layer-C EMR core IP),
not the implemented 1.62× subset. The re-scoped 17-agent expert-persona search (cloud-arch, GPU-infra,
AI/ML-inference, physics-informed-AI, DevOps/K8s, offensive-security) produced 3 EMR spines **tied at
29/35**, merged into **UnifiedConservationWitness (UCW)**. Decision: `phorvex/P-PHYSICS-DECISION.md`
(both-products definition, PRD-completed-and-beaten map, per-feature quantification, honest "ties now,
beat unrun" verdict). A workflow pipeline bug (`l` vs `cand` scope) failed the candidate scoring; fixed
+ resumed (cache hit on 13 agents) so the synthesis was grounded in real candidate data, not the
confabulation the first synth produced from null input.

**Step 2 (built).** Carrier `model.PhysicsWitness` + `WorkloadView.Physics` (honest-absent
`NeutralPhysics()`); ingest scans Nodes + live PodDisruptionBudgets + image-digest + requests;
`internal/platform` = `PlatformPhysics` interface + `generic-k8s` adapter (derives image-rarity,
co-residency, scheduler-slack, live PDB, MIG-geometry, EPSS) + `eks-gpu`/`coreweave`/`gpu-marketplace`
adapter **modules** (one-module-per-platform; DCGM/NVML scan documented; GPU values SP-0); **Layer-C EMR
completed** via `ucw-recon` (one per-asset scarcity scalar = **image-rarity·EPSS·co-residency·model-
rarity** scaling all of an asset's facts — the PRD core IP, stays submodular+monotone ⇒ **zero optimizer
touch**); 4 AI fact-kinds defined audit-only; `tokens-floor` feasibility law **closes the verified-FALSE
`littleslaw.go:78` claim** that a hard tokens/sec constraint existed; `vram-conservation` + `mig-validity`
honest-absent; `AblateScarcity` (separately-ablated standard-recon vs ucw-recon); runner stamps
`view.Physics` + `SetDefault("ucw-recon")`; `phorvex --scan` CLI.

**Step 3 (proven on kind, REAL numbers).** Live scan derives the both-products physics: real node
allocatable (8000m/15.8GiB/0-GPU), **measured image-rarity dispersion 1.18 (common) vs 2.00 (singleton
tail)**, slack **0.88**, MIG-valid; **AI half first-class in definition, every value `[SP-0-PENDING]`
(`GPUPresent=false`, never fabricated).** MEASURED: the **separately-ablated LIVE EMR ablation = 1.20×
recon-per-dollar BEAT** attributable purely to discovery (baseline **1.986 → 2.381**); unit tests **1.84×
K8s / 1.53× AI** lift and an **exact tie at uniform** (the never-worse floor). **No regression:** the
**1.62× IP gate PASSES** (standard-recon), **P3 preserved** with the ucw-recon operator (PX dwell **5.6s**
vs blind 15.2s), phorvex build/vet/test green, **Phoenix + harness unchanged.**

**Honest caveat (recorded):** the tie at nil-data is **guaranteed**; the BEAT is **conditional on
heavy-tailed dispersion** — a small/flat fleet can **dip below baseline** (an early 4-pod demo gave
**0.49×**) before a clean crown-jewel tail gives the 1.20× live beat. Magnitude on real production /
GPU-multi-tenant fleets is **UNRUN** (needs EKS/CoreWeave SP-0); the EMR term stays **separately
ablatable** so a beat is asserted ONLY from a measured ablation on the target fleet.

**Deferred + flagged:** the `featureDim` cost-**denominator** bump (per-dollar beat is numerator-only;
AI per-dollar rests on the `GPUEnvelopeMax=1.0` fail-safe = SP-0), the kill-chain **belief-wall** (AI
stages model-theft/LLM-jacking/prompt-injection-persistence/GPU-side-channel + live-β need a
`killchain.Assess` edit), and the warm-provision **actuation sequence** (only the feasibility precondition
is in-scope). Reports: `phorvex/P-PHYSICS-DECISION.md` (Step 1) + `phorvex/P-PHYSICS-REPORT.md` (Steps 2–3).

### 9.8 P-CONTEXT — the both-products context model: COMPLETE (built + proven on kind)
Same deep search-and-prove treatment context that physics got. Complete + beat the PRD+P1 context
(belief/P(hold)+memory, kill-chain stage, predictive horizon, value/blast, spread) for BOTH the K8s and
AI/inference products, feeding the **UNCHANGED** optimizer / proactive engine / dynamic-action-set
generator / actuation / extended Phoenix through the existing `ContextProvider`/`BeliefEstimator`/
`FactContext` seams + the engine-owned `killchain.Assess` (the one authorized belief-wall edit).
Deterministic, no LLM. **Zero change to the optimizer/dual/conformal/actuation/proactive engine/extended
Phoenix/harness** — only additive phorvex-own edits to `killchain` + `conjugate.go` + `ctxprov`/runner.

**Step 1 (deep search).** A 5-expert-persona search (detection/SOC & kill-chain, Bayesian/sequential
inference, AI/ML inference security, graph/blast-radius, offensive security): 4 gap-mappers → 5 experts
→ candidates → adversarial scoring (the synth **re-ran the CI gates uncached + measured the key divergence
numerically**). Two candidates scored cleanly (one scorer agent failed to emit structured output). Winner:
the **Predictive-Horizon CONTEXT model (35/40)** — a coherent Weibull-**survival** kill-chain unifying
P(hold)+hazard with the AI stages as a parallel chain. Decision: `phorvex/P-CONTEXT-DECISION.md`.

**Step 2 (built).** `killchain/hazard.go`: **4 AI kill-chain stages** (ordinals 5–8:
`gpu-side-channel→model-theft`, `llm-jacking`, `prompt-inject-persist`) classified **off existing fields**
via the `killchain.Assess` edit (never a new SecurityEvent type) + consequences/sojourns (SP-0) + the
`aiNextStage` **successor map that fixes the `next=stage+1` defect** a parallel chain cannot absorb; the
**moved-before-next-stage** metric (`PreemptMargin` + `ProjectedNextStageSec`, additive `Assessment`
fields). `conjugate.go`: **belief upgrades** — hierarchical fleet prior (cold tenant inherits the fleet
base-rate), UCB confidence knob; `coverage.go`: **negative-evidence wiring** (symmetric feedback) **fixing
the monotone confirmation-bias ratchet** (the prior could only go up). `runner`+`sensed`: **Tier-1 live-β
`InfectionFrontier`** (AssetValue lift for a pod adjacent to a known-infected neighbor; zero at empty-I).
`ingest`: `Pod.{ModelID,EndpointPath}` from annotations; `cmd --scan` prints the live kill-chain context.

**Two corrections (honesty in action).** (1) The mandatory one from the decision: the survival-form P(hold)
(shape=2) is NOT byte-identical to the baseline damping (shape=1) on the generic path (+0.025 PHold at
t=60s) → **gated behind `ModelID!=''||HasGPU`** so the generic K8s belief layer is byte-identical to P1.
(2) Caught by `TestKVRecoverScale`: the decision's `RecoverScale=max(30,KVRebuildSec)` for prompt-injection
persistence was **semantically inverted** (a larger scale = MORE P(hold) collapse) → **fixed** so a
prompt-inject-persisted agent gets **no wipe-damping** (the KV implant survives a rotation).

**Step 3 (proven on kind, REAL).** Live `--scan` on a model-annotated NIM + a panic event + a generic pod:
**AI stage classified live** (`nim-llama → prompt-inject-persist [AI]`, generic pod stays `recon`);
**moved-before-next-stage measured live** (`ProjectedNextStageSec ~2763s`, `PreemptMargin`); **Tier-1
live-β fired live** (`web-generic`, co-located neighbor of the infected NIM → `infectionFrontier=1.5`).
Belief unit tests pass (AI classification, horizon monotonicity, KV-no-collapse, **negative-evidence prior
FALLS**, hierarchical cold-tenant inherits the fleet rate). **No regression:** **1.62× IP gate PASS**, UCW
tie + **1.84× K8s / 1.56× AI** lift, **P3 PX dwell 5.7s** (matches baseline), phorvex build/vet/test green,
**extended Phoenix + harness unchanged.**

**Honest verdict (recorded):** baseline **preserved by construction** (AI-gating → generic byte-identity;
gates green; PX 5.7s). Improvement is **structural now, measurable later** — the AI stages classify and the
horizon/frontier measure live, but **all AI magnitudes (300/180/900/3600s sojourns, leakage rates) are
`[SP-0-PENDING]`**; **no AI beat number is falsifiable until a real GPU fleet** calibrates them, and the
belief upgrades only diverge under their conditions. **Deferred + flagged:** the full SIR live-β **value**
(β non-falsifiable without injected-infection ground truth), the **run-time** moved-before-next-stage fleet
aggregate (needs a harness counter the zero-change scope forbids → only the decision-time form claimable),
and `plannedMoveLatencySec=0` (overstates preemption). Reports: `phorvex/P-CONTEXT-DECISION.md` (Step 1) +
`phorvex/P-CONTEXT-REPORT.md` (Steps 2–3).

### 9.9 P3-DEEP — the structural zero-day proof: COMPLETE (792/792 rows, 0 skips)
Prove the zero-day advantage is **STRUCTURAL, not a timing race**: R6's **(static action set, fixed
rate)** pair cannot win the zero-day on the CONSTRAINED class at any feasible interval, while Phorvex's
**(dynamically-regenerated set, solved rate)** wins by being targeted, harm-free, and unlearnable. A
5-expert search designed the suite (eligibility gate: ineligible if it only re-proves timing / K8s-only /
unquantified). Built as ADDITIVE harness plugins — **zero harness-core / zero extended-Phoenix change**:
6 swept-blind arms (`d-blind-3s..60s`, the `timerEngine` nextDelay closure makes each one file), the
`b-recon-lifetime` (K8s + AI-proxy) + `e-dilution-n9` scenarios, and a `phorvex/cmd/p3deep` post-processor
(frontier WIN table + Wilson CIs). 9 arms × 4 scenarios × 20 trials + controls, 95% CIs, masterSeed=1337.
Decision: `phorvex/P3-DEEP-DECISION.md`; reports: `phorvex/P3-DEEP-REPORT.md` + appended to
`EFFECTIVENESS-PHORVEX.md`.

**PROVEN — T-invariant on the CONSTRAINED class (`c2-stateful-training`, rotate = destructive Delete):**
**no blind interval is a WIN** — fast (3–15s) prevents 100% BUT **harm 100% (21/21) + infeasible 100%
(21/21)** (rotate-all destroys the running job — a feasibility-SET defect no rate repairs); slow (30/60s)
**too late, prevent 0%**. **PX is the unique WIN — 100% prevent, 0% harm, 0% infeasible, cost≈1 via
quarantine.** The two horns provably do not overlap.

**RECON-VALIDITY-LIFETIME law (the detector-independent MECHANISM, the "why"):** `L_blind ≈ the interval`
(3s→3.0, 6s→6.1, 9s→9.1, 12s→12.1, 15s→15.1s; 30/60s→20.2s full-window when it can't fire); **PX 5.0s
[5.0,5.1] MEASURED.** There is **no interval that is both short (recon-invalidating) AND harm-free**.
**DILUTION (E):** blind rotate-all cost ~ N vs PX capped (budget 1) — structurally limited on this harness
(uncapped blind + tick-counting DefensiveActions ⇒ argued, not cleanly measured; stated, not fabricated).
**PREDICTION (D):** only the PX arm produces a **moved-before-next-stage** horizon (`PreemptMargin`,
`ProjectedNextStageSec`) — UNDEFINED for a scalar-interval arm (presence-asymmetry, proven live in P-CONTEXT).

**HONEST VERDICT (recorded):** **strongly-evidences, does NOT fully prove.** The prevention/recon-lifetime
legs rest on the **soft proactive floor** (a measured distribution with a CI, not a by-construction
ceiling); the **clean blind interval on the UNCONSTRAINED `c1-heldout-cve` is printed plainly** (fast blind
prevents 100% harm-free at N=1) so the impossibility is **scoped to the constrained class**, not
over-claimed; **learnability is shared with `d-randomequal`** (also unpredictable) — the distinction that
singles out PX is the **recon-lifetime + the harm-frontier**, not predictability alone. The harm/learnability/
prediction-presence legs ARE T-invariant (proven). **No regression:** the **1.62× recon-per-dollar gate +
UCW tests PASS**, **P3 PX dwell 5.1s** (baseline ~5.5s), the prior baseline decodes unchanged; phorvex +
harness build/test green; **extended Phoenix unchanged**. **Patent surface = the regenerated-set +
solved-rate recon-invalidation**, not "rotate sooner". **AI native magnitudes `[SP-0-PENDING]`** (endpoint
stable for all arms; fingerprint/MIG-rebind invalidation GPU-bound), never fabricated.

### 9.10 P-ACTUATOR — Phorvex's own native actuator: COMPLETE (STANDALONE product, brain unchanged)
Give Phorvex its own hands so it enacts its FULL real-time dynamic action set as one cohesive standalone
product: keep everything extended Phoenix does (lose nothing), absorb it as the BASE LAYER, ADD the
advanced/AI moves, unify behind ONE `Actuator` interface with shared safety/inviolability/kill-switch/audit.
A 5-expert search (K8s/operators, GPU ops, MTD actuation, distributed-systems reliability, security) →
**Unified Native Actuator (32/35)**; decision `phorvex/P-ACTUATOR-DECISION.md`, report
`phorvex/P-ACTUATOR-REPORT.md`. **The brain (physics/context/optimizer/proactive) is UNCHANGED** — only
the hands are new.

**Step 2 (built).** A single **`model.MutatingActions` source of truth** (fixes the two-hardcoded-list
drift hazard — `actionset.enabledActions` + `decision.candidateActions` now both iterate it; `ActionEnabled`
keeps a nil policy at the historical `{rotate,quarantine}` default = byte-identical decisions). **12 handlers
behind one `ActionHandler` registry**: 7 K8s LIVE (rotate, quarantine [deny-all NP + relabel-out + **ownerRef
re-parent**], debugger, custom-inject, disable [declared-not-impl], identity-rotate, route-rotate) + 5 AI/GPU
**state machines** (warm-swap 5-phase provision-before-retire, mig-rebind, kv-reset, endpoint-rotate,
model-shard-replace — **code PRESENT now, runs unchanged on real GPU**). The **completeness invariant**
(CI test `completeness_test.go` + a lexically-last `zz_startup.go` init-panic). **Per-action feasibility laws**
for every action (`ai-context-required`, `mig-device-required`; widened VRAM/MIG laws). The **feasibility gate
RE-RUN at the emit boundary** (replaces the trusted cached bool; action-agnostic). Audit forensic fields
(`Handler/ObjectsTouched/RollbackRef/MutationKind`). Namespaced **least-privilege RBAC** markers; CRD enum
widened to 12; `PHORVEX_ACTUATOR=native` selector. **License-clean reimplement** — native imports **ZERO
Phoenix** (k8s.io contract, clean-room); the SSPL-derived `PhoenixActuator` stays **byte-unchanged** as the
optional fallback adapter. (SSPL §13 network-copyleft scope **flagged for the lawyer** — not legal advice.)

**Step 3 (proven on kind, REAL).** **Completeness guard:** removing a handler → `go build` **SUCCEEDS**
(exit 0 — NOT a compile error, documented precisely), `go test` **FAILS**, the **binary PANICS at startup**
(CI + startup teeth). **Live native actuation = 13 PASS / 0 FAIL** (`--native-demo`): rotate (UID gone),
**quarantine fidelity asserted LIVE** (deny-all NP + ownerRef-detach + **POD ALIVE**, RS does not re-adopt),
quarantine **rollback**, debugger/custom-inject (ephemeral container), identity/route/endpoint-rotate (epoch
labels), kv-reset (pod alive + flush epoch, no kill), **warm-swap orchestration** (shadow promoted + leader
retired), mig-rebind + model-shard-replace **FAIL-CLOSED** (honest SP-0), **dry-run guard** (refused + pod
untouched). **Harness re-run with the native actuator REPLACING the Phoenix seam** (`PHORVEX_ACTUATOR=native`):
**lead demo PRESERVED 6/6 harm-0** (blind destroys 6/6), **P3 PX dwell 5.1s** (blind 15.2s, no-MTD 20.5s),
**1.62× IP gate PASS** (decision-layer, actuator-independent). phorvex build/vet/test green; **extended
Phoenix builds unchanged**.

**HONEST (recorded):** **all AI/GPU magnitudes `[SP-0-PENDING]`** — the state machines **fail-closed on kind**
(no device/model) rather than fabricate a GPU effect; warm-swap orchestration is K8s-live but `ColdLoadSec`
is SP-0. The completeness guard enforces a handler **EXISTS, not that it is CORRECT** (quarantine fidelity
rode an assertion — now **asserted live, passed**). **Privilege widening** (native writes pods/NetworkPolicies/
Services directly) needs a **security review → deferred P4c** (namespaced least-privilege Role markers shipped).
Debugger/custom-inject/inject-carrier kv-reset are **irreversible** (K8s can't remove an ephemeral container;
audit-flagged). The **1.62×/P3 parity holds ONLY while AI moves add zero selectable cover** (`GPUPresent=false`
⇒ greedy self-prunes); once GPU magnitudes activate + AI facts enter `CoverByAction`, the baseline must be
**re-established, not assumed**. Phorvex now runs **standalone** (its own hands, no Phoenix CRDs) OR drives
Phoenix via the unchanged adapter — one interface, three impls, one env var, same brain.

---

### 9.11 P-DASHBOARD — production-grade Wiz-style console: COMPLETE (real computed data, brain unchanged)
A production-grade web console for both products. **Next.js static export served by the Go backend on ONE
port** (single binary, same-origin `/api` — no proxy/two-process fragility). Decision/reports:
`phorvex/P-DASHBOARD-DECISION.md`, `phorvex/P-DASHBOARD-REPORT.md` (Parts 1–9). **The brain / actuator /
harness are UNCHANGED** — the console only reads their outputs and triggers their existing entrypoints.

**The journey (Wiz-style, the flat grid is gone).** A guided flow drives everything:
**Landing → Connect → Scan → Discovered → Protect/Run → Prove → Report**, with **Protect/Run** as the obvious
"where I run my methods," plus a **guided demo mode** (auto-advancing investor/customer narration over the
real `/api`) and the **3-lens toggle** (Investor / Operator / Customer-Owner). Step states derive from REAL
signals (`/api/health`, `/api/targets`, a `/api/live` probe, `/api/benchmarks`) — never hardcoded.

**Every subsystem panel on REAL COMPUTED data — verified by RUNNING + change-source proofs, not by build.**
**Physics** (live `phorvex --scan`; a redis-pod test moved `imageRarity 2.0→1.39` / `coResidency 1.5→1.75`),
**Context** (kill-chain stage / P(hold) / moved-before-next-stage horizon), **MTD/Optimization**
(coverage−λ·cost scoring + **SHAP** + **R6 counterfactual** from the real audit Record), **Cost**
(λ / per-$ / cost-vs-coverage), **Actuator** (live `/api/handlers` from `actuator.HandlerRegistry` — **12
handlers, 11/11 generatable covered**, correcting the stale "13/13" label), **Ablation** (live recon-per-$
from `--ablation`). **Increment-2 honesty panels:** **uncovered-ATT&CK frontier** (53 techniques, **36
UNCOVERED shown honestly**, not hidden behind the green), **AI Honest-Boundary** (`d-phorvex-slot` disruption
**≡ 0 across 462 rows** → **NO AI effectiveness number derived anywhere**; AI defense `[SP-0-PENDING-P4]`;
`mtdEffect` shows what MTD structurally cannot do), **52×N matrix + learnability** (**PX 0.95 vs random 0.36
vs blind 0.00**, computed from the adaptive-scenario trials) **+ FP 0%** (0/127 no-attack rows),
**AI split-oracle/Schwartau/reuse** (decoded, honestly labeled **attack-surface NOT defense**), **risk
heatmap** (operator `/metrics` `[PENDING-wire]`, **live-audit fallback** real). All hardcoded hero stats now
COMPUTED: **explainability** from the audit (proven 100%→90% when un-explained decisions added),
**prevention** from harness rows (22/22, moved to 22/23 with an attacker-win row), **native** from the live
registry, **posture sub-scores** from real metrics. **Nothing uncomputed is labeled "real."**

**HARDENING (proven live + tested).** The IP-wall is now **DEFAULT-DENY**: `scoped()` admits ONLY
investor/operator; **owner / missing / unknown lens → 403** (fixes a NO-OP gate where a missing header
defaulted to "operator") — proven live on every vendor endpoint + asserted in **`server_test.go`** (and the
owner stream/endpoints leak **zero** EMR/λ/SHAP/optimizer internals). Exec-spawning endpoints **hardened**
(concurrency cap + rate-limit + input validation). The Phase-1 null-class bug (panels crashing on `null`
slices) fixed at the source (emit `[]`) + frontend guards.

**HONEST STANDING ITEMS (carried, not hidden):** **recon-per-$ is fleet-dependent** — **~0 on a flat fleet,
1.62× only on a heavy-tailed/dispersed fleet**; the live panel shows the REAL ratio and says so — the
production multiplier is **measured at P4a/P4, NOT a universal constant** (the stated "1.62×" is removed from
the dashboard). **Operator start/stop write-path `[PENDING]`** (P4a / P-VCLUSTER). **Real-cluster execution +
live Prometheus/DCGM telemetry `[PENDING-P4a]`.** **AI magnitudes `[SP-0-PENDING-P4]`.** A **Next.js security
advisory — bump before any external demo.** **RL Red-Team `[PENDING-P-REDTEAM]`.** **Lens selection is
demo-trust** (the redaction is real; SSO/identity is `[PENDING-P-VCLUSTER]`). One-command start:
`powershell -ExecutionPolicy Bypass -File .\start-dashboard.ps1` → `http://localhost:8090`.

---

## 10. REMAINING ROADMAP (8 stages, LOCKED)

The build sequence from here. **LOCKED = the order + intent are fixed; each stage's design is flexible to
what its search finds.** Every stage obeys the same **per-stage contract** (the discipline proven through
P-PHYSICS → P-CONTEXT → P3-DEEP → P-ACTUATOR):

> **PER-STAGE CONTRACT (applies to all 8).**
> 1. **Open with a DEEP MULTI-AGENT SEARCH** (expert personas + adversarial scoring) that decides whether to
>    **complete / replace / improve** the relevant baseline — **with proof vs that baseline**, not assertion.
> 2. **BOTH products first-class** (K8s AND AI/inference); a K8s-only result is ineligible.
> 3. **NO hardcoded values where a value should be SCANNED / DERIVED** — discover from the live cluster /
>    physics / telemetry; honest-absent (never fabricate); `[SP-0-PENDING]` only where genuinely GPU-bound.
> 4. Produce a **reasoning + requirement-coverage map** (every requirement → where it's met / deferred + why).
> 5. **STOP for approval** after the search (write `P-<STAGE>-DECISION.md`); build only on approval; prove on
>    kind/real-infra with REAL numbers + honest caveats (`P-<STAGE>-REPORT.md`); preserve the gates
>    (1.62× + P3 + lead-demo) or re-establish them explicitly.
> 6. **Flexible to results** — an honest "baseline wins / defer / smaller-than-hoped" is a valid outcome.

**1. P-DASHBOARD — the professional, demoable console.** Every feature/tab/config/report; **run attack-agents
on demand**; **both investor + customer lenses**; a **platform-OWNER view** showing what changed in THEIR
platform **WITHOUT exposing the IP** (the optimizer/recon math stays private); a **customer-acceptance loop**.
The search audits *every metric a VC + a customer would expect* and maps it to a panel. Built as a **GROWING
SHELL with SLOTS** so stages 2–8 dock their outputs in (redteam runs, ratio ablations, GPU results, the full
benchmark, the final reports) without a rebuild.

**2. P-OPTIMIZE-RATIO — maximize recon-per-dollar (the "beat 1.62×" objective).** A **no-hardcoded audit** +
search to push the recon-per-dollar lift as high as the physics honestly allows, **proven by ablation on
DISPERSED (heavy-tailed) fleets** — measured, not asserted. Establishes the method + the synthetic/real-ish
dispersion proof now; **full magnitude lands at P4** (real GPU/production fleets). Honest: the tie-at-uniform
floor + the dispersion-conditional beat stay as recorded in P-PHYSICS.

**3. P-REDTEAM — a cutting-edge RL pentester tailored to Phorvex.** A **dev server** + an RL adversary that
**continuously co-trains** against the live Phorvex decision loop (attacker learns → Phorvex adapts →
re-search), **human-approved** at each promotion gate. Feeds adversarial scenarios back into the benchmark
(stage 7) and the dashboard (stage 1). Deterministic Phorvex side; the RL is the attacker, never in Phorvex's
decision path.

**4. P-VCLUSTER — multi-tenant.** Per-tenant physics/context (each tenant's discovered dispersion, kill-chain
priors, asset graph) + a **hard isolation proof** (one tenant's signals/moves never leak into another's
decisions or blast radius). Both products per tenant.

**5. P4a / P4b / P4c — real-infra hardening (the three sub-gates).**
  - **P4a** — real **EKS deploy + validate** (the operator + native actuator on a managed cluster, not kind).
  - **P4b** — **soak + chaos + failure-mode** (long-run stability, fault injection, the warm-swap/rollback
    state machines under real crash-resume — the distributed-systems complexity flagged in P-ACTUATOR).
  - **P4c** — **Phorvex self-security review**, INCLUDING the **P-ACTUATOR privilege-widening review** (the
    native actuator's direct pods/NetworkPolicies/Services writes; the namespaced least-privilege Role).

**6. P4 — GPU / CoreWeave (the SP-0 calibration gate).** Calibrate **every `[SP-0-PENDING]` magnitude** on real
GPUs; **validate the 5 AI actuator state machines** (warm-swap/mig-rebind/kv-reset/endpoint-rotate/
model-shard-replace) on real hardware; run **AI/GPU attack scenarios with/without PX**; measure **real-fleet
recon-per-dollar**; **re-establish the 1.62×/P3 parity WITH GPU magnitudes active** (the parity that P-ACTUATOR
flagged must be re-proven once AI facts enter `CoverByAction`); ship the **CoreWeave / neocloud adapter**.

**7. P-BENCHMARK-COMPLETE — the exhaustive matrix.** ~40 scenarios + the GPU set, **all arms** (no-MTD,
R6-blind family, random-equal, reactive, full-Phoenix, PX), **with/without PX**, **all metrics**, **both
lenses** — the single reproducible evidence base the final reports draw from.

**8. P5 — final package.** Final reports (with/without-PX), the **full R6 comparison**, the **investor deck**,
and the **patent-pipeline IP writeup** (the regenerated-set + solved-rate recon-invalidation, the
scarcity-conditioned EMR, the AI kill-chain + moved-before-next-stage, the completeness-invariant actuator).

**EXTERNAL (the user's, NOT build steps):** (a) **SSPL §13 license review with a software-IP attorney before
GA** (the P-ACTUATOR clean-room reimplement reduces but does not clear the question); (b) **a provisional
patent before any public disclosure** (the dashboard demo / investor deck count as disclosure).

**HONESTY LINE (what's true after each milestone):** **raise / demo-ready after stage 1**; **AI validated
after stage 6** (not before — every AI/GPU magnitude is `[SP-0-PENDING]` until then); **production-launch-ready
after stages 5–6** (real-infra hardening + GPU validation); **complete package after stage 8**.
