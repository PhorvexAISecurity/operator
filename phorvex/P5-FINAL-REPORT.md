# Phorvex — Final Capability Report (the fundable package)

**Contract.** Honest proven-vs-pending throughout. Every number traces to a real run, test, or audit on disk
(cited inline). Unmeasured items are labeled `[SP-0-PENDING-P4]` (AI/GPU magnitudes) or `[PENDING-<stage>]`.
**No fabrication, no overclaim.** Documentation only — no code changed in this stage.

---

## 1. Executive summary (one page)

**What Phorvex is.** Phorvex is a **deterministic, physics-informed Moving-Target-Defense (MTD) brain** for
Kubernetes — and, structurally, for AI/GPU inference. Conventional MTD rotates workloads on a fixed timer or
reactively; that is either wasteful (rotating cheap pods on schedule) or too late (reacting after the attacker
acts). Phorvex instead **decides which workloads to rotate/quarantine and when**, to **maximize the recon an
attacker loses per dollar spent**, under hard SLO + budget constraints. Crucially, **there is no machine
learning in the decision** — it is a byte-deterministic optimizer, which makes it auditable, reproducible, and
certifiable. A **separate reinforcement-learning red-team** attacks that deterministic brain and hardens it.

**What is proven (measured, on disk).**
- **The optimizer beats equal-budget random targeting per dollar** — gate-enforced (`ratio > 1.0`), and
  **fleet-dependent 1.62×–5.87×** as measured (not a fixed number).
- **The greedy selection is *exactly* optimal** (ratio 1.000000) for the current cover structure — a stronger,
  rarer guarantee than the usual "near-optimal," turned into a reproducible test.
- **A learning adversary found two real structural vulnerabilities; both were fixed and re-proven neutralized,
  live** (the real Kubernetes pod actually rotated end-to-end).
- **A native K8s actuator** enacts the moves with least-privilege RBAC + rollback, audited clean.
- **On AI attack campaigns**, Phorvex **evicts the persistence foothold** where blind/reactive MTD evades — a
  result that only became visible after we found and fixed a measurement bug in our *own* test harness.

**What is roadmap (honest).** All **AI/GPU effectiveness magnitudes are unproven on hardware**
(`[SP-0-PENDING-P4]` — need a real GPU + DCGM). The **9 AI/GPU actuators are real code behind a mockable
vLLM/NVML stack, CI-tested, but `[PENDING-GPU-VALIDATION]`** until run on hardware. The **full head-to-head
benchmark is `[PENDING-FULL-BENCH]`** (a runbook exists). **Multi-tenant: exact-zero cross-tenant *decision*
isolation is PROVEN (Pass 1, under the real cross-tenant attack), plus verified **OIDC identity**, a **safe
apply-fix write-path** (allowlist + shadow-engine gate-check + two-key + per-namespace-SA), and **per-tenant DoS
quotas** — all BUILT + adversarially proven (Pass 2). The React apply-fix UI, the **production CRD applier**
(`internal/applier` — gate-re-asserted, namespace-guarded, verify-then-rollback; 5 mock-K8s tests), and the
**OIDC config loader** are now built too (§9.23); integration-remaining is real-env **validation** (a live
cluster/CRD/SA, your IdP), labeled `[PENDING-CLUSTER-VALIDATION]`/`[PENDING-IDP-CONFIG]` — not new safety work. The only
not-closed residual is availability blast-radius (R9), which needs hard isolation (vcluster) — and only if a
hostile-multi-tenant SaaS posture requires it.**

**The honest one-liner for a VC:** *the deterministic K8s brain is real, tested, and economically validated
today; the AI/GPU layer is fully built and structurally sound but is design-complete-pending-hardware, not yet
measured on a GPU — and we label every such claim as exactly that.*

---

## 2. Technical capability

### 2.1 The deterministic, physics-informed MTD optimizer (MEASURED-REAL)
- **Objective `coverage − λ·cost`** maximized by a **submodular greedy under a partition matroid (one move per
  asset) + budget B**, with a hard feasibility gate. `internal/decision/coverage.go → CoverageEngine.Decide`
  (the `gain = marginal·prov − λ·ECost` loop). Deterministic — no RNG, no ML.
- **λ is a *solved* budget shadow-price**, not a hand-set constant: `internal/cost/dual.go → DualSolver.Step`
  raises λ when the budget binds and lowers it when slack — and λ is also the proactive-timing knob (an asset
  fires when `perDollar > λ`), so *rotation rate is an optimized decision variable*, not a cadence.

### 2.2 Greedy proven EXACTLY optimal — the corrected, stronger claim (MEASURED-REAL)
A deep search + brute-force exact solve (`P-OPTIMIZE-RATIO-DECISION.md`, §9.20) established that the greedy is
**not merely near-optimal (1−1/e) — it is *exactly* optimal, OptimalityRatio = 1.000000, gap 0**. Reason:
`recon.Fact.Key` prefixes every cover key with its owning asset (`facts.go:65`), so distinct candidates have
**asset-disjoint cover universes**, the objective is **modular** (the strongest case), and matroid-greedy on a
modular objective is exact. Turned into a reproducible test: `TestGreedyIsExactOnShippedFleets` asserts
`ratio = 1.000000`; a self-check surfaces any shared key, and `TestGreedyExactGapSweep` shows the gap would
reappear only under a deliberately-overlapping profile (worst min 0.53 at a binding budget). **Honest scope:**
this is **profile-dependent** — a future profile keying a fact off a shared node would make the objective
genuinely submodular.

### 2.3 The recon-per-dollar gate — the CORRECTED gate-true claim (MEASURED-REAL)
The patentable economic core is that the optimizer invalidates **more recon-weight per dollar than an
equal-budget random rotator**. **Correction (do not overclaim):** the in-repo gate
(`TestAblationP1BeatsRandomPerDollar`, `ablation_test.go:49`) asserts **only `ratio > 1.0`**; the "1.62×" in
`ablation.go:19` is a **comment**, not a guarantee. Measured, the ratio is **strongly fleet-dependent —
1.62× on the P1-REPORT live-kind fleet (8.78/5.41) and 5.87× on the in-repo gate fleet** (§9.20). **Claim:
`ratio > 1.0` (gate-enforced), 1.62×–5.87× observed — NOT a fixed 1.62×.**

### 2.4 The RL red-team + two live-fixed vulnerabilities (MEASURED-REAL)
A real reinforcement-learning attacker (`internal/redteam/`): recurrent-PPO on gradient-checked autodiff
(**max relative error 9.5e-9**, `TestGradientCheck`), GRU policy/value, GAE + clipped surrogate + BPTT;
Population-Based Training + Quality-Diversity (MAP-Elites); continuous co-training behind a **human-approval gate
that never auto-escalates**. **It measurably learns** (seed 1337, `out-redteam-rl/result.json`): climbs
**−1.3 → 35.2** vs an exploitable defender, **flat (3.9 → 2.2)** vs random — it exploits *structure*, not noise.

| Vuln | Mechanism | Gated fix | Proven neutralized (live) |
|---|---|---|---|
| **λ-pump** | flood cheap decoys → pump λ until the real foothold is "not due" → rotation starved | bounded, binding-gated sub-gradient (`dual.go → DualSolver.Step`) | λ stayed **bounded 0.55 → 1.3 under an 8-decoy flood**, foothold rotated anyway (`out-redteam-live-pump`, `action=rotate perDollar=1.51`) |
| **dispersion-steer** | a few high-perDollar fresh decoys out-net the real foothold for the B=1 move → foothold never *selected* | **provenance-weighted selection** (`coverage.go`): genuinely-due/evidence-backed ⇒ `prov=1` (byte-identical); fresh evidence-less decoy ⇒ `provFloor=0.34` | foothold **rotated** despite 3 high-value decoys (`out-redteam-live`, `action=rotate perDollar=1.72`); pre-fix the decoy collapsed to **0.57** |

### 2.5 The deterministic-defender / RL-attacker boundary (verified)
**No ML in the decision path.** `prov` and `DualSolver.Step` are pure deterministic functions of measured
exposure/assessment; *all* learning lives in `internal/redteam/` (the attacker). Verified by grep — the only
`math/rand` in `internal/decision` is the off-path ablation. **The defender is deterministic and auditable; the
attacker learns and hardens it.** This separation (a learning adversary provably finding weaknesses in a
*non-ML* optimizer, each closed as a gated, re-verified change) is itself a contribution (§5).

---

## 3. R6 comparison — measured vs published (honest)

R6 / extended-Phoenix is the unmodified MTD substrate Phorvex *drives*. The comparison is **Phorvex's brain vs
the baseline arms** (no-MTD, R6-blind-timer, random-equal, reactive-only, full-Phoenix), from real data only.

| R6 claim / baseline behavior | Phorvex measured result | Status | Evidence |
|---|---|---|---|
| R6 rotates on a **fixed cadence / reactively**, no feasibility model | PX makes the rate a *solved* decision variable under SLO+budget; acts **targeted** | **confirmed (qualitative)** | `COMPARISON.md:26`; `d-phorvex` wiring |
| Blind/reactive MTD disrupts realistic intrusions | On foothold-eviction campaigns **PX = 1.00 while full-Phoenix / R6-blind / reactive = 0.00** | **narrow-confirmed** (foothold oracle) | `out-apt-smoke` (prompt-injection-apt, c1-escape-persist-apt, c3-imds-theft-apt: PX 1.00 vs 0.00) |
| MTD **overhead ≈ 1–2 %** | used as the ROI overhead default (0.015); not re-measured | **can't-yet-test** | `roiGpuOverheadPercent`; `[SP-0-PENDING-P4]` |
| MTD stops AI in-request attacks | PX **evicts the persistence foothold** (`BOUNDS-ONLY`, 1.00 on 7 AI scenarios) but **cannot stop the in-request/exfil/data-plane leg** (`CANNOT-HELP`, 0.00) | **narrow-confirmed (foothold) + honest ceiling** | `out-oraclefix` vs `out-oraclebefore` (§9.15); §6 |
| Baselines credited correctly (esp. d-fullphoenix) | the oracle had **over-credited d-fullphoenix** (NEUTRALIZES with in-request firing); P-AUDIT made `neutralized` outcome-derived → **NEUTRALIZES→BOUNDS-ONLY** | **more honest on BOTH sides** | `out-audit` (§9.16) |
| Full head-to-head canonical benchmark | **not yet complete** (prior `out-bench` had the PX arm 100% skipped) | **can't-yet-fully-test** | §4, `[PENDING-FULL-BENCH]` |

**Honest note:** `COMPARISON.md` carries stronger PX K8s dwell/disrupt rows (e.g. c1-fast-attacker /
c1-heldout-cve 100% disrupt at 1 move) that need **re-confirmation by the full benchmark** before being cited
as final.

---

## 4. Proven-vs-pending ledger

| Claim | Maturity | Evidence / what's needed |
|---|---|---|
| recon-per-dollar **> equal-budget random** (gate `ratio>1.0`; 1.62×–5.87× fleet-dependent, NOT fixed) | **MEASURED-REAL** | `TestAblationP1BeatsRandomPerDollar`; 1.62× P1-REPORT live-kind, 5.87× in-repo gate fleet (§9.20) |
| greedy selection **exactly optimal** (OptimalityRatio 1.000000) for the asset-keyed structure | **MEASURED-REAL** | `TestGreedyIsExactOnShippedFleets` (modular/disjoint; profile-dependent, §9.20) |
| Deterministic `coverage−λ·cost` optimizer + budget/feasibility; **no ML in Decide** | **MEASURED-REAL** | `coverage.go`, `dual.go`; `internal/decision` suite green |
| Structural zero-day frontier (P3 / P3-DEEP) | **MEASURED-REAL** | 792 rows `out-p3-full`; `P3-REPORT.md`; `TestCoverageZeroDayProactiveNoEvents` |
| RL red-team learns (climbs vs structure, flat vs random) | **MEASURED-REAL** | `result.json` (−1.3→35.2 / flat); `TestGradientCheck` 9.5e-9 |
| Two vulns found + fixed + neutralized (λ-pump, dispersion-steer) | **MEASURED-REAL** | `result.json`, `TestDual*`, `coverage.go`; live `out-redteam-live(-pump)` |
| Live decide→actuate→**real pod rotated** end-to-end | **MEASURED-REAL** | audit: `action=rotate`, foothold UID replaced, λ bounded 0.55→1.3 |
| Lead demo — PX disrupts, preserves the stateful job (no harm) | **MEASURED-REAL** | `TestCoverageStatefulNeverRotated`; lead-demo run `harmCaused=None` |
| K8s engine + **measurement layer audited** (oracles correct) | **MEASURED-REAL** | P-AUDIT §9.16: all 24 K8s oracles robust by-`app`-label (zero `armRotates`/fixed-pod); 4 bug-class fixes; `out-audit` controls clean. *Open gap:* `backdoorAlive`/`measureSurvival` robustness unpinned (flagged) |
| PX evicts the AI **persistence foothold** — 7 scenarios `BOUNDS-ONLY` 1.00 (foothold-eviction only) | **MEASURED-REAL** | oracle-fix §9.15: `out-oraclebefore` 0.00 → `out-oraclefix` 1.00; `inRequestAchieved=true` |
| AI **in-request / exfil / data-plane** legs — PX cannot disrupt (honest ceiling) | **MEASURED-REAL (ceiling)** | `out-oraclefix`: `CANNOT-HELP` 0.00 (endpoint-stable, data-plane, CM-survives) |
| **AI/GPU actuators built** — 9 handlers (5 base + 4 new) real behind a mockable vLLM/NVML stack, CI-tested | **CODE-COMPLETE `[PENDING-GPU-VALIDATION]`** | §9.17/§9.19; 13 + 21 CI tests green. **Per-handler maturity:** endpoint-rotate **complete**; kv-reset / warm-swap (drain now built) **real-pending**; model-shard-replace (TP/PP now built) / mig-rebind (**the real remotecommand node-exec transport now BUILT + sequence/ordering-tested, §9.23**, GPU exec pending) **real-pending**; **4 new** adapter-rotate / request-drain / guardrail-rotate / kv-migrate-invalidate (local real, cross-worker deferred). **The LoRA survival gap is closed by `adapter-rotate`** (built, pending GPU validation) |
| **All AI/GPU magnitudes** (dwell, GPU cost, the actuator effects) | **`[SP-0-PENDING-P4]`** | needs real GPU + DCGM; kind proves structure only |
| **Full ≥20-trial × 6-arm × full-catalog with/without-Phorvex benchmark** | **`[PENDING-FULL-BENCH]`** | partial real PX rows only (`out-focusbench` 553 rows / 4 scenarios + `out-apt-smoke`); re-run per `BENCHMARK-RUNBOOK.md` |
| **Multi-tenant DECISION isolation — exact-zero cross-tenant** (a budget-coupled optimizer made provably non-coupling) | **MEASURED-REAL (Pass 1)** | P-VCLUSTER §9.21: the two real brain leaks (shared λ `coverage.go:117/332`; fleet prior `conjugate.go:92`) closed via per-tenant buckets; O1–O10 green incl. O2 byte-identical under the **real λ-pump attack co-resident**; gates byte-identical; brain change scoped to 4 files |
| Multi-tenant **OIDC identity + safe apply-fix write-path + per-tenant DoS quotas** | **MEASURED-REAL (Pass 2)** | §9.22: OIDC RS256-on-stdlib (6 adversarial tests — forged/`alg=none`/expired/wrong-aud/iss rejected, O6 closed); apply-fix allowlist + **shadow-engine gate-check** (a starve delta REJECTED before the applier, anti-vacuous) + **two-key** + per-namespace-SA + audit (live HTTP flow proven); DoS quota isolates a flooding tenant. **14 tests green; brain untouched.** §9.23: the React apply-fix UI + the production CRD applier (`internal/applier`, 5 tests) + the OIDC config loader are now BUILT; remaining = real-env validation (cluster/IdP), `[PENDING-CLUSTER-VALIDATION]`/`[PENDING-IDP-CONFIG]` |
| Availability blast-radius across tenants (R9) | **`[PENDING]` — hard-isolation escalation** | single-process tick loop; only a supervised process / vcluster per tenant closes it — adopt only if a hostile-multi-tenant posture requires it (disclosed, not closed) |
| The 49 remaining catalog scenarios as **real mechanized attack agents** | **`[PENDING-AGENTS]`** | 3 reference agents scaffolded; the 52 `-apt` are metadata-grade kill-chains, not bespoke exploit code |

---

## 5. IP / patent surface (ranked by honest novelty)

Prior art exists for each *ingredient* (MTD; submodular coverage/influence maximization; Lagrangian/dual budget
pricing; PPO; PBT; MAP-Elites). The novelty is in **specific mechanisms + their combination**, stated without
overclaim. **None of the AI/GPU magnitudes are claimed reduced-to-practice on hardware** — those are
`[SP-0-PENDING-P4]`.

1. **Recon-coverage-per-dollar MTD** — pricing rotations by *recon-coverage value invalidated* ÷ cost, with λ a
   *solved* budget shadow-price (not a fixed cadence). *Novel combination; prior MTD does not optimize
   recon-per-dollar.* (`coverage.go`, `dual.go`; gate `ratio>1.0`, 1.62×–5.87×.) **[strongest]**
2. **Provably exactly-optimal selection via an asset-keyed modular reduction** — keying recon facts by owning
   asset makes the coverage objective *modular*, so the budgeted partition-matroid greedy is *exactly* optimal
   (ratio 1.000), not merely 1−1/e — a deterministic, certifiable optimality guarantee for an MTD selector.
   *Novel framing + proof.* (`facts.go:65`, `optimality.go`; §9.20.) **[strongest]**
3. **Decoy-resistant provenance-weighted selection** — weighting selection gain by a provenance factor a decoy
   *cannot manufacture* (aged exposure / real kill-chain evidence), so adversarial manufactured-coverage decoys
   cannot crowd a genuinely-due asset out of the budget — byte-identical for legitimate inputs. *Novel +
   adversary-derived.* (`coverage.go`, `provFloor=0.34`.) **[strong]**
4. **RL-adversary-vs-deterministic-defender co-evolution as a hardening method** — a learning attacker that
   provably finds structural weaknesses in a *deterministic, non-ML* optimizer, each closed as a gated change
   and re-verified to neutralization, with learning strictly walled off from the decision path. *Novel method*
   (the value is the closed loop + the boundary, not PPO itself). (`internal/redteam/`, `P-REDTEAM-REPORT.md`.)
   **[strong]**
5. **Completeness-of-mechanisms AI/GPU actuator set (incl. `adapter-rotate`)** — a mechanism-coverage discipline
   over the serving-stack state classes (replica/cache/route/GPU-slice/shard/adapter/in-flight/guardrail/KV) with
   a handler per class, behind a swappable vLLM/NVML interface; notably `adapter-rotate` evicts a poisoned LoRA
   that survives every prior MTD move. *Novel coverage framing.* (`P-ACTUATOR-SET-COMPLETENESS.md`,
   `handlers_ai*.go`.) **[strong, but AI/GPU is `[PENDING-GPU-VALIDATION]` — not reduced to practice]**

Adjacent-but-supporting (not headline): scarcity-conditioned coverage weighting (UCW); kill-chain
"moved-before-next-stage" timing; the handler-coverage completeness invariant.

**Multi-tenancy is enterprise-readiness, NOT core IP.** The patentable core is the optimizer (items 1–5 above:
recon-per-$, proven exact-optimality, provenance-weighted selection, RL-vs-deterministic co-evolution,
mechanism-coverage actuation). Per-tenant isolation is table-stakes plumbing. That said, the **exact-zero
cross-tenant decision isolation of a *budget-coupled* optimizer is a genuine diligence/credibility asset**: a
naïve shared-λ optimizer leaks one tenant's budget pressure into another's decisions (a correctness **and**
confidentiality defect we found and closed); proving — under the *real* λ-pump attack, co-resident — that the
delta is *exactly* zero (not "bounded") is the kind of result that survives a security review. The Pass-2
write-path adds to that credibility: an apply-fix that **cannot break the safety gates** (a malicious
policy-delta is rejected by a shadow-engine gate-check before any cluster write; `alg=none`/forged identity
rejected; two-key + per-namespace-SA) — adversarially proven, not asserted. It de-risks the enterprise/SaaS
go-to-market without being claimed as invention.

---

## 6. Where Phorvex is honestly weak (the structural limits)

Stating these plainly is what makes the real claims credible.

- **Rotation cannot un-steal an exfiltrated credential / in-request payload — the genuine ceiling.** A stolen
  cloud/IMDS/SA credential stays valid after the pod rotates; a poisoned in-request payload was already served; a
  served replica was already extracted; a poisoned data plane persists. PX is `CANNOT-HELP` here (0.00):
  `c1-credtheft-rbac`, `c3-imds-theft`; AI `ai1-model-theft`/`inference-manipulation` (endpoint-stable),
  `rag`/`registry`/`embedding` (data-plane), `agent-memory`/`rogue-tool` (ConfigMap-survives). **What PX *does*
  do is evict the persistence foothold** (`BOUNDS-ONLY` 1.00 on 7 AI scenarios) — the 1.00s are
  foothold-eviction ONLY; the in-request leg stays honestly uncredited (`inRequestAchieved=true`, never
  `NEUTRALIZES`). (`out-oraclefix`; §9.15.)
- **recon-per-dollar is fleet-/config-dependent — "1.62×" is not a constant.** Gate is `ratio > 1.0`; measured
  span **1.62×–5.87×**; varies with asset value, blast-radius graph, budget. (What IS invariant: greedy is
  *exactly* optimal for the asset-keyed structure — profile-dependent; §9.20.)
- **All AI/GPU effectiveness is unproven on hardware.** Every AI magnitude is `[SP-0-PENDING-P4]`. The 9
  actuators are real code, CI-tested behind a mockable stack, but `[PENDING-GPU-VALIDATION]` — the vLLM/guardrail/
  KV routes must be confirmed against the deployed stack versions (now ALL per-pod annotations, §9.23), and
  **mig-rebind's `execInPod` node-exec transport is now BUILT** (real remotecommand SPDY into a privileged
  node-agent, sequence/ordering-tested; `WireRemoteNodeExec`) — it still fail-closes until a node-agent + a real
  GPU validate it (`[PENDING-GPU-VALIDATION]`).
- **The actuator set's honest residuals.** Even after the completeness build: **cross-worker KV migrate is
  deferred** (`kv-migrate-invalidate` does local invalidate only); **`request-drain` evicts in-flight but does
  not block re-entry** (pair with quarantine/route-rotate); **registry/source poisoning needs attestation** —
  a *check*, not an actuator (re-pulling from a poisoned source re-introduces the poison). Mechanism-completeness
  is a recurring human review, not a once-proven invariant (the handler-coverage invariant proves only that
  every *declared* action has a handler).
- **Multi-tenant: isolation + identity + write-path + quotas PROVEN (Pass 1+2); two honest residuals.** Exact-
  zero cross-tenant *decision* isolation (§9.21), verified OIDC identity, the safe apply-fix write-path
  (allowlist + shadow-engine gate-check + two-key + per-namespace-SA + audit), and per-tenant DoS quotas (§9.22)
  are all built + adversarially proven. The React apply-fix UI, the **production CRD applier** (`internal/applier`,
  gate-re-asserted + verify-then-rollback, 5 mock-K8s tests), and the OIDC config loader are now built too (§9.23).
  **Integration-remaining** (not a safety gap): real-env **validation** — a live cluster/CRD/per-namespace-SA and
  your IdP (`[PENDING-CLUSTER-VALIDATION]`/`[PENDING-IDP-CONFIG]`; see REAL-ENV-VALIDATION.md).
  **Not closed: (a) availability blast-radius (R9)** — a panic/OOM in one tenant's decision halts all (single
  process); only **hard isolation (vcluster)** closes it, and only a hostile-multi-tenant posture requires it.
  **(b) R1 GPU/MIG side-channel** — AUDIT-ONLY, uncloseable in software. The full canonical benchmark remains
  `[PENDING-FULL-BENCH]` (run per `BENCHMARK-RUNBOOK.md`).
- **Live multi-tick crowd-out degrades, not blocks (pre-fix caveat).** Pre-fix, dispersion-steer delays/degrades
  actuation rather than permanently blocking it; the clean total per-tick suppression is the in-process decision
  result. (`P-REDTEAM-REPORT.md`.)

---

### Provenance
Every cited number traces to a file on disk: per-run `metrics.jsonl` + `raw/` + `provenance.json`
(masterSeed 1337) under `build/test-harness/out-*`; the `internal/{decision,cost,redteam,actuator}` test
suites; `out-redteam-rl/result.json`; the live audit (`action`/`selected`/`actuated`/`lambda`/`perDollar`); the
per-stage reports `P0–P4c`, `P-{PHYSICS,CONTEXT,ACTUATOR,DASHBOARD,REDTEAM}`, `P3`/`P3-DEEP`,
`P-OPTIMIZE-RATIO-DECISION.md`, `P-ACTUATOR-SET-COMPLETENESS.md`, `P4-COMPLETENESS-AUDIT.md`,
`EFFECTIVENESS-PHORVEX.md`, `COMPARISON.md`; and the build log `PROJECT-LOG.md` §9.x. The full canonical
benchmark to close `[PENDING-FULL-BENCH]` is run per `BENCHMARK-RUNBOOK.md`. **No code changed in P5
(documentation only).**
