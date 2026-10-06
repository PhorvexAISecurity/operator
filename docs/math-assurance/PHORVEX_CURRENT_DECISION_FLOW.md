# PHORVEX current decision flow (Phase 2)

Mathematical Assurance, Part I. This is the decision flow as the code implements it,
traced from observed state to action and feedback. It was not copied from earlier design
documents. The diagram is in [PHORVEX_CURRENT_DECISION_FLOW.mmd](PHORVEX_CURRENT_DECISION_FLOW.mmd).

| Pin | Value |
|---|---|
| Code | `main` @ `f8787fa81e5a9844cda01a4910a8ece68f7d2748` (release v0.4.215) |
| Deployed (dev) | operator + console `0.4.215`, Argo `phorvex-stack` synced to the same commit |
| Baseline documents | see [MATH_ASSURANCE_SOURCE_MANIFEST.md](MATH_ASSURANCE_SOURCE_MANIFEST.md) |

All paths are relative to `phorvex/` unless they start with `deploy/` or `workflow/`.
Line numbers are approximate (±5).

**Evidence legend:**
- **✓** I re-read this in the code at the pin while writing this document.
- **◐** Traced during the reconstruction but not independently re-read; treat it as a
  claim to confirm before it enters Math Contract v1.

---

## 1. What the assurance plan assumed versus what exists

The assurance plan's model is *"AI/RL proposes → deterministic Math Gate → admitted
scorer/optimizer/reward"*. That is not the current shape of PHORVEX:

- **No LLM or learned policy is on the decision path.**
  - The Brain baseline states this explicitly (`METHOD-DECISION.md`, `P1-REPORT.md`).
  - The code agrees: decisions come from the deterministic `p1-coverage` engine, a greedy
    submodular recon-fact coverage over a generated feasible action set.
  - The only RL code is `internal/redteam` (POMDP/PPO). It is an **attacker** simulator,
    imported only by `cmd/redteam-rl`, and neither the operator nor the console image
    builds it. ✓
  - The many "LLM" references in `internal/` concern the AI workloads PHORVEX defends
    (vLLM, LiteLLM, Voice). No model is consulted to decide.
- **The plan's "AI/RL proposals" correspond here to *learned, calibrated or externally
  supplied inputs* that feed a deterministic optimizer:**
  - detector SecurityEvents and typed observations;
  - Prometheus telemetry;
  - the EPSS table;
  - the RLS-learned rotate cost and its conformal slack;
  - the runtime λ;
  - in-memory clocks;
  - policy CRD parameters.

  These are the trust transitions in §5, and they are where Runtime Math Gates would sit.
- **There is no RL reward path to protect.** The closest analogue to the plan's
  "Scorer / Reward Gate" (G7) is the set of **online learning signals**: RLS observations,
  the λ update and (designed but unused) conjugate memory. See §4 and §6.

---

## 2. End-to-end chain

```text
S0 Policy admission ──► S1 Tick + cluster snapshot ──► S2 SecurityEvent ingest + trust ─┐
                                   │                                                    │
                                   ├──► S3 Prometheus telemetry                         │
                                   └──► S4 Physics / dispersion (EPSS, rarity)          │
                                                                                        ▼
        S5 View assembly (exposure clock, intents, infection frontier) ◄────────────────┘
                 │
                 ▼
        S6 Context signals (asset value, threat posture, SLO headroom)
                 │
                 ▼
        S7 Kill-chain belief (stage, Weibull hazard, pHold)
                 │
                 ▼
        S8 Recon facts + weights + CoverByAction
                 │
                 ▼
        S9 Candidate generation + gates (capability, feasibility, conformal SLO-cost)
                 │      ▲
                 │      └── S10 Cost (C_norm rubric, C_flow, RLS, conformal slack)
                 ▼               S11 Objective coefficient (λ_runtime | fixed β)
        S12 Selection (greedy, strict positive gain, budget B, M99 existential priority)
                 │      └── side effect: λ dual step (before dispatch)
                 ▼
        S13 Runner gates (dry-run, kill switch, emit re-check, selection-ID, fences, capacity)
                 │
                 ▼
        S14 Actuator (native handlers | Phoenix/AMTD for quarantine)
                 │
                 ▼
        S15 Effect confirmation (journals, readbacks, rotate readiness)
                 │
                 ▼
        S16 Audit emission (after actuation)        S17 Feedback (RLS, conformal, λ, clocks)
```

---

## 3. Stages

Field key:
- **In:** inputs, with their source.
- **Kind:**
  - D = deterministic;
  - L = learned or calibrated online;
  - X = externally supplied.
- **Missing / Fail:** behaviour when data is absent or an error occurs.

| # | Stage | Where | In | Out | Kind | Missing / Fail | Tests |
|---|---|---|---|---|---|---|---|
| S0 | Policy admission | `controller/phorvexpolicy_controller.go:Reconcile`, `runner/manager.go:Upsert`/`buildPolicy` ◐ | PhorvexPolicy CRD | per-tick `model.Policy` | D | Defaults from `api/v1alpha1/defaults.go` (dryRun, λ=0.6, B=3, normSparsity 0.4, flowDisruption 0.6, ceiling 1.2…). An invalid policy is not registered; an invalid **edit** keeps the old entry and the non-dry-run tick exits on the generation mismatch ◐ | `phorvexpolicy_*_test`, `defaults_test` |
| S1 | Snapshot | `ingest/kube.go:collectSnapshot` ✓ | cached Pods, Namespaces, NetworkPolicies, RBAC (required); SAs, SecurityEvents, Nodes, PDBs, Services, EndpointSlices (best-effort) | `*ingest.Snapshot` | D | A required-list error ends the tick (`tickSnapshotFailed`). A failed **SecurityEvent list yields no events, silently** ◐ | `ingest/*`, `runner/m137_*` |
| S2 | Event ingest + trust | `ingest/events.go`, `ingest/eventtrust.go:classifyEvent`; admission stamp `controller/securityevent_webhook.go` (failurePolicy Ignore) + ValidatingAdmissionPolicy ◐ | cluster-scoped SecurityEvents; `--trusted-detectors` | `snap.Events` (each with `Trust`), `snap.EventByPod` (trusted + target-bound only) | X + D filter | An empty allowlist means no evidence; unstamped → untrusted; a missing/future timestamp gives weight 0; self-emitted actuator events are excluded ◐ | `event_trust_test`, `securityevent_webhook_test`, `auditguard/*` |
| S3 | Telemetry | `ingest/prometheus.go:PodMetrics`, `model/signal.go:Usable` ◐ | Prometheus | `model.Telemetry` (Present/Stale/Absent/Error per signal) | X | Only `Present` is usable. Stale/Absent/Error are **never read as zero** ◐ | `prometheus_test`, `telemetry_state_t1c_test` |
| S4 | Physics / dispersion | `platform/platform.go:Derive`, `platform/epss.go:lookupEPSS`, `recon/epss_form.go` ◐ | snapshot, EPSS ConfigMap, DCGM | `model.PhysicsWitness` (ImageRarity, EPSS multiplier, CoResidency, …) | D + X | Pod not in map → `NeutralPhysics()`. EPSS miss → multiplier 1 ◐ | `platform/*`, `epss_form_test` |
| S5 | View assembly | `runner/manager.go:processTenantWithPhysicsObserved` (views appended in `snap.Pods` order, ~L1982–2078) ✓; `exposure/clock.go` ◐ | snapshot + in-memory clocks/intents | `[]*model.WorkloadView` | D (+ in-memory state) | After a restart the exposure clock (including per-action `*-epoch` markers) is seeded from Pod StartedAt ◐ | `exposure/*` |
| S6 | Context | `ctxprov/sensed.go:Context` ◐ | view | `model.ContextSignals` | D | Unknown threatLevel → medium ◐ | `ctxprov/*` |
| S7 | Belief | `killchain/hazard.go:AssessMode`, `conjugate.go:PHoldUCBWithEvidenceMode` ◐ | trusted, age-weighted events (w = 1 − age/horizon), exposure, StageClock, fixed Beta(1,4) prior | `killchain.Assessment` (Stage, Hazard, PHold, urgencies) | D (parametric) | No events → stage Recon, β̄ = 0.2 ◐ | `killchain/*` |
| S8 | Recon facts | `recon/ucw.go:AssetFacts`, `recon/profile.go` ✓ | view, context, belief, physics | `recon.AssetFacts{Facts, CoverByAction}`; weight = AssetValue·pHold·(0.5+0.5·stageUrg)·s, vector-steered facts ×3 | D | A non-finite input sets `AbsentReason`, and every action for the asset is excluded ◐ | `recon/*`, `tools/covermap` |
| S9 | Candidates + gates | `actionset/generator.go:Generate`; `capability/gate.go:eligible` ✓; `feasibility/*` ◐ | facts, policy, capability witness, RBAC SSAR, capacity | `actionset.ActionSet{Candidates, Excluded, …}` | D (+ X: SSAR) | A cover-key collision rejects the whole tick. SSAR error → **fail-open** (`RBACUnknown`). Some feasibility laws pass on missing data: slo-headroom without usable p99; anti-over-rotation/cadence without a clock ◐ | `actionset/*`, `capability/*`, `feasibility/*` |
| S10 | Cost | `cost/p1cost.go:Evaluation`/`normCostP1`, `cost/action_flow.go`, `cost/rls.go`, `cost/conformal.go` ✓ | view, telemetry, RLS state | `P1Evaluation{Norm, Flow, Total=ECost, CHi}` | D rubric + L (RLS for rotate/mig-rebind) | Unknown/draining phase or unusable request rate → phase-prior floor + uncertainty bound. NaN → "unactionable due to NaN" ◐ | `costaudit_test`, `p1cost_test`, `m156_regime_test` |
| S11 | Objective coefficient | `model/economics.go:Policy.Economics` ✓ | policy `objective.lambda` / `objective.disruptionAversion` | `EconomicsMetadata`: `legacy-runtime-lambda-v1` (λ_runtime) or `fixed-disruption-aversion-v1` (β) | D | Non-finite or outside [0,10] rejects the tick ◐ | `post25_economics_test` |
| S12 | Selection | `decision/coverage.go:decideChecked`, `decision/existential.go:chooseRound` ✓ | ActionSet, economics, budget B | `[]model.Decision` + `DecisionTraceV2` (schema v7, vocabulary `v10-live24`) | D | Strict positive gain; on a tie the first candidate in generation order wins ✓. Side effect: `Dual.StepDetailed` commits inside the decision (`coverage.go:1158`) ✓ | `coverage_test`, `o1_golden_test`, `optimality_test`, `existential_test` |
| S13 | Runner gates | `runner/manager.go:actuatePreparedModeWithCapacity` (~L2770–3480) ✓ | decisions, fresh reads | dispatch / not-attempted + reason | D | Kill-switch read error engages it; an **absent** kill-switch ConfigMap leaves it disengaged ◐. The selection-ID gate checks only that DecisionID/TickID are non-empty ✓ | `killswitch*_test`, `dispatch_outcome_test`, `regate_test` |
| S14 | Actuator | `actuator/backend.go:RouteFor`, `actuator/hybrid.go:ForAction` ✓; native handlers; `actuator/phoenix.go` | request (+ typed observation) | `actuator.Result` | D | Hybrid routes only `quarantine` to Phoenix/AMTD; every other action is native ✓ | `actuator/*` |
| S15 | Effect confirmation | `actuator/operation_journal.go`, per-action readbacks; rotate `runner/manager.go:observeReadyRotations` ◐ | cluster reads | journal receipts, readiness labels | D | The strongest decision stamp is `emitted-unconfirmed` ◐ | `operation_journal*_test` |
| S16 | Audit | `audit/log.go:Record` (returns `error`) ✓ | decisions | `phorvex.audit.v2` JSONL | D | **Written after actuation; the runner ignores the returned error** (`manager.go` ~L2192, ~L2310) ✓ | `audit/schema_replay_test` |
| S17 | Feedback | §4 | outcomes | learned state | L | §4 | §4 |

---

## 4. Learned and cross-tick state

| Quantity | Updated by | Signal | Consumed by | Persisted? |
|---|---|---|---|---|
| RLS θ, P (C_flow, rotate & mig-rebind) | `P1Cost.ObserveRotation` (`cost/p1cost.go` ~L354) ✓ | observed readiness delay of the replacement Pod (censored) ◐ | ECost and CHi | memory only ◐ |
| Conformal residuals | same call, `Conformal.Observe` ✓ | \|measured − predicted flow\| | **rotate** CHi only ✓ | memory only ◐ |
| λ_runtime | `Dual.StepDetailed` in `decideChecked` ✓ | move demand vs spent vs budget B (`cost/dual.go` says it is *not* an exact Lagrange dual ✓) | objective coefficient (legacy economics) | memory; seeded from spec ◐ |
| Failure cooldown, emit intents, StageClock, exposure clocks | runner / killchain ◐ | refusals, emits, stage changes | feasibility, hazard | memory only ◐ |
| Conjugate Beta (per-tenant memory) | **no production writer**: `ObserveBernoulli` has no non-test caller ✓ | — | pHold prior (therefore fixed Beta(1,4)) | — |

**Not on the decision path:**
- `internal/belief`: imported only by a test ✓.
- `internal/calib`: shadow mode ◐.
- SLO ledger, loss history, scoped outcomes: reporting/representation only ◐.
- `internal/redteam` ✓.

**Durable across restarts:** operation journals, capacity and kill-switch ConfigMaps,
the EPSS ConfigMap, Phoenix AMTD/SecurityEvent CRs, the audit JSONL and the loss-history
PVC ◐.

---

## 5. Trust transitions

Each row is a point where an external, inferred, learned or calibrated value first
becomes trusted by a deterministic downstream component. These are the candidate
locations for Runtime Math Gates.

| ID | Transition | Admitted by | Not checked / risk if wrong, stale or missing |
|---|---|---|---|
| T1 | Detector SecurityEvent → trusted belief evidence (S2→S7/S8) | Creator identity (webhook stamp + VAP) in the `trustedDetectors` allowlist ◐ | **Not checked:** rule source, per-namespace entitlement (any allowlisted identity can target any Pod), truthfulness of threatLevel/rule type.<br>**If wrong:** raises stage, pHold and urgency; ×3 vector steering; ×1.5 frontier on neighbours; provenance 1.<br>**Age:** belief weights decay to 0 at the horizon, but **vector steering and the infected set have no age check** ◐ |
| T2 | Console-created SecurityEvent → trusted evidence (production) | The console ServiceAccount is in `trustedDetectors` (`deploy/helm/phorvex-stack/values-eks.yaml` ~L449–453) ✓ | Same path as T1; the console's target-UID annotation binds the target, not trust ◐ |
| T3 | Protected-outcome annotations → M99 existential priority (can override gain > 0 and the SLO) | trusted creator + exact policy/asset scope + boundary readiness + age ◐ | LossState/class are self-declared by the trusted creator ◐ |
| T4 | Typed observation annotations → new ×3 facts and covers (adapter, output, voice-*, litellm, crm, endpoint-lease) | trusted creator + per-binder identity checks + policy UID/generation match ✓ (crm) / ◐ (others) | per-binder checks not individually audited ◐ |
| T5 | Prometheus series → phase, SLO gate, cost regime | `State == Present` only ◐ | series provenance not checked; a false request rate or p99 changes phase, regime and vetoes ◐ |
| T6 | EPSS table → dispersion multiplier on fact weights | legacy mode in production: domain/duplicate checks, **no expiry**; values hand-entered in GitOps (`values-eks.yaml`) ◐ | stale scores persist indefinitely ◐ |
| T7 | Workload-owned labels/owners/PDBs → cover grants and feasibility | capability pool/config predicates ◐ | anyone who can edit the workload controls them ◐ |
| T8 | RLS cost estimate → objective and CHi | owner-epoch + same-owner replacement match ◐ | biased rotate pricing; floors limit underestimation; resets on restart ◐ |
| T9 | Conformal quantile → hard SLO-cost feasibility (rotate) | finite residual ◐ | online empirical quantile without exchangeability check ◐ |
| T10 | λ_runtime → objective coefficient | finite and in [0,10] ◐ | self-referential (driven by the engine's own selections) and **steps even when nothing is dispatched** ✓ |
| T11 | Exposure clock / intents → anti-over-rotation, cadence, dwell | fingerprint change ◐ | restart seeds from Pod StartedAt, so recent actions can be forgotten ◐ |
| T12 | RBAC SSAR answers → capability gate | an explicit deny excludes ◐ | **an SSAR error is fail-open** (`RBACUnknown`) ◐ |
| T13 | Kill switch / namespace dry-run / Pod opt-out → dispatch | uncached reads; a read error engages ◐ | an absent kill-switch ConfigMap is disengaged ◐ |
| T14 | Phoenix SecurityEvent status → rotation receipt | — | dormant under the hybrid actuator ◐ |
| T15 | Policy CRD values → every parameter | CRD validation + `ValidatePhorvexPolicy` + `Upsert`; parameter-set hash recorded ◐ | parameter `Domain` metadata is free text and not range-checked ◐ |

---

## 6. Existing assurance machinery, mapped to the plan's gates

| Plan gate | What already exists | Runtime or test-only | Gap observed |
|---|---|---|---|
| **G0** Schema/type | CRD schema + CEL; `ValidatePhorvexPolicy`; audit v2 write validation; NaN guards in ingest, recon and cost ◐ | runtime | audit validation runs **after** actuation and cannot block it ✓ |
| **G1** Provenance/evidence | event trust classification (T1); typed observation binders (T4); telemetry `Present`-only (T5); EPSS authoritative mode exists but is not used in production ◐ | runtime | entitlement per namespace, vector-steering age, EPSS expiry ◐ |
| **G2** Domain/unit | economics finite/[0,10]; NaN categories ◐ | runtime | parameter domains not enforced from a contract ◐ |
| **G3** Semantic/action-effect | capability gate; recon cover map (`tools/covermap` CI drift check); journals/readbacks ✓ | runtime + CI | strongest stamp is `emitted-unconfirmed` ◐ |
| **G4** Independent recomputation | `DecisionTraceV2.Validate()` recomputes netGain, ECost, CHi, marginal ◐; frozen Python validator `workflow/fixes/T0-C/validator/audit_trace_validator.py` | **test-only**: `Validate()` has no operator caller ✓; the Python validator runs in CI via two Go tests ◐ | no runtime recomputation; not applied to live audit ◐ |
| **G5** Feasibility / hard constraints | feasibility law registry (panic → veto), conformal SLO-cost gate, hard resource capacity, emit-boundary re-check, startup preflight ◐ | runtime | some laws pass on missing data (S9) ◐ |
| **G6** Decision/solver consistency | Python validator greedy replay with tie-break rank (CI) ◐; `optimality_test` (exhaustive sweep off in CI) ◐ | test-only | ties are not a canonical function of state: candidate order follows the unsorted cache Pod list ✓ (the map-iteration order of the client-go store is library behaviour, not repo code) |
| **G7** Scorer/reward admission | no RL reward. Learning signals: RLS admission by owner-epoch check (T8); λ (T10); conjugate memory unused ✓ | runtime | λ updates on ticks that dispatch nothing ✓ |

---

## 7. Observations that need a ruling

These go into the delta ledger. They are observations, not proposed fixes.

1. **Per-tenant conjugate memory is not learned.** The Brain baseline describes it, but
   there is no production writer (✓), so pHold uses a fixed Beta(1,4) prior.
2. **The runtime λ is a move-pressure controller, not a Lagrange dual** (✓, the code
   says so), and it steps before dispatch (✓).
3. **"Conformal" is an online empirical quantile applied only to rotate** (✓
   rotate-only; quantile form ◐).
4. **Rotate is pruned whenever load is not measured.** With every deployed policy at
   normSparsity 0.4 / flowDisruption 0.6 / ceiling 1.2, a rotate outside the
   measured-load regime gets CHi ≥ 1.6 > 1.2. This matches live decision rows observed
   on 2026-10-05 ("conformal-slo: worst-case cost 1.60 > ceiling 1.20" for crm, voice and
   litellm).
5. **Tie-breaking depends on cache list order**, so a decision is replayable from its
   trace (`TieBreakRank`) but not reproducible from cluster state alone (✓ code; ◐
   library behaviour).
6. **No runtime decision-consistency check.** `Validate()` is test/console-only, and
   audit is written after actuation with errors ignored (✓).
7. **Console-created events are trusted detector evidence in production** (✓).
8. **Learned state is in memory only and resets on restart or failover** (◐).
9. **Several modules described as learning are not on the decision path:** belief ✓,
   calib ◐, SLO ledger ◐, loss history ◐.
10. **Evidence age is not enforced uniformly:** vector steering and the infected set
    have no age check, and EPSS has no expiry in legacy mode (◐).

---

## 8. Limits of this reconstruction

- **Not traced end to end for every action:** the console UI, the per-handler readback
  internals other than crm, rotate and route, and the M99 existential path's full
  boundary checks.
- **◐ items** must be re-read against the pin before they become Math Contract v1
  facts.
- **Runtime behaviour is inferred from code.** Only the items explicitly tied to live
  decision rows (§7.4) were observed on the cluster.
