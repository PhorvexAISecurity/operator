# Brain / ticket / code delta ledger (Phase 3)

Mathematical Assurance, Part I.

For every math-critical item, this ledger compares:
1. the **Brain baseline**;
2. later **approved rulings**;
3. the **current code**;
4. the intended current rule, where one is determinable.

An item enters Math Contract v1 only if it is `CONFIRMED` or has an explicit approved
ruling. `CONFLICT` and `UNKNOWN` items are not to be encoded as facts.

| Pin | Value |
|---|---|
| Brain baseline | `phorvex/METHOD-DECISION.md` **at the approved revision `803dfe68` (2026-06-07)** + `phorvex/P1-REPORT.md` (2026-06-05) |
| Post-Brain edits treated as rulings | `00f7be82` (2026-08-17, PHVX-22: removed false optimality-bound claims); `fe3ef74c` (2026-09-01, T0-B: λ audit semantics) |
| Code | `main` @ `f8787fa8` (v0.4.215) |
| Ruling sources | `workflow/campaigns/2026-09-20-post25-live/math-design/*` (MD/), `workflow/fixes/*/03-decision.md`, `workflow/issues/entries/*`; see the [source manifest](MATH_ASSURANCE_SOURCE_MANIFEST.md) |

**Why the baseline revision matters.** `METHOD-DECISION.md` was edited after approval:
- The approved text claimed a "provable (1−1/e) guarantee" and that "λ is *solved*".
- The current text withdraws both.

Pinning `803dfe68` keeps those withdrawals visible as rulings instead of silently
rewriting the baseline.

**Statuses:**

| Status | Meaning |
|---|---|
| `CONFIRMED` | baseline, rulings and code agree |
| `DOCUMENTATION_STALE` | code and ruling agree, the baseline document is outdated |
| `CODE_STALE` | an approved ruling exists but the code does not implement it |
| `CONFLICT` | sources disagree and no approved ruling settles it |
| `UNKNOWN` | cannot be determined from the available evidence |

Where only the baseline speaks and the code differs, the status is `CONFLICT`, not
`CODE_STALE`.

**Evidence legend:**
- **✓** I re-read this at the pin while writing this ledger.
- Otherwise the row comes from the reconstruction and must be re-read before it is
  promoted into the contract.

**Abbreviations:**
- `METHOD` = `phorvex/METHOD-DECISION.md`; `P1R` = `phorvex/P1-REPORT.md`.
- `MD/` = the math-design campaign directory.
- `DT` = `phorvex/docs/decision-trace-v2.md`.
- Code paths are under `phorvex/internal/`.

**Owner column.** These are proposed owners, to be confirmed at Checkpoint 1:
- **Math** = OR/Mathematical Assurance;
- **Eng** = Engineering;
- **Sec** = Security/Product.

## Summary

| Status | Count | Rows |
|---|---|---|
| CONFIRMED | 27 | contract-ready once re-read |
| DOCUMENTATION_STALE | 18 | the baseline needs updating; code + ruling govern |
| CODE_STALE | 2 | DL-009, DL-010 |
| CONFLICT | 8 | DL-016, DL-020, DL-022, DL-030, DL-033, DL-034, DL-040, DL-048 |
| UNKNOWN | 2 | DL-027, DL-052 |

The CONFLICT and UNKNOWN rows (plus the two CODE_STALE rows) are the items that block
Math Contract v1. Each one, and the evidence that would resolve it, is listed under
[Resolution needed](#resolution-needed-before-math-contract-v1).

In addition, §G lists 11 conflicts *between post-Brain rulings, contracts and code*
(RC-1…RC-11), and the flow findings F-1…F-6 have no baseline claim. Both also need
rulings before Math Contract v1.

---

## A. Objective and economics

| ID | Item | Brain baseline | Later ruling | Current code | Intended rule | Status | Owner |
|---|---|---|---|---|---|---|---|
| DL-001 | Objective form | METHOD: strict `marginal·provenance − λ·ECost > 0`; P1R §2 `max Σw(covered) − λ·C` | MD/M098-M144-CONTRACT.md; DT §Reconstruction | `decision/coverage.go` `objectiveGain` | gain = marginal·prov − c·ECost, where c is λ_runtime (legacy) **or** fixed β; never both | DOCUMENTATION_STALE | Math |
| DL-002 | Act/skip boundary | P1R §2 "firing = `perDollar > λ`" | DT (perDollar/proactiveRate are legacy reporting fields); M098 | `coverage.go` `strictPositiveGain`; `existential.go` `chooseRound` | strictly gain > 0; equality does not act | DOCUMENTATION_STALE | Math |
| DL-003 | Fixed disruption aversion β | — | M098-M144; `workflow/fixes/POST25-ECONOMICS/03-decision.md` | `model/economics.go` `Policy.Economics` ✓; `api/v1alpha1/defaults.go` | absent → legacy; explicit β ∈ [0,10] replaces λ in scoring while λ keeps updating. **All tenant policies currently run legacy** ✓ | DOCUMENTATION_STALE | Math |
| DL-004 | Meaning of λ | 803dfe68: "λ *solved*, not hand-set"; Lagrangian budget dual | `fe3ef74c` (T0-B); M098 ("no dual convergence follows") | `cost/dual.go` header ✓ | legacy move-pressure controller used as the ECost coefficient; not a Lagrange/Whittle dual | DOCUMENTATION_STALE | Math |
| DL-005 | λ update rule and timing | METHOD: "asymptotic (regret-bounded) budget guarantee" | M098-M144 | `dual.go` transition; applied in `coverage.go` ~L1158 inside the decision, **before dispatch** ✓ | λ′ = clamp[0,10](λ + 0.05·e/B), e = clamp(demand − B, −1, 1); no regret bound proved | DOCUMENTATION_STALE | Math |
| DL-006 | λ seed and demand | METHOD: seeded from policy, updated from move pressure | M098; M-140 | `dual.go` `NewDualSolverWithSeed`; `coverage.go` | seed once per owner bucket; demand = assets with positive provenance-discounted legacy gain | CONFIRMED | Math |
| DL-051 | Trace economics fields | — | M098 (V4), M156 (V5), M103 (V6/V7) | `coverage.go` ~L1360–1399, ~L1605 | λ_legacy, economics version, coefficient + source, conservative regime recorded; schema v7 | CONFIRMED | Eng |
| DL-054 | Attribution | METHOD: marginal-gain decomposition, "SHAP-style" | M098 | `coverage.go` `attributionForEconomics` | full cover weights − c·ECost; equals marginal under disjoint covers | CONFIRMED | Math |

## B. Cost model

| ID | Item | Brain baseline | Later ruling | Current code | Intended rule | Status | Owner |
|---|---|---|---|---|---|---|---|
| DL-007 | Cost form and units | METHOD `C = λ₁·C_norm + λ₂·C_flow`; P1R §4 dollar figures | M098 ("no monetary claim"); DT §Cost representation | `cost/p1cost.go` `componentsWithRespawn`; weights 0.4 / 0.6 | dimensionless weighted sum | DOCUMENTATION_STALE | Math |
| DL-008 | C_norm rubric | — | MD/M108-LEAD-CONTRACT.md | `p1cost.go` `NormCost*`, `normCostP1` ✓ | 0.10/0.15/0.20/0.25/0.35/1.00/1.25, quarantine 1/3, model-shard = parallel size; provisional | CONFIRMED | Math |
| **DL-009** | Parameter-registry parity for C_norm | — | M108: registry-to-producer value parity | `cost/parameters.go` `ProductionNormActionPriors`: **16 entries for 24 mutating actions** ✓ | every per-action prior registered and bound to `MutatingActions` | **CODE_STALE** | Eng |
| DL-011 | C_flow RLS | METHOD: closed-form online RLS fit | MD/M106; MD/M156 | `cost/rls.go`; `p1cost.go` `ObserveRotation` ✓ | 6 features, forgetting 0.99, output clamp [0,2]; learning live in production, in memory only | CONFIRMED | Math |
| DL-012 | Non-respawn flow families | P1R: pending their own measurements | M156 ("keep current behaviour") | `cost/action_flow.go` | fixed family constants; missing load = zero pressure (opposite of respawn) | CONFIRMED | Math |
| DL-013 | Unsupported respawn regimes | — | MD/M156-LEAD-CONTRACT.md | `action_flow.go` `respawnFlow` | floors + uncertainty bound 2; MIG is always a proxy | CONFIRMED | Math |
| DL-014 | C_hi law | METHOD: feasibility uses C_hi, objective uses E[C] | M156 ("the maximum, never the sum") | `p1cost.go` `Evaluation` ✓ | rotate: E + max(q, flowDisruption·GPUenv); unsupported regime: max(…, E + flowDisruption·(2 − flow)); other actions: E | CONFIRMED | Math |
| DL-015 | Conformal guarantee | METHOD: "removed from the feasible set with a coverage guarantee" | M156 ("not a new guarantee of exchangeability or coverage") | `cost/conformal.go` (window 200, α 0.1, index ⌊(n−1)(1−α)⌋); applied to **rotate only** ✓ | an online upper bound; no coverage claim | DOCUMENTATION_STALE | Math |
| **DL-016** | Conformal residual units | — | M156 names it a remaining math obligation | `p1cost.go` ~L216–232 ✓: the quantile (flow units) is added **unweighted** to the weighted total, while GPU-envelope and regime slack are multiplied by `flowDisruption` | undetermined | **CONFLICT** | Math |
| DL-017 | GPU envelope | P1R §5: declared ceiling | M156 | `conformal.go`; `charts/phorvex/values.yaml` env 0.2925 | GPU rotate slack = max(q, flowDisruption·env); the 0.2925 value has no ruling | CONFIRMED | Math |
| DL-018 | Cost ceiling | P1R §2 `C_hi ≤ ceiling` | `workflow/fixes/CAT-POD-TOKEN-CASE/03-decision.md` ("never change the 1.2 ceiling") | `model/types.go` `DefaultCostCeiling = 1.2`; `actionset/generator.go` | exclude iff CHi > ceiling. At default weights every unsupported-regime rotate has CHi ≥ 1.6 (observed live 2026-10-05) ✓ | CONFIRMED | Math |

## C. Feasibility, capacity and constraints

| ID | Item | Brain baseline | Later ruling | Current code | Intended rule | Status | Owner |
|---|---|---|---|---|---|---|---|
| DL-019 | SLO bound classes | METHOD: SLO filter prunes before selection | `issues/entries/M-147.md` | `slo/bound.go`; `runner/manager.go` `selectionBound` | zero-bound = {noop, identity-rotate, disable}; all others unknown; used for the disruption ledger only. M-147 is still labelled OPEN | CONFIRMED | Math |
| **DL-020** | Scope of the availability floor | METHOD: feasibility (PDB, resource conservation) | M103; M101/M117 | `feasibility/defaults.go` `RemovesReadyReplica` gates only {rotate, quarantine} ✓; `slo/bound.go` says kv-reset, warm-swap, request-drain, adapter-rotate and MIG can lose a replica | undetermined | **CONFLICT** | Math + Sec |
| DL-021 | Shared capacity | METHOD: per-candidate feasibility | MD/M103-LEAD-CONTRACT.md | `actionset/generator.go` `addCapacity`; `decision/resources.go` | integer move count + Service-UID replica capacity; unknown inventory → refuse | DOCUMENTATION_STALE | Math |
| DL-025 | Move budget | METHOD: inviolable top-B | `issues/entries/M-022.md`; M103 | `coverage.go` round loop; `EffectiveMaxMovesPerTick` | nil → 3, negative → 0, explicit 0 kept; one move per asset | CONFIRMED | Math |
| DL-046 | Objective universe and generation | METHOD: generation + optimization in one pass | M102; T1-E; M103 | `generator.go` `Generate` | only covered facts are weighted; a cross-block collision rejects the tick; gate order capability → capacity → feasibility → NaN → conformal | CONFIRMED | Math |
| DL-047 | Inviolability | METHOD: "literally not selectable" | MD/M101-M117-LEAD-DISPOSITION.md | `feasibility/constraint.go` `EvaluateWithSLOSeparation` | SLO floors are relaxable only for a qualified M99 incident with MayBreachSLO; capacity is never relaxed | DOCUMENTATION_STALE | Math + Sec |
| **DL-048** | Feasibility law set | METHOD: "PDB, resource conservation, affinity/taints, stateful-warm-first" | — | 12 laws in `feasibility/*.go`; **no affinity/taint law** | undetermined | **CONFLICT** | Math + Sec |
| DL-049 | M99 existential priority | — | M101-M117 | `decision/existential.go` | a qualified full-containment move outranks ordinary gain, even at non-positive gain | DOCUMENTATION_STALE | Sec |
| DL-050 | Missing-data semantics | METHOD/P1R: "never fabricate" | M156; M103; M104; M-111 | `p1cost.go` NaN handling; `feasibility/defaults.go`; `ctxprov/sensed.go` | NaN → excluded; absent p99 → SLO-headroom gate skipped (fails open); absent request rate → conservative regime; unknown capacity → refuse | CONFIRMED | Math |

## D. Selection, optimality and determinism

| ID | Item | Brain baseline | Later ruling | Current code | Intended rule | Status | Owner |
|---|---|---|---|---|---|---|---|
| **DL-022** | Exactness of greedy | 803dfe68: greedy with "provable (1−1/e) guarantee"; METHOD: greedy exact under a modular objective | MD/M102-LEAD-DISPOSITION.md; `00f7be82` | `decision/optimality.go` reports "greedy provably exact" for disjoint covers ✓ | exact only for a modular objective with partition + cardinality constraints. M103 Service capacity couples assets, and a constructed counterexample (A{rotate 10, kv-reset 9}, B{rotate 9}, shared Service limit 1, B=2 → greedy 10 vs optimum 18) suggests the exactness label can be wrong. **The counterexample is reasoning, not yet an oracle test** | **CONFLICT** | Math |
| DL-023 | (1−1/e) approximation claim | 803dfe68: "provable (1−1/e) guarantee" ✓ | `00f7be82` (PHVX-22) removed it ✓ | `recon/ucw.go` header: no constant claimed | no approximation constant | DOCUMENTATION_STALE (corrected in the current METHOD) | Math |
| DL-024 | Greedy algorithm | METHOD: lazy greedy O(B·\|F\|·log) | — (P1R §8: "plain, not yet CELF/lazy") | `coverage.go` + `chooseRound` | plain greedy; same selections; performance claim only | DOCUMENTATION_STALE | Eng |
| DL-026 | Within-asset tie-break | — | M098 control 5; DT ("within-asset strict-`>` candidate order") | `model/types.go` `MutatingActions` order; `existential.go` ✓ | first in generation order wins; the trace records a per-asset `tieBreakRank` | CONFIRMED | Math |
| **DL-027** | Cross-asset determinism | P1R: "deterministic brain" | — | views are appended in `snap.Pods` order with no sort anywhere downstream ✓; `ingest/kube.go` lists Pods through the cached client ✓ | stable, canonical order | **UNKNOWN**: depends on the cache List order (a library property; the client-go store iterates a map) | Eng |
| DL-028 | NoOp | implicit | M098 control 6 ("honest NOOP") | `coverage.go` noop + `coverageReason` | noop when nothing wins; reason recorded | CONFIRMED | Math |
| DL-029 | Provenance discount | METHOD uses provenance without defining it | `workflow/fixes/T3-M026/03-decision.md` | `coverage.go` `provFloor = 0.34` | 1 if exposure ≥ floor or event evidence; otherwise 0.34 + 0.66·exposure/floor | CONFIRMED | Math |
| DL-053 | Proactive floor | P1R §5: fires from the λ-crossing | M-28; T3-M026 | `feasibility/proactive_cadence.go` | motion without evidence allowed but capped to the ProactiveFloor cadence and provenance-discounted | DOCUMENTATION_STALE | Math |
| **DL-052** | 1.62× ablation | P1R §4: "ratio 1.62 PASS" | `issues/entries/M-139.md` | `decision/ablation.go` | — | **UNKNOWN**: not re-run after the provenance, M156 and M103 changes; "per-dollar" is dimensionless | Math |

## E. Facts, belief and weights

| ID | Item | Brain baseline | Later ruling | Current code | Intended rule | Status | Owner |
|---|---|---|---|---|---|---|---|
| **DL-030** | Base fact weight | METHOD: `w = asset_value × blast_radius × P(hold) × stage-urgency` | — | `recon/profile.go`; `ctxprov/sensed.go`: (labels + 0.8·secrets **+ blast**)·frontier·P(hold)·(0.5 + 0.5·urgency); session ×0.6, networkIdentity ×0.8 | undetermined (additive vs multiplicative blast) | **CONFLICT** | Math + Sec |
| DL-031 | Stage urgency | "stage-urgency" | `workflow/fixes/T1-B/03-decision.md`; M-25 | `killchain/hazard.go` | clamp01(0.5·cons(s) + 0.5·F·cons(next)); provisional consequence table | CONFIRMED | Sec |
| DL-032 | Hazard semantics | METHOD: stage-exit hazard h_s(t) | T1-B | `hazard.go` `weibullCDF` (k=2) | the code's "hazard" is the cumulative probability F(t), not a rate | DOCUMENTATION_STALE | Math |
| **DL-033** | HSMM inference | METHOD: closed-form forward recursion O(\|S\|²·Dmax) | M-25 (merge rule only) | `hazard.go` `AssessMode`: stage is a max-consequence rule; no posterior or recursion | undetermined | **CONFLICT** | Math |
| **DL-034** | Explicit-ignorance flag | METHOD (approved graft): "Explicit-ignorance flag" ✓ | — | **no symbol in code** ✓ | undetermined | **CONFLICT** | Math |
| DL-035 | P(hold) | Beta-Bernoulli P(hold) | `issues/entries/M-143.md`; T1-B | `hazard.go`; `killchain/conjugate.go` | clamp01([μ + p(1−μ)]·damping), prior Beta(1,4), cap 0.5; UCB bonus off (ConfidenceK = 0) | DOCUMENTATION_STALE | Math |
| DL-036 | Conjugate-memory learning | METHOD: per-tenant learned prior | MD/M106-LEAD-CONTRACT.md; `workflow/fixes/POST25-M106-SCOPED-OUTCOMES` | `ObserveBernoulli` has **no production caller** ✓ | no self-training from outcomes; the prior is effectively static | DOCUMENTATION_STALE | Math |
| DL-037 | Event evidence weight | — | M-27, M-29 | `hazard.go` | w = 1 − age/τ (τ default 1h, uncalibrated); eventAlpha += w(1 + 2·sev) | CONFIRMED | Sec |
| DL-038 | Threat posture | `P-THREAT-POSTURE-DECISION.md`: audit-only in P1 | `AUDIT-CONTRACT.md` | `ctxprov/sensed.go` | audit-only | CONFIRMED | Sec |
| DL-039 | Vector dominance | — | `workflow/fixes/T2-M123/03-decision.md`; CAT-POD-TOKEN-VECTOR | `recon/ucw.go` `vectorDominance = 3` ✓ | ×3 once on the matching fact; grants no cover | CONFIRMED | Sec |

## F. Physics and cover

| ID | Item | Brain baseline | Later ruling | Current code | Intended rule | Status | Owner |
|---|---|---|---|---|---|---|---|
| **DL-010** | Infection-frontier κ in the parameter registry | P-CONTEXT §3d: "[1, 1+κ]" | M108 inventory (registry completeness) | `runner/manager.go` `infectionFrontier` returns the literal 1.5 ✓; **absent from `decision/parameter_manifest.go`** ✓ | registered and hashed | **CODE_STALE** | Eng |
| **DL-040** | Scarcity-scalar form | `P-PHYSICS-DECISION.md` §2a: per-fact Σ base·bits·m_dispersion | none in the ruling set (PHVX-70 only in code comments) | `ucw.go` `DispersionMultiplier`: one clamped scalar s ∈ [1,4] applied to every fact; the `ucw.go` header still describes a per-fact split | undetermined | **CONFLICT** | Math |
| DL-041 | Rarity | P-PHYSICS: `1 + (−log₂ freq)/log₂ N` | MD/M104-M151-LEAD-DISPOSITION.md | `platform/platform.go` | ∈ [1,2], population-relative | CONFIRMED | Math |
| DL-042 | Co-residency | P-PHYSICS: distinct-tenant count | `workflow/fixes/T5-M150/03-decision.md` | `platform.go` | 1 + clamp01((namespaces − 1)/4); a proxy, not tenant evidence | DOCUMENTATION_STALE | Math |
| DL-043 | EPSS | P1R §8: CVSS/CVE utilities a roadmap input | M104-M151 (`1 + EPSS·(CVSS/10)`) | `recon/epss_form.go` | recon layer only; absent → 1 with a reason. Production values are hand-entered in GitOps (flow doc T6) | DOCUMENTATION_STALE | Sec |
| DL-044 | Rotate/quarantine cover | P1R §2: rotate ↦ in-pod facts, quarantine ↦ network/lateral | MD/M044-LEAD-CONTRACT.md | `recon/profile.go`; `docs/recon-cover-map.generated.md` | rotate {podIdentity, inMemory, session, podBoundAPIAuth}; quarantine {networkIdentity, lateralEdge} | CONFIRMED | Math |
| DL-045 | Specialized cover | — | M043; M044; M-035; T2-M123 (superseded by M44) | `recon/profile.go`; `recon/ucw.go`; generated cover map | warm-swap / model-shard → 3 process facts; kv-reset / kv-migrate → session; request-drain → inflight; MIG → contention; route / endpoint / identity / guardrail-rotate coverless; each app-scoped revoke covers only its own bound fact | CONFIRMED | Math |

---

## G. Conflicts between rulings, contracts and code

These conflicts are among post-Brain sources themselves, found while building the
ruling set in the [source manifest](MATH_ASSURANCE_SOURCE_MANIFEST.md) §4. They block a
Math Contract v1 rule just as a baseline conflict does.

| Ref | Item | Disagreeing sources | Status | Owner |
|---|---|---|---|---|
| RC-1 | Domain of β (M-98) | `md/M098-M144-CONTRACT.md`: "explicit finite `>= 0`", dimensionless ✓; `workflow/fixes/POST25-ECONOMICS/03-decision.md`: "the existing coefficient range [0,10]" ✓; CRD admits ≤ 10 | CONFLICT (bound) | Math |
| RC-2 | Where the M-156 regime delta lands | contract: "add its nonnegative weighted delta to ExpectedCost through the maximum with existing conformal/GPU slack" ✓; code adds it to **CHi only**, ECost = Total (`cost/p1cost.go` ~L229–231) ✓. The wording is ambiguous because the slack itself lives in CHi | CONFLICT (needs a clarifying ruling) | Math |
| RC-3 | M-106 learning rule | lead contract: held/revoked outcomes add a Bernoulli count; `workflow/fixes/POST25-M106-SCOPED-OUTCOMES` decision: outcomes never call `ObserveBernoulli`; priors Beta(1,4) (governance) vs Beta(1,1) (cohorts). Code follows the second | CONFLICT | Math |
| RC-4 | Can existential priority relax capacity? | `M99-EXISTENTIAL-CONTAINMENT.md`: `mayBreachSLO` may relax the availability floor; M-103 capacity is enforced in existential selection with no exception | CONFLICT | Math + Sec |
| RC-5 | guardrail-rotate cover | `build/test-harness/ACTUATOR_COVERAGE.md` and the steering comment in `model/types.go` credit guardrailBypass; CAT-GUARDRAIL-COVER and the generated cover map make guardrail-rotate coverless (code agrees with the latter) | DOCUMENTATION_STALE | Eng |
| RC-6 | kv-migrate session cover (M-39) | `recon/ucw.go` grants full session cover at selection while post-effect credit is withheld | CONFLICT | Math |
| RC-7 | Trace/audit versioning | `decision-trace-v2.md` lists 4 dispatch outcomes, code accepts 8 under any version (yet V7 was bumped for one vocabulary addition); the 10 action-vocabulary markers are undocumented; `AUDIT-CONTRACT.md` stays at audit.v2 despite new fact kinds and a guardrailBypass meaning change, although it requires a bump | CONFLICT | Eng + Math |
| RC-8 | Evidence predicate for the proactive cap (M-28) | `fx/T1-M028` decision says broad `HasEvidence`; its evidence fix and the merged code use strict `HasEventEvidence` | DOCUMENTATION_STALE | Math |
| RC-9 | route-rotate cost family | `P-ACTION-FLOW-COST-DECISION.md`: lightweight 0.02; M-147 treats it as an unknown-SLO cutover | CONFLICT | Math |
| RC-10 | Exactness and tie-break for new actions | `METHOD-DECISION.md` requires a new proof for any overlapping cover profile; no ruling re-establishes it for the 9 application-scoped actions/facts merged without records, and the `MutatingActions` tie-break order grew to 24 without a ruling | CONFLICT (see DL-022, DL-026) | Math |
| RC-11 | Exposure counted twice (M-105) | exposure enters both pHold and provenance; open issue, no ruling | UNKNOWN | Math |

Rows marked ✓ were re-read. The others come from the ruling inventory and must be
re-read before encoding.

---

## Flow findings with no baseline claim

These come from the [decision flow](PHORVEX_CURRENT_DECISION_FLOW.md). They have no
counterpart in the Brain baseline, so they cannot take a ledger status. They still need
a ruling before Math Contract v1.

| Ref | Finding | Evidence |
|---|---|---|
| F-1 | No runtime decision-consistency check: `DecisionTraceV2.Validate()` has no operator caller; audit is written after actuation and its error is ignored | ✓ `audit/log.go:Record` returns error; `runner/manager.go` ~L2192/2310 |
| F-2 | Console-created SecurityEvents are trusted detector evidence in production | ✓ `deploy/helm/phorvex-stack/values-eks.yaml` `trustedDetectors` |
| F-3 | Any allowlisted detector can target any namespace (no entitlement check) | flow doc T1 |
| F-4 | Vector steering and the infected set have no evidence-age check; EPSS has no expiry in legacy mode | flow doc T1, T6 |
| F-5 | RBAC SSAR errors are fail-open; an absent kill-switch ConfigMap is disengaged | flow doc T12, T13 |
| F-6 | All learned state (RLS, conformal residuals, λ, clocks) is in memory and resets on restart/failover | flow doc §4 |

---

## Resolution needed before Math Contract v1

| ID | What would resolve it |
|---|---|
| DL-009, DL-010 | A registry-completeness test binding `normCostP1` priors and runner constants (κ) to the parameter manifest (implementation follows an existing M108 ruling) |
| DL-016 | A math ruling on whether the conformal residual is in total-cost units (×flowDisruption) or flow units, evaluated on recorded rotations |
| DL-020 | A ruling on whether actions that `slo/bound.go` says can lose a replica must consume availability capacity, backed by live replica-loss measurements |
| DL-022 | An exhaustive-oracle test on the coupled-capacity counterexample, or a ruling that withdraws "greedy provably exact" when Service scopes are shared (plus a solver choice) |
| DL-027 | Confirm the cache List ordering in the pinned controller-runtime version, or add a canonical view sort and a replay-determinism test |
| DL-030 | A ruling choosing additive vs multiplicative blast radius in asset value, with an ablation |
| DL-033, DL-034 | A ruling that formally drops or re-requires the approved HSMM recursion and explicit-ignorance grafts |
| DL-040 | A ruling ratifying PHVX-70's uniform scarcity scalar, with updates to P-PHYSICS §2a and the `ucw.go` header |
| DL-048 | A ruling on whether placement constraints (affinity/taints) belong to the scheduler or must be a feasibility law |
| DL-052 | A fresh ablation at the current head, reported in dimensionless units |
| RC-1 … RC-11 | A single superseding ruling per item naming the governing text; documentation-stale rows (RC-5, RC-8) only need the stale document updated |
| F-1 … F-6 | Security/Product + Math rulings on each, before any is encoded as contract behaviour |
