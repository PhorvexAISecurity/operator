Workstream input. The architecture docx (Rev 4) is the source of truth.

# WS-3 — Validator (Actuator/Defender) Architecture, the "Actuator Works" Gate, and the Ranking Rubric

Status: READ-ONLY design. Authorized defensive-security architecture.
Scope: design the roster that *proposes* actuators and *proves* each one provably defends a
confirmed attack, where "works" is adjudicated by the REAL deterministic brain — never by LLM
agreement. Numeric thresholds are **configurable parameters (docx §14)** read from policy/config
at run time with a safe default and logged with the verdict; every metric value is **measured on
the twin, never estimated** (docx §8).

**Tag legend:** `[CODE-CITED]` `file:line` — literal in this repo's code (the `file:line` follows
the tag); `[DOC-CITED]` — a doc, report, markdown file (incl. the generated
`docs/recon-cover-map.generated.md`) or paper, incl. the architecture docx; `[INFERRED]` — derived
from cited code; `[UNVERIFIED]` — asserted, labelled, not yet grounded.

Repo root: `/home/hami/mostafa/operator`. Code paths below are relative to
`phorvex/internal/` unless prefixed otherwise.

---

## 0. The non-negotiable principle

An actuator "works" against a confirmed attack **iff the deterministic brain itself, replaying the
attack on an isolated twin, reaches a pass on every gate below and SELECTS it.** No persona, and no
LLM, is permitted to over-ride a brain verdict. The brain's selection code already *fuses*
feasibility and the conformal-SLO gate into selection (a vetoed or gated action is structurally
unreachable), so "the brain selected it" is the strongest single fact we have. The validator's job
is to *decompose* that fact into separately-auditable gates, plus the two post-dispatch proofs the
engine does not perform inline (capability-gone probe, availability-SLO ledger hold), and to
reproduce the result across the scenario battery while parsing the brain's explainability each
iteration.

The brain's own honesty contract is the anchor: a stub that "cannot yet verify a fixture MUST return
`ok=true` with `why` prefixed `unverified: ` (never a silent false), so an unverified capability can
never masquerade as a checked one (P-08)" `[CODE-CITED]` `actuator/actuator.go:241-243`. The validator
inherits this: an unproven gate is UNVERIFIED, never a silent pass.

---

## 1. Validator hierarchy + roster (grounded)

The validator is a **proposer/prover roster** sitting *outside* the brain. It proposes actuators and
feeds each through the real brain; it never scores defenses itself. The brain surface it drives is
the swappable `Actuator` interface — `Name()`, `EnsurePolicy()`, `Actuate()`, `SupportsAction()`
`[CODE-CITED]` `actuator/actuator.go:226-244` — behind which all three real hands sit
(`PhoenixActuator`, `NativeActuator`, and the stubbed Phase-2 native path), proven by the
compile-time interface assertions `[CODE-CITED]` `actuator/native.go:369-375`.

### 1.1 Tier structure

| Tier | Name | Role | Authority it may NOT override |
|---|---|---|---|
| T0 | **Brain-in-the-loop adjudicator** | Runs `CoverageEngine.Decide` / `DecideShadowChecked` on the isolated twin; the *only* component that returns pass/fail. | — (it is the authority) |
| T1 | **Explainability reader** | Parses the brain's decision trace every iteration; extracts WHY selected / WHY declined; routes a decline back to the proposer. | Cannot re-interpret a trace reason into a pass. |
| T2 | **Proposer roster (personas)** | Each persona proposes actuators from its domain; proposals are *inputs*, never verdicts. | Cannot declare an actuator "works". |
| T3 | **Prover harness** | Executes the ordered Stage 0–5 gate pipeline (§2) on the twin and the scenario battery; records the seven-metric scorecard (§3). | Cannot relax a gate (G1–G3). |

### 1.2 Persona roster (proposer T2), mapped to the code each persona must respect

- **CISO / defender strategist** — owns the confirmed-attack → obligation framing. Maps to the
  existential obligation the brain must contain: a qualified, trusted, scoped, boundary-enforced,
  `irreversible-catastrophic`, `at-risk` outcome `[CODE-CITED]` `decision/existential.go:34-60`.
- **SRE / availability owner (SLO veto)** — holds a hard veto wired to the availability floor and
  SLO headroom laws `[CODE-CITED]` `feasibility/defaults.go:44-97` and the availability-bound proof
  `[CODE-CITED]` `slo/bound.go:199-215`. This persona's veto is a GATE including co-tenants —
  defends-but-breaches = FAIL — not a score (§3, G2).
- **Network engineer** — proposes `quarantine` (networkpolicy create/update/delete + pod update)
  `[CODE-CITED]` `actuator/verbs.go:33`; cover = `networkIdentity` + per-neighbour `lateralEdge`
  `[DOC-CITED]` `docs/recon-cover-map.generated.md:68`.
- **K8s platform security** — proposes `rotate` (pods/eviction create) `[CODE-CITED]`
  `actuator/verbs.go:31`; cover = `podIdentity,inMemory,session,podBoundKubeAPIAuthPotential`
  `[DOC-CITED]` `docs/recon-cover-map.generated.md:67`; must respect `code-exec-guard`
  (debugger/custom-inject forbidden in system namespaces) `[CODE-CITED]`
  `feasibility/actions_native.go:109-121`.
- **AI / MLOps security** — proposes the serving/GPU moves (`kv-reset`, `warm-swap`, `mig-rebind`,
  `adapter-rotate`, `request-drain`, `model-shard-replace`, `kv-migrate-invalidate`, the voice/LLM
  policy actions, `endpoint-lease-revoke`) `[CODE-CITED]` `actuator/native.go:97-176`,
  `feasibility/actions_native.go:18-27`; must respect `ai-context-required` (the move is infeasible
  on a pod lacking its GPU/serving/detector witness) `[CODE-CITED]` `feasibility/actions_native.go:32-69`.
- **Cloud engineer** — owns `EnsurePolicy`/tenant→namespace binding and the O7 cross-tenant fail-close
  `[CODE-CITED]` `actuator/native.go:189-232`, `actuator/native.go:283-307`.
- **Detection & IR (closed-loop confirmation)** — owns G1 and dwell (S1) (§3): the capability-gone
  probe (Stage 3), timed — the
  deterministic serving-inventory/readback that proves the attacker capability is GONE, e.g. the
  adapter inventory probe `AdapterLoaded` `[CODE-CITED]` `actuator/adapter_rotate.go:404-410` and the
  terminal membership re-check `[CODE-CITED]` `actuator/adapter_rotate.go:314-320`.
- **Brain-explainability reader** — see T1; the decision-trace parser (§2.5 / §4). Every decline is
  a machine class that routes a *different* actuator back next round, and the brain is quoted
  exactly (metric-rule 4, §3.3).

### 1.3 Roster governance

- **Completeness is enforced by the build, not by a reviewer.** Every generatable action must have a
  registered native handler, no orphan hands, canonical order stable, and the *real* feasibility laws
  return the expected verdict family for every action `[CODE-CITED]` `actuator/completeness_test.go:1-28,41-60`.
  The honest limit of that invariant is stated in-source: it proves dispatchability and bounded
  verdicts, **not** that a handler mutates a cluster correctly — "a handler that returns success while
  doing nothing still satisfies the registration tier" `[CODE-CITED]` `actuator/completeness_test.go:14-20`.
  This is exactly why §2.3 (capability-gone probe) and §2.5 (battery) exist: registration is not proof
  of defense.

---

## 2. The "actuator works" gate — an ordered deterministic pipeline

Each stage is a hard GATE. A failure at any stage ends the evaluation for that actuator against that
attack with a tagged reason; the actuator is **REJECTED / CANNOT-HELP**, never "ranked low" (§3).
Stages run on an **isolated twin** so production state and operational counters are untouched —
shadow evaluation "must read production knowledge and cost state, compute its hypothetical decision,
and leave production state and operational counters untouched" `[CODE-CITED]`
`decision/m163_shadow_isolation_test.go:1-4`, and co-resident tenants are byte-isolated
(delta == 0) `[CODE-CITED]` `decision/vcluster_isolation_test.go:1-7`. The twin entrypoint is
`DecideShadowChecked` `[CODE-CITED]` `decision/coverage.go:752`; the shadow builds a per-view local
copy so the hypothetical action set is generated from hypothetical evidence without writing the
runner's view `[CODE-CITED]` `decision/coverage.go:634-665`.

> Ordering note `[INFERRED]`: the brain fuses capability + feasibility + conformal-SLO *into*
> selection within one tick (an infeasible or gated action is never a selectable candidate), so in
> the live engine Stage 1 (select) already implies Stages 2 and 4a. The validator still evaluates
> them as *separate named gates* for auditing and for routing a decline back to the proposer (§4).
> Stages 3 (capability-gone probe) and 4b (ledger hold) are genuinely post-dispatch and are not
> performed inline by the engine.

### Stage 0 (pre-gate) — capability / no-cover admission

Before scoring, the T1-E capability gate runs cheapest-first, first-failure-wins, exactly one
reason per excluded action: `1 not-installable → 2 no-cover → 3 capability-unsupported →
4 no-rbac` `[CODE-CITED]` `capability/gate.go:15-19,32-37`. The decisive class for the honest
CANNOT-HELP set is **no-cover**: "An action with no row content is coverless in every fixture and is
excluded by the capability gate's `no-cover` step before scoring" `[DOC-CITED]`
`docs/recon-cover-map.generated.md:63`. This is **the endpoint-rotate NO-OP the brain refuses**:
`endpoint-rotate` is generatable yet "— (coverless in every fixture)" `[DOC-CITED]`
`docs/recon-cover-map.generated.md:76`, the route exclusion reads "recon-cover: action invalidates
no facts for this asset" with `FeasibilityEvaluated=false, CostEvaluated=false` `[CODE-CITED]`
`capability/m044_route_claim_test.go:74-75`, and a negative control proves it never steals another
actuator's credit: "endpoint-rotate gained credential invalidation credit" is a test *failure*
`[CODE-CITED]` `actionset/endpoint_lease_test.go:43`. The companion coverless set the brain likewise
refuses: `route-rotate`, `guardrail-rotate`, `debugger`, `custom-inject`, `identity-rotate`
`[DOC-CITED]` `docs/recon-cover-map.generated.md:69-72,80`.

### Stage 1 — the brain SELECTS it (on the twin)

`CoverageEngine.Decide` runs the bounded-greedy selection `[CODE-CITED]` `decision/coverage.go:735-742`.
A candidate wins only with **strict positive gain** — `strictPositiveGain(gain) = gain > 0`, "no
epsilon and equality does not pass" `[CODE-CITED]` `decision/coverage.go:557-559` — where
`objectiveGain = marginal*provenance - costCoefficient*expectedCost` `[CODE-CITED]`
`decision/coverage.go:565-567`. When a confirmed attack raises a qualified existential obligation,
selection additionally requires **containment**: every `RequiredKey` of the obligation must be in the
candidate's `CoverKeys`, else `Contains=false` with `no-sound-cover` / `MissingKeys` `[CODE-CITED]`
`decision/existential.go:99-112`, and the decision resolves `selected` vs `uncontainable`
`[CODE-CITED]` `decision/existential.go:154-162`. A coverless actuator (Stage 0) therefore can never
contain — it is structurally incapable of being SELECTED, which is the deterministic restatement of
"the brain refuses the endpoint-rotate no-op." PASS = decision trace `SelectedAction == this action`
and `Result == "selected"`.

### Stage 2 — feasibility law ACCEPTS it

`feasibility.Evaluate` runs ALL registered constraints in deterministic order and returns the FIRST
veto; a noop short-circuits to feasible `[CODE-CITED]` `feasibility/constraint.go:56-69`. It is
**fail-closed**: a panicking law vetoes the move rather than crashing the tick — "uncertainty must
never become actuation" `[CODE-CITED]` `feasibility/constraint.go:44-54`. The registered laws the
validator must see a PASS from:

- `availability-floor` — `readyReplicas-1 ≥ MinAvailableReplicas` for replica-removing moves
  (rotate/quarantine), plus PDB observation/overlap handling `[CODE-CITED]` `feasibility/defaults.go:44-78`;
  the removing-vs-nonremoving predicate is shared with SLO via `RemovesReadyReplica` `[CODE-CITED]`
  `feasibility/defaults.go:31-37`.
- `slo-headroom` — vetoes a move on a pod already at/over the p99 ceiling `[CODE-CITED]`
  `feasibility/defaults.go:82-97`.
- `anti-over-rotation` — forensic/evidence-retention window, per-action exposure clock, fail-OPEN
  only on an unclocked-but-mapped variable `[CODE-CITED]` `feasibility/defaults.go:102-167`.
- `stateful-integrity` — rotate (Delete) on a stateful pod is infeasible; quarantine is fine
  `[CODE-CITED]` `feasibility/defaults.go:193-202`.
- `native-rotation-owner` `[CODE-CITED]` `feasibility/defaults.go:211-228`;
  `ai-context-required`, `mig-device-required`, `code-exec-guard` `[CODE-CITED]`
  `feasibility/actions_native.go:32-69,73-85,109-121`.

PASS = `Evaluate(...).Feasible == true`. The brain exercises these laws against the *real* registry
under a fixed fixture battery `[CODE-CITED]` `actuator/completeness_test.go:265-338`.

### Stage 3 — deterministic probe: attacker capability is GONE

This is the stage registration cannot fake (§1.3). The handler performs a deterministic readback
against the serving/runtime surface and credits mitigation **only** when the capability is observably
absent. Canonical example — adapter eviction: the pre-dispatch probe `AdapterLoaded` returning absent
credits NO new mitigation (`NoEffectSatisfied`: "inventory confirms adapter already absent")
`[CODE-CITED]` `actuator/adapter_rotate.go:404-410`; convergence to `loaded=false` is awaited
`[CODE-CITED]` `actuator/adapter_rotate.go:62-82`; and the terminal membership re-check fails the
operation if membership drifts back `[CODE-CITED]` `actuator/adapter_rotate.go:314-320`. The
disposition vocabulary that encodes "gone vs refused vs reconciled vs already-satisfied" without
string-sniffing is `NoEffectDisposition` `[CODE-CITED]` `actuator/actuator.go:43-51`, and a positively
established pre-mutation refusal is `NoEffectRefusal` `[CODE-CITED]` `actuator/actuator.go:30-36`.
PASS = probe observes the capability absent with a clean (non-refused) disposition. On `kind`/no-GPU
twins the stack is UNREACHABLE and the handler records that honestly — never fakes a GPU effect
`[CODE-CITED]` `actuator/handlers_ai.go:1-11` — which is a Stage-3 **UNVERIFIED**, not a pass.

### Stage 4 — availability SLO HOLDS (incl. co-tenants)

Two deterministic halves, plus co-tenant isolation: availability must hold for **every affected
workload including co-tenants** — exact-zero co-tenant isolation (co-tenant byte streams unchanged)
`[CODE-CITED]` `decision/vcluster_isolation_test.go:1-107` (docx §7.1 Stage 4, §8.1 G2).

- **4a — bound proof (pre-dispatch).** The action's availability impact is classified
  `StatusZero | StatusBounded | StatusUnknown`; "Unknown must never be serialized as a numeric zero"
  `[CODE-CITED]` `slo/bound.go:28-31`. `AvailabilityFor` returns `Zero` when declared max replica loss
  preserves `minAvailableReplicas`, `Bounded` with a finite breach window, else `Unknown`
  `[CODE-CITED]` `slo/bound.go:199-215`; the per-contract derivation requires an enforced,
  stop-at-deadline, safe-return-verified path inventory `[CODE-CITED]` `slo/contract.go:130-187,192-233`.
  Every live serving action is currently `Unknown` with a stated missing-proof reason `[CODE-CITED]`
  `slo/bound.go:94-141` — an honest UNVERIFIED for Stage 4a until each contract is bounded. In the
  engine this surfaces as the conformal-SLO gate: a generated candidate "passed the conformal SLO
  gate" (`SLOGateResult=true`) `[CODE-CITED]` `decision/coverage.go:1612-1613`; a rejected one records
  `SLOGateResult=false` / `exclusionKind=slo-gate` `[CODE-CITED]` `decision/coverage.go:1667-1670`.
- **4b — ledger hold (post-dispatch).** Phorvex-caused disruption is recorded and the in-window
  consumption totalled per tenant, with censored/overlap accounting and an explicit measured-vs-
  unmeasured split so unknown is never counted as zero `[CODE-CITED]` `slo/ledger.go:57-110,174-216,294-322`.
  The ledger is honestly in-memory/process-scoped (two-hour Prometheus retention, no PV) `[CODE-CITED]`
  `slo/ledger.go:149-169`. PASS = the realized breach seconds keep the tenant within its SLO window,
  bound is `Zero`/`Bounded` (never `Unknown`-as-zero), and co-tenants are unchanged (exact-zero).

### Stage 5 — reproduced across the scenario battery (with per-iteration explainability parse)

The verdict must hold on **every** archetype fixture in the battery, with the brain's explainability
parsed each iteration; **one failing scenario fails the actuator** (docx §7.1 Stage 5). Grounding
batteries already in-tree: the recon cover-map fixture battery (plain / stateful / neighbors / gpu* /
sensitive-output / vector-* …) `[DOC-CITED]` `docs/recon-cover-map.generated.md:32-59`; the v3
decision-trace battery (action-status completeness, SLO-gate reject, NaN fail-closed, reactive-only
honesty, trace on/off selection equivalence) `[CODE-CITED]`
`decision/decision_trace_v3_test.go:32-71,207-238,242-263,267-300,346-369`; and the adversarial
disjointness guard proving covers never collide under a hostile topology `[CODE-CITED]`
`decision/disjointness_guard_test.go:67-92`. Each iteration, the explainability reader (§4) parses
WHY; a decline routes a *different* actuator back to the proposer (next round, §2A). PASS = all
battery scenarios pass and every trace reason is a selected/pass reason.

---

## 2A. How the validator participates in the adversarial competition (docx §3)

The validator does not run once. Generator and validator compete over **rounds** on the isolated
twin, and the attacker must come back and beat the defender that just won `[DOC-CITED docx §3]`.

**One round** `[DOC-CITED docx §3.1]`:
1. **Attack agents propose** HYPOTHESIZED fragments (WS-2) — from round 2, against the *winning
   actuator set* already in place.
2. **Deterministic gate confirms real** (WS-2, checks C1–C6); unconfirmed → quarantined.
3. **Actuator agents propose.** For each REAL attack, this roster (§1) proposes candidate actuators.
4. **The real brain decides** on the twin (`DecideShadowChecked`): an actuator wins only if the
   brain SELECTS it AND feasibility ACCEPTS it AND the deterministic probe confirms the attacker
   capability is GONE AND availability HOLDS for every affected workload including co-tenants —
   i.e. it clears the Stage 0–5 pipeline (§2) and gates G1–G3 (§3).
5. **Store the proven triple** — the winning (attack, actuator, brain-verdict), with the brain's
   explanation quoted exactly and the seven-metric scorecard (§3) attached, is appended to the
   per-customer RL record, shadow only (WS-6).
6. **Next round: re-attack the winners.** The winning actuators join the twin's defended state;
   the attack agents search for a new real path around them.

**How WS-3 participates.**
- **Validators re-prove every round.** Each round's REAL attack is evaluated afresh against the
  twin's current defended state; nothing is carried forward as "already proven" for a new attack
  `[INFERRED from docx §3.1]`.
- **A decline routes a different actuator next round.** The explainability reader (§4) turns each
  decline into its closed machine class (no-cover, MissingKeys, slo-gate, feasibility veto, …) and
  feeds it back as the decline memo, so the proposers return a *different* actuator next round
  (docx §9.1, §13 explainability-reader verdict; WS-4).

**Termination** `[DOC-CITED docx §3.2]`: **STABLE** — a full attack round against the current
winning set yields no deterministically-confirmed attack that gets through; **CANNOT-HELP** — for
the latest confirmed attack no actuator is selected-and-confirmed without breaking availability or
the brain; **not stabilised within budget** — the configurable max-rounds budget (docx §14, P2) is
reached, reported honestly, never as a false win.

**Round ledger** `[DOC-CITED docx §3.3]`. Each WIN row quotes the brain's explanation verbatim and
carries the seven-metric scorecard (§3); the ledger also records STABLE / CANNOT-HELP outcomes per
round. The ledger shape is given in WS-2 §0.1 and docx §3.3.

---

## 3. The actuator verdict — seven measured metrics (docx §8)

> **Rev 4 change.** The earlier five-axis rubric (defense strength / availability safety / brain-fit
> / attack-graph coverage / cost vs rotation baseline) is **replaced** by the docx §8 seven-metric
> verdict below. **Continuity note** (docx §8.4): "brain-fit / no structural change" is now a
> **global design invariant** (docx §2, rail 1) rather than a per-actuator axis, and "attack-graph
> coverage" is captured by the round-by-round edges-cut record (round ledger, §2A / docx §3.3) and
> durability (S3). The per-attack output is unchanged in spirit: the ranked actuators, each with the
> seven-metric scorecard and the brain's quoted explanation, plus the honest CANNOT-HELP set.

Every actuator the brain selects in a round is scored on **seven metrics, computed OUTSIDE the
brain** (the brain is unchanged): **three gates and four scores**. The gates decide admissibility;
the scores order the admissible actuators and feed the RL record. All measured, never estimated.
`[DOC-CITED docx §8]`

### 3.1 The three gates (binary; any fail ⇒ CANNOT-HELP, never a low rank)

| Gate | | PASS condition (measured on the twin) |
|---|---|---|
| **G1** | Defense effect confirmed | The attacker capability is observably GONE — the Stage-3 deterministic probe passes AND the post-actuation reachability edge is removed `[CODE-CITED]` `actuator/adapter_rotate.go:314-320,404-410`, `graph/reachability.go:144-165` |
| **G2** | Availability holds for all affected workloads incl. co-tenants | feasibility `availability-floor` + `slo-headroom` PASS; `slo.Bound` `Zero/Bounded` + ledger hold; co-tenant byte streams unchanged (exact-zero) `[CODE-CITED]` `feasibility/defaults.go:44-97`, `slo/bound.go:199-215`, `slo/ledger.go:294-322`, `decision/vcluster_isolation_test.go:1-107` |
| **G3** | No selection on a clean no-attack control run | Replayed against a no-attack control twin, the brain does NOT select this actuator — proving it is a response to the attack, not an always-on move `[INFERRED from DecideShadowChecked on a control snapshot, decision/coverage.go:746-754]` |

An actuator failing **any** gate is placed in the **CANNOT-HELP** set with its tagged reason. It is
*never* assigned a low numeric rank, because a low rank would imply "usable if nothing better
exists" — false for a gate failure. A gate whose value cannot be measured is `unknown`, and an
`unknown` gate **blocks** (rule 2, §3.3).

**Canonical CANNOT-HELP (docx §7.2).** `endpoint-rotate` never even reaches G1: it is coverless,
excluded at the Stage-0 no-cover gate before scoring, and so can never be SELECTED (Stage 1) — the
deterministic restatement of "the brain refuses the no-op" `[DOC-CITED]`
`docs/recon-cover-map.generated.md:63,76`; `[CODE-CITED]` `capability/m044_route_claim_test.go:74-75`,
`actionset/endpoint_lease_test.go:43`. It is the canonical CANNOT-HELP entry, never ranked low.

### 3.2 The four scores (measured, never estimated; `unknown` if unmeasurable)

| Score | | What is measured | Source |
|---|---|---|---|
| **S1** | Time-to-contain / dwell (**PRIMARY**) | measured time from attack onset to capability-gone on the twin | twin clock deltas on the probe transition `[CODE-CITED]` `actuator/adapter_rotate.go:62-82` |
| **S2** | Collateral | measured impact on non-target workloads (replicas disrupted beyond the target) | SLO ledger per-workload disruption `[CODE-CITED]` `slo/ledger.go:57-110` |
| **S3** | Durability over a hold window | does containment hold when re-probed over a configurable hold window (docx §14, P6) | repeated Stage-3 probe over the window `[CODE-CITED]` `actuator/adapter_rotate.go:314-320` |
| **S4** | Measured vs predicted cost | actual cost on the twin vs the brain's predicted `ExpectedCost` (and vs the rotation baseline it replaces, recorded for the RL record) | trace `ExpectedCost` vs measured `[CODE-CITED]` `model/decision_trace.go:435-437`; switching-cost `K(i→j)` `[CODE-CITED]` `cost/model.go:5-26` |

### 3.3 The four rules for all seven metrics `[DOC-CITED docx §8.3]`

1. **A metric can only fail an actuator, never pass one the brain did not select.** Brain selection
   is a precondition; metrics are strictly subtractive. A metric never promotes an action the brain
   excluded.
2. **A metric that cannot be measured is `unknown`, never zero or pass.** Mirrors the engine's own
   rule — "Unknown must never be serialized as a numeric zero" `[CODE-CITED]` `slo/bound.go:28-31`.
   An `unknown` gate blocks; an `unknown` score is carried as unknown, not a win.
3. **Metrics reach the brain only through the RL record as shadow proposals with human approval —
   never directly.** No metric is wired into `Decide`; the brain is unchanged. Promotion is the
   human Approve gate (`AutoEscalate()==false`) `[CODE-CITED]` `redteam/cotrain.go:20-52` (WS-6).
4. **The brain's explanation is quoted exactly, never rewritten by an agent.** The verdict carries
   verbatim trace fields — `SelectedAction`, `Result`, `SelectionReason`, `ExclusionKind`,
   `SLOGateResult`, `NoopReason` `[CODE-CITED]` `decision/coverage.go:1700-1718`.

### 3.4 Ranking rule (among actuators passing all three gates)

Order by, in strict precedence (ties fall through to the next key) `[DOC-CITED docx §8.4]`:

1. **S1 dwell / time-to-contain** — shorter first. **Primary key, fixed** by founder directive
   (docx §14.1).
2. **S3 durability** over the hold window.
3. **S2 collateral** — less collateral first.
4. **S4 measured-vs-predicted cost.**
5. **Tie-break: actuator id** — the canonical `MutatingActions` order `[DOC-CITED]`
   `docs/recon-cover-map.generated.md:26`, matching the trace's canonical action-status ordering
   `[CODE-CITED]` `decision/decision_trace_v3_test.go:41-48`.

The secondary precedence (keys 2–4) is a configurable parameter (docx §14, P6); the primary key
(dwell) is fixed.

### 3.5 Build order `[DOC-CITED docx §8.4, §15.2]`

- **Phase 1 — the three gates (G1, G2, G3) + dwell time (S1).** The minimum viable verdict: an
  actuator is admissible and we know how fast it contains.
- **Phase 2 — collateral (S2), durability (S3), and measured-vs-predicted cost (S4).** These refine
  ordering and enrich the RL record.

### 3.6 Per-confirmed-attack output (the deliverable the validator emits)

For each confirmed attack (per round):

1. **Ranked actuators** — the passed-all-gates set, ordered by §3.4.
2. **Seven-metric scorecard** — one row per candidate actuator:

   | Actuator | G1 effect confirmed | G2 availability incl. co-tenants | G3 clean control | S1 dwell | S2 collateral | S3 durability | S4 cost meas. vs pred. | Verdict |
   |---|---|---|---|---|---|---|---|---|
   | … | PASS/FAIL/unknown | PASS/FAIL/unknown | PASS/FAIL/unknown | measured / unknown | measured / unknown | measured / unknown | measured / unknown | RANK k / CANNOT-HELP |

3. **Brain's quoted explainability** — verbatim trace fields (rule 4, never paraphrased):
   `SelectedAction`, `Result` (`selected`/`uncontainable`), per-action `SelectionReason`,
   `ExclusionKind`, `SLOGateResult`, and `NoopReason` when the tick degraded to noop (e.g.
   `"priced-out: no net-positive feasible move"`, `"budget-exhausted"`, `"not selected by current
   greedy round"`, `"reactive-only: no direct foothold"`) `[CODE-CITED]` `decision/coverage.go:1700-1718`.
4. **Honest CANNOT-HELP set** — every actuator that failed (or could not measure) a gate, with its
   tagged reason and `file:line` (coverless no-cover, infeasible veto, SLO-Unknown, co-tenant
   breach, selected on the clean control run).

---

## 4. Brain-explainability reader — what it parses every round

The decision trace is the ground truth, and it is a **complete, validated** record: exactly one row
per canonical mutating action, in canonical order, unique, with `Validate()` rejecting a malformed
record `[CODE-CITED]` `decision/decision_trace_v3_test.go:32-71,388-416`. Every round (and every
battery iteration) the reader extracts, and the verdict quotes verbatim (rule 4, §3.3):

- **WHY selected** — `row.Status == selected`, `ExclusionKind == none`, `SelectionReason ==
  selected_full_containment` `[CODE-CITED]` `decision/existential.go:238-245`.
- **WHY declined** — the exact cause, each a distinct machine class:
  - `no-cover` / coverless → propose a covering actuator instead `[DOC-CITED]`
    `docs/recon-cover-map.generated.md:63`; `[CODE-CITED]` `capability/m044_route_claim_test.go:74-75`.
  - `existential_no_full_cover` / `no-sound-cover` + `MissingKeys` → propose an actuator covering the
    missing keys `[CODE-CITED]` `decision/existential.go:99-112`.
  - `slo-gate` (`SLOGateResult=false`) → propose a gentler, in-process actuator `[CODE-CITED]`
    `decision/coverage.go:1667-1670`, `decision/decision_trace_v3_test.go:267-300`.
  - `cost-nan` → data-quality fail-closed, distinct from a real exclusion `[CODE-CITED]`
    `decision/decision_trace_v3_test.go:207-238`.
  - `reactive-only` → no foothold; suppress proactive move `[CODE-CITED]`
    `decision/decision_trace_v3_test.go:242-263`.
  - feasibility veto reason string (availability / slo-headroom / anti-over-rotation / stateful /
    ai-context / code-exec) `[CODE-CITED]` `feasibility/defaults.go:44-202`,
    `feasibility/actions_native.go:32-121`.

A decline is never an end-state: the reader returns the machine reason to the proposer (T2) as the
next round's *decline memo* (WS-4 / docx §9.1), which proposes a **different** actuator next round,
re-entering Stage 1 on the twin (§2A). Trace-on vs trace-off
is selection-equivalent, so reading the trace never perturbs the verdict `[CODE-CITED]`
`decision/decision_trace_v3_test.go:346-369`.

---

## 5. Worked CANNOT-HELP exemplar (illustrative, grounded)

Confirmed attack: suspect LoRA adapter on a GPU-served pod (fixture `gpu-adapter`, trusted UID-bound
detector event) `[DOC-CITED]` `docs/recon-cover-map.generated.md:50`.

- `adapter-rotate` → covers `adapterIntegrity` (the only actuator that does) `[DOC-CITED]`
  `docs/recon-cover-map.generated.md:78`; Stage 3 probe `AdapterLoaded` proves the adapter gone
  `[CODE-CITED]` `actuator/adapter_rotate.go:404-410,314-320` (G1). → **admissible if G1–G3 all pass
  on the twin**; its rank then follows from the measured S1–S4 (§3.4), not asserted here.
- `endpoint-rotate` → coverless; excluded at Stage 0 (no-cover) and cannot be SELECTED (Stage 1) →
  **CANNOT-HELP** (canonical, docx §7.2) `[DOC-CITED]` `docs/recon-cover-map.generated.md:76`;
  `[CODE-CITED]` `capability/m044_route_claim_test.go:74-75`.
- `rotate` → high-blast-radius Delete; may pass G2 only with headroom; if admissible, its order
  relative to adapter-rotate follows from the measured S1–S4 (§3.4); on a single-replica stateful
  serving pod it is vetoed by `stateful-integrity` → CANNOT-HELP for that asset `[CODE-CITED]`
  `feasibility/defaults.go:193-202`.

(Measured dwell, collateral, durability, cost and the final ranked order come from the twin run —
measured, never estimated; `unknown` if unmeasurable.)

---


## 2B. Actuator design by agents — when the enabled set is exhausted (docx §3.4, §7.3)

Sections 1–2A prove actuators that **already exist**. When every enabled actuator returns
**CANNOT-HELP** for a confirmed attack (brain never SELECTs one without breaking availability),
the loop opens a **design round** — the synthesis arm the original objective asked for (a new
actuator that provably defends each attack), not a pick from a fixed list.

- **Who proposes.** Design agents, one persona per **enforcement level**, sized from the scan
  exactly as the validator roster is (WS-1): network / dataplane (CNI, eBPF, drop of *established*
  flows, not only deny of new ones), K8s platform, AI/GPU serving, credential, process, artifact.
  Each proposes a NEW actuator spec at the **lowest enforcement level** that would truly remove the
  attacker capability the CANNOT-HELP attack exploits. `[DOC-CITED docx §3.4]`
- **How they agree.** The §9 deliberation protocol runs over the specs: proposers emit, critics
  predict the gate each would fail (no-cover / infeasible / SLO / not-installable), the deterministic
  aggregator ranks, and an evidence-bearing minority spec is always kept. Agreement sets the order
  engineers see; it never approves. `[DOC-CITED docx §9, §3.4]`
- **What a spec must contain (Actuator Capability Contract).** the capability removed, the exact
  cover keys it may claim, the enforcement mechanism, required RBAC, the per-cluster capability check,
  the **deterministic effect-confirmation probe** (how the loop will later prove the capability is
  gone — the Stage-3 analogue), availability impact + rollback, and the determinism statement. A spec
  that cannot name its confirmation probe is **rejected, not ranked low**. `[DOC-CITED docx §3.4]`
- **What agents do NOT do.** They never write, compile or deploy actuator code, and never touch the
  brain. Output is a ranked spec list for the AI and platform engineers. No LLM in the decision path.
- **Closing the loop.** Once engineers build a spec and register it behind the existing `Actuator`
  interface `[CODE-CITED actuator/actuator.go:226-244]`, it is an ordinary enabled actuator: it
  re-enters the competition (§2A), is re-attacked, and must clear the seven-metric verdict (§3) like
  any other. The design round **widens the actuator set, it never lowers the bar**.

---
## 6. What is proven vs. what is deferred (honesty ledger)

- `[CODE-CITED]` — the interface, the four-class capability gate, the no-cover/coverless refusal, the
  feasibility laws + fail-closed semantics, the strict-positive-gain + containment selection, the
  SLO bound proof + ledger, the capability-gone adapter probe, the twin/shadow isolation, the
  complete validated decision trace, and the completeness invariant (with its own stated limits).
- `[INFERRED]` — the *ordering* of the validator's Stage 0–5 gate as a standalone pipeline (the live
  engine fuses capability+feasibility+SLO into selection; §2 ordering note). The persona→code
  mapping in §1.2. G3 (clean no-attack control run) as a `DecideShadowChecked` replay on a control
  snapshot.
- `[UNVERIFIED]` — every live serving action's Stage-4a availability bound is currently
  `StatusUnknown` with a stated missing-proof reason `[CODE-CITED]` `slo/bound.go:94-141`; the
  capability-gone probe is honestly unreachable on non-GPU twins `[CODE-CITED]`
  `actuator/handlers_ai.go:1-11`; the ledger is process-scoped `[CODE-CITED]` `slo/ledger.go:149-169`.
  These are declared UNVERIFIED, never silently passed (P-08) `[CODE-CITED]` `actuator/actuator.go:241-243`.
  Under metric-rule 2 the corresponding gate value is `unknown`, and an `unknown` gate **blocks**
  (G1/G2 → CANNOT-HELP), never a pass.
- **All numbers** — metric values are **measured on the twin** (never estimated); thresholds (hold
  window, secondary ranking precedence, max-rounds budget) are **configurable parameters (docx
  §14, P2/P6)**; this document fixes only their sources.

**Open questions: none.** Every gate, metric, ordering rule, tie-break, and output artifact is bound
to a code citation, to the docx (§3, §7, §8), or to a configurable parameter (docx §14); unverified
bounds are labelled UNVERIFIED.
