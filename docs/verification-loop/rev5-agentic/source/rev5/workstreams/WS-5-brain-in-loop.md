Workstream input. The architecture docx (Rev 4) is the source of truth.

# WS-5 — Brain-in-the-Loop Harness & Determinism

**Workstream:** Verification loop · **Mode:** READ-ONLY design · **Repo:** `/home/hami/mostafa/operator`
**Scope:** Design the isolated-twin harness on which attacks are replayed, the brain-explainability read
contract, the deterministic replayable verdict, and the proof that the brain stays read-only in the loop.

Claim tags: **[CODE-CITED]** grounded at a code `file:line` (given inline or in the adjacent column);
**[DOC-CITED]** grounded in a doc, report, markdown file or paper (incl. the architecture docx);
**[INFERRED]** composed from cited primitives; **[UNVERIFIED]** asserted without a direct citation. Every design decision below is anchored to a cited
primitive that already exists in the tree.

---

## 0. The three hard constraints and where the code already enforces them

| Constraint | Enforcing primitive | Cite |
|---|---|---|
| Brain is deterministic and NOT modified; never tuned during the loop | `EvalShadow` reads existing state and writes none of it; `Commits()` gates every write site; `mode.Commits()==false` for shadow | `phorvex/internal/killchain/evalmode.go:16-41`, `phorvex/internal/decision/coverage.go:746-754` **[CODE-CITED]** |
| No live brain writes (loop replays are counterfactual) | Shadow prices from a **transient, never-registered** cost bucket: no seed consumed, no `BucketMeta` minted, `creationEvent` does not move; `DualUpdate.Applied=false` | `phorvex/internal/decision/coverage.go:435-465`, `phorvex/internal/decision/decision_trace_test.go:257-259` **[CODE-CITED]** |
| No attack ever runs on production (live cluster is read-only scan) | Attacks are replayed against a provisioned twin (§1); the live cluster contributes only observed **facts** that feed `WorkloadView`/`Policy` inputs | §1 **[INFERRED]** from input-only `Decide` signature `coverage.go:735-754` |
| Deterministic, replayable verdicts | Injectable clock `e.Now`; content-addressed SHA-256 `DecisionID`/`TickID`; byte-stable canonical serialization; `Validate()` reconstruction laws; shipped-JSONL replay harness | §3, `coverage.go:1215-1222`, `model/decision_trace.go:884`, `audit/schema_replay_test.go:66-137` **[CODE-CITED]** |

The decisive fact for the whole workstream: `CoverageEngine.Decide`/`DecideChecked`/`DecideShadowChecked`
take **only** `([]*model.WorkloadView, model.Policy)` and return `[]model.Decision` — the brain is a pure
function of its input snapshot plus the owner-scoped learned state it is allowed to read
(`coverage.go:735-754` **[CODE-CITED]**). Everything the loop needs to make a verdict transfer from the twin
to production is therefore reducible to *reproducing those inputs*.

---

## 1. Isolated-twin provisioning / teardown contract

### 1.1 Why a twin, and why byte-exact isolation is already a tested property

The engine already ships adversarial-isolation proofs that are stronger than "bounded": two tenants
**co-resident in one engine** produce **byte-identical** decision streams with and without an adversary's
decoy-flood / λ-pump activity — the delta is asserted `== 0`, not merely bounded
(`phorvex/internal/decision/vcluster_isolation_test.go:1-107`, `TestO2_LambdaNonInfluenceExactZero`
and `TestO4_RLSConformalNonInfluenceExactZero` **[CODE-CITED]**). This is the formal basis for running the
attack in an isolated owner/tenant scope: the twin is a **distinct owner key** whose learned state cannot
perturb — and is not perturbed by — any production owner (`costFor` builds an "isolated per-owner bucket,
zero cross-feed", `coverage.go:383-419` **[CODE-CITED]**).

### 1.2 Provisioning contract (per competition — one twin spans all rounds)

A twin is provisioned **per competition** and **spans all rounds** of that competition (docx §10.1),
then torn down after. Provisioning materializes the four input families the brain reads, from the
live read-only scan plus the attack scripts. **[INFERRED]** from the
`Decide` input structs:

1. **Workload snapshot** — one `*model.WorkloadView` per asset: `Pod` identity (`Namespace`, `Name`,
   `UID`, `Node`, `StartedAt`, the epoch fields), `Phase`, `ReadyReplicas`/`DesiredReplicas`, `BlastRadius`,
   `ExposureByVariable` fingerprint clocks, `Telemetry`, `Physics`, `OutcomeEvents`
   (`vcluster_isolation_test.go:33-47`, `m030_replay_test.go:27-57` show the exact construction **[CODE-CITED]**).
2. **Policy** — `PolicyUID`, `Tenant`, `Namespace`, `PolicyName`, `EnabledActions`, `MaxMovesPerTick`
   (budget), `Lambda` seed, `CostCeiling`, `BrainImage`, `GitSHA`, `TraceEnabled=true`
   (`decision_trace_test.go:16-26` is the canonical policy fixture **[CODE-CITED]**). The twin runs under its
   **own** `Tenant`/owner so §1.1 isolation applies.
3. **Clock** — a frozen `e.Now = func() time.Time { return <fixed> }` (`decision_trace_test.go:28-32`,
   `m030_replay_test.go:24-26` **[CODE-CITED]**). The run records the frozen instant as the replay seed (§3).
4. **Capability / RBAC witness** — the twin wires the **read-only** `ShadowCapability` gate (answers from
   already-observed state: no SelfSubjectAccessReview, no cache write, no timestamp refresh), never the
   production `Capability` (which writes the shared authorization cache)
   (`coverage.go:79-98` **[CODE-CITED]**).

Each round, attack injection (and the winning actuators that join the twin's defended state, docx §3.1)
mutates **only** twin `WorkloadView`/`OutcomeEvents`/`Telemetry`/`Physics` — the same
surface the fixtures mutate to stage NaN telemetry, EPSS hits, decoy floods, GPU cold-starts
(`decision_trace_v3_test.go:207-209`, `epss_trace_present_test.go:21-30`,
`vcluster_isolation_test.go:33-47` **[CODE-CITED]**). The adapter/actuation path on the twin authenticates
against twin-local `SecurityEvent` objects with a freshness horizon and creator allowlist, so a replayed
attack cannot forge a production detector event (`actuator/adapter_evidence.go:41-93` **[CODE-CITED]**).

### 1.2a The clean control run (G3)

The same twin is replayed **with the attack removed**; the brain must **NOT** select the candidate
actuator — a no-attack false-positive guard proving the actuator is a response to the attack, not an
always-on move (docx §10.1, §8.1 G3). It uses the same `DecideShadowChecked` path on a no-attack
control snapshot. **[INFERRED]** from `coverage.go:746-754` (per docx §8.1).

### 1.3 Teardown contract

After the competition: discard the twin engine (`NewCoverageEngine()` is a fresh instance per run —
`vcluster_isolation_test.go:60-61`, `m030_replay_test.go:19` **[CODE-CITED]**) and all twin owner buckets.
Because the loop evaluated with `DecideShadowChecked`, **no production owner state was ever touched** even
had the twin shared an engine: shadow seeds no owner, moves no dual price, teaches no conjugate memory,
stamps no view, increments no counter (`coverage.go:746-754` **[CODE-CITED]**). Teardown therefore has no
production-state obligations to reverse; it only frees the transient objects. **[INFERRED]**

### 1.4 Twin-fidelity requirement (a verdict must transfer)

A verdict computed on the twin transfers to production **iff** the twin reproduces every brain-read fact
that the decision trace records as an input. Fidelity is **checkable from the trace itself**, not asserted:
re-run the identical `WorkloadView`/`Policy`/clock and the two traces must be byte-identical after
`Canonical()` — exactly the property `m030_replay_test.go:66-78` proves across four ticks ("decisions
drift" is a hard failure) **[CODE-CITED]**. The fidelity surface is `DecisionModelInputsV2`
(`model/decision_trace.go:314-391` **[CODE-CITED]**): telemetry **presence** (a missing series must stay
absent, never a measured zero — `decision_trace_test.go:71-101`), physics/EPSS/CVSS presence
(`epss_trace_present_test.go:43-56`), the Little's-law flow basis and its five components
(`flow_trace_test.go:31-43`), SLO headroom, exposure clocks, and the asset identity tri
(`AssetUID`/`PolicyUID`/`TickID`, mandatory per `Validate` `model/decision_trace.go:993-998`).
**Fidelity rule:** if any trace input field reads `present:false` / `notAvailable` on the twin where
production observed it present (or vice-versa), the verdict does **not** transfer and the run is marked
*non-transferable* rather than pass/fail. **[INFERRED]** from the presence-honesty invariants above.

---

## 2. Brain-explainability read contract (concrete field list)

Each round the harness reads the following fields from `model.Decision.Trace` (`*model.DecisionTraceV2`) and
the per-asset `model.Decision`, and the verdict **quotes them verbatim — never rewritten by an agent**
(docx §8.3 rule 4, §10.2). The list is drawn from the real decision-trace tests; every row cites the
field's definition and the test that pins its meaning.

### 2.1 Was the actuator (action) selected?
- `trace.SelectedAction`, `trace.SelectedCandidateKey`, `trace.SelectionRound` — `model/decision_trace.go:595-597`; selected candidate must back-reference these `decision_trace_test.go:84-86` **[CODE-CITED]**
- `candidate.Selected` + per-action `trace.ActionStatus[i].Status == "selected"` with `ExclusionKind == "none"` — `model/decision_trace.go:444`, `:124`, `:220-231`; `decision_trace_v3_test.go:65-69` **[CODE-CITED]**
- One `ActionStatus` row **per canonical action in canonical order** (complete action accounting, including actions the model never considered) — `model/decision_trace.go:587-591`; completeness pinned `decision_trace_v3_test.go:32-71,304-343` **[CODE-CITED]**

### 2.2 Feasibility-accepted? If declined, why?
- `candidate.Feasible` (`OptionalBool`: distinguishes false from "not evaluated"), `candidate.ExistingExclusionReason` — `model/decision_trace.go:443`, `:474`; current-pod infeasible recorded `decision_trace_test.go:119-121` **[CODE-CITED]**
- `trace.ActionStatus[i].Status` ∈ closed vocab `{not-enabled, no-cover, infeasible, conformal-slo, priced-out, budget-exhausted, candidate, selected, not-evaluated-by-current-model, not-installable, ineligible}` — `model/decision_trace.go:116-128` **[CODE-CITED]**
- `trace.ActionStatus[i].ExclusionKind` ∈ closed vocab `{none, not-enabled, recon-cover, resource-capacity, feasibility, cost-nan, slo-gate, reactive-only, selection, not-installable, no-rbac, capability-unsupported, action-failure-cooldown, operator-opt-out}` — `model/decision_trace.go:133-150` **[CODE-CITED]**
- `trace.ActionStatus[i].Reason` (verbatim, redacted) and `.Scored` (did the greedy loop evaluate a marginal?) — `model/decision_trace.go:220-231`; reactive-only honesty (`scored=false`) `decision_trace_v3_test.go:259-261`; cost-NaN fails closed to `infeasible`+`cost-nan` `decision_trace_v3_test.go:220-228` **[CODE-CITED]**
- Fail-closed on the feasibility surface itself: a panicking law vetoes (`Feasible:false` with reason) — `feasibility/constraint.go:44-54`; first-veto wins `:59-69`; relaxable SLO laws separated from hard vetoes `:74-94` (`Verdict{Feasible, Reason}` `:24-28`) **[CODE-CITED]**

### 2.3 Coverage witnesses
- `candidate.MarginalCoverage`, `candidate.GrossFullValue`, `candidate.CoverKeys`, `candidate.Provenance`, `candidate.LambdaContribution`, `candidate.NetGain` — reconstruction law `NetGain = MarginalCoverage·Provenance − LambdaContribution` is re-derived in-test — `model/decision_trace.go:431-442`; `decision_trace_test.go:218-223,273-275` **[CODE-CITED]**
- `trace.Facts[].FinalWeight` / `.CoveredRound` / `.CoveredBeforeDecision` / `.CoveringActions`, `trace.EvaluationRound`, `trace.SelectionRound` — round semantics + marginal law (`marginal == Σ finalWeight` over not-covered-before keys) — `model/decision_trace.go:396-419`, `:580`, `:597`; `decision_trace_v3_test.go:78-147` **[CODE-CITED]**

### 2.4 Cost witnesses
- `candidate.ExpectedCost` (= `NormWeight·CNorm + FlowWeight·CFlow`), `candidate.CNorm`, `candidate.CFlow` — `model/decision_trace.go:435-437`, `:567-568`; reconstructed in-test `decision_trace_test.go:266-271` **[CODE-CITED]**
- `candidate.CostHigh` (CHi law: `ExpectedCost + (rotate ? max(ConformalQuantile, applied?GPUEnvelopeSlack:0) : 0)`), `candidate.ConformalQuantile`, `candidate.ConformalCalibrated`, `candidate.GPUEnvelopeApplied`, `candidate.GPUEnvelopeSlack` — `model/decision_trace.go:446-456`; CHi quad pinned `decision_trace_v3_test.go:151-201` **[CODE-CITED]**
- `trace.CostCeiling` (effective conformal-SLO ceiling), `trace.CostModelVersion`, `trace.EffectiveCostCoefficient`, `trace.CostRepresentationVersion`, `trace.CFlowUnitStatus`, `trace.SelectorComparator` — `model/decision_trace.go:564-579`; semantic identifiers required `decision_trace_test.go:252-256` **[CODE-CITED]**

### 2.5 SLO witnesses
- `candidate.SLOGateResult` (`OptionalBool`: present/true = generated past the gate; present/false = conformal-SLO exclusion; absent = excluded upstream of the gate) — `model/decision_trace.go:467-471`; gate-reject records `status=conformal-slo`, `exclusionKind=slo-gate`, `sloGateResult=false`, and the effective `trace.CostCeiling` `decision_trace_v3_test.go:267-299` **[CODE-CITED]**
- `trace.Inputs.SLOHeadroom`, `trace.Inputs.ProjectedNextStageSec`, `trace.Inputs.NextStage` — `model/decision_trace.go:388-390` **[CODE-CITED]**
- Underlying SLO contract (for twin-provisioning of the action-contract facts): `slo.Bound{Status ∈ zero|bounded|unknown, MaxUnavailableReplicas, MaxUnavailableDuration, MaxReplicaSeconds, Evidence, MissingBound}` — `slo/bound.go:22-49`; derived by `DeriveContract` / `AvailabilityFromContract` which return `unknown` on any incomplete path inventory — `slo/contract.go:130-233` **[CODE-CITED]**

### 2.6 Dispatch outcome (stamped by the runner after the actuation attempt, before the audit write)
- `trace.DispatchOutcome` ∈ `{not-attempted, emitted, emitted-false, dispatch-error, refused-no-effect, already-satisfied, reconciled-no-new-mutation, declared-only}`, `trace.DispatchReason` — `model/decision_trace.go:152-163`, `:591-593`; required non-empty `decision_trace_v3_test.go:339-341` **[CODE-CITED]**
- On the twin the dispatch is simulated; `DispatchOutcome` is the field that distinguishes a brain *selection* from an actual *actuation effect* (`model.Decision.Selected`/`.Feasible`/`.DryRun`/`.KillSwitch` separate the gates — `model/types.go:1339-1356` **[CODE-CITED]**).

### 2.7 Economics / read-only witness (direct read-only proof — see §4)
- `trace.DualUpdate.Applied` — **false under shadow**, true only in production — `decision_trace_test.go:257-259` (shadow) vs `:293-319` (production applies the dual move) **[CODE-CITED]**
- `trace.DualUpdate.{Demand,Spent,Budget,RawExcess,EffectiveExcess,LambdaBefore,LambdaAfter,UpdateReason}` — `model/decision_trace.go:496-508` **[CODE-CITED]**

### 2.8 Noop / honesty witnesses
- `trace.NoopReason`, `candidate.NotClassifiedByCurrentModel` — `model/decision_trace.go:599`, `:476`; honest noop/exclusion `decision_trace_test.go:104-124` **[CODE-CITED]**
- `trace.Existential` (`*ExistentialDecision`) + per-candidate `existential` (containment `Result`, `Contains`, `MissingKeys`, priority order) — `model/decision_trace.go:513`, `:425`; `existential.go:87-114,219-275` **[CODE-CITED]**

### 2.9 Validity gate (read every round)
- `trace.Validate()` — rejects wrong schema version, non-canonical `ActionStatus` order, non-finite cost/controller values, out-of-range λ, missing `BrainImage`/`GitSHA`/identities, missing `DispatchOutcome`, and runs the NetGain/CHi/marginal reconstruction laws — `model/decision_trace.go:884-998+`; negative half pinned `decision_trace_v3_test.go:388-416` **[CODE-CITED]**. **The loop treats a trace that fails `Validate()` as a loop-integrity error, not an attack verdict.** **[INFERRED]**

---

## 3. Deterministic, replayable verdict object

The verdict is a single serializable record per (round, tick, asset) of a competition run (docx §10.3). It embeds the canonical trace and the
replay seed, and is reproducible because every input is pinned and every identity is content-addressed.

```
BrainInLoopVerdict {
  // --- replay identity / seed ---
  runID            string   // twin run id (one per competition)
  round            int      // competition round (docx §10.3: per (round, tick, asset))
  replaySeedClock  string   // the frozen e.Now instant, RFC3339Nano           [coverage.go:1360]
  brainImage       string   // trace.BrainImage (binary pin)                    [decision_trace.go:519,993]
  gitSHA           string   // trace.GitSHA     (source pin)                    [decision_trace.go:520,993]
  inputsHash       string   // sha256 over the canonical WorkloadView+Policy snapshot  [INFERRED; method = coverage.go:1215-1222]

  // --- brain selection ---
  decisionID       string   // sha256(decision|tickID|podUID|assetKey)          [coverage.go:1362,1215-1222]
  tickID           string   // sha256(tick|clock|policyUID|tenant) or pol.TickID [coverage.go:1355-1357]
  selectedAction   string   // trace.SelectedAction                             [decision_trace.go:595]
  selectedCandKey  string   // trace.SelectedCandidateKey                        [decision_trace.go:596]
  actionStatus[]   row      // complete per-action accounting (status/exclusionKind/reason/scored) [decision_trace.go:587-591]

  // --- feasibility result ---
  feasible         bool     // model.Decision.Feasible                          [types.go:1340]
  infeasibleWhy    string   // first blocking constraint                        [types.go:1341]

  // --- probe (attack) result ---
  dispatchOutcome  string   // trace.DispatchOutcome (simulated on twin)        [decision_trace.go:592]
  dispatchReason   string   // trace.DispatchReason                             [decision_trace.go:593]
  existential      obj      // trace.Existential containment result             [decision_trace.go:513]

  // --- SLO result ---
  sloGateResult    OptBool  // selected candidate.SLOGateResult                 [decision_trace.go:471]
  costCeiling      float64  // trace.CostCeiling (effective)                    [decision_trace.go:578]
  sloHeadroom      OptFloat // trace.Inputs.SLOHeadroom                         [decision_trace.go:388]

  // --- full evidence ---
  trace            DecisionTraceV2  // canonicalized, Validate()-clean          [decision_trace.go:654,884]
}
```

### 3.1 What makes it reproducible (all [CODE-CITED])
1. **Frozen clock.** `e.Now` is injected; no wall-clock read in the decision path — `decision_trace_test.go:28-32`, `m030_replay_test.go:24-26`.
2. **Content-addressed identities.** `DecisionID`/`TickID` are SHA-256 over null-separated inputs (`decisionTraceID`, `coverage.go:1215-1222`); identical inputs → identical ids.
3. **Byte-stable serialization.** `Canonical()` redacts + deterministically sorts facts, candidates, cover keys, steering events (`model/decision_trace.go:654-799+`); `TestDecisionTraceFactsCandidatesAndCoverKeysSerializeInStableOrder` `decision_trace_test.go:200-225`; attribution ties break by source, byte-stable over 200 rounds `attribution_determinism_test.go:21-89`.
4. **Reorder-invariance.** Pod/map reordering does not change normalized traces or selection — `decision_trace_test.go:170-198`.
5. **Trace-on == trace-off selection equivalence.** Emitting the verdict cannot change the decision — `decision_trace_test.go:127-151`, `decision_trace_v3_test.go:346-369`.
6. **Multi-tick byte-identical replay.** `TestM030ReplayOnlyRemovesNodePlacement` re-runs 4 ticks on two engines and asserts `string(a) == string(b)` on marshaled decisions — `m030_replay_test.go:66-78`.
7. **Persisted-verdict replay harness.** Every shipped audit JSONL under `build/test-harness/out-*/phorvex-audit-*.jsonl` is re-decoded and re-validated; required keys must be *physically present* — `audit/schema_replay_test.go:66-137`. Verdict persistence uses the same audit `Record` key set: `schemaVersion, kind, time, tenant, namespace, pod, action, selected, feasible, dryRun, actuated, coverageValue, cost, net, residual, threatPosture, exposure, pHold, assetValue, blastRadius, sloHeadroom, phase, reason, r6Counterfactual` — `audit/schema_replay_test.go:14-19`, `audit/contract.go:5-16`.

### 3.2 Verdict semantics (aligned to docx §3.1, §8, §9.4, §10)

The brain-in-loop record reports what the brain did; it does **not** by itself declare an actuator a
winner. Outcomes:

- **SELECTED** — `selectedAction == this actuator`, `ActionStatus.Status == "selected"`,
  `ExclusionKind == "none"`, feasibility accepted, and (under a qualified obligation) every
  `RequiredKey` is covered. This is a *precondition* for a WIN, not a WIN (metric-rule 1, docx §8.3).
- **WIN (actuator works)** — only when, in addition to SELECTED, the measured gates pass on the twin
  (docx §3.1 step 4, §8.1): **G1** the deterministic probe confirms the attacker capability is GONE
  and the post-actuation reachability edge is removed; **G2** availability holds for every affected
  workload including co-tenants; **G3** the brain does NOT select the actuator on the clean no-attack
  control run (§1.2a). An `unknown` gate blocks (docx §8.3 rule 2). `dispatchOutcome` is recorded
  but is **never on its own** a pass — "Dispatch is not effect confirmation", and a
  `NoEffectRefusal` / `already-satisfied` disposition credits no new mitigation (docx §9.4; WS-3
  Stage 3).
- **DECLINED** — `selectedAction == noop` or this actuator is excluded, with the exact
  `status`/`exclusionKind`/`reason` quoted verbatim as the why; the decline reason routes a
  different actuator next round (docx §9.1 decline memo). If no actuator for the latest confirmed
  attack reaches WIN without breaking availability or the brain, the competition reports an honest
  **CANNOT-HELP** for that attack (docx §3.2).
- **NON-TRANSFERABLE** — twin fidelity (§1.4) fails: the twin does not reproduce every brain-read
  input the trace records; not pass/fail (docx §10.1). A trace that fails `Validate()` is a
  loop-integrity error (§2.9), never a WIN.

**[INFERRED]** from the field semantics cited in §2, per docx §3.1/§8.1/§10.

## 4. Proof: the brain stays read-only in the loop

1. **The loop calls `DecideShadowChecked`, never `DecideChecked`.** Its contract: "reads exactly the same
   existing state, computes the hypothetical result from it, and writes none of it … the shadow folds no
   stage entry, seeds no owner state, moves no dual price, teaches no conjugate memory, stamps no
   caller-owned view and increments no operational counter" — `coverage.go:746-754` **[CODE-CITED]**.
2. **Write permission is gated structurally.** `persist := mode.Commits()` and every write site reads
   `mode.Commits()`; a future mode "cannot silently inherit write permission by falling through an
   `!= EvalShadow` test" — `coverage.go:771`, `killchain/evalmode.go:30-33` **[CODE-CITED]**.
3. **Cost state is read from a transient, unregistered bucket.** Shadow pricing never consumes a seed,
   never mints `BucketMeta`, never claims the legacy alias, never moves `creationEvent`; the first real
   production tick still creates the owner's bucket itself — `coverage.go:435-465` **[CODE-CITED]**.
4. **The capability gate is the read-only variant.** The loop wires `ShadowCapability` (no
   SelfSubjectAccessReview, no cache write, no timestamp refresh); if only the impure production
   `Capability` is available, the shadow is reported `ErrShadowCapabilityUnavailable` rather than run —
   `coverage.go:79-98` **[CODE-CITED]**.
5. **The trace itself attests the read-only outcome.** `trace.DualUpdate.Applied == false` on every shadow
   decision (`decision_trace_test.go:257-259`), versus a real dual move in production
   (`decision_trace_test.go:293-319`) — so each verdict carries machine-checkable proof it did not mutate
   the brain **[CODE-CITED]**.
6. **The brain binary is pinned and unmodified.** `BrainImage` and `GitSHA` are mandatory trace fields
   (`Validate` rejects empty — `model/decision_trace.go:993-995`) and are copied verbatim from the policy
   (`coverage.go:519-520` region) into every verdict, so a replay is provably against the same brain build
   **[CODE-CITED]**.
7. **Co-residency cannot leak either way.** Even if a twin shared an engine with production owners, the
   exact-zero cross-tenant isolation proofs (`vcluster_isolation_test.go:58-107`) guarantee the attacker's
   activity changes no other owner's byte stream **[CODE-CITED]**.

Taken together (1)–(7): the loop evaluates a pinned, unmodified brain in a mode that is *statically
incapable* of writing learned state, reading only a read-only gate and a transient cost view, and each
verdict carries its own proof (`DualUpdate.Applied=false`, `BrainImage`/`GitSHA`) that no live brain write
or tuning occurred. **Constraint satisfied. [INFERRED from the cited primitives]**

---

## 5. Open questions

None. Every field, vocabulary, law, and isolation property in this design is anchored to an existing,
tested primitive cited above.
