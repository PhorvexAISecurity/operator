# Decision Trace V2 / V3 / V4

`phorvex.decision-trace.v4` supersedes `v3` and `v2`, which remain readable. It is
nested under `decisionTrace` in each `phorvex.audit.v2` per-asset decision record.
It records the current P1 decision path.

**V4 additions (versioned economics):** `economicsVersion`, optional
`disruptionAversion`, `effectiveCostCoefficient`, and `costCoefficientSource`
identify the coefficient used by scoring. In fixed mode
`objectiveCostContribution` is authoritative and `lambdaContribution` is absent.
`lambdaDemand` is the counterfactual demand used by the legacy count-pressure
controller; the retained `candidateDemand` field is its compatibility alias.
`objectiveCandidateDemand` records demand under the coefficient that actually
ranked candidates. The same economics metadata is also retained at the audit
record top level when rich decision tracing is disabled, including the exact
runtime lambda and exact configured beta; these fields are not rounded with the
legacy display values. The legacy top-level audit `lambda` remains rounded to
four decimals for wire compatibility and must equal the descriptor's exact
runtime lambda after that documented rounding.

**V3 additions (the complete decision path):** `actionStatus` — exactly one row per
canonical mutating action (`not-enabled` / `no-cover` / `infeasible` /
`conformal-slo` / `priced-out` / `budget-exhausted` / `candidate` / `selected` /
`not-evaluated-by-current-model` / `not-installable`), each with a closed
`exclusionKind` (`none` / `not-enabled` / `recon-cover` / `feasibility` /
`cost-nan` / `slo-gate` / `reactive-only` / `selection`) and a `scored` flag; the
CHi reconstruction terms per costed candidate (`conformalQuantile`,
`conformalCalibrated`, `gpuEnvelopeApplied`, `gpuEnvelopeSlack`) with the pinned law
`costHigh = expectedCost + (rotate ? max(quantile, envelopeSlack if applied) : 0)`;
`sloGateResult`; round semantics (`evaluationRound` per record, `coveredRound` per
fact, with `coveredBeforeDecision` derived as `coveredRound < evaluationRound`);
per-fact `coveringActions` and `decompositionAvailable`; the effective `costCeiling`
and `costModelVersion`; `sloHeadroom` / `nextStage` / `projectedNextStageSec` in the
inputs; and the runner-stamped `dispatchOutcome` (`not-attempted` / `emitted` /
`emitted-false` / `dispatch-error`) with `dispatchReason` covering every
pre-dispatch guard (`dry-run`, `kill-switch`, `ensure-policy-failed`,
`inviolability-guard`, `no-tick-view`, `emit-boundary-infeasible`, `unselected`).
Kill-switch refusals include the stable observation cause in `killSwitchCause` and
`dispatchReason`; the value is sampled fresh at route and dispatch boundaries rather
than inferred from the tick-start snapshot.

## Identity and scope

Each trace identifies the decision, tick, timestamp, operator image, source Git
SHA, engine, policy/tenant, and pod UID. The operator image is injected by the
Helm deployment. The Docker build links the exact Git revision into the binary.
An ad-hoc build that cannot expose either value emits the explicit string
`notAvailable`; it never invents an identity.

The trace is per asset. Its candidate array is the complete set of enabled
actions for that asset in the current tick: surviving generated candidates plus
actions rejected by an existing generator gate. `notClassifiedByCurrentModel`
states that CRD installability, RBAC, runtime-handler availability, and fixture
availability were not classified by this Tier-0 model.

## Explicit absence

Potentially absent numeric/boolean inputs use:

```json
{"present": false, "value": 0}
```

`value: 0` is meaningful only when `present` is true. Telemetry presence is
tracked per Prometheus signal. Physics fields use their existing source witness;
for example SM occupancy is present only with an SM source and VRAM is present
only when both used/free series supplied a usable denominator.
`primed` records the current cost learner's actual RLS state.

`phaseReason` records how application telemetry supports the workload phase.
`idle-measured` requires a fresh, finite, nonnegative request-rate sample within
the existing idle boundary and no contradictory app activity. Positive queue
depth or token throughput keeps the phase Warm. `warm-no-app-signal` means all
application activity signals are genuinely absent; `warm-uncertain-app-signal`
means app telemetry exists but is stale, errored, invalid, or insufficient to
establish measured idle. Infrastructure-only cAdvisor signals remain outside this
classification and do not claim application load.

## Reconstruction

Facts are ordered by `factKey`; candidates use canonical action order; cover
keys are lexical. Legacy mode is exactly:

```text
lambdaContribution = lambdaRuntimeLegacy * expectedCost
netGain = marginalCoverage * provenance - lambdaContribution
ordinary selection only when netGain > 0
```

Fixed opt-in mode is exactly:

```text
objectiveCostContribution = disruptionAversion * expectedCost
netGain = marginalCoverage * provenance - objectiveCostContribution
ordinary selection only when netGain > 0
```

The two coefficients are never added. Runtime lambda continues to learn in fixed
mode, but it does not price the fixed-mode objective.

The existing M99 trusted protected-outcome comparator remains a distinct hard
containment ordering and can select a certified full-containing move with a
non-positive ordinary objective gain. Such a record names the M99 comparator
and containment reason; it does not describe the gain as positive.

The comparator is strict: equality does not pass. `perDollar` and
`proactiveRate` are legacy reporting fields and do not select an action.

`grossFullValue` is the full sum of a candidate's fact weights.
`marginalCoverage` is the value observed when that candidate was last evaluated
by the greedy selector; it is explicitly absent if the current gates never
reached scoring. `selectionReason` records selection, partition loss, strict
non-positive gain, budget exhaustion, reactive-only suppression, or an existing
generator exclusion.

`tieBreakRank` records the current within-asset strict-`>` candidate order.
A selected outcome references exactly one candidate and records its 1-based
selection round. A noop references none and carries the current reason, such as
an existing feasibility exclusion, `priced-out`, `budget-exhausted`, or the
reactive-only gate.

## Lambda roles and update

`lambdaConfiguredPolicy` is the configured seed. `lambdaRuntimeLegacy` is the
per-tenant state frozen at the start of the tick. Compatibility aliases
`lambdaConfiguredSeed` and `lambdaRuntime` carry the same respective values for
existing readers. The runtime value is called legacy/mixed because its update
signal is move-count pressure while it multiplies a weighted disruption score;
it is not certified as an exact move-budget dual.

The trace records `lambdaDemand`, `spent`, `budget`, `rawExcess`, `effectiveExcess`,
lambda before/after, whether the transition was applied, and a stable reason
code. The move budget consumes one slot per selected asset/action; demand counts
assets, not actions or disruption cost. A shadow decision records the same
deterministic preview with `applied: false`.

## Cost representation

The current representation is `weighted_dimensionless_v1`:

```text
expectedCost = normWeight * cNorm + flowWeight * cFlow
```

`cNorm`, `cFlow`, their weights, and `expectedCost` are dimensionless.
`cFlowUnitStatus` is `confirmed_dimensionless_disruption_loss`; none of these
fields is a dollar value. Rotation's learned CFlow target is replacement Ready
delay divided by 400 seconds and clamped to `[0,2]`; other action families use
their declared bounded dimensionless disruption terms.

Pre-T0-B V2 records do not contain the new representation/update fields. They
remain readable for deterministic rollback; new records are identifiable by the
non-empty `costRepresentationVersion`.

## Redaction

The schema has no fields for Secret values, request bodies, prompts, headers, or
credentials. Serialization also redacts bearer tokens and credential-like
key/value fragments from all free-text fields. Secret names are not collected by
the trace. Detailed facts/candidates remain in JSON audit output and are never
added as Prometheus labels.
