# Decision Trace V2

`phorvex.decision-trace.v2` is nested under `decisionTrace` in each
`phorvex.audit.v2` per-asset decision record. It records the current P1 decision
path; it does not change candidate generation, feasibility, cost, λ, scoring,
selection, learning, or actuation.

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

## Reconstruction

Facts are ordered by `factKey`; candidates use canonical action order; cover
keys are lexical. For every feasible candidate with recorded terms:

```text
lambdaContribution = lambdaRuntime * expectedCost
netGain = marginalCoverage * provenance - lambdaContribution
```

`tieBreakRank` records the current within-asset strict-`>` candidate order.
A selected outcome references exactly one candidate and records its 1-based
selection round. A noop references none and carries the current reason, such as
an existing feasibility exclusion, `priced-out`, `budget-exhausted`, or the
reactive-only gate.

## Redaction

The schema has no fields for Secret values, request bodies, prompts, headers, or
credentials. Serialization also redacts bearer tokens and credential-like
key/value fragments from all free-text fields. Secret names are not collected by
the trace. Detailed facts/candidates remain in JSON audit output and are never
added as Prometheus labels.
