# PHORVEXSEC-208 — M99 implementation contract

Authority: Zeinab Alizadeh's `M_99_MATH_RULING.md`, 7 September 2026, and Mostafa's Q1 outcome definition on the card. This implements conditional full containment under the existing move budget. It does not classify fact kinds as existential, introduce new cover grants, change cost calibration, or certify successful prevention from dispatch.

## Detector input

An allowlisted detector supplies a JSON array in its SecurityEvent annotation `phorvex.ai/protected-outcomes-v1`. The event must target the decision workload, pass the authenticated creator boundary and the existing event-age validity rule, and postdate the current configuration epoch of the dedicated fail-closed outcome stamping hook. Re-emit older assertions as new events after enforcement is installed or its configuration changes. Existing events are not retroactively authenticated by installing a webhook.

Example shape, using placeholders for deployment-specific identifiers and an existing sound grant key:

```json
[{
  "id": "remaining-customer-records",
  "policyUID": "POLICY-UID",
  "decisionAsset": "namespace/pod",
  "decisionAssetUID": "POD-UID",
  "protectedAsset": "customer-dataset",
  "version": "dataset-version",
  "portion": "identified-undisclosed-records",
  "property": "confidentiality",
  "outcome": "unauthorized-disclosure",
  "recovery": "not-applicable",
  "classBasis": "protected customer information threatened with unauthorized disclosure",
  "scopeBasis": "documented scope accounts for every relevant copy of this portion",
  "lossState": "at-risk",
  "stateBasis": "detector evidence establishes that this identified portion remains preventable",
  "requiredKeys": ["EXISTING-SOUND-SCOPED-FACT-KEY"],
  "mappingComplete": true,
  "mappingBasis": "documented evidence that invalidating all these keys interrupts this outcome"
}]
```

These are explicit detector assertions about protected outcomes and prevention requirements. The operator cannot infer their security/product truth from severity, an arbitrary source name, a positive fact weight, model identity, or the existence of an action. Detector producers must supply defensible scope, recovery, state and mapping bases. Missing mapping does not remove an otherwise qualified exposure: it makes full containment uncertifiable.

Supported outcomes are `unauthorized-disclosure`, `destruction-corruption`, `control-integrity-loss`, `service-disruption`, `revocable-access` and `replacement-reset`. Destruction/control loss is irreversible only with explicit `no-trustworthy-recovery`; `trusted-rebuild-restore` is recoverable. Missing recovery evidence is unresolved, not proof of unrecoverability. Reversible access/reset can use `revocable`. Unrecognized outcomes remain unresolved.

Loss states are `at-risk`, `already-lost` and `unknown`. Different portions remain separate. Accepted established loss prevents prevention credit for the same protected asset/version/property/outcome/portion. An untrusted claim cannot suppress a qualified risk. Audit keeps raw records, including unresolved and lost portions. Historical audit records remain the evidence of prior reported losses; absence from the current event stream is never a recovery or safety assertion.

## Selection

Before economic ranking, qualified active assets require one candidate covering their complete, nonempty required-key sets through the existing `CoverByAction` grants. Missing, audit-only and unmapped requirements remain visible and cannot pass vacuously.

Each greedy round gives the union of full-containing candidates priority over ordinary actions. Within that union, SLO-admitted actions precede breaching actions, followed by the existing marginal economic score and original generation order. Zero and negative score are allowed for containing actions. No arbitrary penalty or extra move is introduced. Predicted shared cover does not erase another exposure obligation.

`spec.existential.mayBreachSLO` defaults to false. Opt-in can relax availability-floor, SLO-headroom, tokens-floor and conformal-SLO exclusions only for qualified full containment. Capability/RBAC uncertainty, enforcement, stateful restrictions, rotation windows, input-data failures and other physics/execution laws remain binding. Panicking laws fail closed. Dry-run, kill switch and dispatch controls remain effective.

Without a qualifying exposure in the coupled scope, baseline selections and numerical fields remain unchanged. In mixed ticks, `prioritySelections` identifies the competing trusted selections and `remainingBudget` records the shared-budget context. This context is not a claim that every ordinary action would have won the counterfactual baseline.

## Trust deployment

The chart adds `stamp-protected-outcomes.phorvex.ai` as a separate fail-closed CREATE/UPDATE webhook matching only outcome-bearing events. The ordinary M94 hook keeps its original event-flow policy. The runner uses the uncached API reader to read webhook configuration and accepts no activation when the dedicated hook, operations, match condition, endpoint/CA, installation timestamp or detector allowlist cannot be verified. It does not grant the operator permission to modify webhooks.

This deployment changes availability specifically for outcome-bearing event writes: those writes fail if their stamping endpoint is unavailable. It uses admission `matchConditions` and therefore requires a Kubernetes version supporting that API field. A chart render/source merge alone is not evidence of live activation. Apply the CRD and chart through the normal deployment process and check the running image, configured detector identities and admission enforcement before claiming live behavior.

## Reporting and effect limits

The additive `existential` object is present on decision audit records and traces, with candidate containment, trust, exposure references, missing keys, exclusions, generation rank, actual selected SLO exception and priority order. `m99_bounded_full_containment` identifies the active comparator. Unselected active assets produce the ticket-labelled interim `uncontainable` result, `ExistentialUncontainable` status condition and Warning Event. Events are emitted on transitions rather than repeated unchanged every tick.

`phorvex.existential-inventory.v1` preserves policy-level raw assertions, including scope gaps when no workload is selected. `ExistentialScopeComplete=False` marks unresolved scope. True means no gap was found in the supplied inventory, not that every possible exposure is known. Free-text audit metadata passes the existing credential redaction rules.

Effect status is `not-attempted`, `failed-or-unconfirmed`, or `attempted-unconfirmed`. No M99 path emits a confirmed-containment claim: the current actuator result does not establish scoped prevention or exclude intervening disclosure. Raw risk, loss and unknown records remain visible. A future T2-01 scoped effect/state witness must establish prevention before adding such credit.

## Verification

`internal/decision/existential_test.go` replays the ruling's numeric A/B counterexample through the production round selector at lambda 0, 1, 10, 22, 30 and 100, including cost-ratio variation. It tests trust/scope/state classification, empty and audit-only mappings, partial coverage, priority/budget/partition, SLO tiers, retained gates, inactive baseline identity and valid trace records. Ingestion, runtime-boundary, runner status/Event, effect-reporting and redaction tests cover the corresponding interfaces.

Representative records can be exported without live mutation:

```sh
M99_RECORD_PATH=/tmp/m99-records.json M99_RECORD_SHA="$(git rev-parse HEAD)" \
  GOMAXPROCS=2 go test -p 2 ./internal/decision -run TestM99TraceAndRepresentativeRecords -count=1
```

Those records are synthetic fixtures using the production engine and existing grants. They are not observations of an attack or deployed containment.
