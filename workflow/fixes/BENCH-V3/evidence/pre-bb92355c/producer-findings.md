# Producer findings and bounded capture contract

Inspected source baseline: `1c23931621d47218ded424b58e4db127344fb33b`.
Historical incident/corpus source: `0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`.

The real ingest producer in `phorvex/internal/ingest/kube.go` groups observed pods
by their immediate owner and assigns that count to `DesiredReplicas`. A Deployment
with `spec.replicas=4` and one observed pod therefore records 1 in that existing
field. The counterexample test exercises the actual snapshot producer, confirms
valid rotation lineage and reads the Deployment back from the fake Kubernetes
API before requiring the additive authoritative observation. Production admission
continues using its existing fields; this change is read-only evidence.

`bindServiceAvailability` captures EndpointSlice membership and readiness at an
observation instant. It does not provide durable transition timestamps, a
move-attributed start/end interval, or continuous coverage. The runner's
`observeReadyRotations` measures from actuation invocation to replacement
`Pod.ReadyAt`, and records censored lower bounds while recovery is unknown. This
is replica-readiness evidence. Endpoint membership, readiness, execution
confirmation and measured endpoint loss are different observations. There is no
qualified endpoint interval producer to wire in this bounded change.

The manager's default-off `--math-lab-capture-cost-evidence` flag produces an
optional `phorvex.endpoint-cost-evidence.v1` envelope. Exact policy owner,
namespace and known pod/workload UIDs bind available history. Export owns its
slices, preserves IDs and outcome/censoring states, and reports unattributed or
future rows and count/byte truncation. `process_observed_since` is ledger creation
time only. In-memory retention, restarts, pre-existing rows and unsupported
unmeasured actions prevent a completeness claim. The envelope therefore keeps
`endpoint_loss_status=unavailable`, `admission_ledger_status=not-authoritative`,
and `replica_history.history_complete=false` in every branch.

Flow is Kubernetes owner reader -> model.Pod -> sensor response/wire -> runner
capture -> brain capture wire -> brainsvc.Local -> mathlab.Recorder -> stored
Inputs -> mathlab.Inspect. The manager, sensor and brain need compatible source
for all fields. Phoenix requests without an owner reader explicitly retain
`owner-reader-unavailable`; no silent additional authorization/read path is
introduced. The evidence reader can access only the existing snapshot owner
cache, never issue an additional API Get/List. StatefulSet/direct-Deployment
objects absent from that cache remain `owner-object-not-observed`. Old files decode without the optional field and expose
`endpoint_cost_evidence:not-recorded` without changing legacy replay completeness.

A future paired candidate export is also missing. `coverage.assembleSet` has real
Recon facts and context, but `actionset.Generate` prunes the legacy CHi ceiling
before returning its candidates. Provenance, reactive containment, existential
outcome handling, resource-constrained selection and positive-gain decisions
also occur downstream. Final selected traces alone cannot recover a complete
candidate universe. Any later offline hook must preserve the exact grounded
facts and all applicable non-cost gates while separately replacing the intended
legacy cost logic, and must reject missing recorded collaborator verdicts. This
change does not claim such a producer or a complete V3 dataset.

No shared cluster, actuator, production service or Telegram message was used by
this worker. The reviewed source proposal requires separate deployment scope.
