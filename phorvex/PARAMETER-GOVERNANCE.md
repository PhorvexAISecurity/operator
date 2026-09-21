# Decision parameter governance

Phorvex exports the current production decision registry with:

```sh
go run ./cmd/parameter-manifest
```

The command emits `phorvex.decision-parameters.v1`, sorted by stable parameter
name, plus its canonical SHA-256 hash. Pass the deployment's configured GPU
envelope with `--gpu-envelope-max`; otherwise the export truthfully contains the
shipped conservative fallback. Each new P1 decision carries only the compact
manifest identity/hash and the identity/hash of its exact resolved policy
values. Retain one full manifest and effective-policy document with the audit
set. A record without the compact reference is legacy data whose parameter
provenance is unavailable.

The registry describes what the source uses. `expert-prior` means a selected
engineering value, `configuration-bound` means an admission or deployment
limit, `derived` means an algebraic consequence, and
`measured-with-evidence` is reserved for an entry with retained measurements.
None of these labels means that the complete decision policy is calibrated,
optimal, or transferable to another workload.

## Historical inventory disposition

The historical “61 constants” list was a research inventory, not an
authoritative count. Current source has these dispositions:

| Historical group | Current disposition | Production source |
|---|---|---|
| Dispersion maximum | Present at 4; a positive `PhysicsWitness.DispersionCap` is shadow-only. | `internal/recon/ucw.go` |
| Co-residency scale | Present as a cap of 4 on a running-namespace-count proxy. It does not identify tenants or shared GPU hardware. | `internal/platform/platform.go` |
| Load / healthy band | The old scalar healthy-band threshold is removed from production selection. Current load inputs are presence-aware request-rate and connection-count normalizers and action-family flow priors. `internal/physics/profile.go` has no live decision consumer. | `internal/cost/rls.go`, `internal/cost/action_flow.go` |
| Legacy lambda | Present as seed 0.6, step 0.05, range [0,10] and a one-unit per-tick excess cap. It is a move-count controller and is not certified as an exact disruption-price dual. | `internal/cost/dual.go` |
| Fixed disruption preference | Optional beta in [0,10]. Absence keeps legacy runtime-lambda scoring; explicit zero is distinct. | `internal/model/economics.go` |
| Hazard / sojourn | Present as the Weibull shape, stage scales, consequence ladder, recovery scale and exposure-pressure cap. Defaults are provisional expert priors unless a registry entry says otherwise. | `internal/killchain/hazard.go` |
| Persistence prior | Present as Beta(1,4), bounded to effective mass 200. A raw qualified-label count is not effective posterior mass after rescaling. | `internal/killchain/conjugate.go` |
| Fact weights | Present as session/network relative weights, stage-urgency blend, vector dominance and the minimum held-asset floor. These are structural modeled weights, not measured mitigation. | `internal/recon/profile.go`, `internal/recon/ucw.go` |
| Selection provenance | Present at 0.34 for fresh assets without trusted event evidence. | `internal/decision/coverage.go` |
| Cost priors and bounds | Present as phase/RLS priors, action-family flow priors, structural normalized costs, conformal settings, ready-delay normalization and the configured GPU minimum. | `internal/cost` |
| Legacy `switching-cost` literals | Retained only as a registered modular compatibility model. The supported P1 engine constructs `P1Cost` directly and does not select this registry entry; its duplicate literals are therefore excluded from the production-decision manifest. | `internal/cost/switching.go`, `internal/decision/coverage.go` |
| Model-rarity / co-residency multiplicity | Present in the current UCW formula: the terms contribute to their own facts and the bounded scarcity multiplier. The manifest records the shared dispersion cap; it does not call the formula empirically calibrated or silently remove either contribution. | `internal/recon/ucw.go` |
| Conformal rank and exchangeability | The finite-window alpha, window and minimum-sample values are present. Adaptive conformal inference is absent. The manifest describes the current residual bound and cold-start behavior without promoting it to a universal coverage guarantee. | `internal/cost/conformal.go` |
| RLS innovation and robustness | Raw prediction residual with forgetting and a bounded per-coordinate update remains present. Measurement-noise inflation and a Huber loss are absent; the registry records the shipped forgetting, covariance, step and prediction bounds. | `internal/cost/rls.go` |
| Historical exposure saturation / cost-ceiling slack claims | The old scalar exposure saturation and additive cost-ceiling slack are not separate current P1 parameters. Exposure pressure uses a policy scale/cap; the hard SLO gate uses the resolved cost ceiling and action-specific robust cost. | `internal/killchain/hazard.go`, `internal/cost/p1cost.go` |

The manifest records dynamic or conditional values separately where a single
action name is insufficient. For example, endpoint rotation has route-ready and
fallback normalized costs, and model-shard replacement is per rank. Learned RLS
coefficients and the runtime lambda remain decision state with their existing
trace fields; the registry supplies their source defaults and bounds rather than
misrepresenting a changing state vector as a static default.

## Sensitivity and adoption

`decision.EvaluateSensitivity` calls the actual checked shadow decision path on
owned copies of a frozen snapshot. It supports bounded dispersion maximum,
fixed beta, exposure-pressure cap, hazard shape, and per-stage sojourn scales.
It records action/selection switches, expected cost, modeled benefit, net value,
and hard-feasibility results. Equivalent seconds and milliseconds normalize to
one canonical value. Unknown parameters, missing snapshots, non-finite values,
and values outside the declared domain are rejected. A sensitivity result shows
dependence only; it does not choose a better value.

No learned or shadow value may enter production scoring until a separate
reviewed adoption contract records all of the following:

- independently attributable labels and workload domain;
- sample units, censoring and refused/unknown observations;
- held-out performance and service-impact measurements;
- a bounded proposed change and exact parameter-set version;
- a rollback version and trigger;
- proof that shadow evaluation did not mutate production learning,
  deduplication, counters, reservations, or actuation state.

## Remaining empirical work

| Group | Available non-MIG workload | Required measurements and falsifier |
|---|---|---|
| Dispersion and namespace-count proxy | CPU and T4 multi-namespace workloads | Compare isolated rarity/co-residency changes with fixed evidence and load. Record ranking changes and actual attacker reacquisition; reject a value that increases healthy churn without a measured security effect. |
| Load normalization and phase priors | CPU HTTP and T4 inference at idle and load | Record request rate, connections, tail latency, throughput, readiness and clipping frequency by service class. Reject pooled scales that hide saturation or phase-specific loss. |
| RLS and conformal controls | Repeated CPU/T4 replacements including failures and right-censoring | Measure drift response, raw residuals, rank/coverage by regime and interval width. A sample count of 20 alone does not establish coverage. |
| GPU envelope | Ordinary T4 cold and warm replacements | Measure creation-to-ready and service recovery independently from non-GPU residual training. No MIG hardware is needed for this control. Reject an envelope that under-covers cold recovery or prunes safe non-GPU moves. |
| Hazard, sojourn and consequences | Controlled event timelines plus censored no-transition episodes | Estimate stage dwell with censoring and separate cumulative urgency from finite-horizon transition probability. Reject values that change stage/evidence semantics or miss action completion latency. |
| Persistence prior and confidence | Independently observed retained-operation outcomes | Measure label quality, effective posterior mass, tenant isolation, censoring and held-out reliability. No qualified live label producer is connected yet; selection or acknowledgement is not a label. |
| Legacy lambda and fixed beta | Frozen replay with binding/nonbinding budgets and matched service load | Report selections, demand, spend, cost and service effect separately. Reject claims that zero scarcity price implies zero fixed disruption preference, or that the move-count recurrence is a calibrated resource price. |
| Fact weights and provenance floor | Event-free proactive, trusted-event and decoy fixtures on CPU/T4 | Ablate each weight/floor with the same capability and exposure opportunity. Reject lost protection for due assets, false evidence creation, or security credit without an effect witness. |
| Action cost priors | One action family at a time on supported local/T4 backends | Retain attempts, failures, censoring, tail latency, throughput, unavailable capacity and recovery. The retained KV-reset TTFT sample does not calibrate unrelated actions or hardware. |

Production adoption still requires deployment identity, a bounded canary and
service-owner rollback thresholds. Source tests and local shadow runs do not
close those live obligations.
