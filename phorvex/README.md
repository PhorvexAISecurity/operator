# Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD (P0 / MVP)

Reported coverage is modeled coverage of the detector-visible, reversible projection, not confirmation of security effect. Live audit claims name their record-time configured trusted-detector set and build; configured does not mean connected, and recall is unmeasured. Historical records without this metadata remain unknown.

Phoenix can **act** (delete / quarantine / probe a workload) but decides **blindly**
— by a clock or a hand-written exact-match table, with no notion of what a move costs
or what is worth protecting. **Phorvex is the missing brain.** For the MVP it sits on
top of **UNMODIFIED extended Phoenix** and decides *which* workload to move, *when*,
and *which action*, by optimizing security gained against disruption cost — then
drives Phoenix through Phoenix's own CRDs (**Seam 1**: emit `SecurityEvent` + maintain
an `AdaptiveMovingTargetDefense` strategy). The default Phoenix backend does not write
pods; native/hybrid actuation is opt-in and uses per-tenant namespaced Roles.

> This is a **separate Go module** (`github.com/phorvex/phorvex`). It depends on the
> Phoenix module ONLY to construct/emit Phoenix's typed CRs, via a consumer-side
> `replace github.com/r6security/phoenix => ../build/phoenix-extended`. That replace
> does **not** modify extended Phoenix — Phoenix and the attack harness still build
> and run unchanged.

## What P0 builds

- **`PhorvexPolicy` CRD** (`phorvex.ai/v1alpha1`) — exactly the PRD PART 7 spec
  (`selector / objective{lambda,costWeights} / budget{maxMovesPerTick,tickInterval,
  antiOverRotationWindow,proactiveFloor} / slo / assetValue / triggers / actions / brain{killChain} /
  mode:dryRun`). **Namespace-scoped = per-tenant from line one** so vcluster
  multi-tenancy is not a retrofit.
- **Ingest** (FR1): Prometheus metrics (pluggable, honest-absent), the SecurityEvent
  CR stream, and the K8s graph (pods / labels / NetworkPolicy / RBAC / nodes / MIG).
- **Blast-radius / reachability graph** over NetworkPolicy + RBAC (+ co-location).
- **Decision engine** (FR4): greedy top-B maximizing Σ(risk − λ·cost) under
  feasibility + budget + anti-over-rotation, with the **R6 counterfactual** logged.
- **Modular swappable interfaces** (registered, one-file-to-add): `PhysicsProfile`,
  `FeasibilityConstraint`, `CostModel`, `BeliefEstimator`/ReconInvalidation,
  `ContextProvider`.
- **Per-variable exposure-clock** scaffold (pod identity + node placement live; image
  / env / GPU / network / session declared).
- **Actuator interface**: `PhoenixActuator` (Seam 1) plus native/hybrid handlers behind
  an explicit backend setting and namespaced write RBAC.
- **Dry-run decision log** + **Prometheus metrics** + **Grafana risk heatmap**.
- **Least-privilege RBAC**: writes ONLY its own CRD + SecurityEvent/AMTD; never pods.

## Functional-requirement map (PRD PART 7)

| FR | Requirement | Where | Status |
|----|-------------|-------|--------|
| **FR1** | Ingest: Prometheus, SecurityEvents, K8s graph (pods/labels/NetworkPolicy/RBAC/nodes/MIG) | [internal/ingest/](internal/ingest/) (`kube.go`, `events.go`, `prometheus.go`, `metricssource.go`) | ✅ built |
| **FR2** | Physics: feasibility set + switching-cost K per move | [internal/feasibility/](internal/feasibility/), [internal/cost/](internal/cost/) | ✅ built |
| **FR3** | Context: CVE/value/blast-radius, kill-chain state, exposure timer, SLO headroom | [internal/ctxprov/](internal/ctxprov/), [internal/graph/](internal/graph/), [internal/exposure/](internal/exposure/), [internal/belief/](internal/belief/) | ✅ built (CVE/CVSS prior = roadmap; posture is recorded for audit; raw event severity drives P1 through kill-chain P(hold)/stage urgency) |
| **FR4** | Optimizer: argmax(E[sec] − λ·E[K]) s.t. feasibility + budget + anti-over-rotation; ranked + explainable | [internal/decision/engine.go](internal/decision/engine.go) | ✅ greedy top-B (the PRD's MVP form; mixed-strategy solver = later) |
| **FR5** | Trigger: event-driven + proactive exposure floor (detection-independent) | [internal/belief/reconexposure.go](internal/belief/reconexposure.go), `budget.proactiveFloor` | ✅ built |
| **FR6** | Actuation: emit SecurityEvent + maintain AMTD → Phoenix runs rotate\|quarantine | [internal/actuator/phoenix.go](internal/actuator/phoenix.go) | ✅ built (Seam 1) |
| **FR7** | Audit/dashboard: per-decision inputs, action, attribution, R6 counterfactual; Grafana heatmap | [internal/audit/](internal/audit/), [internal/metrics/](internal/metrics/), [grafana/phorvex-heatmap.json](grafana/phorvex-heatmap.json) | ✅ built |
| **FR8** | Safety: global kill-switch; per-namespace dry-run; configurable B/λ/thresholds/window; evidence-retention guard | [internal/runner/killswitch.go](internal/runner/killswitch.go), `mode:dryRun`, `feasibility/anti-over-rotation` | ✅ built |
| **FR9** | *(not defined in the PRD; the PRD lists FR1–FR8.)* Mapped here to the **CRD config surface + NFR envelope**: PhorvexPolicy knobs, least-privilege RBAC (NFR4), restart-safe exposure (NFR3), <1s tick metric (NFR1) | [api/v1alpha1/](api/v1alpha1/), [config/rbac/role.yaml](config/rbac/role.yaml) | ✅ built — **FR9 itself is undefined upstream; flagged honestly** |

## Extending Phorvex (one file, zero core change)

Each modular surface is a registry. To add, say, a VRAM-conservation feasibility
constraint, drop ONE file in `internal/feasibility/` with:

```go
func init() { Registry.Register(myConstraint{}) }
```

The decision engine reads providers back through the registry (`Default()`/`All()`),
never by importing a concrete impl — so no core file changes. The same pattern holds
for `physics`, `cost`, `belief`, `ctxprov`, and the `ingest.MetricsSource`.

## Build / test / run

```powershell
# build + vet + test (no envtest needed — pure unit tests)
go build ./... ; go vet ./... ; go test ./...

# regenerate deepcopy + CRD after editing api/v1alpha1
go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.17.2 object:headerFile=hack/boilerplate.go.txt paths=./api/v1alpha1
go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.17.2 crd paths=./api/v1alpha1 output:crd:artifacts:config=config/crd/bases

# install the CRD + a dry-run policy, then run the operator against your cluster
kubectl apply -f config/crd/bases/phorvex.ai_phorvexpolicies.yaml
kubectl apply -f config/samples/phorvex_v1alpha1_phorvexpolicy.yaml
go run ./cmd/main.go --base-interval=5s --metrics-bind-address=:8080

# Seam-1 integration proof (emit ONE SecurityEvent + ensure the AMTD, then exit):
go run ./cmd/main.go --integration-emit \
  --emit-namespace=default --emit-pod=<pod> --emit-matchlabels=app=demo --emit-action=rotate
```

## Safety (P0 is dry-run by construction)

- **`mode: dryRun`** (the default) decides + logs + emits metrics but **never
  actuates**. The decision loop calls the actuator ONLY in `mode: active`.
- **Global kill-switch** (`--global-kill-switch` or the `phorvex-killswitch`
  ConfigMap) suppresses all actuation regardless of mode.
- **Anti-over-rotation window** is a hard feasibility constraint (evidence-retention
  guard) — Phorvex never rotates the same pod faster than the forensic window.
- **Least-privilege RBAC** — the default chart remains read-only on workload objects.
  Native/hybrid writes are granted only in namespaces explicitly listed under
  `phorvex.actuatorNamespaces`; Secrets and EndpointSlices remain denied.

### `route-rotate` deployment contract

`route-rotate` is emitted only for a pod that names its fronting Service with the
`phorvex.ai/route-service` annotation. That Service must select the pod through
`phorvex.ai/route-key`, and at least two matching Ready replicas must exist before a
restitch. The handler re-keys the target pod and the Service selector together; rollback
restores both. See `config/samples/route-rotate-contract.yaml` for a complete reference.

For native/hybrid operation, list each protected tenant namespace in Helm values:

```yaml
phorvex:
  actuator: hybrid
  actuatorNamespaces:
    - default
```

This renders a Role/RoleBinding per listed namespace. Service permission is exactly
`get,update`; it grants no Service create/delete/patch and no Secret or EndpointSlice access.

## Honest scope limits (P0)

- The optimizer is the **greedy top-B** the PRD calls the MVP form; the offline
  mixed-strategy (Stackelberg/Markov-game) solver is a later phase.
- **CVSS/CVE utilities** are a roadmap input. The default P1 engine targets from
  consequence-weighted recon facts, exposure, and kill-chain P(hold)/stage urgency;
  `ThreatPosture` is a live audit scalar, not an additional targeting multiplier.
- The **Prometheus** ingest is real but OPTIONAL; with no backend Phorvex runs on
  K8s-only signals and reports telemetry absent — it never fabricates a metric.
- Native/hybrid actuation requires explicit per-namespace RBAC opt-in; an unlisted
  namespace remains read-only and the handler fails closed.
- Active-mode actuation requires a **matchLabels** selector (the Phoenix AMTD guest
  list is matchLabels-only in P0).

See [P0-REPORT.md](P0-REPORT.md) for the real build/test/live results.
