# Phorvex P0 — Build & Live-Run Report (REAL results)

**Date:** 2026-06-04 · **Module:** `github.com/phorvex/phorvex` · **Status: P0 COMPLETE.**
Every pass-filter met with real, reproduced results. No fabricated numbers.

Phorvex is a **separate Go module** that adds the *brain* on top of **UNMODIFIED
extended Phoenix** and reuses Phoenix's *hands* over Seam 1. It depends on Phoenix
ONLY via a consumer-side `replace github.com/r6security/phoenix =>
../build/phoenix-extended` (which does not modify Phoenix). Extended Phoenix and the
attack harness still build and run unchanged (verified below).

---

## 1. Pass-filter scorecard

| Pass filter | Result |
|---|---|
| `go build ./...` green | ✅ exit 0 |
| `go vet ./...` green | ✅ exit 0 |
| `go test ./...` green | ✅ exit 0 (fresh `-count=1`; 5 test packages pass) |
| Runs live on the kind cluster | ✅ 6 ticks against `kind-amtd-test` (K8s v1.35.0) |
| Ingests + builds graph + dry-run-logs **without actuating** | ✅ 5 pods ingested, blast-radius graph built, 30 decisions logged, **0 actuations** |
| Proves integration: emits a test SecurityEvent **extended Phoenix consumes** | ✅ Phoenix log: `Pod "web-768b7c59dd-25v4b" was sucessfully deleted with ACTION: delete` |
| Extended Phoenix + harness still build unchanged | ✅ both `go build`+`go vet` exit 0 |

**Toolchain (real):** Go 1.26.3 windows/amd64; controller-gen v0.17.2 (deepcopy + CRD
via `go run`); kind cluster `amtd-test`, node `amtd-test-control-plane`, K8s v1.35.0;
kubectl/kind at `C:\kube`. Phoenix AMTD CRDs already installed on the cluster.

**Code inventory:** 39 hand-written `.go` files (5 test files), **4,497 LOC** +
252 generated (deepcopy), across **18 packages**.

---

## 2. What P0 builds (FR map)

| FR (PRD PART 7) | Built | Where |
|---|---|---|
| FR1 Ingest (Prometheus, SecurityEvents, K8s graph: pods/labels/NetworkPolicy/RBAC/nodes/MIG) | ✅ | `internal/ingest/` |
| FR2 Physics (feasibility set + switching-cost K) | ✅ | `internal/feasibility/`, `internal/cost/` |
| FR3 Context (asset value/blast-radius, kill-chain state, exposure timer, SLO headroom) | ✅ | `internal/ctxprov/`, `internal/graph/`, `internal/exposure/`, `internal/belief/` |
| FR4 Optimizer (argmax E[sec]−λE[K] s.t. feasibility+budget+anti-over-rotation; ranked + explainable) | ✅ greedy top-B (the PRD's MVP form) | `internal/decision/engine.go` |
| FR5 Trigger (event-driven + proactive exposure floor, detection-independent) | ✅ | `internal/belief/reconexposure.go`, `budget.proactiveFloor` |
| FR6 Actuation (emit SecurityEvent + maintain AMTD → Phoenix runs rotate\|quarantine) | ✅ Seam 1 | `internal/actuator/phoenix.go` |
| FR7 Audit/dashboard (inputs, action, attribution, R6 counterfactual; Grafana heatmap) | ✅ | `internal/audit/`, `internal/metrics/`, `grafana/phorvex-heatmap.json` |
| FR8 Safety (global kill-switch; per-namespace dry-run; configurable B/λ/window; evidence-retention) | ✅ | `internal/runner/killswitch.go`, `mode:dryRun`, anti-over-rotation constraint |
| FR9 *(undefined in the PRD — flagged)* → CRD config surface + NFR envelope (least-priv RBAC, restart-safe exposure, <1s tick) | ✅ | `api/v1alpha1/`, `config/rbac/role.yaml` |

**Modular surfaces (registered, one-file-to-add, zero core change):** `PhysicsProfile`
(`littles-law`), `FeasibilityConstraint` (`availability-floor`, `slo-headroom`,
`anti-over-rotation`, `stateful-integrity`), `CostModel` (`switching-cost`),
`BeliefEstimator` (`recon-exposure`), `ContextProvider` (`sensed-context`),
`MetricsSource` (`none` default, `prometheus-http`). **Actuator** interface:
`PhoenixActuator` (Seam 1) + `NativeActuator` (Phase 2 stub → `ErrNotImplemented`).
**Per-tenant from line one:** `PhorvexPolicy` is namespace-scoped, keyed by tenant.

---

## 3. Live dry-run on kind (REAL — ingest + graph + decisions, NO actuation)

Demo: `phorvex-demo` namespace — a `web` Deployment (3 replicas, label `data-class:
restricted`, mounts a Secret, ServiceAccount with pods create/delete → RBAC lateral
reach) and a `state` StatefulSet (2 replicas, PVC-backed → stateful, `data-class:
internal`). One `PhorvexPolicy` (tenant `phorvex-demo`, selector `app=demo`, budget 2
moves/tick, tickInterval 5s, proactiveFloor 30s, **mode: dryRun**).

**Operator metrics after 6 ticks (`/metrics`, real scrape):**

- `phorvex_ticks_total{tenant="phorvex-demo"} 6`
- `phorvex_protected_pods 5`, `phorvex_selected_moves 2` (budget honored)
- `phorvex_tick_duration_seconds_sum 0.0193` over 6 → **~3 ms/tick** (NFR1 <1 s met by ~300×)
- `phorvex_kill_switch_engaged 0`
- **Blast radius (graph, real):** `state-0/1 = 0.930`, `web-* = 0.814` — the graph
  correctly ranks the state pods higher (they reach the secret-bearing web pods).
- **Per-variable exposure clocks:** `podIdentity` + `nodePlacement` published per pod
  (e.g. `web-* = 107.7s`), reconstructed from pod age (restart-safe).

**Decision log (last tick, real — this is the PRD's lead demo):**

| pod | action | selected | feasible | risk | cost | net | blast | **R6 would** |
|---|---|---|---|---|---|---|---|---|
| state-0 (stateful) | **quarantine** | false | true | 0.932 | 0.283 | 0.730 | 0.930 | **rotate** |
| state-1 (stateful) | **quarantine** | false | true | 0.932 | 0.283 | 0.730 | 0.930 | **rotate** |
| web-…qn89v | **quarantine** | **true** | true | 1.446 | 0.283 | 1.141 | 0.814 | **rotate** |
| web-…25v4b | **quarantine** | **true** | true | 1.446 | 0.283 | 1.141 | 0.814 | **rotate** |
| web-…cf4zn | **quarantine** | false | true | 1.446 | 0.283 | 1.141 | 0.814 | **rotate** |

`infeasible=0`, `dryRun=true`, `actuated=0`. **R6's blind timer would rotate (Delete)
all 5 pods — destroying the two stateful pods' data. Phorvex instead decides
QUARANTINE** (contain the high-blast pods, preserve state), and spends its 2-move
budget on the two highest-net pods. (All pods are co-located on kind's single node →
all high blast → quarantine is the cost-optimal call; the **rotate** path is selected
for low-blast/idle pods — proven by unit test `TestRotateCheapLowBlastPod` and by the
live Seam-1 rotate below.)

---

## 4. Seam-1 integration proof (REAL — extended Phoenix consumes a Phorvex event)

With extended Phoenix running, Phorvex's `--integration-emit` ensured the per-tenant
AMTD and emitted a controlled SecurityEvent for a target pod:

```
{ "Actuator":"phoenix", "AMTDName":"phorvex-phorvex-demo",
  "EventName":"phorvex-rotate-kwbgx", "RuleType":"phorvex.rotate",
  "RuleThreatLevel":"high", "RuleSource":"PhorvexController", "Emitted":true }
```

Extended Phoenix consumed it (real operator log):

```
SecurityEvent found: "phorvex-rotate-kwbgx, targets: [phorvex-demo/web-768b7c59dd-25v4b]"
SecurityEvent was sucessfully applied to the pod
Pod: "web-768b7c59dd-25v4b" was sucessfully deleted with ACTION: delete
```

`kubectl get pod web-768b7c59dd-25v4b` → **NotFound**; the ReplicaSet respawned a
clean `web-768b7c59dd-m98q6`. The mechanism is genuine, not a no-op: the FIRST emit
(before the AMTD controller had stamped the pods) was correctly **rejected** by
Phoenix — `Pod ... is a SecurityEvent target but not AMTD managed` — and the move only
fired once the pod carried Phoenix's `amtd.r6security.com/managed-by:
phorvex-phorvex-demo` guest-list annotation. Phorvex authored BOTH the AMTD strategy
and the matching event, so Phoenix's exact-match matcher fired deterministically.

> Operational note for active mode: ensure the AMTD a few seconds before the first
> event (let Phoenix stamp the guest list). Phorvex's standing-policy active loop does
> `EnsurePolicy` every tick, so by the time it actuates the pods are already stamped;
> the race is only visible in the one-shot proof.

---

## 5. No-regression (REAL)

- `go -C build/phoenix-extended build ./...` → exit 0; `go vet ./...` → exit 0.
- `go -C build/test-harness build ./...` → exit 0; `go vet ./...` → exit 0.
- No `go.work`; the `replace` is consumer-side only — **extended Phoenix and the
  harness are byte-for-byte untouched.** The Phoenix binary used for the proof was
  built to `c:\tmp` (no write into the phoenix-extended tree).

Clean teardown: `phorvex-demo` namespace deleted; the two Phorvex SecurityEvents
deleted; Phoenix process stopped. The `phorvexpolicies.phorvex.ai` CRD remains
installed (harmless).

---

## 6. Honest scope limits (P0)

- Optimizer is the **greedy top-B** (the PRD's stated MVP form); the offline
  Stackelberg/Markov-game mixed-strategy solver is a later phase.
- **CVSS/CVE utilities** are a roadmap input. This historical P0 risk blend consumed
  threat posture; the default P1 coverage engine does not. P1 consumes raw event
  severity once through kill-chain P(hold)/stage urgency and records the derived
  `ThreatPosture` scalar for audit only (PHORVEXSEC-58).
- **Prometheus ingest is real but was not exercised live** — the kind cluster has no
  Prometheus, so the run used K8s-only signals and reported telemetry absent (never
  fabricated). The `prometheus-http` source is implemented and wired (`--prometheus-url`).
- **NativeActuator** is a deliberate stub (`ErrNotImplemented`) — Phase 2.
- Active-mode actuation requires a **matchLabels** selector (Phoenix's AMTD guest list
  is matchLabels-only; matchExpressions on the AMTD is Phase 2).
- The physics residual / risk-blend weights and the quarantine-benefit factors are
  **flagged design proposals**, never paper or R6 numbers.

---

## 7. Reproduce

```powershell
# build/vet/test
go -C phorvex build ./... ; go -C phorvex vet ./... ; go -C phorvex test ./... -count=1
# install CRD + dry-run policy, run operator
kubectl apply -f phorvex/config/crd/bases/phorvex.ai_phorvexpolicies.yaml
kubectl apply -f phorvex/config/samples/phorvex_v1alpha1_phorvexpolicy.yaml
phorvex/bin/phorvex.exe --base-interval=5s --audit-json=audit.jsonl --metrics-bind-address=:8085
# Seam-1 proof (Phoenix must be running):
phorvex/bin/phorvex.exe --integration-emit --emit-namespace=<ns> --emit-pod=<pod> --emit-matchlabels=app=demo --emit-action=rotate
```

## 8. Artifact inventory

- `phorvex/api/v1alpha1/` — PhorvexPolicy CRD types + defaults + generated deepcopy
- `phorvex/internal/{model,registry,physics,feasibility,cost,belief,ctxprov,graph,exposure,ingest,actuator,decision,audit,metrics,runner,controller}/` — the engine
- `phorvex/cmd/main.go` — manager + one-shot Seam-1 emitter
- `phorvex/config/{crd,rbac,samples}/` — CRD, least-privilege RBAC, sample policy
- `phorvex/charts/phorvex/` — Helm chart (CRD + least-priv RBAC + Deployment)
- `phorvex/grafana/phorvex-heatmap.json` — risk heatmap dashboard
- `phorvex/README.md` — FR1–FR9 map + extension guide
- `phorvex/P0-REPORT.md` — this report
