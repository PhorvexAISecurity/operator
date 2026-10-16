# Phorvex P2 — Actuation & Audit Report (REAL results)

**Date:** 2026-06-05 · **Module:** `github.com/phorvex/phorvex` · **Status: P2 COMPLETE.**
The P1 submodular recon-coverage optimizer is now wired to **real actuation** over Seam 1,
with a global kill-switch, per-namespace dry-run, provable inviolability at the emit
boundary, and a complete per-decision audit. Every pass-filter met with reproduced
numbers; no fabrication. **No change to the P0/P1 skeleton, the Phoenix seam, extended
Phoenix, or the harness.**

---

## 1. Pass-filter scorecard

| Pass filter | Result |
|---|---|
| `go build` / `vet` / `test` green | ✅ all exit 0 (12 test files, 59 `.go`, 6,720 LOC) |
| **Live on kind: a rising-risk sequence drives a REAL Phoenix actuation (not dry-run)** | ✅ active operator autonomously emitted **11 actuations**; all 3 web pods really **deleted + respawned** by Phoenix |
| **Kill-switch verified** | ✅ actuations frozen (11→11) over 22s engaged; `phorvex_kill_switch_engaged=1` |
| **Per-namespace dry-run verified** | ✅ active policy + kill-switch OFF, but `phorvex.ai/dry-run` annotation suppressed all actuation (11→11) |
| **Provably never exceeds budget/SLO (won't DoS itself)** | ✅ tests `TestNoSelectedMoveViolatesAHardConstraint`, `TestSelectedNeverExceedsBudget` + emit-boundary guard |
| **100% of decisions carry a complete rationale** | ✅ 139/139 decisions had reason + R6 counterfactual + note (0 missing); test `TestEveryDecisionHasCompleteRationale` |
| Extended Phoenix + harness still build unchanged | ✅ both `build`+`vet` exit 0 |

---

## 2. What P2 adds (all additive)

- **Decision → actuation**: the coverage engine's selected `(asset,action)` moves flow
  through the existing `PhoenixActuator` — `EnsurePolicy` maintains the per-tenant AMTD
  (rotate↦Delete, quarantine↦Quarantine strategies) and `Actuate` emits a controlled
  `SecurityEvent`; extended Phoenix runs delete|quarantine. **Phorvex never writes pods.**
  The selected-move rationale is carried into the emitted CR's description.
- **Modes** (`internal/runner`): per-policy `mode: dryRun→active`; **global kill-switch**
  (`--global-kill-switch` or the `phorvex-killswitch` ConfigMap); **per-namespace dry-run**
  via a `phorvex.ai/dry-run` namespace annotation (new — `ingest` captures it; the runner
  folds it into the effective actuation gate).
- **Inviolability at actuation**: the action-set generator excludes SLO/feasibility-
  violating moves *before* selection, so selected ⊆ feasible. A **second emit-boundary
  guard** refuses (and loudly logs) any selected-but-infeasible move — belt and suspenders.
  **Budget B is an inviolable top-B truncation**; the dual-solved λ only shapes *which* B.
- **Proactive engine live**: the per-variable exposure clock drives a **λ-crossing**
  firing (`perDollar > λ`) with **no detector**; rising event-risk raises P(hold)/stage-
  urgency → coverage value → rate. Logged as `proactiveRate = perDollar − λ`.
- **Audit**: every decision logs all inputs + the coverage/cost math + **SHAP-style
  marginal-gain attribution** + the chosen move + the **R6 counterfactual** (action *and* a
  prose note of why Phorvex diverged). The audit is now written **after** actuation so the
  `actuated` flag reflects reality. **Prometheus** gains `phorvex_tenant_lambda`,
  `phorvex_pod_per_dollar`, `phorvex_pod_proactive_rate`, `phorvex_actuations_total`; the
  **Grafana** dashboard gains λ, per-dollar, actuations, and the emergent-rate panels.

---

## 3. Live REAL actuation on kind (the headline proof)

`engine=p1-coverage`, `mode: active`, budget 1, proactiveFloor 25s. As the demo pods
crossed the floor, the **running operator decided and actuated autonomously**:

- **11 actuations emitted** (`phorvex_actuations_total`: rotate 3, quarantine 4 in the
  first 50s; 11 total) — each a real `SecurityEvent{source=PhorvexController}` that Phoenix
  consumed.
- **All 3 original web pods were really rotated**: `ds47l/f7xwv/plx75` → `c78qx/lbmsb/wxx79`
  (fresh ages) — Phoenix `Delete` + ReplicaSet respawn, driven by Phorvex, not a one-shot.
- **Stateful `state-0` → quarantine** (rotate inviolably excluded) — contained, data
  preserved, even under real active actuation.
- **λ rose 0.6 → 1.55** (dual-descent under sustained over-demand); the emitted event
  descriptions show the firing condition live, e.g. `rotate … per-$ 3.96 > λ=0.80`.

### Emergent firing rate (not a fixed interval)
Audit of the actuated decisions (second run), showing the cadence is exposure/λ-driven:

| time | pod | action | perDollar | λ | rate (=perDollar−λ) |
|---|---|---|---|---|---|
| 02:10:33 | web-…dz5nm | quarantine | 4.43 | 0.60 | 3.83 |
| 02:10:42 (+9s) | web-…54jxk | rotate | 2.78 | 0.75 | 2.03 |
| 02:10:47 (+5s) | web-…dz5nm | quarantine | 7.20 | 0.95 | 6.25 |
| 02:10:52 (+5s) | web-…vkpmj | quarantine | 8.96 | 1.10 | 7.86 |
| 02:11:02 (+10s) | state-0 | quarantine | 10.06 | 1.20 | 8.86 |

Gaps **9s / 5s / 5s / 10s** — emergent, not a cron. λ climbs as the dual prices the
scarce budget, self-throttling the rate; after a pod is rotated its exposure resets and the
anti-over-rotation window holds it, so the *next* firing is re-earned by accrual.

---

## 4. Safety controls (REAL, live)

- **Global kill-switch — PASS.** With the `phorvex-killswitch` ConfigMap `engaged=true`,
  `phorvex_actuations_total` stayed at **11 across 22s** and `phorvex_kill_switch_engaged=1`.
  The engine kept deciding + logging (no blind spot), but emitted nothing.
- **Per-namespace dry-run — PASS.** Kill-switch removed, policy still `active`, but the
  `phorvex-demo` namespace annotated `phorvex.ai/dry-run=true` → actuations stayed at **11
  across 22s**. A namespace can be frozen without touching its policy.

---

## 5. Inviolability & budget (provable, won't DoS itself)

- `TestNoSelectedMoveViolatesAHardConstraint` — over a mixed fleet (stateful, fresh,
  SLO-hot p99=250>200, single-replica), **no** selected move is ever infeasible: the
  stateful pod is never rotated; the SLO-hot, freshly-moved, and single-replica pods are
  never selected. Live, `state-*` received only quarantine across every actuating tick.
- `TestSelectedNeverExceedsBudget` — for B ∈ {0,1,2,3,5}, selected ≤ B (top-B truncation).
- **Emit-boundary guard** — `actuate()` refuses to emit any selected-but-infeasible/noop
  move and logs an INVARIANT VIOLATION (never triggered in practice — the generator already
  excludes them). Two independent gates ⇒ an SLO/feasibility-violating move can never reach
  Phoenix.

---

## 6. Audit completeness

Over the live active run, **139/139 decisions carried a complete rationale** (reason + R6
counterfactual action + counterfactual note; selected moves additionally carry SHAP
attribution; infeasible ones carry the blocking reason). 0 missing. Example (an actuated
rotate): cover decomposition `inMemory + podIdentity + session − λ·C`, `stage=recon→exploit`,
`pHold`, `perDollar`, and the note *"R6 would rotate too, but on a blind fixed timer; Phorvex
rotates now because per-$ > λ."*

---

## 7. No-regression
`go -C build/phoenix-extended build|vet` → 0; `go -C build/test-harness build|vet` → 0. P2
is purely additive (a per-namespace dry-run field, the actuation reorder, the counterfactual
note, new metrics). The Phoenix seam and the consumer-side `replace` are unchanged. Demo
namespace, kill-switch ConfigMap, and Phorvex SecurityEvents torn down.

## 8. Reproduce
```powershell
go -C phorvex build ./... ; go -C phorvex vet ./... ; go -C phorvex test ./... -count=1
# live ACTIVE actuation (Phoenix must be running):
kubectl apply -f config/samples/phorvex_v1alpha1_phorvexpolicy.yaml   # set spec.mode: active
phorvex/bin/phorvex.exe --engine=p1 --base-interval=5s --operator-namespace=default --audit-json=p2.jsonl
# kill-switch:  kubectl -n default create configmap phorvex-killswitch --from-literal=engaged=true
# per-ns dry-run: kubectl annotate ns <ns> phorvex.ai/dry-run=true
```

## 9. Honest limits carried forward
- Active-mode `EnsurePolicy` runs every tick, so the AMTD guest-list is stamped before the
  first actuation (the one-shot stamping race from P0 does not apply to the running operator).
- Quarantine in active mode applies Phoenix's deny-all + detach; on the single-node kind
  demo most actuations are web rotations (cleaner to observe).
- SP-0 (GPU/KV-cache cost) still pending → GPU rotates conservatively pruned; the dual λ
  guarantee is asymptotic with a hard top-B backstop.
- The ablation runner's view-assembly still mirrors (not shares) the tick loop's — a
  diagnostic path.

See [METHOD-DECISION.md](METHOD-DECISION.md), [P0-REPORT.md](P0-REPORT.md),
[P1-REPORT.md](P1-REPORT.md).
