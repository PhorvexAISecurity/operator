# T1-E — 05 Evidence

Base `5fe1c8e` (`v0.4.84`) · go1.27.1 · `GOTOOLCHAIN=local GOFLAGS=-mod=readonly` · 2026-09-05. T0-A live-satisfied (installed CRD 17/17, K3 bus 345-reply).

## Change set (21 files; `04-diff.patch`)
**New:** `internal/authz/{ssar,ssar_test}.go` (cached SSAR, fail-open), `internal/capability/{gate,gate_test}.go` (the one predicate home + gate), `internal/model/installed.go` (NotInstallable set + pure diff), `internal/actuator/verbs.go` (the single verb-set source).
**Modified:** `actuator/{actuator,native,phoenix,hybrid}.go` (SupportsAction = transport-only), `actionset/generator.go` (gate via Deps.Eligible + EligibilityKind/RBACUnknown), `model/decision_trace.go` (3 kinds + ineligible status + rbacUnknown + validator flip), `decision/coverage.go` (structural eligibilityTrace arm + gate wiring + metrics), `runner/{actions_supported,manager}.go` (∃ de-OR + per-tick witness + Authz field), `metrics/metrics.go` (2 counters), `cmd/main.go` (SSAR checker wiring), `charts/phorvex/templates/rbac.yaml` (the one Role line), + 3 runner test mocks.

## What was built (all green)
- **Four exclusion classes, cheapest-first, SSAR last** (`capability.Witness.Eligible`): not-installable → no-cover → capability-unsupported → no-rbac; first-failure-wins; exactly one reason per excluded action. An ineligible-by-a-cheaper-check candidate never triggers an SSAR (P-BOUNDED-AUTHZ by construction).
- **SSAR error ⇒ NOT excluded** (fail-open + flag + counter, P-NO-FREEZE). Deny ⇒ excluded. Cache per (ns,verb), TTL 5m, errors never cached.
- **One predicate home:** the per-pod capability predicate was EXTRACTED from the pre-T1-E `runner.unsupportedEnabledActions` (it read `model.Pod`'s typed witnesses), de-smeared (per-pod conjunction, ∃-aggregation), and pool indices precomputed ONCE per tick (R1: zero per-candidate fleet scans). Both the gate (actionset) and the status (runner) call it — no M-20 mirror.
- **M-19** (guardrail-rotate on a non-guardrail pod) and **M-79** (mig-rebind while node-exec transport unwired) are now excluded pre-scoring with a reason; `actuator.SupportsAction` answers the transport leg (the only fixture the actuator package uniquely knows).
- **Record:** structural trace mapping (`eligibilityTrace`, no string sniffing); T0-C's `not-installable` status emitter finally reachable (validator flipped from reject → status↔kind consistency); two new closed-vocabulary kinds; no-cover reuses recon-cover byte-identically.

## Tests
- `authz`: deny-excludes / error-fails-open / per-namespace; **cache bound (100 checks → 1 SSAR)**; error-not-cached. → ticket (c),(e).
- `capability`: all-predicates-green; **config predicates** (mig/serving/lora/guardrail/route/gpu-nodes) ported to per-pod `Capable`; **cheapest-first order** (a,b,d,g); **M-79 transport-unwired**. → (a),(b),(d),(g).
- `runner`: **∃-not-OR kill shot** (smeared conjunction: pod A GPU / pod B endpoint → kv-reset unsupported; old fleet-OR said supported) + quiet-on-heterogeneity; debounce/event/upsert retained. → (f) + M-20 old-fails/new-passes.
- **RED positive control** (`evidence/RED_gate.txt`): remove the capability check → order test FAIL (`want capability-unsupported, got <nil>`); revert the de-OR to a fleet-OR → kill-shot FAIL (`want kv-reset unsupported, got []`); revert → green.
- **Full module:** `go build ./...` clean; `go test ./...` — **zero new failures**; the only FAIL is the pre-existing `internal/recon` (M-157, unrelated). gofmt clean on all authored files.

## Metrics
`phorvex_candidates_excluded_total{tenant,action,reason}` + `phorvex_candidates_rbac_unknown_total{tenant,action}`, emitted at the generate site.

## P3 fixes (K3 bus 351, CHANGES-REQUESTED → all applied)
1. **`rbacUnknown` now reaches the trace row** — added `RBACUnknown` to `DecisionCandidateV2`, populated at the actionset.Candidate→V2 conversion (coverage.go), stamped in `buildActionStatus`'s wasGenerated branch. (3 edits; the field is no longer dead.)
2. **verbs completeness test added** (`actuator/verbs_test.go`) — map keys == `model.MutatingActions` (+ well-formedness). It immediately caught a real defect: `disable` was in the verb map but is declared-only (not a MutatingAction, never generated) → removed. RED re-run: dropping a verb entry FAILs the test.
3. **Pool-predicate tests ported** to `capability/gate_test.go`: request-drain `servingServiceSelects` (was zero-test, new logic), zero-MIG-capacity-not-a-GPU-node, label canonicality (TRUE≠true), unrelated swap-group/model-shard rejection, parallel-shard group (no-size / incomplete-with-duplicate-rank / complete), non-AI-pod-uncapable-for-all-9, + mig-node/mig-gpu-id folded into the config table.
- Nit: dropped the unused `Target.Annotations`. K3 filed the NotInstallable-discovery deferral as **M-158**.
Patch now 22 files (+verbs_test.go). Full module: zero new failures.

## Scope-fidelity deviations (recorded)
1. **`RequiredVerbs` is a single authoritative map + completeness intent (`actuator.RequiredVerbs`), not a method on all 16 handlers** — lower ripple, more testable, same "one source of truth from code." Verbs are the MUTATING ops per handler (reads excluded: broadly granted + bounds SSAR).
2. **`internal/runner` edited** (the fleet-OR removal) though the ticket's Code field omits it — unavoidable; K3 concurred.
3. **`actuator.SupportsAction` is transport-only**; config predicates read `model.Pod` typed witnesses in `capability` (03 addendum; K3 accepted bus 348).
4. **`ActionsSupported` status is now Honest-∃** (K3 bus 348 ruling (i)): unsupported iff ZERO pods fully eligible — a live status behavior change (the M-20 fix); per-pod gaps in the message, not the flip.

## NOT done (deferred, recorded)
- **NotInstallable BOOT DISCOVERY** — `model.NotInstallable` is empty (honest on a 17/17 CRD); the reason + mechanism + gate + trace + test all exist, but populating the set from live CRD-enum discovery at boot is deferred (T1-E-followup). On this cluster it is empty either way, so the gate behaves identically; a STALE deployed CRD would not yet be caught until discovery lands.
- **L3** (K3): per-pod exclusions visible, not-installable empty @17/17, rbac-unknown counter zero-absent-errors, SSAR rate bounded, ActionsSupported condition-diff = exactly the smeared-conjunction pods.
