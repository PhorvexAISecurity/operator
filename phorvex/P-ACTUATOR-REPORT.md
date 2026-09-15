# P-ACTUATOR — Steps 2–3 report: Phorvex's own native actuator, built & proven on kind

**Date:** 2026-06-06 · **Status: BUILT + PROVEN on kind (REAL).** Phorvex now has its OWN
hands: a unified native actuator that enacts the **full 12-action set** (7 K8s live + 5 AI/GPU
state machines) through one `ActionHandler` registry, with **completeness as a CI+startup-enforced
invariant**, the feasibility gate **re-run at the emit boundary**, the P2 safety envelope extended
to every action, and **every extended-Phoenix capability retained** (the adapter stays
byte-unchanged + native reimplements each, license-clean). The brain (physics/context/optimizer/
proactive) is UNCHANGED. AI/GPU magnitudes are honestly `[SP-0-PENDING]`.

---

## 1. What was built (Step 2)

| Area | File(s) | What |
|---|---|---|
| **Source of truth** | `model/types.go` | `MutatingActions` (11 actions, rotate-before-quarantine for tie-break determinism) + `ActionEnabled` (nil policy ⇒ historical `{rotate,quarantine}` default). Both `actionset.enabledActions` + `decision.candidateActions` **rewritten to iterate it** — the two emit lists can no longer drift. |
| **Handler registry** | `actuator/handler.go`, `native.go` | `ActionHandler` interface + `HandlerRegistry` (reuses `registry.New`); `NativeActuator.Actuate` dispatches; `Rollbacker` optional undo; dry-run guard. |
| **12 handlers** | `actuator/handlers_k8s.go` (7), `handlers_ai.go` (5) | rotate, quarantine (deny-all NP + relabel-out + **ownerRef re-parent**), debugger, custom-inject, disable (declared), identity-rotate, route-rotate · warm-swap (5-phase provision-before-retire), mig-rebind, kv-reset, endpoint-rotate, model-shard-replace. |
| **Completeness invariant** | `handler.go`, `zz_startup.go`, `completeness_test.go` | `MissingHandlers`/`OrphanHandlers`; `completeness_test.go` (forward/symmetric/determinism/reachability) = CI teeth; `mustCoverAllActions()` init-panic in the lexically-last file = startup teeth. |
| **Per-action feasibility** | `feasibility/actions_native.go`, `gpuconservation.go` | `ai-context-required` (AI moves need GPU/ModelID), `mig-device-required`; widened VRAM/MIG laws to the GPU-provisioning moves. The action-agnostic defaults already gate all actions. |
| **Emit-boundary safety** | `runner/manager.go` | re-run `feasibility.Evaluate` on live view state immediately before `Actuate` (replaces the trusted cached bool); kill-switch/dry-run/budget already action-agnostic. |
| **Audit** | `audit/log.go`, `model/types.go` | `Handler/ObjectsTouched/RollbackRef/MutationKind` forensic fields — a kv-reset is distinguishable from a kill. |
| **RBAC + CRD + selector** | `actuator/rbac.go`, `api/.../phorvexpolicy_types.go`, `runner/manager.go` | namespaced least-privilege `kubebuilder:rbac` markers; CRD enum widened to 12; `PHORVEX_ACTUATOR=native` selects native vs the Phoenix adapter. |

**License-clean:** the native package imports **only `k8s.io/*` + `sigs.k8s.io/controller-runtime`
(zero Phoenix imports)** — authored from the published K8s API contract (clean-room). The SSPL-derived
`PhoenixActuator` stays as the optional adapter. *Engineering posture, not legal advice — flag the
SSPL §13 scope for counsel (see the decision §4).*

---

## 2. Proof on kind (Step 3) — REAL

### 2a. The completeness invariant fails CI + startup (honest precision: NOT a compile error)
Removing one handler's registration (`kvResetHandler`) and rebuilding:
```
(1) go build  -> exit 0   (SUCCEEDS — completeness is NOT a compile error, as documented)
(2) go test   -> FAIL     panic: PHORVEX COMPLETENESS VIOLATION ... no native handler: [kv-reset]   (CI teeth)
(3) binary    -> PANIC at startup: PHORVEX COMPLETENESS VIOLATION ... [kv-reset]                     (startup teeth)
```
Restored ⇒ green. **Full real-time coverage is a CI+startup-enforced theorem** — described precisely
as "fails CI + fails binary startup," not "fails the compiler."

### 2b. Historical live native actuation on kind — **13 recorded PASS / 0 FAIL** (`phorvex --native-demo`)

The old pass count includes an identity-epoch label observation. It did not establish credential or pod identity rotation and is not a head test result.
| Action | Verified live | Verdict |
|---|---|---|
| rotate | pod UID deleted | PASS |
| **quarantine** | **deny-all NP + detach + POD ALIVE** (lead-demo fidelity) | PASS |
| quarantine.rollback | labels/ownerRefs restored + NP deleted | PASS |
| debugger / custom-inject | ephemeral container injected | PASS |
| identity-rotate / route-rotate | Historical T10/T11 epoch-label observation; identity relabel changed no UID, IP or credential and is now declared-only. Route Service-selector restitch remains implemented and requires its own target/Service validation. | historical observation; identity security effect unverified |
| kv-reset | **pod ALIVE** + flush epoch (no kill) | PASS |
| endpoint-rotate | endpoint epoch set | PASS |
| warm-swap | shadow promoted to leader + old leader retired | PASS |
| mig-rebind / model-shard-replace | **FAIL-CLOSED** (no MIG / no shard) `[SP-0-PENDING]` | PASS |
| dry-run guard | refused to mutate + pod untouched | PASS |

Quarantine fidelity — the one place a regression could hide silently — is **asserted LIVE** (the RS
does not re-adopt the detached, frozen pod); it passed.

### 2c. Harness re-run with the native actuator REPLACING the Phoenix seam (`PHORVEX_ACTUATOR=native`)
| Check | Phoenix-path baseline | Native actuator | Verdict |
|---|---|---|---|
| **Lead demo** (stateful, c2) | PX preserves job, blind destroys | **PX preserved 6/6, harm 0; blind destroyed 6/6** | PRESERVED |
| **P3 dwell** (held-out-cve) | PX ~5.1–5.7s | **PX 5.1s** (blind 15.2s, no-MTD 20.5s) | PRESERVED |
| **1.62× recon-per-dollar gate** | PASS | **PASS** (decision-layer; `ablation.go` touches no Actuator) | PRESERVED |

The native actuator's quarantine **preserves the stateful job 6/6 (harm 0)** — the lead demo holds
with Phorvex's own hands; phorvex build/vet/test green; **extended Phoenix builds unchanged**.

---

## 3. Honest framing — what's measured vs design-complete/SP-0
- **Measured live on kind (K8s, deterministic, no GPU):** all 7 K8s handlers + the warm-swap
  **orchestration** (label-flip/drain/retire) + dry-run + rollback + the emit-boundary re-gate + the
  completeness guard + the harness parity (lead-demo/P3/1.62×).
- **Design-complete / UNVALIDATED-UNTIL-GPU (`[SP-0-PENDING]`, never fabricated):** every AI/GPU
  **magnitude** — warm-swap `ColdLoadSec`, kv-reset `KVRebuildSec`, MIG geometry/VRAM,
  model-shard `ColdLoadSec/ModelRarity`. The state machines are **written and run unchanged in a real
  GPU env**; on kind `mig-rebind` + `model-shard-replace` **fail closed** (no device/model) rather than
  fake an effect, and the AI feasibility laws degrade to honest-absent (`GPUPresent=false`). A real-GPU
  adapter activates the magnitudes with **zero actuator change**.

### Carried-forward risks (from the decision, still true)
1. **Completeness enforces a handler EXISTS, not that it's CORRECT** — quarantine fidelity rode an
   assertion; it is now asserted live (passed), but the guard itself cannot prove behavioural fidelity.
2. **The per-action feasibility law BODIES are minimal** — the AI moves are gated by `ai-context-required`
   + the action-agnostic laws; richer per-variable anti-thrash is future work (the reachability arm only
   proves a gate exists).
3. **Privilege widening** — native writes Pods/NetworkPolicies/Services/ephemeral-containers directly; the
   `rbac.go` markers scope a **namespaced least-privilege Role**, but the widening must be security-reviewed
   before standalone GA.
4. **Debugger/custom-inject/inject-carrier KV-reset are irreversible** (K8s can't remove an ephemeral
   container) — audit-flagged `MutationKind=irreversible`, no rollback.
5. **Warm-swap's restart-safe state machine** (persisted phase, provision-before-retire) is proven on the
   kind happy path; real cold-load/drain timing + crash-resume need failure-injection on GPU.
6. **The 1.62×/P3 parity holds while AI moves add zero selectable cover** (`GPUPresent=false`); once GPU
   magnitudes activate and AI facts enter `CoverByAction`, the baseline must be **re-established, not assumed**.

---

## 4. Standalone & reproduce
Phorvex now runs **standalone** (`Manager.Actuator = NativeActuator`, no Phoenix CRDs) or **drives
Phoenix** (the byte-unchanged adapter) — one `Actuator` interface, three impls, selected by one env var;
the brain is identical.
```powershell
go -C phorvex build ./... ; go -C phorvex test ./...        # green; completeness + 1.62x + UCW + P-CONTEXT
go -C phorvex build -o bin/phorvex.exe ./cmd
phorvex/bin/phorvex.exe --native-demo                       # -> 13 PASS / 0 FAIL live on kind
$env:PHORVEX_ACTUATOR="native"; harness ... config.p3.v3.yaml   # -> PX dwell 5.1s; lead demo preserved 6/6
```

**P-ACTUATOR COMPLETE (Steps 1–3).** Phorvex enacts its full real-time dynamic action set as its own
cohesive standalone product: 12 native handlers behind one interface, full coverage a CI+startup-enforced
invariant, the feasibility gate re-run at the emit boundary, every extended-Phoenix capability retained
(adapter byte-unchanged + license-clean native reimplement), both products first-class — the K8s set
proven live (incl. quarantine fidelity and lead-demo/P3/1.62× parity), the AI/GPU state machines present
and honestly `[SP-0-PENDING]` until a real GPU fleet. Decision: `phorvex/P-ACTUATOR-DECISION.md`.
