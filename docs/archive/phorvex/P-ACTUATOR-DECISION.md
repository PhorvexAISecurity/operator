# P-ACTUATOR — Step 1 decision: Phorvex's own native actuator

**Date:** 2026-06-06 · **Status: DECISION FOR APPROVAL — STOP before building (Steps 2–3).**

Build Phorvex's **own native actuator** — its own hands — so it enacts its FULL real-time
dynamic action set as one cohesive standalone product. Keep everything extended Phoenix does
(lose nothing), absorb it as the BASE LAYER, ADD the advanced/AI actions, unify behind ONE
cohesive `Actuator` interface with shared safety/inviolability/kill-switch/audit. Both K8s and
AI first-class. Deterministic, no LLM. The brain (physics/context/optimizer/proactive) stays
UNCHANGED — the actuator is the new hands.

**Method.** A 5-expert search (K8s/operators, GPU ops, MTD actuation, distributed-systems
reliability, security): 4 seam-mappers → 5 experts → 3 architectures, **adversarially scored**
against an eligibility gate (ineligible if it drops any Phoenix capability, leaves any generatable
action unhandled, is K8s-only, or misses real-time safety on any action type). The synth verified
every load-bearing claim against `internal/`. I authored this decision from the structured result.

---

## 1. Candidates (all eligible; the gate is strict)

| Candidate (spine) | Total | Note |
|---|---:|---|
| **Unified Native Actuator** ✅ (one ActionHandler registry; build-enforced completeness) | **32/35** | winner on the tiebreak — completeness framed as provably failing CI, no misstated machinery |
| Enveloped Hands (safety-envelope-first) | 32/35 | architecturally equal, but **misstated proposed machinery as already-existing** (honesty deduction) |
| Retention-first, license-clean | 30/35 | most honest prose — self-corrected its own completeness claim DOWN (init-panic is runtime, not compile-time) |

The winner puts the weight on **one source of truth + a self-registering handler registry + a
build/CI-enforced completeness theorem**, and is the candidate that does not over-claim.

---

## 2. THE FULL ACTION SET — 12 native handlers (each one self-registering file)

**Retained extended-Phoenix base** (reimplemented natively as peer handlers):
| # | Action | Product | Native enactment | Rollback | SP-0 |
|---|---|---|---|---|---|
| 1 | `rotate` (=Phoenix Delete) | K8s | `Pods().Delete` w/ UID precondition; owner respawns clean | none (respawn IS recovery) | no |
| 2 | `quarantine` (=Phoenix Quarantine, **lead demo**) | K8s | deny-all NetworkPolicy + relabel-out-of-owner-selector (ReplicaSet/StatefulSet/DaemonSet/Job; matching Services when no owner selector is readable) + **ownerRef re-parent** (both, or the owner re-adopts) | reversible (snapshot labels/ownerRefs) | no |
| 3 | `debugger` (=Phoenix Debugger, NEW const) | K8s | `pods/ephemeralcontainers` Update | **irreversible** (K8s can't remove an ephemeral container) | no |
| 4 | `custom-inject` (=Phoenix CustomAction, NEW) | K8s | fixed bounded marker ephemeral-container (`echo phorvex-custom-action; sleep 1`); does not flush KV state | irreversible | no |
| 5 | `disable` (=Phoenix declaration, NEW) | K8s | declared-not-implemented (matches Phoenix's posture); EXCLUDED from emittable set, but the handler exists so completeness stays green | n/a | no |

**Advanced K8s** (native-only — Phoenix cannot):
| 6 | `identity-rotate` | K8s | declared-only for new execution; historical identity-epoch relabel did not rotate SA-token, UID or IP | restore historical label snapshots only | no |
| 7 | `route-rotate` | K8s | `Services()`/`EndpointSlices()` selector repoint — stales the learned route without denying all traffic | snapshot prior selector | no |

**Advanced AI/GPU** (native-only; structure ships now, **magnitudes `[SP-0-PENDING]`** under `GPUPresent=false`):
| 8 | `warm-swap` | AI/GPU | 5-phase restart-safe state machine: verify Ready shadow → flip leader → drain → retire old → rewarm | **provision-before-retire** (failed cutover re-flips to the alive old leader) | yes (ColdLoadSec) |
| 9 | `MIG-rebind` | AI/GPU | patch MIG device-request + affinity off the co-resident partition, then warm-swap cutover | re-flip to alive original | yes |
| 10 | `KV/session-reset` | AI | flush KV-cache/agent-session through the serving-client reset surface; **no pod kill** — the only move that defeats a wipe-surviving prompt-inject implant | none needed (dropping poisoned state IS the goal) | yes (KVRebuildSec) |
| 11 | `endpoint-rotate` | AI | re-key the served-model route / Service fronting `EndpointPath` | snapshot prior route | yes |
| 12 | `model-shard-replace` | AI/GPU | warm-swap-style replace a shard on target model-id/version | re-flip to alive original | yes |

**Source of truth:** `model.MutatingActions` = every const except `ActionNoop` and `ActionDisable`.
Both `actionset.enabledActions` (generator.go:61) and `decision.candidateActions` (engine.go:102)
— **today both hardcoded `{Rotate,Quarantine}`** — are rewritten to ITERATE it (policy-filtered) so
the two emit lists can never drift again (a live drift hazard today).

---

## 3. Phoenix-retention proof — lose nothing (two independent ways)
- **Path A — the Phoenix adapter stays byte-unchanged.** `phoenix.go` is untouched; any deployment
  can still drive Phoenix (the AMTD + SecurityEvent path). `RuleTypeFor` correctly stays 2-entry
  (Phoenix owns only its 2 Phorvex-private rules; advanced moves are native-only by construction).
- **Path B — the native actuator reimplements every retained capability as a peer handler** (Delete,
  Quarantine, Debugger, CustomAction, Disable) with **zero Phoenix imports**.
- **Honest note:** `model.Action` today holds only Noop/Rotate/Quarantine — Debugger/CustomAction
  **do not exist anywhere yet**, so "retain" for those means *reimplement faithfully from the K8s
  contract*; nothing existing is dropped because there is nothing there to drop.

---

## 4. Absorb-vs-reimplement + LICENSE (engineering posture — **NOT legal advice; flag for your lawyer**)
**Recommendation: clean REIMPLEMENT the whole native package; absorb nothing executable from Phoenix.**
Each retained basic is one-to-a-few client-go calls authored from the **published k8s.io API
contract** (Delete = 1 call; Quarantine = a NetworkPolicy literal + an ownerRef patch ~40 LOC;
Debugger/CustomAction = 1 ephemeral-container Update each). Native imports **only `k8s.io/*` +
`sigs.k8s.io/controller-runtime` — zero Phoenix imports** → the standalone IP is SSPL-unencumbered.
The SSPL-derived `PhoenixActuator` stays STRICTLY as the optional integration adapter (its Phoenix
import is confined to `phoenix.go`, loaded only when a deployment chooses the Phoenix layer). Keep a
**written clean-room record** (native handlers authored from k8s.io docs, not Phoenix source).
**Flag to counsel:** the SSPL §13 network-copyleft scope (does Phorvex-as-a-service trigger
source-availability for the combined work?); whether shipping the optional adapter in the same binary
changes the analysis; whether the clean-room record is sufficient. **Reimplement reduces, does not by
itself eliminate, the SSPL question — a lawyer must clear it before standalone GA.**

---

## 5. The completeness contract — the KEY guarantee (with honest precision on "fails the build")
**One source of truth + a self-registering handler registry + a check** (all reusing the existing
`registry.New` machinery — no new-mechanism risk):
- `actuator.HandlerRegistry = registry.New[ActionHandler]()`; each action self-registers via
  `init()→Register`. `NativeActuator.Actuate` dispatches `HandlerRegistry.Get`; a miss is a LOUD error.
- `GeneratableActions()` = union(`MutatingActions`, every `CoverByAction` key) — the **union is
  necessary** (a cover-less-but-listed action would otherwise slip through unhandled; verified the
  greedy self-prunes empty-cover actions at coverage.go:169).
- `internal/actuator/completeness_test.go`: **FORWARD** (every generatable action has a handler →
  `t.Fatalf`), **SYMMETRIC** (no orphan handlers), **COVER DUAL** (every CoverByAction key has a
  handler; no `[SP-0]` AI fact enters CoverByAction until handler+cover ship — machine-checks the
  falsifiability gate), **FEASIBILITY REACHABILITY** (every generatable action is named by ≥1
  feasibility constraint or an explicit `AlwaysFeasible` — this is what forces the per-action
  constraint files to exist).

> **HONEST PRECISION (the mandatory correction):** this is **NOT a compile-time error.** The teeth
> are (a) `go test` completeness_test.go = **CI gate** + (b) a package-level `var _ =
> mustCoverAllActions()` **init-panic = the binary cannot START** (`go build` still produces a
> binary; it dies on first run) + (c) optionally a golangci-lint `exhaustive` analyzer (the only true
> vet-time gate, easily skipped). **In a real CI pipeline this is not bypassable** and the eligibility
> clause becomes a CI-enforced theorem — but I will describe it as "fails CI + fails startup," not
> "fails the compiler." And it enforces a handler **EXISTS, not that it is CORRECT** (see §6).

---

## 6. Real-time safety for EVERY action type (4 layers free, 1 layer to-write)
- **Feasibility re-gate at the EMIT boundary (the decisive move):** `manager.actuate()` re-runs
  `feasibility.Evaluate(view, Move{Action}, pol)` — the SAME registry the generator uses — immediately
  before `Actuator.Actuate()`, replacing today's *trusted cached bool* (manager.go:365). Action-agnostic
  (keys only on `Move{Action}`), so "no infeasible move ever enacts" is structural for all 12 with zero
  per-action runner code.
- **Kill-switch, per-namespace dry-run, per-decision audit, budget B** — all **action-agnostic** (they
  wrap the single actuate boundary), retained from P2 (which proved inviolability + kill-switch +
  per-namespace dry-run + 139/139 audited) and extended to all 12 (audit gains
  `Handler/ObjectsTouched/RollbackRef/MutationKind` + per-action SHAP + R6 counterfactual).
- **Rollback per type:** provision-before-retire re-flip for the 3 stateful AI swaps; snapshot-undo for
  the reversible moves (quarantine/identity/route/endpoint); KV-reset needs none; Delete/inject forward-only.

> **HONEST — the load-bearing gap:** the **per-action feasibility LAWS are unwritten.** Every existing
> constraint is default-allow, and the GPU laws veto ONLY `ActionRotate` (gpuconservation.go:28,45). So
> the 9 new actions have **zero hard-law coverage until their constraint files exist.** "Safety for every
> action" is true only because the completeness test's feasibility-reachability arm **fails the build
> until they do** — the mechanism is sound, but **the constraint bodies are to-be-written, and the test
> enforces existence, not correctness.** Two other honesty flags: the "fail-closed kill-switch" is a
> *proposed* flip of today's fail-OPEN behavior (killswitch.go:44), not a retained property; and
> **quarantine fidelity is assertion-dependent** — a handler that misses the ownerRef re-parent compiles
> green but silently regresses the lead demo, so it MUST be asserted live on kind.

---

## 7. Standalone architecture + the new risk
**Three impls behind ONE byte-identical interface**, decided by deployment, not by a brain change:
**NativeActuator** (its own hands — writes Pods/NetworkPolicies/Services/EndpointSlices/Secrets/
ephemeral-containers directly, **no Phoenix CRDs installed**) · **PhoenixActuator** (the optional layer
adapter) · the stub-assertion seam-reality proof. Standalone = `Manager.Actuator = NativeActuator`;
driving Phoenix = a one-line wiring change. The brain imports ONLY the interface (proven by the
compile-time assertions + the single call site manager.go:374); `Action` is a string so 9 new moves are
additive with zero schema/brain change.

> **THE GENUINELY NEW ATTACK SURFACE — privilege widening.** The Phoenix path held only `phorvex.ai`
> CRD verbs; the native path writes core/networking/discovery objects directly, so a stolen actuator
> token is materially more dangerous. **Containment:** a separate, **namespaced, least-privilege
> ServiceAccount+Role (not ClusterRole) per protected tenant namespace**, granting only the exact verbs
> used. Must be reviewed and the RBAC explicitly approved before standalone GA.

---

## 8. Both products + prove-on-kind plan
**K8s (historically measured on kind):** rotate/quarantine/debugger/custom-inject/identity-rotate/route-rotate. The identity entry observed only an epoch relabel; it did not prove UID, IP or credential rotation and is declared-only for new execution.
are pure client-go, deterministic, no GPU. **AI (definition-complete now, magnitudes `[SP-0-PENDING]`):**
warm-swap/MIG-rebind/KV-reset/endpoint-rotate/model-shard-replace handlers self-register and the
feasibility *structure* ships, but every magnitude reads the `GPUPresent`-gated `PhysicsWitness`
(0/false on kind). **Verified:** an empty-cover action self-prunes in the greedy (coverage.go:169), so AI
moves add **zero selectable cover** on kind — the brain never enacts an uncalibrated AI move and no GPU
number is fabricated. A real-GPU adapter activates every AI magnitude with **zero actuator change**.

**Prove plan (measured / `[SP-0]`):** (1) **completeness guard proves itself** — delete one handler's
`init()`, confirm `go test` FAILS + the binary START fails (note: `go build` still succeeds); re-add →
green. (2) **Live native enactment on kind** — drive each K8s handler, verify cluster state (rotate→UID
change; quarantine→deny-all NP + relabel + **ownerRef re-parent asserted, RS does not re-adopt**;
inject→ephemeral container; identity/route→relabel/repoint). (3) **Lead demo re-verified against native
quarantine** specifically (the one place a regression can hide) — stateful job survives. (4) **Safety for
every action** — emit-boundary feasibility blocks an infeasible move per action; kill-switch suppresses
all 12; dry-run reaches no handler; budget B truncates; per-action audit populated; a simulated
warm-swap mid-failure re-flips cleanly. (5) **Harness re-run with `NativeActuator` replacing the Phoenix
seam** — assert byte-identical decisions (verified: `ablation.go` touches no Actuator, so the **1.62× is
a pure decision-layer property**; pin the `MutatingActions` iteration order — Rotate before Quarantine —
with a determinism test since `bestNet` ties break first-seen); **lead demo + P3 + 1.62× preserved-or-improved, REAL numbers.**

---

## 9. Honest open risks (carried openly)
1. **Per-action feasibility laws are unwritten** (the load-bearing gap) — the completeness test enforces a constraint *exists*, not that its *body* is correct.
2. **Privilege widening** — native writes core/networking objects directly; needs a separate namespaced least-privilege SA; review before GA.
3. **Quarantine fidelity is assertion-dependent** — miss the ownerRef re-parent and the lead demo regresses with no compile error; assert live.
4. **Debugger/custom-inject are irreversible** (K8s can't remove an ephemeral container) — only audit-flagging, no rollback. KV-reset is separate and does not inject an ephemeral container.
5. **All 5 AI/GPU magnitudes `[SP-0-PENDING]`**, unvalidated on real hardware; the provision-before-retire argument is sound in design, unproven against real cold-load/drain timing.
6. **Warm-swap's restart-safe state machine** (persisted phase, RequestID dedupe, crash-resume) adds distributed-systems complexity the codebase doesn't currently carry; needs failure-injection beyond the happy path.
7. **KV-reset depends on the model server exposing the serving-client flush surface**; without it the action is unavailable rather than degrading to custom-inject, which never flushes KV state.
8. **The 1.62×/P3 parity holds ONLY while AI moves add zero selectable cover** (GPUPresent=false); once GPU magnitudes activate and AI facts enter CoverByAction, the baseline must be **re-established, not assumed**.
9. **License is engineering posture, not legal clearance** — a lawyer must clear the SSPL question before standalone GA.

---

## 10. If approved — Step 2/3 + pass filters
**Build:** `model.MutatingActions` + the new Action consts; rewrite the 2 emit lists to iterate it
(determinism-pinned); the `HandlerRegistry` + 12 self-registering handler files (7 K8s real, 5 AI
structure/SP-0); `completeness_test.go` (forward/symmetric/cover-dual/feasibility-reachability) + the
`mustCoverAllActions()` init-panic; the emit-boundary feasibility re-gate; the 9 new per-action
feasibility constraint files; the audit + RBAC extensions; keep the brain UNCHANGED.

**Prove:** the completeness guard fails CI+startup on a removed handler (demonstrated); live K8s
enactment on kind (incl. ownerRef-faithful quarantine); real-time safety per action (kill-switch /
dry-run / audit / budget / rollback); harness re-run with the native actuator **preserves the lead demo
+ P3 + 1.62×** with REAL numbers; AI handlers present + `[SP-0-PENDING]`.

**PASS filters:** go build/vet/test green; **completeness invariant enforced (CI + startup, demonstrated
build-fail)**; every Phoenix capability retained (proven, incl. live quarantine fidelity); both products;
native actuator enacts the full K8s set live on kind; real-time safety proven for every action type;
harness re-run preserves lead-demo + P3 + 1.62×; deterministic; AI/GPU values `[SP-0-PENDING]`, never
fabricated; license-clean path applied + clean-room record.

---

## 11. Decision
**Build the Unified Native Actuator** — one self-registering `ActionHandler` registry (12 handlers: 7
K8s live + 5 AI `[SP-0-PENDING]`), driven by a single `MutatingActions` source of truth, behind the
byte-unchanged `Actuator` interface, with a **CI + startup-enforced completeness theorem**, the
feasibility gate re-run at the emit boundary, and the P2 safety envelope (kill-switch/dry-run/audit/
budget) extended to every action. Every extended-Phoenix capability is retained two ways (the adapter
stays + native reimplements). License-clean reimplement; flag the SSPL question for counsel.

**Honest headline:** this gives Phorvex its own hands and makes full real-time coverage a *provable
invariant* — with the precise caveats that the completeness check fails **CI + startup, not the
compiler**, enforces handler **existence, not correctness** (quarantine fidelity asserted live), the
**per-action feasibility law bodies are to-be-written**, the native path **widens privilege** (needs a
least-privilege SA), and **all AI/GPU magnitudes stay `[SP-0-PENDING]`** until a real GPU fleet.

**>>> STOPPING for your approval before building Step 2/3. <<<**
Approve the Unified Native Actuator (with the honesty corrections + the license-clean reimplement, as
scoped), or tell me to adjust scope first (e.g. K8s-handlers-only first, defer the AI state machines).
