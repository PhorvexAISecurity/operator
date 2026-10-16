# P4c-REPORT — Phorvex self-security hardening (F1–F6 built + proven by running)

**Date:** 2026-06-08 · **Status: BUILT + PROVEN ADVERSARIALLY.** The Step-1 threat model
([P4c-DECISION.md](P4c-DECISION.md)) found 10 defects (3 CRITICAL) and caught a fail-OPEN gate the panel had
rubber-stamped. This pass fixed F1–F6 **additively — decision logic byte-identical** — ran a **systematic
fail-closed sweep** of every safety gate, and proved each finding closed **by running** (admission denials,
the `can-i` matrix, the cross-tenant probe), not just by unit test. **Gates preserved:** 13 packages green,
`git diff` shows **decision/recon/killchain/physics source byte-unchanged**. `PHORVEX_ACTUATOR=native` stays
**OFF** pending your review.

## The systematic FAIL-CLOSED sweep (the headline — this was the 3rd fail-open found)
Every safety gate now fails CLOSED on error/uncertainty (each with a test):
| Gate | Was | Now (fail-closed) | Proof |
|---|---|---|---|
| Kill-switch read error | (P4b) actuated on any Get error | non-NotFound error → ENGAGED | `TestKillSwitchFailsClosedOnReadError` |
| **Emit re-gate map-miss (D3)** | **SKIPPED the re-gate → actuated on stale bool** | **missing live view → VETO** | `TestEmitRegateFailsClosedOnMapMiss` (LIVE actuate path) |
| **Kill-switch ns-empty (D4)** | **returned "not engaged" → actuated** | **client+empty-ns → ENGAGED** | `TestKillSwitchFailsClosedOnReadError` (d) |
| Feasibility law panic | would crash the tick | panic → VETO (infeasible) | `TestEvaluateFailsClosedOnLawPanic` |
| Dry-run / EnsurePolicy fail | (already) suppresses actuation | unchanged, confirmed | sweep audit |

## The fixes (F1–F6), each with its adversarial close-proof
### F5 / D3 — emit-boundary re-gate fail-CLOSED (CRITICAL; the caught rubber-stamp)
`manager.go` ran the re-gate only inside `if v, ok := viewByKey[k]; ok {` — a **map-miss skipped it** and
actuated on the cached bool. Now a missing live view **vetoes**. **Proof (live actuate path):** a
selected+feasible decision whose pod is absent from `viewByKey` → **0 actuations**; a present one still
actuates.

### F2 / D1 — ephemeral-container code-exec gate (CRITICAL)
Added the action-specific `code-exec-guard` feasibility law that debugger/custom-inject **lacked**: it vetoes
ephemeral-container injection in a **system namespace**. **Proof:** `TestCodeExecGuardDeniesSystemNamespace`
(kube-system/kube-public custom-inject → infeasible; tenant ns → passes to the other layers; rotate/quarantine
unaffected). Reinforced by F3 (admission) + F1 (RBAC) + the busybox-only handler image.

### F3 / D6 — CRD enum sync + a DESIGNED admission barrier (HIGH)
The shipped CRD enum was the *stale* `{rotate,quarantine,noop}` (an **accidental** code-exec block that
vanishes on regen). Synced it to the full 12-action vocabulary AND added a **ValidatingAdmissionPolicy**
(native CEL — a CRD `x-kubernetes-validations` rule **can't see `metadata.namespace`**, verified; a VAP can)
denying code-exec policies in system namespaces. **Proof (LIVE, kind v1.35):**
```
custom-inject policy in kube-system  → Forbidden: ValidatingAdmissionPolicy denied (system namespace)
custom-inject policy in a tenant ns  → created (admitted; gated by code-exec-guard + RBAC + image)
rotate/quarantine policy             → created (autonomous path intact)
```

### F1 / D2 — minimal namespaced actuator Role + dedicated SA (CRITICAL)
Committed `config/rbac/phorvex-actuator-role.yaml`: a **per-managed-namespace Role** (not a ClusterRole) bound
to a **dedicated `phorvex-actuator` SA** (split from the read/scanner SA), **no cluster-write**. Role A
(routine) = `pods[get;list;delete;update]` + `networkpolicies[create;get;delete]` + **`replicasets[get]`**
(kept — load-bearing for quarantine's stateful-preserving RS-detach / the lead demo); dropped the dead
`pods/patch`, `serviceaccounts;secrets`, `services`, `endpointslices`. Role B (code-exec) is a **separate,
off-by-default** opt-in. **Proof — `kubectl auth can-i` matrix (as the actuator SA):**
```
yes: delete/update/get/list pods · create/get/delete networkpolicies · get replicasets   (in <NS>)
no : delete pods --all-namespaces · delete pod -n kube-system · get/delete secrets ·
     update services · update endpointslices · patch pods · delete nodes
```
**Honest finding (proven by running):** an ephemeral-container injection (the `kubectl debug` *patch* path)
is **FORBIDDEN** for the Role-A SA — verified live (`cannot patch pods/ephemeralcontainers`). RBAC subresource
authz is cluster-dependent and `can-i` over-reports the `update` verb, so **the code-exec control does NOT
rest on RBAC subresource isolation alone** — it is the **layered, independently-proven** stack: the VAP
(admission) + the code-exec-guard (actuation) + `actions.enabled` off-by-default (the brain never selects
debugger/custom-inject unless enabled) + the busybox-only image. Role B + the kubectl-debug-blocked result are
belt-and-suspenders.

### F4 / D7 — cross-tenant leak (HIGH)
`/api/owner/events` skipped its tenant filter on an empty `?tenant=` (returned **all** tenants); `/api/live`
SSE had **no** tenant scoping. Both now **fail-closed** (empty tenant → nothing; scoped → only that tenant).
**Proof (LIVE, 2-tenant audit):** empty `?tenant=` → `[]`; `?tenant=tenant-a` → `[tenant-a]`; `?tenant=tenant-b`
→ `[tenant-b]`.

### F6 / D4 — kill-switch namespace bypass (HIGH)
Covered in the sweep (client + empty namespace → fail-CLOSED engaged). **D5 (policy-zeroable soft-law floors)
— STEELMANNED, deliberately NOT "clamped":** the availability/SLO/anti-over-rotation floors are *legitimately
operator-tunable* (a single-replica workload validly sets `minAvailable=0`); hard-clamping them would break
real configs. The correct control for a *malicious* policy is **admission + RBAC + budget**, all proven here:
a malicious policy is **bounded to its own namespace** (the namespaced Role — `can-i` shows no cross-namespace
write), **cannot target a system namespace** (the VAP), and is capped **per tick** (`MaxMovesPerTick`). The
honest residual is a **cumulative cross-tick blast-radius cap** (additive follow-up).

## P4a fixes RE-CONFIRMED under attack (the red-team tried and failed)
SSRF guard (IMDS v4+v6 blocked, dial-pinned vs rebind), `scoped()` default-deny, `rawlog`/`spa()` traversal
guards, `runs.go` exec hardening, audit logs carry **no secret contents**.

## Requirement coverage → proof
A (privilege-widening) → F1 minimal Role + `can-i` (LIVE). B (attack surface) → F3/F4 + P4a re-confirmed.
C (weaponization) → the VAP + code-exec-guard + namespaced RBAC (LIVE denials). D (fail-secure) → the
fail-closed sweep (4 gates + tests). E (both products) → the AI handlers route through the SAME re-gate +
code-exec-guard; GPU magnitudes `[SP-0-PENDING-P4]`. Filters: centerpiece closed ✅, nothing fabricated
(every claim ran) ✅, not K8s-only ✅, not a rubber-stamp (the fail-open D3 the panel missed is fixed +
proven) ✅.

## Gate preservation
13 packages green; `git diff` → **decision/recon/killchain/physics source byte-unchanged**. The
code-exec-guard vetoes ONLY debugger/custom-inject (never rotate/quarantine/AI) and the panic-recover is pure
robustness, so the `{rotate,quarantine}` decision on kind is byte-identical → **1.62× + P3 + lead-demo
preserved**. The actuator change is **only the additive RBAC/VAP manifests** + the two feasibility veto laws —
the existing handlers + the decision engine are untouched.

## Honest residual risks (carried)
1. **`PHORVEX_ACTUATOR=native` must stay OFF until you bind the namespaced Role** (the operator's wider write
   credential is the deployment step F1 enables; the in-process read/write *token* split is a deployment-model
   change, documented, not yet a dual-client in the binary).
2. **RBAC cannot cleanly isolate the ephemeral-container subresource** — the code-exec gate is the layered
   VAP+feasibility+opt-in+image stack (proven), not subresource RBAC.
3. **Tenant identity stays demo-trust** (spoofable `X-Phorvex-Lens`) until `[PENDING-P-VCLUSTER]`; the console
   must stay **code-enforced localhost-bound**.
4. **D5 cumulative blast-radius cap** + the warm-swap promotion-attestation (E) are additive follow-ups; GPU
   magnitudes `[SP-0-PENDING-P4]`.
5. The VAP requires `ValidatingAdmissionPolicy` (k8s ≥1.30 GA); on older clusters the feasibility+RBAC layers
   still hold and a webhook is the fallback.

**P4c BUILT + PROVEN — stopping for your on-screen review.** P4 (GPU/CoreWeave magnitudes) remains the final
separate stage. brain/decision-logic/recon/killchain + extended Phoenix + the attack harness are UNCHANGED.
