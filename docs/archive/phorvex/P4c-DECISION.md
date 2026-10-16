# P4c-DECISION — Phorvex self-security review + threat model (for approval; change nothing)

**Date:** 2026-06-08 · **Status: THREAT MODEL — STOP for approval. Build/change nothing.** A 16-agent
premortem-driven review (4 code-readers → 10 world-class adversarial personas → a red-team judge → synthesis)
**attacked Phorvex at source.** Panel scores converged high (privilege-widening 9 · attack-surface 9 ·
weaponization 9 · fail-secure 8–10 · both-products 7–9). **Adversary verdict: PASS WITH MANDATORY
CORRECTIONS** — the centerpiece is genuinely (not cosmetically) closable, and the red-team caught a **partial
rubber-stamp** (one "inviolable" gate is actually fail-open) that this doc folds in.

> **PREMISE CORRECTED AT SOURCE (load-bearing).** The brief assumed the shipped actuator ClusterRole carries
> broad pod/NetworkPolicy *write*. **VERIFIED FALSE:** `config/rbac/role.yaml` + `charts/.../rbac.yaml` grant
> pods/NP/nodes/configmaps/RBAC = **get;list;watch ONLY**; the only writes are on `amtd.r6security.com` +
> `phorvex.ai` CRDs. So **as-shipped, every native write is RBAC-Forbidden — the dangerous handlers don't
> fire today.** The real defect is *subtler and worse for a self-security claim* (below).

## A — PRIVILEGE-WIDENING (the centerpiece)
**The real defect (3 parts, file-grounded):**
1. **No committed least-privilege write Role.** The per-tenant namespaced write Role exists ONLY as
   **unrendered kubebuilder markers** (`internal/actuator/rbac.go:26-32`) — `controller-gen` was never run, no
   Role/RoleBinding YAML exists, nothing is bound. The markers document intent but grant nothing.
2. **The only committed write-capable binding is cluster-wide.** So for `PHORVEX_ACTUATOR=native` to actuate,
   an operator must hand-grant the write verbs out-of-band, and any realistic grant lands **cluster-wide,
   unpinned in source.**
3. **No credential separation.** `selectActuator` (`manager.go:88-93`) passes `mgr.GetClient()` to the native
   actuator — the **read scanner and the write actuator share ONE ServiceAccount token** (the kill-switch
   rides it too).

**The ephemeral-container code-exec path (CRITICAL, verified `handlers_k8s.go:202-243`).** `debugger` /
`custom-inject` call `SubResource("ephemeralcontainers").Update` appending a container — **IRREVERSIBLE** (K8s
cannot remove it), hardcoded `busybox:1.36` / `sh -c` → **a shell in the victim pod sharing its SA
token/network/volumes.** They're in `model.MutatingActions` + the Go CRD enum, and **there is NO action-specific
feasibility law** (`actions_native.go` gates only AI moves + mig-rebind) → they pass on ANY pod (incl.
kube-system) once enabled. The **only** barrier today is an *accidental* stale-CRD enum (below) that vanishes
on the next regen.

**Also found:** dead/over-broad markers in `rbac.go` — `serviceaccounts;secrets get;delete` backs a documented
**no-op** (`identityRotateHandler` never touches a Secret), and `services`/`endpointslices` verbs are dead
(route/endpoint-rotate touch only pod labels). Granting that Role would let a stolen token **wipe Secrets** for
zero functional benefit.

### The minimal least-privilege actuator Role (red-team-verified sufficient)
Generate + **commit** a **namespaced Role + RoleBinding per managed namespace** (no ClusterRole, no
cluster-write), bound to a **dedicated actuator SA** distinct from the read/scanner SA:
- **Role A — routine** (per ns): `pods [get;list;delete;update]` · `networkpolicies [create;get;delete]` ·
  **`replicasets [get]`** *(LOAD-BEARING — quarantine's RS-detach reads the owning RS selector; dropping it
  re-adopts the frozen pod and destroys the stateful job = the exact lead-demo failure → MUST keep)*.
- **Role B — code-exec** (SEPARATE, **off by default, opt-in per ns**): `pods/ephemeralcontainers [update]`
  ONLY — never co-granted with routine verbs.
- **DROP entirely:** `pods patch` (unused), `serviceaccounts;secrets` (dead), `services` + `endpointslices`
  (dead). No `nodes`, no cluster-scoped verbs.
- **`kubectl auth can-i` close-proof:** EXPECT *yes* — delete/update/get/list pods, create/get/delete NP, get
  replicasets in a managed ns; *no* — `delete pods --all-namespaces`, `delete pod -n kube-system`,
  `delete secrets -n managed`, `update services -n managed`, `update pods/ephemeralcontainers` unless Role B
  bound.

**Steelman (tighter-RBAC vs functionality):** dropping `replicasets get` would tighten the Role but **break
quarantine's stateful-preserving detach** (the lead demo). Keep it. **Steelman (approval-gate vs autonomy):**
gate ONLY the irreversible/code-exec minority (debugger/custom-inject/warm-swap/model-shard-replace); leave
`rotate`/`quarantine` autonomous so the 1.62×/P3/lead-demo loop is untouched.

## B — FULL ATTACK-SURFACE AUDIT
**P4a fixes CONFIRMED HOLD (the red-team tried and failed):** the SSRF guard (`safefetch.go` — scheme
allowlist, IMDS v4+v6 blocked, all-resolved-IPs checked, dial-pinned vs rebind, no-redirect; covers
`/api/metrics` + `/api/scan?prometheus-url=`) · `scoped()` default-deny · `rawlog`/`spa()` traversal guards ·
`runs.go` exec hardening (whitelist + `scenarioRe` + arg-vector + rate-limit) · audit logs **no secret
contents**.

**NEW DEFECTS (file-grounded, adversary-confirmed):**
| # | Sev | Defect |
|---|---|---|
| D1 | **CRITICAL** | **No code-exec feasibility law** — debugger/custom-inject pass on ANY pod (incl. kube-system) once enabled; ephemeral-container = irreversible in-pod RCE |
| D2 | **CRITICAL** | **No committed least-privilege write Role** + cluster-wide binding + single shared SA token (§A) |
| D3 | **CRITICAL** | **Emit-boundary re-gate FAIL-OPEN on a map-miss** — `manager.go:437 if v, ok := viewByKey[k]; ok {` *skips* the inviolability re-check when the key is absent (only 1/9 personas caught it; the "structural inviolability" claim was a partial rubber-stamp) |
| D4 | HIGH | **Kill-switch namespace-empty bypass** — `killswitch.go:37-39` returns "not engaged" before any read if `Namespace==""`; and config ships **no Deployment manifest** wiring the sentinel |
| D5 | HIGH | **Soft-law relaxation** — availability/SLO/anti-over-rotation floors are policy-parameterized + zeroable (`P99Ms=0`, `MinAvailableReplicas=0`, `AntiOverRotationWindow=0`) → an attacker-authored active policy enables fleet DoS |
| D6 | HIGH | **CRD enum drift** — shipped CRD enum is stale `{rotate,quarantine,noop}` vs the 12-action Go marker; the *accidental* code-exec admission block **silently vanishes on the next `controller-gen` regen** |
| D7 | HIGH | **Cross-tenant leak** — `/api/owner/events` fail-open on empty `?tenant=` (`server.go:249`) returns ALL tenants; `/api/live` SSE applies **no** tenant scoping |
| D8 | MEDIUM | **Cross-tenant defense-suppression** — the shared cluster-wide blast-radius normalization denominator (mounted-secret count in `genericAssetValue`) is the **only genuine cross-tenant brain poison** (no grant/policy needed) |
| D9 | MEDIUM | **Console exec env-inheritance** — `envBase()=os.Environ()` → every triggered subprocess inherits `AWS_*`/`KUBECONFIG` (credential-blast-radius; downgraded from "AWS cred theft") |
| D10 | LOW | SSRF residual — `blockedTarget` doesn't block RFC1918 outright (gated by `--metrics-allow`; operator-config caveat); dead over-broad `rbac.go` markers |

## C — WEAPONIZATION (defense → weapon) + controls
The premortem's ranked paths: **P1 [CRITICAL]** ephemeral-container RCE (foothold = author a policy in a ns
you control or plant in kube-system + native grant + CRD regen) → busybox shell in the victim, irreversible.
**P2 [CRITICAL]** cluster-wide weaponization once the write credential is granted (one token). **P3 [HIGH]**
quarantine-all/rotate-all fleet DoS (broad selector + self-relaxed floors; per-tick cap only — **no cumulative
cap**, `MovesThisWindow` is a status counter never read back). **Controls:** the namespaced Role (D2), the
code-exec hard gate + image/command allowlist + system-namespace denylist (D1), a ValidatingWebhook bounding
selector/actions/namespace (D5/D6), a cumulative blast-radius cap.

## D — FAIL-SECURE (adversarial)
**Holds (forge-proof):** the emit-boundary re-gate re-derives feasibility from *live* state (a crafted policy
cannot forge a feasible verdict without in-process code-exec); `stateful-integrity` + `ai-context-required` +
`mig-device-required` are **non-relaxable**; the kill-switch is a cluster ConfigMap (not policy-driven);
NaN self-suppresses in selection. **Bypassable (must fix):** D3 (re-gate fail-open on map-miss), D4
(kill-switch namespace-empty), D5 (policy-relaxable soft floors). **Correction:** the "structural inviolability
proof" is qualified to the *hit path*; F5 makes it fail-closed-on-miss.

## E — BOTH PRODUCTS (AI/GPU vectors)
**Warm-swap = leadership hijack** (the marquee): `readyShadow` trusts `role=warm-shadow`+`model-loaded=true`
labels **with no provenance** → an in-namespace label-write stages a malicious leader, the Service reroutes,
the real leader is deleted; the P4b crash-resume keeps the attacker's fresh shadow. **Control:** signed/
controller-set promotion attestation (image-digest allowlist / SA-bound identity), not a self-settable label.
**kv-reset = forced session/KV wipe** through its separate serving-client action; custom-inject is only a
fixed bounded marker and does not flush KV state. **model-shard-replace / mig-rebind** = model-swap / device manipulation. GPU magnitudes
`[SP-0-PENDING-P4]` — the K8s-mechanical halves are exploitable/defensible now; the quantitative GPU exposure
is unvalidated-until-GPU.

## Requirement-coverage map
A → privilege-widening + minimal-Role (premise corrected; the 3-part defect; code-exec path). B → all ~22
endpoints + CRD + ingest + audit + supply-chain (P4a holds; D1–D10). C → 9 additive controls each with a
close-proof. D → forge-proof gates + the 3 bypasses corrected. E → AI/GPU state machines + input-trust gaps,
GPU `[SP-0-PENDING-P4]`. Ineligibility filters: centerpiece covered ✅, nothing fabricated (all source-cited)
✅, not K8s-only ✅, **not a rubber-stamp** (the red-team caught + corrected the one over-claim) ✅.

## Gate preservation
This is a REVIEW — it changes nothing. Every Step-2 fix is **additive RBAC/validation/guardrail** hardening:
the brain/optimizer (`engine.go`/`coverage.go`)/recon/killchain/physics are **untouched** (the action-risk
gate + webhook are emit-time/admission-time VETO-only, never altering selection math); the approval gate is
scoped to the irreversible/code-exec minority, so the autonomous `{rotate,quarantine}` loop that the 1.62× /
P3 / lead-demo depend on is untouched; extended Phoenix + the harness + the clean-room `native.go` are
unchanged.

## Honest residual risks (after the fixes)
Tenant identity stays **demo-trust** until `[PENDING-P-VCLUSTER]` (the console must be **code-enforced
localhost-bound**, not doc-asserted); GPU magnitudes `[SP-0-PENDING-P4]`; the kill-switch sentinel is a
ConfigMap (anyone with `configmaps/update` in the operator ns can flip it — mitigated, not eliminated, without
signing); soft-law floors become tighten-only but are still operator-set.

## STEP-2 FIX PLAN (prioritized; additive-where-possible; each with an adversarial close-proof)
- **F1 [CRITICAL]** — ship the namespaced least-privilege write Role + RoleBinding per managed ns; split the
  actuator SA from the read SA; delete the cluster-wide write path; minimal verbs (Role A + opt-in Role B).
  *Close-proof:* the `can-i` matrix above.
- **F2 [CRITICAL]** — action-risk tier + a HARD gate for debugger/custom-inject: image+command allowlist
  (busybox-only), **system-namespace denylist**, the **missing code-exec
  feasibility law**, optional human-approval for irreversible code-exec. *Close-proof:* a custom-inject policy
  in kube-system is vetoed; a non-busybox image rejected; rotate/quarantine stay autonomous.
- **F3 [HIGH]** — ValidatingWebhook/CEL on PhorvexPolicy: deny kube-system/kube-public/kube-node-lease
  targets, risk-tier `actions.enabled` (code-exec needs opt-in + non-default mode), cap selector breadth;
  **sync the CRD enum** so the barrier is *designed*, not accidental. *Close-proof:* a planted/over-broad
  policy is rejected at admission.
- **F4 [HIGH]** — fix the cross-tenant leaks: `/api/owner/events` empty-tenant fail-closed; `/api/live`
  tenant-scoped. *Close-proof:* empty `?tenant=` returns 0 cross-tenant rows.
- **F5 [CRITICAL]** — make the emit-boundary re-gate **fail-CLOSED on a map-miss** (veto if the live view key
  is absent). *Close-proof:* a pod absent from `viewByKey` is NOT actuated.
- **F6 [HIGH]** — kill-switch: treat `Namespace==""` as **fail-closed/required** + ship the Deployment wiring;
  **tighten-only** clamp on the soft-law floors; fix the D8 shared-normalization cross-tenant poison; scrub
  the subprocess env (D9) + code-enforce the localhost bind.

## Recommendation
**APPROVE as a review (Step 1) with the mandatory corrections; do NOT ship `PHORVEX_ACTUATOR=native` until
F1–F6 land.** The premise is correctly inverted at source, the minimal-Role direction genuinely closes the
privilege-widening, and the new console/CRD/ingest/fail-secure defects are real and file-grounded. **Three
corrections are baked into this doc:** (1) the emit re-gate is fail-OPEN on a map-miss → F5; (2) the minimal
Role drops services/endpointslices but **keeps `replicasets get`** (lead-demo load-bearing); (3) severity
recalibrated (the cross-tenant normalization poison is the only no-grant cross-tenant brain poison; console
env-inheritance is credential-blast-radius, not direct AWS theft).

**STOP — awaiting your approval (and any scope steer on F1–F6) before Step 2 (fix + adversarial prove-by-
running).** brain/decision-logic/recon/killchain + extended Phoenix + the attack harness stay UNCHANGED.
