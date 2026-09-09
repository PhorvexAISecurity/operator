# M-6 · 01 Proposal — code-exec admission protection (rev 3, answers 02B B1–B6 + round-2 R1–R3)

**Author:** claude (proposer/implementer) · original written independently of Codex's sealed 02A;
rev 2 answered 02B (B1–B6); rev 3 answers Codex's round-2 (R1 race, R2 freshness, R3 concrete profile).
**Baseline pin:** source `main`@`79c0370dd460` (v0.4.97); cluster `phorvex-dev-eks` k8s `v1.36.2`;
image `0.4.97` digest `sha256:e5ba82916f18…`; embedded source `c8c708145f2f`. Re-pin at verify time.
**Change class:** **A** (deterministic capability gating + declarative admission; no math, no
scoring/cover change) — see B6; the L4 runtime-freshness/dispatch component is called out with
measured bounds and its class deferred to the coordinator. **Verification:** L0–L2 + **L3 required**
(live API-server allow/deny on the real subresource) + **L4 required** (runtime freshness, removal,
queued work, restoration). `live_required: true`, `soak_required: true`.

---

## 1. Root cause (traced through the real producers)

`debugger`/`custom-inject` call `injectEphemeral(...)` →
`client.SubResource("ephemeralcontainers").Update(pod)` (`internal/actuator/handlers_k8s.go:312-353`).
Declared 4-layer gate vs. baseline:

| Layer | State | Evidence |
|---|---|---|
| 1 — VAP on the **request** | **ABSENT + wrong target** | committed `config/admission/codeexec-denylist.yaml` matches `phorvex.ai/phorvexpolicies` CREATE/UPDATE (denies *enabling* the action in a system ns), **not** `pods/ephemeralcontainers` UPDATE. Cluster has no code-exec VAP (only unrelated `phorvex-phorvex-e2e-detector`). |
| 2 — feasibility guard | present, **narrow** | `codeExecGuard` denies code-exec only in **system** namespaces. |
| 3 — off by default | present | nil `EnabledActions` ⇒ rotate+quarantine only; code-exec actions carry no recon cover ⇒ manual dispatch only. |
| 4 — hardcoded image | present, **weak** | `busybox:1.36` mutable **tag**; **no `securityContext`**; no command/target/env/mount constraints. |

**The real defect is layer 1**: no admission control on the actual injection request, and no boot/runtime
check keeping the capability unavailable while layer 1 is missing. Layers 2–4 reduce reachability; none
is an enforceable boundary outside the operator's own decision logic (P-SECURITY-BOUNDARY).

## 2. Effective identity + permission baseline (corrected per B1)

**Deployed principal:** `phorvex-system/phorvex-phorvex-manager` (BASELINE.md; chart
`charts/phorvex/templates/deployment.yaml:26` runs as `phorvex.serviceAccountName`, and
`rbac.yaml` binds `…-manager-role`). The standalone `config/rbac/phorvex-actuator-role.yaml`
(SA `phorvex-actuator`, "Role B unbound") is a **non-deployed placeholder** — a P1
source-vs-deployed discrepancy; do not treat unbound Role B as the effective boundary.

**Effective injection grants (Codex live obs):** `phorvex-actuation` RoleBindings in **litellm** and
**vllm** bind the manager SA to a ClusterRole granting `pods/ephemeralcontainers` **get/create/update/patch**.
So the operator **already can inject** in those namespaces today. Consequences folded in below:
- **Teardown/least-privilege must enumerate and revoke the *actual* `phorvex-actuation` grants**, not the
  proposed Role B. (Independent finding; reconciling the placeholder file with the deployed grants may be
  its own follow-up — flagged, not silently expanded here.)
- **Object-label scope is bypassable**: the manager holds pod `update/patch` in litellm/vllm, so it can
  relabel a pod to dodge an object-label selector. Scope must not rest on labels the operator can set (B3).

**Before-state is UNVERIFIED (per B1):** "an arbitrary privileged ephemeral container is admitted today"
is a *hypothesis* — PSA or other admission may already reject some payloads. It is proven only by the
attributable isolated L3 test (approved test identity, real subresource dry-run); until then it stays a
prediction, not a measured result.

## 3. Exact request inventory (source-fact; the contract the VAP validates)

Verb/resource: **`UPDATE` on `pods/ephemeralcontainers`** by the manager SA. Each call **appends one**
ephemeral container, idempotent by name; **irreversible**.

| Field | `debugger` | `custom-inject` |
|---|---|---|
| `name` | `phorvex-debugger` | `phorvex-custom` |
| `image` | `busybox:1.36` (tag) | `busybox:1.36` (tag) |
| `command` | *(unset → image entrypoint)* | `["sh","-c","echo phorvex-custom-action; sleep 1"]` |
| `tty`/`stdin` | false/false | false/false |
| `securityContext`/`targetContainerName`/`env`/`args`/`volumeMounts` | **unset** | **unset** |

Newly-added members (UPDATE sees `oldObject`+`object`):
`object.spec.ephemeralContainers.filter(ec, !(has(oldObject.spec.ephemeralContainers) &&
oldObject.spec.ephemeralContainers.exists(o, o.name==ec.name)))` — the `has()` guard is **required** so
the first injection into a pod with no prior ephemeral containers isn't spuriously failed (B5). Pre-existing
entries pass unchanged (migration semantics).

## 4. Proposed change (minimal; nothing enabled by installation)

1. **Request-level VAP** `config/admission/codeexec-ephemeral-vap.yaml`: `ValidatingAdmissionPolicy` +
   `…Binding(validationActions:[Deny])`, `resources:["pods/ephemeralcontainers"]`, `operations:["UPDATE"]`,
   `failurePolicy: Fail`. Validate each newly-added container against the approved profile (§SEC-1).
   **Inline constants** (no param object) as the single recommended model (B3); the old policy-level VAP is a
   separate concern and does not satisfy this ticket.
2. **Boot-time capability check** (`cmd/main.go`): if a code-exec action is enabled anywhere, verify (a) VAP
   API served, (b) policy present with expected content/version, (c) applicable **Deny** binding matches, (d)
   scope selector correct. Any miss ⇒ capability unavailable (fail-closed), specific reason (§B5 table).
   **Initialize unavailable**: the capability is unavailable until the first successful verification (B4).
3. **Runtime freshness + dispatch (L4, specified per B4)** — see §6.
4. **Fail-closed via the existing capability-witness gate** (same path as the T1-E gate) with a distinct,
   vocabulary-consistent reason `codeexec-admission-unverified`; unrelated defenses continue (approved
   degraded mode). No scoring/cover/feasibility-law/default change.
5. **Off by default**: installing admission binds no role and enables no action. Rollout: install+verify
   admission → *then* human-gated grant/enable. Teardown reverses: disable actions + block new submissions +
   **revoke the effective `phorvex-actuation` ephemeralcontainers grants** before weakening the VAP.

**Paired handler+VAP change (resolves the B2 contradiction).** The current requests carry a mutable tag and
no `securityContext`; a VAP that requires a digest + hardened `securityContext` would reject the operator's
**own** requests → self-DoS. So the recommended path is **one paired change** (needs SEC-1 + a P2
companion-scope note, since it alters the emitted request):
- Handler emits: `image: busybox@sha256:<pinned>` (exact digest chosen at SEC-1); `securityContext:
  {privileged:false, allowPrivilegeEscalation:false, runAsNonRoot:true, runAsUser:<numeric>,
  runAsGroup:<numeric>, capabilities:{drop:["ALL"]}, readOnlyRootFilesystem:true, seccompProfile:{type:
  RuntimeDefault}}`; explicit `command`/`args` (debugger: the pinned image's approved entrypoint;
  custom-inject: the existing `sh -c …`); no `targetContainerName`/`env`/`volumeMounts`/`tty`/`stdin`.
  **Runnability note (B2):** the `busybox` image's default user is **root (UID 0)**, so `runAsNonRoot:true`
  is unsatisfiable without an explicit numeric `runAsUser`/`runAsGroup` — the digest and the UID/GID are
  chosen together, and the VAP asserts exactly what the handler sends.
- VAP requires exactly that profile. **Compatibility alternative** (if SEC-1 declines the handler change):
  VAP validates only the fields the handler currently sends (name-prefix + image-tag + forbid
  privileged/target/env) — a weaker profile, explicitly labeled as not the recommended boundary.
- API admission is not runnable/effective defense; M-57/M-61 (action efficacy) stay separate — no efficacy
  claim added here.

## 5. Decisions for Mostafa (recommendations)

| ID | Recommendation |
|---|---|
| **SEC-1** — what may execute / on which targets / which identities / who changes the profile | Approve the **paired** narrow profile in §4: name prefix `phorvex-`, **digest-pinned** image, mandatory hardened `securityContext` with explicit numeric UID/GID, constrained `command`, no target/env/mount/tty/stdin. Profile changes owned by the installer/admin identity only. Keep code-exec disabled until agreed. |
| **SEC-2** — managed-only vs broader scope / exceptions | Scope by **namespace-label selector set by the installer on namespaces the operator cannot relabel** (object-label scope is bypassable — B1/B3). Deny the manager SA's out-of-profile requests regardless of RBAC; deny an unapproved identity submitting an approved payload (identity rule). Leave genuine admin/human `kubectl debug` on unmanaged namespaces unaffected; emergency exceptions explicit + auditable. No protection claim vs a cluster-admin who removes the policy. |
| **PO-1** — supported versions / install models / degraded mode | **Tested/targeted: k8s 1.36.2 only** (dev); VAP GA ≥1.30 is API availability, **not** a tested matrix (B6) — other versions unverified until tested; PO-1 must not inherit a blanket support claim. Customer-managed admission only under the verifiable content-check contract. Unsupported/unverified ⇒ code-exec unavailable, other defenses continue with visible degraded status. |

### 5a. Concrete candidate profile / naming / scope / migration (R3 — fills the Mostafa package)

**Requests emitted (the paired handler change, exact values):**

| field | `debugger` | `custom-inject` |
|---|---|---|
| `name` | `phorvex-debugger` | `phorvex-custom` |
| `image` | `busybox@sha256:<DIGEST>` — the installer resolves `busybox:1.36` to its registry digest at SEC-1 and pins the **same** value in the handler and the VAP; the operator SA cannot create/update the VAP (`evidence/baseline/authorization-review.json`) so the installer owns the pinned value | same |
| `command`/`args` | `["sh","-c","sleep 3600"]` — a bounded idle diagnostic replacing the image-entrypoint default, so the request is fully attributable (SEC-1 may keep the entrypoint instead) | `["sh","-c","echo phorvex-custom-action; sleep 1"]` (unchanged) |
| `securityContext` | `privileged:false, allowPrivilegeEscalation:false, runAsNonRoot:true, runAsUser:65534, runAsGroup:65534` (nobody/nogroup exist in busybox ⇒ `runAsNonRoot` is satisfiable), `capabilities.drop:["ALL"], readOnlyRootFilesystem:true, seccompProfile.type:RuntimeDefault` | same |
| `tty`/`stdin`/`targetContainerName`/`env`/`volumeMounts` | unset (VAP forbids) | unset |

**Admission naming (cluster-scoped, resolves B3):** one installer-owned
`ValidatingAdmissionPolicy phorvex-codeexec-ephemeral` + one Binding `phorvex-codeexec-ephemeral` whose
`matchResources` carries the namespace selector. Cluster-scoped ⇒ a single installer-owned policy serves all
releases; **multi-release** is handled by the binding's namespace selector, **not** per-release policy copies
(which would collide on the cluster-scoped name). The manager SA cannot create/update either object
(authz-review.json) ⇒ installer/admin owns them (separate installer authority).

**Scope selector (namespace-level, non-bypassable):** match namespaces carrying an installer-applied label
(e.g. `phorvex.ai/codeexec-managed: "true"`). Codex's authz review confirms the manager SA **cannot
patch/update namespaces** (nor update the VAP, nor create clusterrolebindings), so it cannot self-relabel
into/out of scope. Approved admin/human debugging on unlabeled namespaces is unaffected.

**Migration semantics:** the CEL validates **only newly-added** containers (the `has()`-guarded diff);
ephemeral containers already in `oldObject` pass unchanged, so enabling the policy does not retroactively deny
pods that already carry non-conforming ephemeral containers. Recommended default; the L3 matrix tests it.

**Exact content/version match:** the boot/runtime check verifies the policy CEL + the binding's
`validationActions:[Deny]` / `failurePolicy:Fail` by content hash and a declared `policyVersion` annotation,
not by name presence alone.

Baseline + proposal + tests proceed now; the paired handler change, Role/grant changes, scope binding, and
any persisted-injection L3 wait on SEC-1/SEC-2/PO-1 + explicit scope.

## 6. Freshness & dispatch semantics (answers B4; revised for round-2 R1/R2)

**Primary enforcement is the API-server VAP, not the operator check.** The operator's verification is
defense-in-depth governing whether Phorvex *chooses* to dispatch; it cannot be atomic with the API
submission, so it **reduces, not eliminates,** the exposure window. The fail-closed VAP at admission is the
actual boundary at the instant of the request.

- **Authoritative inputs, uncached (R2):** the VAP, its Deny binding, and the namespace-scope selector are
  read **live/uncached** (direct GET + SSAR against the API server) for the gating decision — the
  informer/watch is only an early-warning trigger, **never** the freshness source. Each gating read carries a
  **deadline D ≤ 2 s**; a read that does not complete within D ⇒ **unknown → unavailable**.
- **Independent expiry (R2):** a successful uncached verification stamps `verifiedUntil = now + TTL (30 s)`.
  The verified state **expires on that timer regardless of watch activity** — a quiet watch never refreshes it
  (no-change ≠ verified). Past `verifiedUntil` ⇒ unavailable until the next successful uncached verification.
- **Observed-state invariant (R1, replaces "zero after weakening"):** Phorvex does not dispatch a code-exec
  action unless it holds an **unexpired uncached verification** (obtained within D immediately before submit)
  that the contract holds. It never dispatches into a state it has *observed* invalid/stale/weakened. This is
  an invariant over *observed* state, not a zero-race guarantee.
- **Explicit residual race (R1):** a weakening applied in the window between the last verification and the API
  submission can still let one operator-originated request reach the API server, where it meets whatever
  admission state exists at that instant — if the VAP was *removed* in that window the API admits; if merely
  invalidated under Fail/Deny the API denies. The window is bounded by D and **acknowledged, not claimed
  zero**. A dispatch-time SSAR/dry-run can shrink it further but is still non-atomic; the durable guarantee
  is the API-server VAP.
- **Init before execution:** unavailable until the first successful uncached verification post-start;
  post-start enablement triggers a verification before eligibility.
- **Falsifiable L4 bounds (measured, not asserted):**
  (i) after an enforcement-weakening change, reported capability becomes unavailable within **≤ TTL + D
  (≤ 32 s)**;
  (ii) **no code-exec is dispatched while the operator holds an observed invalid/stale/expired verification**
  (the observed-state invariant — not a zero-race claim);
  (iii) a queued request is re-verified (uncached, within D) at dispatch and dropped-with-reason if invalid;
  (iv) restoration requires a fresh successful uncached verification (restoring object *names* alone does not
  clear it).

## 7. Per-failure-mode enforcement table (answers B5 — API ≠ runtime, attributable)

| Configuration state | API-server behavior | Runtime capability | Attributed layer |
|---|---|---|---|
| Policy absent / binding absent | **Admits** (contract not enforced) | **Unavailable** (`codeexec-admission-unverified: policy/binding absent`) | boot/runtime check |
| Binding present but `validationActions:[Warn/Audit]` | **Admits** (no deny) | **Unavailable** (`…: binding not Deny`) | runtime check |
| Invalid params under `parameterNotFoundAction: Deny` (if parameterized) | **Denies** (fail-closed) | Unavailable (`…: invalid params`) | VAP param |
| Invalid CEL / eval error under `failurePolicy: Fail` | **Denies** (fail-closed) | Unavailable (`…: invalid policy`) | VAP failurePolicy |
| Discovery/read of admission objects fails | Depends (may still enforce) | **Unavailable** (`…: state unknown`) | runtime check (unknown) |
| Stale watch (`lastVerifiedAt` past deadline) | Depends | **Unavailable** (`…: stale`) | runtime freshness |
| Full approved contract present | Enforces per rules | Available | VAP |

Every L3 deny is attributed to its rule (image / securityContext-field / command / identity / scope) and
distinguished from RBAC/PSA denials; each restrictive rule has a valid **allow** and an isolated
**violation** case; the absent-`oldObject` first-injection case is in the CEL/filter tests.

## 8. Acceptance criteria & tests (P4)
L0–L2 (mine): CEL unit tests (newly-added filter incl. absent-oldObject; each profile rule allow+violation);
boot-check unit tests (each §7 row → available/unavailable + reason); capability-gate test (unverified ⇒
code-exec excluded + queued not dispatched; others unaffected); freshness tests (§6 bounds); chart-render
(failurePolicy:Fail, Deny binding, scope selector; no role bound). L3 (Codex, isolated fixture, real
subresource dry-run): the ticket's verification matrix, each row attributed. L4: §6 bounds measured.

## 9. Predicted output band
```
Before (UNVERIFIED until L3): the manager SA can UPDATE pods/ephemeralcontainers in litellm/vllm via
  phorvex-actuation; whether an arbitrary privileged/tagged payload is admitted is proven only by the
  isolated test (PSA/other admission may already reject some).
After (approved contract): reviewed VAP+Deny-binding present; approved identity+paired-profile+in-scope
  admitted by THIS policy; each isolated forbidden attribute denied by its own rule (attributable, distinct
  from RBAC/PSA); missing/weakened/invalid/unreadable/stale/unsupported ⇒ code-exec unavailable via the
  capability gate with a specific reason, 0 stale dispatches, unaffected defenses continue; actions still off
  by default; no scoring/cover/efficacy change.
```

## 10. Responses to 02B
- **B1 — adopted.** Principal corrected to `phorvex-phorvex-manager`; effective `phorvex-actuation`
  ephemeralcontainers grants in litellm/vllm enumerated; placeholder file flagged as non-deployed;
  teardown revokes actual grants; object-label scope rejected as bypassable; before-state marked UNVERIFIED
  (§2, §9).
- **B2 — adopted.** Single recommended **paired** handler+VAP change with exact image-digest/securityContext/
  command/target/identity defaults, the busybox root-UID runnability note, P2 companion scope, and a
  compatibility alternative (§4). No efficacy claim (M-57/M-61 separate).
- **B3 — adopted.** Concrete **namespace-label** scope the operator cannot relabel; inline-constants as the
  single model; cluster-scoped naming/multi-release ownership + exact content/version matching to settle at
  packaging; Mostafa approves the boundary (§4, §5).
- **B4 — adopted.** Authoritative inputs, 30 s resync + 60 s staleness→unknown, synchronous pre-dispatch
  recheck (0 stale dispatches), init-unavailable, and falsifiable ≤60 s / 0-dispatch / queued / restoration
  bounds (§6).
- **B5 — adopted.** Per-failure-mode API-vs-runtime table with attributed layers; absent-`oldObject`
  first-injection handled in the CEL tests; pre-existing + per-field violations retained (§7, §8).
- **B6 — adopted.** Tested version = 1.36.2 only, GA≥1.30 stated as availability not a matrix, PO-1 no blanket
  claim; change_class reconciled to **A** with the L4 runtime-state component flagged and its class deferred
  to the coordinator (header, §5, PO-1).

## 11. Responses to Codex round-2 (R1–R3)
- **R1 — adopted.** Removed the "zero after weakening" claim; §6 now states the **API-server VAP as primary
  enforcement**, an **observed-state invariant** (no dispatch while holding an observed invalid/stale/expired
  verification), and an **explicit residual race** bounded by D and acknowledged, not claimed zero.
- **R2 — adopted.** §6 gating uses **uncached, deadline-bounded** (D ≤ 2 s) verification, with **independent
  TTL expiry** (30 s) that a quiet watch cannot refresh; the informer is early-warning only. L4 bound
  restated as ≤ TTL + D.
- **R3 — adopted.** §5a gives the concrete emitted requests (digest-pin ownership, `runAsUser/Group:65534`,
  exact commands, full securityContext), cluster-scoped VAP/binding naming + multi-release ownership,
  namespace-label scope proven non-bypassable by Codex's authz review (`authorization-review.json`: manager
  SA cannot patch namespaces / update the VAP), migration semantics, and exact content/version matching.
- **change_class:** confirmed **A** per Codex (L4 does not require B); L4 acceptance bounds are in §6.

**Next:** hand back to `codex-m006` — confirm convergence; then I prepare the SEC-1/SEC-2/PO-1 decision
record for Mostafa. No implementation until `03-decision`.
