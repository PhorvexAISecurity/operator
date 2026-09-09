# M-6 · 03 Decision — code-exec admission protection

**Stage:** DESIGN (decision package). Independent **technical** review may precede Mostafa; **the decision is
NOT frozen/AGREED/signed before SEC-1/SEC-2/PO-1 are recorded.** **Drafted by:** claude (proposer);
independent technical review by codex-m006 (skeptic) → Mostafa's SEC-1/SEC-2/PO-1 → **then** the decision
check freezes it → AGREED.
**Technical convergence:** Codex rev5 critique = **PASS** (bus #24; `02B-critique.md` Rev5 section) — C1–C3
converge with the independent model; architecture accepted. **No decision signature, implementation, or
security approval yet.**
**Ruling reference:** `evidence/decision/three-round-ruling.md` (Mehrdad approved one focused closure package).
**Baseline pin:** source `main`@`79c0370dd460` (v0.4.97); cluster `phorvex-dev-eks` k8s **1.36.2 (observed/
targeted, not yet M6-tested — L3 pending)**; image `0.4.97`; image profile `busybox@sha256:b7f3d86d…`
(linux/amd64, `evidence/baseline/busybox-1.36-amd64.json`). **Change class A.** **Verification: L0–L2 + L3
(live API-server allow/deny on the real subresource) + L4 (freshness/removal/queued/restoration).**

## 1. Agreed technical contract (frozen; detail in `01-proposal.md`)
- **Admission:** one installer-owned, cluster-scoped `ValidatingAdmissionPolicy phorvex-codeexec-ephemeral`
  + Binding `validationActions:[Deny]`, `failurePolicy:Fail`, **inline constants** (no param object), matching
  `pods/ephemeralcontainers` `UPDATE`. Validate only **newly-added** containers (`has()`-guarded
  old/new diff); pre-existing entries pass (migration).
- **Principal:** `system:serviceaccount:phorvex-system:phorvex-phorvex-manager` (the deployed manager SA;
  the committed `phorvex-actuator`/Role-B file is a non-deployed placeholder).
- **Scope:** installer-set namespace label `phorvex.ai/codeexec-managed:"true"`; the manager SA was observed
  unable to patch/update namespaces or the VAP (`evidence/baseline/authorization-review.json`) — the specific
  observed direct denials, not a general non-bypassability proof.
- **Frozen field rules (the VAP allow-set):** `name ∈ {phorvex-debugger, phorvex-custom}`;
  `image == busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f` (pinned
  identically in the handler and the VAP);
  `securityContext == {privileged:false, allowPrivilegeEscalation:false, runAsNonRoot:true, runAsUser:65534,
  runAsGroup:65534, capabilities.drop:["ALL"], readOnlyRootFilesystem:true, seccompProfile.type:RuntimeDefault}`;
  **forbidden** (must be absent/empty): `tty, stdin, targetContainerName, env, envFrom, volumeMounts,
  volumeDevices, capabilities.add`. **`command`/`args`:** `custom-inject` = `command:["sh","-c"]`,
  `args:["echo phorvex-custom-action; sleep 1"]` (its current behavior, asserted exactly); `debugger` per
  SEC-1 — **Option A** `command`+`args` **positively required empty** (C1, recommended) or **Option B** exact
  bounded values `command:["sh","-c"]`,`args:["sleep 3600"]`.
- **Runtime read permission (implementation prerequisite — Codex boundary review):** the manager SA currently
  **cannot get/list/watch** the VAP or its binding (`evidence/baseline/authorization-boundary-review.json`),
  so the runtime check cannot verify enforcement as-is. The package MUST add a minimal **installer-owned,
  resourceName-scoped `get`** on the two named objects (`ValidatingAdmissionPolicy` +
  `…Binding` `phorvex-codeexec-ephemeral`), plus the already-allowed namespace `get`. This is **read-only, NOT
  an injection grant**. Any `list`/`watch` (informer) extension is broader and must be **explicitly justified +
  scoped**; recommended default is **get-by-resourceName only** (no informer) — the 10 s periodic re-verify is
  a GET, not a watch.
- **Runtime capability contract (§6 of 01-proposal):** uncached verification via **GET-by-resourceName** on
  the two named objects + SSAR, under a single **aggregate deadline D**; **independent TTL expiry** (a quiet watch never refreshes); a process-local,
  **atomically-published `invalidationEpoch`** — any observed invalidation, **including a timeout or partial
  read failure, increments it**; a verification success clears/refreshes only if its captured `startEpoch`
  still equals the current epoch at completion (an older in-flight success cannot override a later
  invalidation); a **final pre-submit check** re-confirms unexpired verification + matching epoch + the
  specific target in verified scope; **fresh verification after a timeout recovers unchanged, valid objects.**
- **Out-of-scope target ⇒ capability unavailable** (C3): a target the VAP does not cover is treated
  fail-closed (RBAC-allowed ≠ verified admission).
- **Alternate exec paths OUT of M6's protection claim (Codex boundary review):** the manager SA holds
  `pods/exec` CREATE in phorvex-system, vllm, litellm — a **separate** exec path this VAP (which validates
  `pods/ephemeralcontainers` UPDATE) does **not** cover. M6 makes **no** claim to stop `pods/exec`; it is
  explicitly out of scope, tracked with **M4/M8**. The boundary evidence (60 probes, 6 yes / 54 no —
  policy/binding/namespace/cluster-RBAC mutation, secret-read, token-create, pod-create, impersonate/escalate/
  bind all denied) strengthens but does **not universally** exclude indirect escalation (broad `can-i` can miss
  resourceName-restricted grants).
- **Fail-closed wiring:** the existing capability gate excludes debugger/custom-inject with reason
  `codeexec-admission-unverified` when unverified; boot + runtime checks; **off by default** (no Role bound,
  no action enabled by install); teardown revokes the effective `phorvex-actuation` ephemeralcontainers
  grants before weakening the VAP. **No scoring/cover/feasibility-law/default change.** The handler's
  **emitted request IS changed** by the approved paired profile (pinned digest + hardened `securityContext` +
  the Option A/B command rule) — an explicit **P2 companion change, SEC-1-gated**, recorded here, not a silent
  handler-semantic change.

## 2. Exact timing test targets (L4 asserts against these — not approximate)
- **Aggregate verification deadline `D = 2000 ms`** (all reads for one gating decision share it).
- **Verification `TTL = 30 s`** (independent expiry; a quiet watch never refreshes it).
- **Periodic re-verify poll `= 10 s`** (early-warning + independent of watch events).
- **Report-latency target `≤ 40 s`** (= `TTL` + one poll) from an external enforcement-weakening to the
  capability reporting unavailable, under bounded L4 conditions.

L4 asserts each exactly: report-latency `≤ 40 s`; observed-invalid ⇒ **0** dispatches (the observed-state
invariant); queued re-verify at dispatch; restoration requires a fresh success (object names alone do not
clear). **No** absolute operator-path bound between the final check and the API submit is claimed — that
residual window is acknowledged; the API-server VAP is the durable enforcement. These values are a decision
input for SEC-1/PO-1 and may be adjusted there, but are exact for testing as written.

## 3. Engineering recommendations → Mostafa (PENDING decisions)
| ID | Decision | **Recommendation** | Required before |
|---|---|---|---|
| **SEC-1** | executable payload / targets / identities / who edits the profile | **Option A** (debugger `command`+`args` **empty, VAP-required**); pinned digest above; the frozen hardened `securityContext`; exact name set; forbid the listed fields. Profile edited by installer/admin only. | finalizing enforcement rules / enabling code-exec |
| **SEC-2** | managed-only vs broader scope / exceptions | Enforce the **namespace-label** managed scope; deny out-of-profile requests **regardless of RBAC**; deny an unapproved identity + approved payload; admin/human debug on unlabeled namespaces unaffected; exceptions explicit + auditable. No protection claim vs a cluster-admin who removes the policy. | deploying a binding affecting other workflows |
| **PO-1** | versions / install model / degraded mode | **Single-release-per-cluster initial limit** (the singleton cluster-scoped VAP) **unless Mostafa requires an explicit release→(label-value, SA) multi-release mapping**; k8s 1.36.2 observed/targeted but **M6-untested until L3**; targeted-support matrix is Mostafa's; unsupported/unverified ⇒ code-exec unavailable, other defenses continue with visible degraded status. | publishing compatibility + degraded behavior |

## 4. Acceptance criteria (must hold at closure)
- L0–L2: CEL rules (each allow + isolated violation; absent-`oldObject`; **C1** empty command/args required);
  boot/runtime checks per failure-mode incl. **C3** out-of-scope→unavailable; **C2** epoch interleaving
  (bump-mid-verify ⇒ in-flight success cannot clear; timeout-then-fresh-verify recovers); capability-gate
  exclusion + queued-not-dispatched; chart render (Deny/Fail/scope; no role bound).
- **L3 (Codex, isolated fixture, real-subresource dry-run):** the ticket verification matrix, **each denial
  attributed to its VAP rule vs RBAC/PSA**; both action request forms covered.
- **Incident-evidence gate (before P3):** independently reproduce the current admission gap through the real
  producers (the manager SA against the real subresource), signed `incident` — a mocked flag is not that proof.
- **L4:** the §2 targets measured under bounded conditions.
- Effective-permission migration (revoke `phorvex-actuation` grants) and off-by-default verified; **the
  installer-owned runtime read grant is present and minimal** (resourceName-scoped `get` on the two named
  admission objects + namespace `get`; no injection, no `list`/`watch` unless justified).

## 4a. Supported singleton ownership + rollout / rollback (Codex request)
- **Ownership.** The cluster-scoped `phorvex-codeexec-ephemeral` VAP + Binding are **installer/admin-owned**
  (the manager SA was observed unable to create/update the VAP). Single-release-per-cluster (PO-1 default): one
  release owns them. Explicit multi-release mapping: the installer owns the shared policy; each release owns
  only its namespace-scoped binding + label value.
- **Install order (no unsafe window):** (1) installer applies VAP + Deny binding + scope label → (2)
  boot/runtime check confirms present + content-hash + Deny + scope → only then (3) **human-gated**: grant the
  ephemeralcontainers permission + enable the action. Never enable execution before admission is verified.
- **Rollback/uninstall order (no unsafe window):** (1) disable the code-exec actions + block new submissions →
  (2) drain/account for in-flight + queued requests → (3) revoke the effective `phorvex-actuation`
  ephemeralcontainers grants → (4) only then remove/downgrade the VAP. Removing the VAP first opens an
  enable-without-admission window.
- **Upgrade:** content/version-hash re-verified after any chart/policy change; a mismatch marks the capability
  unavailable until re-verified.
- **Helm:** `helm uninstall` of a release must not orphan the shared singleton for other releases (the
  single-release limit avoids this); shared-resource ownership is documented explicitly.

## 5. Explicitly NOT authorized by this package
No admission install, no Role-B/`phorvex-actuation` grant, no action enablement, no persisted-injection, no
deployment. Enforcement rollout, execution permissions, and persisted injections require Mostafa's approved
SEC-1/SEC-2/PO-1 + explicit scope. Independent live verification (Codex) is required; the implementer
(claude) may not sign it. This decision authorizes proceeding to implementation of the **frozen contract**
only after the decision check + Mostafa's decisions.

**Next:** codex-m006 independent **technical** review of this package (may precede Mostafa) → **Mostafa
SEC-1/SEC-2/PO-1** → **then** the decision check freezes it (AGREED). **No freeze/sign before Mostafa's
choices.** Then implementation of the frozen contract (L0–L2), then Codex incident/L3 + live verify.
