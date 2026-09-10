# M-6 · 03 Decision — code-exec admission protection

**Stage:** human choices recorded; independent decision check follows. **Author:** claude (proposer);
**independent reviewer/coordinator:** codex-m006. **Actual approving human:** Mehrdad (`human_owner`),
as recorded by Claude in `evidence/decision/human-decision-2026-09-08.md` and bus #33. The ticket names
Mostafa; this cycle proceeds on the human owner's explicit approval of all three recommendations.
No separate Mostafa signature or approval is asserted. Technical critique passed before that approval.
**Authorized scope:** implementation of the selected contract and independent verification. Deployment,
execution grants, action enablement and persisted injections are separate steps and are not authorized here.
**Ruling reference:** `evidence/decision/three-round-ruling.md` (Mehrdad approved one focused closure package).
**Baseline pin:** source `main`@`79c0370dd460` (v0.4.97); cluster `phorvex-dev-eks` k8s **1.36.2 (observed/
targeted, not yet M6-tested — L3 pending)**; image `0.4.97`; image profile `busybox@sha256:b7f3d86d…`
(linux/amd64, `evidence/baseline/busybox-1.36-amd64.json`). **Change class A.** **Verification: L0–L2 + L3
(live API-server allow/deny on the real subresource) + L4 (freshness/removal/queued/restoration).**

**Fresh operational observation (2026-09-08):** the live operator is now **0.4.98**, manager digest
`sha256:4531ec35a151bc7cfcac09f5989564168d302478b529bf9a26f6fa233c0fe621`, embedded source
`a4d91cb196b4f28902b371c33db9157bb7ec26cd`. Fetched main is
`5a0fd3fa6f00ae93da442d84ac2b651b6a2573f9`; its `phorvex/` module matches that deployed source.
The source/image above remain the **historical analysis baseline**, not a current-deployment claim.
The original 02A seal is retained. `evidence/baseline/source-drift-0.4.98.json` confirms the M6 handlers,
actuator routing, native feasibility guard and old VAP are unchanged. M99 changed surrounding runner and
capability/feasibility integration: incorporate current main before implementation and regression-test that
its qualified-outcome path cannot bypass M6 admission unavailability. This is an exposed integration review,
not a new blind derivation. Live provenance is in `live-0.4.98-source-pin.json` (one valid audit row;
the bounded stream then timed out) and `authorization-boundary-review.json`.


## 1. Selected technical contract
- **Admission:** one installer-owned, cluster-scoped `ValidatingAdmissionPolicy phorvex-codeexec-ephemeral`
  + Binding `validationActions:[Deny]`, `failurePolicy:Fail`, **inline constants** (no param object), matching
  `pods/ephemeralcontainers` `UPDATE`. Validate only **newly-added** containers (`has()`-guarded
  old/new diff); pre-existing entries pass (migration).
- **Principal:** `system:serviceaccount:phorvex-system:phorvex-phorvex-manager` (the deployed manager SA;
  the committed `phorvex-actuator`/Role-B file is a non-deployed placeholder).
- **Scope:** installer-set namespace label `phorvex.ai/codeexec-managed:"true"`; the manager SA was observed
  unable to patch/update namespaces or the VAP (`evidence/baseline/authorization-review.json`) — the specific
  observed direct denials, not a general non-bypassability proof.
- **Selected field rules (the VAP allow-set):** `name ∈ {phorvex-debugger, phorvex-custom}`;
  `image == busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f` (pinned
  identically in the handler and the VAP);
  `securityContext == {privileged:false, allowPrivilegeEscalation:false, runAsNonRoot:true, runAsUser:65534,
  runAsGroup:65534, capabilities.drop:["ALL"], readOnlyRootFilesystem:true, seccompProfile.type:RuntimeDefault}`;
  **forbidden** (must be absent/empty): `tty, stdin, targetContainerName, env, envFrom, volumeMounts,
  volumeDevices, capabilities.add`. **`command`/`args`:** `custom-inject` = `command:["sh","-c"]`,
  `args:["echo phorvex-custom-action; sleep 1"]` (its current behavior, asserted exactly); `debugger` uses
  approved **Option A**: `command`+`args` **positively required empty** (C1). Option B (sleep 3600) was not selected.
- **Runtime read permission (implementation prerequisite — Codex boundary review):** the manager SA currently
  **cannot get/list/watch** the VAP or its binding (`evidence/baseline/authorization-boundary-review.json`),
  so the runtime check cannot verify enforcement as-is. Follow-up exact-name probes also returned no for
  both proposed objects (`evidence/baseline/named-admission-reads.json`), closing the broad-query limitation
  for this specific read prerequisite. The package MUST add a minimal **installer-owned,
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
  `codeexec-admission-unverified` when unverified; boot + runtime checks; **off by default** (no execution Role bound,
  no action enabled by install; the separate named-object read grant is required); teardown revokes the effective `phorvex-actuation` ephemeralcontainers
  grants before weakening the VAP. **No scoring/cover/feasibility-law/default change.** The handler's
  **emitted request IS changed** by the approved paired profile (pinned digest + hardened `securityContext` +
  the selected Option A command rule) — an explicit **P2 companion change, SEC-1-gated**, recorded here, not a silent
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
residual window is acknowledged; the API-server VAP is the durable enforcement. These values were approved
for SEC-1/PO-1. They are exact acceptance targets; changing them requires a recorded contract amendment.

**L4 test conditions:** record monotonic timestamps at the mutation response, verification completion,
expiry and published capability update. Exercise normal polling, watch-independent expiry, bounded API
errors/timeouts, and concurrent invalidation. The report target assumes the process is running and its
scheduler can run the configured checks; record suspension/overload separately, with no universal timing
SLA claim. A target miss in an applicable case is FAIL; do not redefine the target after measuring it.

## 3. Recorded human-owner decisions — APPROVED
| ID | Decision | **Approved selection** | Applies to |
|---|---|---|---|
| **SEC-1** | executable payload / targets / identities / who edits the profile | **Option A** (debugger `command`+`args` **empty, VAP-required**); pinned digest above; the selected hardened `securityContext`; exact name set; forbid the listed fields. Profile edited by installer/admin only. | finalizing enforcement rules / enabling code-exec |
| **SEC-2** | managed-only vs broader scope / exceptions | Enforce the **namespace-label** managed scope; deny out-of-profile requests **regardless of RBAC**; deny an unapproved identity + approved payload; admin/human debug on unlabeled namespaces unaffected; no administrator-debug exception in this initial contract; any later exception requires an explicit amendment. No protection claim vs a cluster-admin who removes the policy. | deploying a binding affecting other workflows |
| **PO-1** | versions / install model / degraded mode | **Single-release-per-cluster initial limit** (the singleton cluster-scoped VAP); multi-release support was not selected; k8s 1.36.2 observed/targeted but **M6-untested until L3**; targeted-support matrix is Mostafa's; unsupported/unverified ⇒ code-exec unavailable, other defenses continue with visible degraded status. | publishing compatibility + degraded behavior |

## 4. Acceptance criteria (must hold at closure)
- L0–L2: CEL rules (each allow + isolated violation; absent-`oldObject`; **C1** empty command/args required);
  boot/runtime checks per failure-mode incl. **C3** out-of-scope→unavailable; **C2** epoch interleaving
  (bump-mid-verify ⇒ in-flight success cannot clear; timeout-then-fresh-verify recovers); capability-gate
  exclusion + queued-not-dispatched; chart render (Deny/Fail/scope; no execution role bound; minimal read grant).
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
  (the manager SA was observed unable to create/update the VAP). The approved single-release-per-cluster limit means one
  release owns them. Both policy and binding are cluster-scoped (confirmed by live API discovery); selection
  does not change their resource scope. A multi-release design needs a separate approved amendment.
- **Install order (no unsafe window):** (1) installer applies VAP + Deny binding + scope label → (2)
  install the minimal named-object read grant, then boot/runtime check confirms present + content-hash + Deny + scope → only then (3) **human-gated**: grant the
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
deployment. Enforcement rollout, execution permissions, and persisted injections require explicit further authorization;
approval of SEC-1/SEC-2/PO-1 here is not permission to perform those operations. Independent live verification (Codex) is required; the implementer
(claude) may not sign it. The recorded human choices authorize implementation of this selected contract after the independent
decision check. No separate Mostafa approval is claimed.

**Next:** independent decision-check signature → AGREED → Claude implementation/L0–L2 on the reviewed
current-main integration base → independent incident/P3 review → separately authorized deployment/live checks.
Preserve the original 02A and historical analysis source. Do not label M6 verified or closed on this agreement.

## Approval attribution and scope

Mehrdad approved SEC-1, SEC-2 and PO-1 as recommended, via Claude's recorded in-session relay. The accepted
SEC-2 consequence is that non-allowlisted administrator ephemeral debugging is denied in labelled protected
namespaces, including the named examples litellm, vllm and phorvex-system when covered. This does not itself
label any namespace, authorize a rollout, or relax the existing native system-namespace feasibility guard.
The approving actor remains `human_owner`; the named security decision owner is not silently impersonated.
