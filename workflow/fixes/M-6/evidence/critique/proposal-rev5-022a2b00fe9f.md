# M-6 · 01 Proposal — code-exec admission protection (rev 5 — closure package + C1–C3)

**Author:** claude (proposer/implementer). Original written independently of Codex's sealed 02A.
**Three-round ruling (recorded):** Codex ruled critique=FAIL with the architecture accepted; **Mehrdad
(human_owner) ruled APPROVE one focused closure package — same scope, no weakening/redesign, then
independent re-review** (citable reference: `fixes/M-6/evidence/decision/three-round-ruling.md`). rev 4 was
that package (R3-1/R3-2/R3-3, single timing contract / name rule / attributable API wording); **rev 5
incorporates Codex's rev4-review contract corrections C1 (debugger command+args must be empty), C2 (epoch
invalidation latch), C3 (out-of-scope ⇒ unavailable; multi-release mapping)** and the captured image metadata.
**Baseline pin:** source `main`@`79c0370dd460` (v0.4.97); cluster `phorvex-dev-eks` k8s `v1.36.2`;
image `0.4.97` digest `sha256:e5ba82916f18…`; embedded source `c8c708145f2f`. Re-pin at verify time.
**Change class:** **A** (deterministic capability gating + declarative admission; no math/scoring/cover
change) — confirmed by Codex. **Verification:** L0–L2 + **L3** (live API-server allow/deny on the real
subresource) + **L4** (freshness, removal, queued work, restoration). `live_required: true`,
`soak_required: true`. **No implementation until `03-decision`.**

---

## 1. Root cause
`debugger`/`custom-inject` call `client.SubResource("ephemeralcontainers").Update(pod)`
(`internal/actuator/handlers_k8s.go:312-353`). The declared 4-layer gate: **layer 1 (request-level VAP)
is absent and mis-targeted** (committed `config/admission/codeexec-denylist.yaml` matches
`phorvex.ai/phorvexpolicies`, not `pods/ephemeralcontainers`; the cluster has no code-exec VAP, only the
unrelated `phorvex-phorvex-e2e-detector`). Layer 2 (`codeExecGuard`) denies only in **system** namespaces;
layer 3 (off by default) holds; layer 4 (hardcoded `busybox:1.36`) is a **mutable tag** with **no
`securityContext`**. None of 2–4 is an enforceable boundary outside the operator's own decision logic.

## 2. Effective identity + permission baseline
**Deployed principal:** `phorvex-system/phorvex-phorvex-manager` (BASELINE.md; chart runs as
`phorvex.serviceAccountName`, `rbac.yaml` binds `…-manager-role`). The standalone
`config/rbac/phorvex-actuator-role.yaml` (SA `phorvex-actuator`, "Role B unbound") is a **non-deployed
placeholder** — a P1 source-vs-deployed discrepancy; unbound Role B is **not** the effective boundary.

**Effective injection grants (Codex live authz review, `evidence/baseline/authorization-review.json`):**
the manager SA can **`ephemeralcontainers: update` in vllm**, **`patch` in litellm**, and **`pods: update`**
in those namespaces — so it **already can inject there today**. The same review observed **`no`** for
namespace `patch/update`, VAP `update`, clusterrolebinding `create`, and vllm rolebinding `update`.
**Scope of that evidence (narrowed per R3-2):** it proves the **queried direct** permissions **at that
observation only**. It does **not** exclude all indirect privilege routes, nor every create/update/delete on
policy/binding objects. It is used below only for the specific observed namespace/VAP-write denials.

Consequences: teardown/least-privilege must enumerate and revoke the **actual `phorvex-actuation` grants**
(not the placeholder Role B); object-label scope is bypassable (manager holds pod `update/patch` in
litellm/vllm) so scope uses **namespace** labels the manager was observed unable to write.
**Before-state is UNVERIFIED:** "an arbitrary privileged ephemeral container is admitted today" is a
hypothesis — PSA or other admission may already reject some payloads — proven only by the isolated L3 test.

## 3. Exact request inventory (source-fact)
`UPDATE pods/ephemeralcontainers` by the manager SA; appends one container; idempotent by name; irreversible.

| Field | `debugger` | `custom-inject` |
|---|---|---|
| `name` | `phorvex-debugger` | `phorvex-custom` |
| `image` | `busybox:1.36` (tag) | `busybox:1.36` (tag) |
| `command` | *(unset → entrypoint)* | `["sh","-c","echo phorvex-custom-action; sleep 1"]` |
| `args` | unset | unset |
| `tty`/`stdin` | false/false | false/false |
| `securityContext`/`targetContainerName`/`env`/`envFrom`/`volumeMounts` | unset | unset |

Newly-added members (UPDATE has `oldObject`+`object`):
`object.spec.ephemeralContainers.filter(ec, !(has(oldObject.spec.ephemeralContainers) &&
oldObject.spec.ephemeralContainers.exists(o, o.name==ec.name)))` — the `has()` guard lets the **first**
injection (no prior list) pass. Pre-existing entries pass unchanged (migration).

## 4. Proposed change (minimal; nothing enabled by installation)
1. **Request-level VAP** `config/admission/codeexec-ephemeral-vap.yaml`: `ValidatingAdmissionPolicy` +
   Binding `validationActions:[Deny]`, `resources:["pods/ephemeralcontainers"]`, `operations:["UPDATE"]`,
   `failurePolicy: Fail`, **inline constants** (no param object). Validate each newly-added container against
   the §5a profile. The old policy-level VAP is a separate concern.
2. **Boot-time check** (`cmd/main.go`): if a code-exec action is enabled anywhere, verify VAP API served,
   policy present + content/version match, applicable **Deny** binding, scope selector. Any miss ⇒ capability
   unavailable (fail-closed) with a specific reason (§7). **Initialize unavailable** until first success.
3. **Runtime freshness + dispatch** — the single contract in §6.
4. **Fail-closed via the existing capability-witness gate** with reason `codeexec-admission-unverified`;
   unrelated defenses continue. No scoring/cover/feasibility/default change.
5. **Off by default**: installing admission binds no role and enables no action. Rollout: install+verify
   admission → then human-gated enable. Teardown reverses: disable actions + block new submissions + revoke
   the **`phorvex-actuation` ephemeralcontainers grants** before weakening the VAP.
6. **Paired handler+VAP change** (a VAP requiring a digest/`securityContext` the handler doesn't send would
   reject the operator's own requests). Needs SEC-1 + a P2 companion-scope note; exact values in §5a. API
   admission is not a runnable/effective defense; M-57/M-61 stay separate (no efficacy claim added).

## 5. Decisions for Mostafa
| ID | Recommendation |
|---|---|
| **SEC-1** — what executes / targets / identities / who edits the profile | Approve the §5a paired profile: **exact name set** `{phorvex-debugger, phorvex-custom}`, digest-pinned image, mandatory hardened `securityContext` with explicit numeric UID/GID, explicit `command`+`args`, forbid `tty/stdin/targetContainerName/env/envFrom/volumeMounts/capabilities.add`. Profile edited by installer/admin only. Also rule the debugger-command question (§5a). Code-exec stays disabled until agreed. |
| **SEC-2** — managed-only vs broader / exceptions | Scope by an **installer-set namespace label** the manager was observed unable to write; deny out-of-profile requests regardless of RBAC; deny an unapproved identity + approved payload (identity rule). Admin/human debug on unlabeled namespaces unaffected; exceptions explicit + auditable. No protection claim vs a cluster-admin who removes the policy. |
| **PO-1** — versions / install models / degraded mode | Distinguish **tested vs targeted**: **tested = k8s 1.36.2 only** (dev cluster); the **targeted-support matrix** is a PO-1 decision, not asserted — VAP GA≥1.30 is API availability, not a tested matrix, and every other version is unverified until tested. Customer-managed admission only under the content-check contract. Unsupported/unverified ⇒ code-exec unavailable; other defenses continue with visible degraded status. **Multi-release install limit (C3):** state either one-release-per-cluster (singleton VAP) or an explicit release→(label-value, SA) mapping. |

### 5a. Concrete profile / naming / scope / migration (R3-2)
**Name rule — single, exact (resolves §5/§5a conflict):** the VAP allows exactly
`name in ['phorvex-debugger','phorvex-custom']`. No prefix rule.

**Emitted requests (paired handler change), exact:**

| field | `debugger` | `custom-inject` |
|---|---|---|
| `image` | `busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f` (linux/amd64) | same |
| `command` | **SEC-1 decision — Option A: empty; Option B: `["sh","-c"]`** | `["sh","-c"]` |
| `args` | **Option A: empty; Option B: `["sleep 3600"]`** | `["echo phorvex-custom-action; sleep 1"]` |
| `securityContext` | `privileged:false, allowPrivilegeEscalation:false, runAsNonRoot:true, runAsUser:65534, runAsGroup:65534, capabilities:{drop:["ALL"]}, readOnlyRootFilesystem:true, seccompProfile:{type:RuntimeDefault}` | same |
| forbidden | `tty, stdin, targetContainerName, env, envFrom, volumeMounts, volumeDevices, capabilities.add` (VAP asserts these are unset/empty) | same |

- **Digest resolved (R3-2):** Codex captured `busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f`
  (linux/amd64), config `Cmd=[sh]`, into `evidence/baseline/busybox-1.36-amd64.json`. `Entrypoint`/`User`
  were **not captured** — so treat busybox's user as **unconfirmed**; if `User` is empty it defaults to root
  (UID 0), which is why `runAsNonRoot:true` needs the explicit numeric `runAsUser/runAsGroup:65534` rather
  than relying on the image. The handler and VAP pin this **same** digest. No execution/efficacy is proven by
  the metadata (M-57/M-61 separate).
- **`command`/`args` separately + C1:** `custom-inject` = `command:["sh","-c"]`, `args:["echo
  phorvex-custom-action; sleep 1"]` (current behavior, split). `debugger` currently sends **no** command
  (busybox `Cmd=[sh]`, an idle shell). **Debugger-command is a SEC-1/P2 decision:**
  - **Option A (default, no behavior change): the VAP MUST assert `command` and `args` are BOTH absent/empty
    for `phorvex-debugger` (C1).** "No command in the profile" is not enough — an unconstrained field lets an
    injected `phorvex-debugger` carry an arbitrary command; the VAP must positively require emptiness.
  - **Option B:** explicit bounded diagnostic `command:["sh","-c"], args:["sleep 3600"]` (attribution +
    bounded lifetime); the VAP asserts exactly those values. **Compatibility:** Option B changes the
    container's runtime behavior/lifetime and must be approved. **Recommendation: Option A.**
  Either way the VAP constrains both fields exactly — never leaves them unconstrained.
- **Identity allowlist + identity→namespace mapping (R3-2):** allowed submitter =
  `system:serviceaccount:phorvex-system:phorvex-phorvex-manager` (the single deployed manager SA). That SA
  operates only in the **managed namespaces** (currently litellm, vllm per the authz review); the VAP's
  identity rule denies any other `userInfo.username` submitting to an in-scope target.
- **Out-of-scope target ⇒ capability unavailable (C3):** on an unlabeled namespace the VAP does not match, so
  **at the API level** the request is governed by RBAC/other admission only — this ticket does not extend
  API enforcement there. But **RBAC-allowed ≠ verified admission**, so Phorvex must mark its **target-specific
  code-exec capability UNAVAILABLE** for any target the VAP does not cover: the capability gate treats a
  target outside the verified admission scope as fail-closed (no dispatch), the same as missing admission.
- **Multiple releases (C3):** a boolean namespace label + one allowed SA does **not** distinguish releases.
  Resolve in **PO-1/SEC-2** by one of: (a) **installation limit** — one Phorvex release per cluster owns the
  singleton cluster-scoped VAP; or (b) **explicit mapping** — a release-scoped label *value* + that release's
  SA named in the identity rule, so each release's binding/identity pair is distinct. State the chosen limit;
  no per-release policy copies (they collide on the cluster-scoped name).
- **Scope selector:** managed namespaces carry an installer-applied label (e.g.
  `phorvex.ai/codeexec-managed:"true"`). The authz review observed the manager SA **could not** patch/update
  namespaces, so it could not self-relabel — this is the specific observed denial, not a general
  non-bypassability proof (R3-2).
- **Migration:** only newly-added containers are validated; pre-existing `oldObject` entries pass.
- **Content/version match:** the boot/runtime check verifies the policy CEL + binding
  `validationActions:[Deny]`/`failurePolicy:Fail` by content hash and a `policyVersion` annotation, not by
  name presence.

## 6. Freshness & dispatch — single timing contract (R3-1)
**Primary enforcement is the API-server VAP.** The operator's verification is defense-in-depth over whether
Phorvex *chooses* to dispatch; it is **not atomic** with the API submission, so it **reduces, not
eliminates,** the exposure window. No absolute timing bound is claimed for the operator path.

- **Uncached, aggregate-deadline verification:** the gating decision reads the VAP, its Deny binding, and the
  scope selector **live/uncached** (direct GET + SSAR). All reads for one decision share **one aggregate
  deadline `D`**; if the aggregate does not complete within `D` ⇒ **unknown → unavailable**. The informer is
  an early-warning trigger only, never the freshness source.
- **Independent expiry:** a successful verification stamps `verifiedUntil = now + TTL`. The state **expires on
  that timer regardless of watch activity** (a quiet watch never refreshes it). Past `verifiedUntil` ⇒
  unavailable until a new successful verification.
- **Invalidation epoch (C2, replaces the generation latch):** a process-local monotonic counter
  `invalidationEpoch`. Any observed invalidation (weakened/absent/invalid/stale) **increments** it and marks
  unavailable. Each verification captures `startEpoch = invalidationEpoch` when it begins; its success may
  clear/refresh the gate **only if `startEpoch == invalidationEpoch` at completion** (no invalidation occurred
  while it ran). Benign recovery is clean — after a timeout with no invalidation, a fresh verification of the
  unchanged, valid objects recovers — while an **older in-flight success that completes after an invalidation
  was observed carries a stale `startEpoch` and cannot override it.** No dependence on object-generation
  ordering.
- **Final pre-submit check:** immediately before submit, require an unexpired verification whose `startEpoch`
  still equals the current `invalidationEpoch` (no invalidation since it succeeded); fail ⇒ do not dispatch.
- **Observed-state invariant (not a bound):** Phorvex does not dispatch while it holds an observed
  invalid/stale/expired/latched verification. It cannot bound the residual window between the final check and
  the API submit (goroutine pause, in-flight, admission propagation); that window is acknowledged, and the
  API-server VAP is the durable guarantee.
- **Init:** unavailable until the first successful uncached verification; post-start enablement triggers a
  verification before eligibility.
- **Values + reporting latency are PROPOSED TARGETS, not measured (R3-1):** propose `D` and `TTL` (e.g. `D≈2s`,
  `TTL≈30s`); the reported-status refresh is driven by the same verification loop + expiry. The
  time-to-report-unavailable after an external weakening is a **target to be measured in L4 under bounded
  conditions** (see §8), not an asserted number.

## 7. Per-failure-mode enforcement (R3-3 — API outcomes attributable)
"This contract does not deny" ≠ "the API admits." Other admission/authorization may still reject; and a
**policy-config write** accept/reject is distinct from **evaluation errors during a workload request**.

| State | This VAP on the workload request | Runtime capability | Attributed |
|---|---|---|---|
| Policy/binding absent | **Does not deny** (other admission/authz may still reject) | Unavailable (`…: policy/binding absent`) | boot/runtime check |
| Binding `Warn/Audit` | **Does not deny** (other controls may) | Unavailable (`…: binding not Deny`) | runtime check |
| Invalid params/CEL under `failurePolicy:Fail` | **Denies** the workload request (fail-closed) | Unavailable (`…: invalid policy`) | VAP failurePolicy |
| Admission-object read/discovery fails | Undetermined here (other controls unchanged) | Unavailable (`…: state unknown`) | runtime (unknown) |
| Stale/expired verification or bumped `invalidationEpoch` | Undetermined here | Unavailable (`…: stale/invalidated`) | runtime freshness |
| Target outside verified scope (unlabeled ns) | This VAP does not match (RBAC/other admission govern) | **Unavailable for that target** (`…: target out of verified scope`) — C3 | capability gate |
| Full approved contract present, in-scope target | Denies each isolated violation by its own rule | Available | VAP |

(Separately: a **write** to the policy/binding objects themselves is accepted/rejected by RBAC+admission on
those resources — not by this workload VAP.)

## 8. Acceptance criteria & tests (P4)
L0–L2 (mine): CEL unit tests — newly-added filter incl. **absent-`oldObject`** first-injection; each profile
rule allow + isolated violation (name, image-digest, each `securityContext` field, command/args,
tty/stdin/target/env/envFrom/mount, `capabilities.add`); **C1: `phorvex-debugger` with a non-empty command
or args is denied** (empty is positively required, not merely unspecified); boot-check tests per §7 row incl.
**C3 out-of-scope target ⇒ unavailable**; **deterministic check/remove/submit interleaving test (round-2)**
exercising the **C2 invalidation-epoch** (bump epoch mid-verification ⇒ the in-flight success cannot clear;
timeout-then-fresh-verify of unchanged valid objects recovers) + final pre-submit check + queued-work
re-verify; capability-gate test (unverified ⇒ code-exec excluded + queued not dispatched; others unaffected);
chart render (Deny binding, `failurePolicy:Fail`, scope selector; no role bound). L3 (Codex, isolated fixture, real-subresource dry-run): the ticket's verification matrix, each
row attributed (VAP rule vs RBAC/PSA). L4: §6 targets **measured** under bounded conditions — time-to-report,
observed-invalid → no-dispatch, queued re-verify, restoration-requires-fresh-success; distinguish
observed-invalid from unknown-external-change.

## 9. Predicted output band
```
Before (UNVERIFIED until L3): the manager SA can UPDATE pods/ephemeralcontainers in litellm/vllm via
  phorvex-actuation; whether an arbitrary privileged/tagged payload is admitted is proven only by the
  isolated test (PSA/other admission may already reject some).
After (approved contract): reviewed VAP+Deny-binding present; approved identity+paired-profile+in-scope is
  admitted by THIS policy; each isolated forbidden attribute is denied by its own rule (attributable, distinct
  from RBAC/PSA); on missing/weakened/invalid/unreadable/stale admission the capability is unavailable per the
  §6 contract (no absolute-timing claim; observed-invalid ⇒ no dispatch), unaffected defenses continue; actions
  off by default; no scoring/cover/efficacy change.
```

## 10. 02B responses (kept current)
- **B1** ✓ principal `phorvex-phorvex-manager`; effective `phorvex-actuation` grants; placeholder flagged;
  before-state UNVERIFIED; object-label scope rejected (§2).
- **B2** ✓ single paired change, exact defaults, busybox root-UID note, compatibility alternative (§4/§5a).
- **B3** ✓ namespace-label scope; inline constants; naming/multi-release/content-match settled (§5a).
- **B4** ✓ **replaced by the single §6 contract** (no separate 30s/60s or zero-stale-dispatch claim).
- **B5** ✓ per-failure-mode table with attribution + absent-`oldObject` handling (§7/§8).
- **B6** ✓ tested=1.36.2 only; change_class A.

## 11. Round-3 responses (R3-1/R3-2/R3-3)
- **R3-1** ✓ single §6 contract: aggregate deadline, independent expiry, **monotonic latch**, final pre-submit
  check, **no absolute-bound claim**; timing values + report-latency are **proposed targets measured in L4**;
  **removed the contradictory zero-stale/30s/60s text from §9/§10**; interleaving test kept (§8).
- **R3-2** ✓ single exact name set (no prefix); candidate digest+platform+capture method+metadata (actual
  `sha256` needs registry access — Codex/installer, flagged); command **and** args separate; debugger-command
  is an explicit **SEC-1/P2 decision** (Option A default / Option B bounded) with rationale+compatibility;
  identity allowlist + identity→namespace mapping + out-of-scope behavior; `capabilities.add`/`envFrom`/etc.
  forbidden; "proven non-bypassable" narrowed to the **observed direct denials** only (§2/§5a).
- **R3-3** ✓ "this contract does not deny; other admission/authz may reject" throughout; policy-config write
  vs workload-request evaluation separated; §6 no longer concludes "the API admits" from VAP removal (§6/§7).

## 12. Rev4-review responses (C1–C3 + metadata/ruling/version)
- **C1** ✓ the VAP positively **requires `command` and `args` empty** for `phorvex-debugger` under Option A
  (and asserts exact values under Option B) — never leaves them unconstrained (§5a; test in §8).
- **C2** ✓ replaced the object-generation latch with a **process-local `invalidationEpoch`**: benign timeout
  recovers on fresh verification of unchanged valid objects; an older in-flight success with a stale
  `startEpoch` cannot override an observed invalidation (§6; interleaving test §8).
- **C3** ✓ an out-of-scope (unlabeled) target: this VAP does not match at the API level, but Phorvex marks its
  **target-specific code-exec capability unavailable** (RBAC ≠ verified admission); multi-release resolved by
  an installation limit or explicit release→(label,SA) mapping in PO-1/SEC-2 (§5a/§5/§7).
- **Image metadata** ✓ real digest `busybox@sha256:b7f3d86d…` (linux/amd64, `Cmd=[sh]`) from
  `evidence/baseline/busybox-1.36-amd64.json`; `User` uncaptured ⇒ root not assumed, explicit `runAsUser:65534`
  retained. **Ruling reference** ✓ `evidence/decision/three-round-ruling.md`. **Version wording** ✓ tested
  (1.36.2) vs targeted (PO-1 decision) distinguished (§5/PO-1).

**Next:** `codex-m006` independent re-review of this closure package. On convergence I prepare the
SEC-1/SEC-2/PO-1 decision record for Mostafa. No implementation until `03-decision`.
