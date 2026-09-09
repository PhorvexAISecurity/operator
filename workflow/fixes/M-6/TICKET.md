````markdown
**Named fix:** `M-6` · **Tier:** Parallel — no established implementation dependency

**Subsystem:** `CONTRACT` · **Initial owner:** **DEVOPS**

**Owner flow:** **DEVOPS baseline → security contract review → DEV/DEVOPS implementation → independent DEV + DEVOPS review → isolated verification**

**Implementation owner:** **DEVOPS for admission manifests/chart, RBAC, and deployment; DEV for startup/runtime capability checks and reporting**

**Reviewer:** **independent DEV with Kubernetes admission-security expertise + independent DEVOPS reviewer** · **Verifier:** **DEVOPS**

**Named assignees:** Confirm the accountable DEVOPS owner, implementing DEV, and independent reviewers. The attachments do not establish individual assignments.

**Product / cybersecurity decision owner:** **Mostafa** — approved execution scope, permitted request profile, customer compatibility, and release conditions. Engineering supplies the threat model and test evidence before requesting decisions.

**Math gate:** **NO for the declared admission/deployment correction.** Security review is mandatory. Consult **MATH before the affected change** if implementation changes risk/value weights, action cover credits, cost/budget equations, optimizer assumptions, or claims a new quantitative protection guarantee. Excluding an unavailable action through the existing capability mechanism does not itself require a new mathematical ruling.

**Code:** admission manifests and `charts/phorvex` templates; RBAC definitions in `config/rbac` and chart-generated equivalents; source-reported startup entry `cmd/main.go`; actual policy/capability evaluation and reporting paths identified during preflight. Inspect `debugger`/`custom-inject` request construction to determine what the policy must validate. Do not assume schema or handler changes are required.

**Closes:** M-6 — deployment and verification of the declared admission safeguard, with detection and safe handling of its absence or invalid configuration.

**Severity / evidence:** **HIGH · 🔴 LIVE as reported in the register; current deployment must be re-screened** · **Priority:** **P2 / parallel severity order**, retained from the supplied drafts.

**Depends on:** no established implementation dependency — baseline and implementation preparation can start now.

**Coordinates with:** M-1/M-7 for effective RBAC; M-4 for identity separation and other execution privileges; M-57/M-61 for separate action-functionality limitations. Confirm actual companion ticket IDs before linking them.

**Blocks:** **Proposed operational gate:** enabling `debugger`/`custom-inject` in a supported deployment requires the approved admission contract to be installed and verified. This is an issue-specific enablement prerequisite, not an invented numbered-tier dependency.

**Branch:** `parallel/contract-m006-code-exec-admission`

> **Tier rule.** No numbered-tier dependency has been established. This issue may start alongside the numbered tiers.
>
> **Tier exit criterion.** Close only when the shipped policy actually enforces the approved request contract and Phorvex handles loss of that contract correctly. Object existence alone is insufficient evidence.

---

## What is wrong

The Master Register describes four safeguards for `debugger`/`custom-inject`: a ValidatingAdmissionPolicy (VAP), a feasibility guard, actions disabled by default, and a hardcoded image. It reports that the latter three exist in code, while the admission manifest exists in the repository but the observed cluster has zero VAPs. Role B, permitting `pods/ephemeralcontainers`, is reportedly unbound by default.

**Title correction:** the original phrase “three-quarters unshipped” is unsupported by that description: it identifies one absent admission layer, not three absent layers. No percentage of protection or readiness is established.

The supplied second version correctly adds a policy binding and ongoing checks. However, a presence-only check, an image-and-identity-only example, and an unscoped cluster-wide binding are not sufficient to establish the intended security boundary.

## Why it matters

Phorvex turns security observations into workload-changing actions selected by its decision engine. Code-execution capability therefore requires an enforceable boundary outside the operator's own decision logic.

If a principal has effective ephemeral-container permissions, missing admission enforcement can allow requests beyond the intended action profile. An unbound Role B does not prove that no other role grants equivalent access.

An admitted request proves API acceptance, not that the action achieved a defensive outcome. Anatomy V2 marks these actions' security outcomes unconfirmed; M-57 and M-61 remain separate. This ticket must not increase their claimed cover or effectiveness merely because admission is installed.

## ⚠️ Known traps — read before starting

- **Re-screen exact versions.** Record source SHA, image digest, chart revision/values, Kubernetes version and served APIs. The register/Brain Contract reference `v0.4.58 / aedd218`; Anatomy V2 references `fb52e6c`.
- **Policy and binding are both required.** Rejection requires an applicable binding with `Deny`; warning/audit-only behavior is insufficient. Parameter resources, when used, are part of the contract. [Kubernetes VAP overview](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- **Fail-closed settings are not universal coverage.** Require `failurePolicy: Fail`, and `parameterNotFoundAction: Deny` for parameterized bindings. Verify actual matching and effective references; a policy absent from the cluster cannot enforce its failure policy. [Binding API](https://kubernetes.io/docs/reference/kubernetes-api/admissionregistration/validating-admission-policy-binding-v1/)
- **Match the actual mutation.** Cover `UPDATE` requests to `pods/ephemeralcontainers`, including relevant client update/patch paths. Inspect exclusions, namespace/object selectors, and match conditions; an excluded request is not rejected by a validation expression. [Policy API](https://kubernetes.io/docs/reference/kubernetes-api/admissionregistration/validating-admission-policy-v1/)
- **Do not mistake image identity for safe execution.** Review commands/arguments, privilege settings, capabilities, target-container choice, and relevant environment/mount references against the intended handler request. Document any unconstrained field. Do not ship the draft CEL as an approved security specification.
- **Do not silently restrict every customer's debugging workflow.** An empty binding scope combined with an operator-only rule can affect unrelated administrators and tools. Mostafa must approve the scope and exceptions.
- **Protect the whole configuration.** Policies, bindings, parameter objects, and labels used to select protected resources must not be alterable by identities they constrain. Review effective grants, including indirect privilege paths; a read-only admission Role alone is insufficient. [RBAC guidance](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- **Separate installer authority from runtime authority.** The installer needs appropriately scoped administrative permissions, not necessarily blanket cluster-admin. Do not grant the operator admission write/delete authority or permission to rewrite its own allowlist.
- **API discovery is not a support policy.** VAP is stable since Kubernetes 1.30. Propose and test a supported version matrix; do not assert that D-14 already approved one. Unsupported or unverified enforcement means code-exec remains unavailable. [Kubernetes VAP overview](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
- **Continuous observation is not instantaneous protection.** Account for cache freshness, failed reads, parameter/selector changes, and queued work. Measure detection time. An operator check does not stop direct API use of a stolen credential when admission has been removed.
- **Keep failures attributable.** A request denied by RBAC or Pod Security Admission does not prove this VAP worked. Test identity and payload restrictions independently.

## Recommendation

**From the register — verbatim:**

> ship and apply the VAP; add a boot-time check that it exists when code-exec is enabled anywhere.

**Explicit implementation extensions:** include the enforcing binding and any parameters; validate configuration rather than only names; reevaluate after startup and configuration changes; keep affected actions unavailable when the safeguard is missing, invalid, or unverified. These are proposed closure requirements, not additional historical findings.

### Code-wise recommendation

1. **Define the enforceable request contract.** DEV inventories the exact requests emitted by both actions. Security review specifies permitted identities, targets, image references, commands, privilege profile, and controlled exceptions. Reconcile this with existing layers 2–4 without silently changing them.
2. **Ship a complete admission bundle.** DEVOPS packages the reviewed VAP, binding, and parameters if necessary. Include approved scope, deny behavior, installation ownership, and compatibility checks. Resolve cluster-scoped naming and multiple-release ownership explicitly.
3. **Keep execution off by default.** Do not bind Role B or enable either action as a side effect of installing admission. For customer-managed admission, verify the agreed contract rather than overwriting customer policy.
4. **Implement startup and runtime capability validation.** DEV checks API availability, expected policy content/version, applicable deny binding, parameter integrity, scope coverage, and relevant validation diagnostics. Observe all resources that can change this result, including parameter objects and relevant selectors; provide justified resynchronization/freshness handling.
5. **Fail closed for the affected capability.** Missing, invalid, unreadable, stale, or unsupported admission state excludes both actions through the existing capability gate and prevents dispatch of queued work once that state is known. Report the reason; preserve other defenses where existing contracts allow. Restoring object names alone must not clear the condition.
6. **Report deployment health separately from enforcement evidence.** Use existing status, structured logs, and metrics where possible. Distinguish reasons such as missing policy, missing/non-denying binding, invalid parameters, scope mismatch, unsupported API, and state unknown. Proposed new names must follow the repository's vocabulary.
7. **Sequence rollout and rollback safely.** Install and verify admission before enabling execution permissions/actions. Before removing or downgrading enforcement, disable affected actions, prevent new submissions, revoke effective execution permissions as appropriate, and account for in-flight requests. Document uninstall/Helm rollback behavior and shared-resource ownership.

## Tasks and handoffs

| # | Who | Task | Required output |
|---:|---|---|---|
| 1 | **DEVOPS + DEV** | Capture current installed state, API/version support, effective identities/RBAC, admission contents, defaults, and actual request paths. Inspect layers 2–4 without assuming their security effectiveness. | `Baseline operational matrix + request inventory` |
| 2 | **Security-qualified independent DEV reviewer + Mostafa** | Review threat boundary, permitted request profile, customer scope, exceptions, and proposed compatibility/degraded behavior. Mostafa resolves the product/security choices below. | `Versioned security contract + decision record` |
| 3 | **DEVOPS + DEV** | Deliver admission packaging/read access and startup/runtime capability validation. Add regression tests for missing, invalid, changed, stale, and restored states. | `Manifest/chart/code PRs + focused tests` |
| 4 | **Independent DEV + independent DEVOPS reviewers** | Review CEL and effective permissions, anti-bypass scope, runtime behavior, first install, upgrade, rollback, and test attribution. Implementers may not approve their own work. | `Code/security approval + operational approval` |
| 5 | **DEVOPS** | Run the independent allow/deny matrix and lifecycle checks in an isolated fixture. Attach raw requests/results and actual-versus-predicted behavior. | `Version-tagged verification package` |

### Product / cybersecurity questions — Mostafa

| ID | Decision needed | Engineering recommendation | When required |
|---|---|---|---|
| SEC-1 | What may these actions execute, on which targets, and under which identities? Who may change the approved profile? | Approve a narrow, versioned request profile; review digest pinning, command/privilege restrictions, and control of any parameters. Keep code-exec disabled until agreed. | Before finalizing enforcement rules or enabling the capability. |
| SEC-2 | Should enforcement cover Phorvex-managed workloads only or a broader customer scope? What administrator/debugging exceptions are permitted? | Enforce the declared managed scope using selection controls tenants cannot bypass; make any emergency exception explicit, limited, and auditable. Do not assume protection against a trusted cluster administrator. | Before deploying a binding that could affect other customer workflows. |
| PO-1 | Which Kubernetes/API versions and installation models are supported, and may other defenses continue when code-exec is unavailable? | Start with tested stable VAP support; allow customer-managed admission only under a verifiable contract. Keep code-exec unavailable on unsupported/unverified clusters and continue unaffected defenses with visible degraded status. | Before publishing compatibility and degraded-mode behavior. |

Baseline, source review, and test preparation can proceed while these decisions are open. No unsupported reference to a “signed sheet” counts as approval.

## Required properties

### P1 — Source fidelity

Every claim identifies the source/build/configuration. Historical zero-VAP evidence is reproduced or updated. Count the relevant policies, bindings, and parameters; unrelated VAPs do not close this issue.

### P2 — Scope fidelity

M-6 retains `CONTRACT`. Startup/capability wiring is recorded explicitly; substantial CONTROL, CHOICE, RECORD, or ACTUATION changes use separately tagged companion work. No silent change to mathematical scoring, cover, feasibility laws, action defaults, image identity, or handler behavior.

### P3 — Review independence

Independent technical security review and operational review are required. Mostafa approves product/security choices; specialist reviewers supply the technical evidence. Math involvement follows its explicit trigger.

### P4 — Evidence discipline

Every denial identifies the actual rejecting layer and failed rule. Each restrictive rule has an otherwise valid allow case and an isolated violation case. Object presence and fake-client tests do not certify CEL execution by an API server.

### P-CONTRACT — Contract coherence

Documented capability, installed admission, effective RBAC, and runtime availability agree. Installed does not mean enabled; enabled does not mean the defensive outcome has been confirmed.

### P-FAIL-CLOSED — Capability-specific failure

Known missing, invalid, unsupported, or unverified admission state prevents new operator-generated code-exec requests; unrelated defenses continue according to the approved degraded-mode contract. Detection/propagation delays and in-flight behavior are measured, not described as instantaneous.

### P-SECURITY-BOUNDARY — Independent enforcement

While the approved admission contract applies, disallowed requests are denied at the API server even when submitted directly using an otherwise RBAC-authorized test identity. Operator/workload credentials cannot rewrite their own protection through effective permissions. The boundary excludes unaddressed alternate execution paths and does not guarantee safety after a privileged administrator removes enforcement.

## Verification matrix

Use server-side dry-run against the actual ephemeral-container subresource where supported to prove admission without persisting an injection; it still exercises authorization and admission. Use disposable pods for any persisted integration check. Operator dry-run is not equivalent. [Kubernetes API dry-run](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run)

| Scenario | Required result |
|---|---|
| Approved identity + fully approved payload + in-scope target | Admitted by this policy in a fixture satisfying the other admission controls; both action request forms covered. |
| Approved identity + forbidden image | Denied by this VAP's image rule. |
| Unapproved identity + approved payload | Denied by this VAP's identity rule; give this disposable test identity the necessary scoped RBAC so an earlier RBAC denial cannot mask the test. |
| Approved identity/image + individually forbidden command, privilege, or target | Each violation is rejected by the intended rule. Test each changed field independently. |
| Scope/exemption boundary | In-scope requests cannot bypass via permitted label changes; approved out-of-scope workflows remain unaffected. Test pre-existing ephemeral containers against the chosen migration semantics. |
| Policy/binding/parameters missing or altered; binding Warn/Audit-only; failure behavior weakened | Runtime capability becomes unavailable with a specific reason. Separately test actual API enforcement for each applicable configuration. |
| Invalid CEL or parameters; reads/discovery fail; watch becomes stale | Unknown/invalid state does not authorize execution. Exercise actual API-server behavior as well as client-side state handling. |
| Enable an action after startup; remove/change protection with queued work; restore it | Revalidation occurs before eligible dispatch; known invalid state blocks new work. Measure transitions and require valid configuration before recovery. |
| Effective permission review | Runtime/workload identities cannot mutate protection/parameters or obtain equivalent rights through the reviewed escalation paths. Role B remains unbound by default. |
| Fresh install, upgrade, rollback, uninstall, and multiple releases | Enforcement ownership is explicit; no permission-enabling or admission-removal window is introduced by the supported procedure. |
| Unrelated defenses and optimizer behavior | Unrelated workflows pass regression checks. Excluding code-exec may legitimately change selected actions; do not require byte-identical decisions or claim new defensive efficacy. |

## Definition of done

- [ ] Named delivery owners and independent reviewers are recorded.
- [ ] Current source/deployment baseline and actual request inventory are attached.
- [ ] Mostafa's affected scope/profile/support decisions are recorded before enforcement rollout or enablement.
- [ ] Policy, enforcing binding, and any parameters are shipped or verified under the supported customer-managed route.
- [ ] Effective RBAC protects the admission configuration, parameter data, and relevant scope controls; operator permissions remain least privilege.
- [ ] Startup and runtime checks cover absence, weakening, invalidity, read failure, freshness, post-start enablement, and recovery.
- [ ] Behavioral regressions fail on the confirmed old defect and pass after correction.
- [ ] Independent allow/deny probes prove each rule; raw evidence distinguishes VAP denial from other rejection layers.
- [ ] Code-exec stays disabled by default and unavailable when its admission contract is unverified.
- [ ] Fresh-install, upgrade, rollback/uninstall, and ownership behavior are verified without an unsafe supported transition.
- [ ] Non-code-exec behavior and legitimate customer debugging compatibility are checked.
- [ ] Independent DEV/security and DEVOPS approvals are attached.
- [ ] Evidence includes source SHA, image digest, chart/values, Kubernetes version, rendered policy/binding/parameter versions, identities, fixtures, timestamps, requests, and responses.
- [ ] Register M-6 closes with accurate scope and evidence; M-4/M-57/M-61 and any other unresolved prerequisites remain separately tracked.

## Predicted-output band before implementation

```text
Before:
- Historical register: zero VAPs; layer 1 absent; Role B unbound by default.
- Verify current counts, bindings, effective permissions, and action defaults.
- Establish the admission gap with an otherwise authorized isolated fixture.

Expected after:
- Supported install: reviewed policy + deny binding + required parameters available.
- Actions and execution permissions are not enabled by installation alone.
- Approved identity/payload/target passes; each isolated forbidden attribute fails.
- Failures identify the actual VAP/rule rather than an unrelated RBAC/PSA denial.
- Missing, weakened, invalid, unreadable, stale, or unsupported protection:
  affected capability unavailable; reason reported; unaffected defenses continue as approved.
- Post-start action enablement and configuration changes trigger revalidation.
- Detection latency, queued/in-flight work, and restoration are measured explicitly.
- Supported upgrades/removal disable execution safely before weakening enforcement.
- No claim of instantaneous revocation, arbitrary-code prevention from image identity alone,
  or successful defensive effect from API acceptance.
- Scoring equations and cover credits remain unchanged; selected actions may differ
  because unsafe/unavailable candidates are excluded.
```

## Evidence from the Master Register / source basis

**M-6 · HIGH · 🔴 LIVE · `CONTRACT`** — source-reported absence of the declared VAP layer, with layers 2–4 present in code and Role B unbound by default. **Fix:** quoted verbatim above. *Source: A-179.*

**Phorvex context:** Anatomy defines CONTRACT as installed/permitted capability. Anatomy V2 identifies `Pod/ephemeralcontainers` writes for both actions and distinguishes API acknowledgement from security effect. The Brain Contract governs mathematical changes and does not certify current source/runtime behavior.

**Reference corrections:** M-79 describes MIG node-exec wiring, not an established dependency for these actions. PX-P-003, PX-P-002, T1-E, T1-M079, D-14, and execution-protocol compliance are not independently established by the supplied attachment set; verify their actual records before asserting dependencies, settled decisions, or completion.

**Review status:** attachment-grounded ticket specification with upstream platform checks; no claim that this review executed repository tests, inspected current cluster state, or implemented the fix.
````
