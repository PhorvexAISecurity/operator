# dev-eks migration decision — HOLD

**2026-10-24: open a held PR; do not merge, sync, change either stack's scope,
remove RBAC, or retire the monolith.** Milad and Claude must verify and resolve the
blockers below before rollout. This task made no live changes. The temporary
`phvx93-rotate-eviction-proof` Role/RoleBinding remains in place.

This is the unsafe-overlap branch of the requested execution. Configuration can
expand the new stack's scope, but the observed stacks cannot provide an atomic,
exclusive handoff with uninterrupted defense. There are also concrete capability
and admission dependencies. Successful rendering does not resolve those blockers.

## Confirmed population and source pins

The gateway's default context was **phorvex-281-lab**, not dev-eks. Initial default-
context reads were discarded. All evidence below uses this explicit context:

```text
arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks
kube-system UID: f113d464-d8cb-4145-b83d-45638c2a196e
```

Three successful inventories at 15:33:43, 15:34:01 and 15:34:10 UTC returned
**13 policies in 12 namespaces**, with identical policy names, UIDs and generations.
Three deployment inventories returned 45 deployments; three RoleBinding inventories
returned 112 bindings, also with stable identities/generations. Old-manager tick
logs independently cover every one of the 12 policy namespaces. The baseline,
full policy specs/status, RBAC rules, image identities, logs reduced to tick samples,
and capture metadata are in
[`baseline.json`](docs/migrations/dev-eks-20261024/baseline.json).

| Tenant namespace | Policies |
|---|---|
| ci-reports | ci-reports-defense |
| console-identity-shared | console-id-fixture |
| crm | crm-defense |
| document-store | chroma-defense, mongo-defense |
| litellm | litellm-defense |
| mcp | mcp-defense |
| nats | nats-defense |
| phorvex-staging-demo | demo-api-defense |
| phorvex-verify-m100-loss-history-v2 | m100-protected-server |
| phorvex-verify-m106-scoped-outcome-v4 | m106-session-target |
| vllm | vllm-defense |
| voice | voice-defense |

The old manager has **no `--policy-namespaces` flag**: it watches policies cluster-
wide, including future namespaces. Its per-namespace RoleBindings corroborate all
12 namespaces. They additionally grant access in **costbench-opus** and
**phorvex-catalogue-cpu**, which have no policy in the three inventories. These are
retained RBAC/fixture dependencies, not silently counted as active policy tenants.
They require a disposition before old resources can be removed. No historical
metric label or leftover AMTD was treated as a current policy.

| Component | Observed pin |
|---|---|
| Fetched operator-refactored main / this branch base | aa1f711a029ba57eb08087798a344d168f7d82ff |
| OLD Argo phorvex-stack | operator.git@6d581657ba138139cb7876e7e89dc99cb77978ff; Healthy, OutOfSync, SyncError |
| OLD running manager | phorvex:kv-drain-reset-0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec; runtime digest sha256:0c4dd5c59d67e069d31b509b6c87b89bb134549d17edeb7c7f5c7bef452db740; hybrid |
| NEW manager | phorvex/manager:0.11.1; digest sha256:d005e77ed2fa58d057e7d970731711f6dc5f8ae07cce173aa661c6aa97b3c35b; native |
| NEW manager / actuator embedded source | f34bc429582fc1418b680b9e159942c07aea4438, observed in both startup/tick logs and manager release values |
| NEW actuator | phorvex/actuator:0.6.1; digest sha256:8541c1b37c311c23fe16b7c8a5c83d6b3e0b593f081a7a9094b2183f6de5f571 |
| NEW six service Applications | operator-refactored@main, observed Synced/Healthy at aa1f711a; automatic sync and self-heal enabled, prune false |

The old Argo pin, live image tag, runtime digest, and new released source are
separate identities. Syncing the old app or rolling it back to its Argo pin would
not reliably restore the observed experimental runtime.

## Ownership finding: overlap permits double actuation

1. [`tenant_collision.go`](phorvex/internal/runner/tenant_collision.go) builds its
   `collisionState` from one manager's in-memory `m.policies`. `TenantCollision=False,
   reason=UniqueOwner` means a display tenant name resolves to one policy-owned
   economic unit **inside that manager**. It does not identify a winning deployment.
   `Upsert` in [`manager.go`](phorvex/internal/runner/manager.go) rejects duplicate
   policy UID aliases only inside the same registry. Neither is a cluster lease.
   This was also checked in the old image-tag source and the new manager's pinned
   source, not just current main.
2. [`cmd/main.go`](phorvex/cmd/main.go) uses leader-election ID
   `phorvex.phorvex.ai` without a shared election namespace. Live leases show
   **two simultaneous leaders**, renewing independently:
   `phorvex-system/phorvex.phorvex.ai` holds the old pod;
   `phorvex-staging/phorvex.phorvex.ai` holds the new manager pod.
   Phoenix separately holds `phorvex-system/548c5e7b.r6security.com`.
3. [`policyscope.go`](phorvex/cmd/internal/policyscope/policyscope.go) says an empty
   scope watches every namespace. Scope handshakes compare services within one
   stack; they do not arbitrate between stacks. The actuator service delegates
   requests to its backend in [`local.go`](phorvex/internal/actuatorsvc/local.go).
   Action-specific receipts, policy-owner checks and capacity limits do not establish
   exclusive authority over every mutation path across these deployments.
4. Existing demo overlap is live: both managers log active-mode ticks for
   `phorvex-staging-demo/demo-api-defense`, UID
   `a4c45a56-a549-4f77-bfe6-de3ae6d1d99d`, with `killSwitch=false`. Both export
   active decision counters for that tenant. Both have a rotate execution path;
   the old manager now also has the temporary eviction grant. **No simultaneous
   destructive mutation was induced or claimed.** The samples show no selected
   demo moves, not proof of an ownership fence. The new manager's sampled demo
   tick has three infeasible candidates, so existing overlap is not a parity proof.

Therefore it is unsafe to expand live overlap. The already-present demo overlap
must be resolved under the same supervised handoff; this task did not enlarge it
or remove its temporary grant.

## Capability and retirement blockers

| ID | Tenant / dependency | Evidence and required resolution |
|---|---|---|
| B1 | Every active tenant | No cross-stack execution fence. Prove exclusive mutation authority, readiness and in-flight-operation handling before any handoff. |
| B2 | vllm | Old image-tag source includes `kv_reset_warm_drain.go::drainResetReopen`, called from `serving_effect_journal.go` on under-load negative ACK. The refactored main and pinned actuator source lack this function; their protected KV-reset path retains a negative ACK instead. Old live logs also report confirmed KV-reset maintenance. Preserve and independently verify this capability in the actual replacement actuator image; scope expansion cannot supply it. |
| B3 | vllm | Old serving-security ConfigMap binds exact policy UID, workload SA and `vllm-serving-admin` credential/CA references; old deployment also supplies endpoint-lease approvals and journal grants. New actuator has no serving-security file/bindings or these approvals. Provision reviewed credentials in its operator namespace, exact bindings, capability grants and recovery continuity through GitOps; do not copy secrets into this PR. |
| B4 | voice, litellm, crm, console-identity-shared | Old manager has feature-specific Roles (Voice memory/output/refund/MCP, LiteLLM client revoke, CRM refund, identity rotation). New service values leave those features off and lack their feature grants and credentials. Old logs show repeated confirmed Voice memory-rule maintenance. Transfer supported behavior and per-Pod protected-operation recovery, including pending/confirmed receipts, before old maintenance stops. Existing false ActionsSupported conditions do not authorize removing working maintenance. |
| B5 | All detector-driven tenants, especially vllm | Old trusts vllm detectors, Phoenix and the old console/e2e detectors. New trusts only `phorvex-staging/staging-attacks`. Map each producer and its admission identity to the new stack, verify comparable telemetry/EPSS and decisions. Retain the trust boundary; do not blindly trust every detector. |
| B6 | Cluster admission / all tenants | Old serves fail-closed PhorvexPolicy validation and protected-outcome SecurityEvent stamping. New admission webhook and identity-policy installation are off; new manager/sensor explicitly depend on the old creator-identity policy `phorvex-system-phorvex-phorvex-se-creator-8acf73b8d0`. Rehome admission and the external guard without weaker enforcement or a service outage before stopping the old manager. |
| B7 | costbench-opus, phorvex-catalogue-cpu, old observers/fixtures | RBAC exists without current policies. The old app tracks cost fixtures, identity fixture, EPSS feed/observer resources, CRD and admission guards as well as the brain. Establish retained owners; never cascade-delete the app or namespace. |

The new actuator startup log reports the same f34bc429 source as the manager;
the running actuator digest matches its staged values. This establishes the source
gap in the observed release. Verify any replacement image digest and its behavior
again before clearing B2.
Feature Roles show configured capability, not a claim that every enabled action
currently works. Gaps that are already present in the old deployment are preserved
as baseline debt, not described as migration regressions or waived.

## Coordinated cutover: why the current config cannot satisfy the contract

For a tenant, let `(old, new)` represent permission to actuate. The required
handoff is `(1,0) -> (0,1)` with exactly one authority at every instant, a prepared
replacement, and no stale in-flight writer. Independent Argo Application rollouts
and independent RBAC writes cannot make that transition atomically:

| Attempt | Intermediate state | Result |
|---|---|---|
| Add NEW scope/RBAC, then exclude OLD | (1,1) | Unsafe overlap; separate leases do not serialize it. |
| Exclude/revoke OLD, then add NEW | (0,0) | Defense gap; old stays running for other tenants but this tenant loses service. |
| Change both "at the same time" / sync waves | Unordered rollouts | No atomicity, readiness or stale-request guarantee. |
| Set the policy dryRun / engage a kill switch | Actuation suppressed | Weaker defense; it is not an authorized workaround. |
| Restart OLD with a smaller scope | Old Recreate rollout | Risks defense gaps for every tenant it still owns; it is also a gated old-stack change. |
| Revoke OLD native RBAC only | Phoenix/maintenance may remain | Does not fence hybrid's other execution paths or queued Phoenix work. |

**There is no verified, executable no-gap/no-overlap config-only sequence for the
current stacks.** Do not interpret a sleep, zero recent moves, a shared policy
condition, manual Lease edits or a successful render as that sequence.

Milad/Claude's next decision is to authorize a separate prerequisite for an atomic,
fenced execution handoff (or provide an already-tested mechanism), together with
B2–B7 parity/admission work. A bare shared leader-election Lease is insufficient
without handling stale writers and all hybrid/Phoenix paths. This PR does not
implement brain changes or relax either safety rule.

The supervised protocol, once that prerequisite exists, must be:

1. Capture and pin both runtime digests, all policy UIDs/generations, dependencies,
   RBAC, audit history, protected-operation journals and the old app's desired and
   observed states. Freeze only the approved rollout controls.
2. Bring the replacement to full capability and telemetry parity **without granting
   it concurrent execution authority**. Stage an inventory-derived allowlist and
   exact per-tenant credentials/grants through operator-refactored GitOps. A standby
   mode/fence with this behavior is a prerequisite, not an existing chart option.
3. For one tenant, require replacement readiness and protected-state continuity,
   then use the verified atomic authority-transfer mechanism. It must serialize
   or finish old in-flight operations, reject stale writers, preserve existing
   protection, and transfer recovery/maintenance as well as fresh decisions.
4. Verify the new stack's source-attributed ticks, action support **per selected
   target/action**, decisions and confirmed effects against the frozen baseline.
   Show that old fresh dispatch and maintenance have ceased for that tenant while
   the rest retain their baseline defense. Preserve policy modes and selectors.
5. On any regression, use the same verified authority-transfer mechanism in reverse;
   do not re-enable an unscoped old manager while NEW can still act. Complete and
   verify the reversal before the next tenant.
6. Repeat for every policy, including both document-store policies and the two
   verification tenants. Resolve the existing demo overlap under this protocol.
   Only after full independent verification may the retirement gate be requested.

## Proposed GitOps change and rollout hold

- `deploy/environments/staging/phorvex.yaml`: proposed policy/actuator scope is the
  12 confirmed namespaces. Proposed attack scope is the 10 established application
  namespaces with observed workloads and generic/specialized attack surfaces; the
  two historical verification fixtures remain defense-only. Disabled specialized
  attack profiles stay disabled; namespace RBAC is not profile parity.
- `deploy/argocd/services/project.yaml`: exact tenant destinations required for those
  namespaced Roles/RoleBindings. The live AppProject permits only staging and demo.
  It is not reconciled by the current root. Its destinations must be adopted by a
  reviewed operator-refactored Argo bootstrap before rollout; ad-hoc project edits
  would violate this migration's GitOps-only scope rule.
- Existing human/e2e console grants remain demo-only. Tests now distinguish service
  scope from user grants and preserve native-actuator workload-write separation.
- **Do not merge this branch, point any Application at it, enable auto-merge, or
  manually sync it.** The live service Applications track `main` and auto-sync;
  merging is a rollout trigger. Comments are a review hold, not an admission lock.
  A future rollout must first install a reviewed mechanism that controls auto-sync
  and handoff; no live sync-policy changes were made by this task.

## Per-policy before/after verification

Before is the 15:34:10 UTC snapshot. Policy status is shared: in the demo it cannot
identify which of the two managers wrote it. Every listed policy had Ready=True
and a progressing old-manager tick in sampled logs. `F` means
ActionsSupported=False/UnsupportedActionsEnabled, not zero working actions.
`T` means True/AllEnabledActionsSupported; `U` means Unknown/NoSelectedAssets.

| Namespace / policy | Mode | Selected pods in status | Before ActionsSupported | NEW after this task |
|---|---|---:|---|---|
| ci-reports / ci-reports-defense | active | 1 | F | Not migrated; live unchanged |
| console-identity-shared / console-id-fixture | active | 1 | F | Not migrated; identity parity blocked |
| crm / crm-defense | active | 2 | F | Not migrated; feature/trust parity blocked |
| document-store / chroma-defense | active | 1 | F | Not migrated; parity unverified |
| document-store / mongo-defense | active | 1 | F | Not migrated; parity unverified |
| litellm / litellm-defense | active | 2 | F | Not migrated; feature/trust parity blocked |
| mcp / mcp-defense | active | 1 | F | Not migrated; parity unverified |
| nats / nats-defense | active | 3 | F | Not migrated; parity unverified |
| phorvex-staging-demo / demo-api-defense | active | 3 | T, shared status | NEW already ticks; exclusive ownership/effect parity unverified |
| phorvex-verify-m100-loss-history-v2 / m100-protected-server | dryRun | 1 | T | Not migrated; preserve dryRun |
| phorvex-verify-m106-scoped-outcome-v4 / m106-session-target | active | not reported | U | Not migrated; no per-target support proof |
| vllm / vllm-defense | active | 1 | F | Not migrated; confirmed source/config gaps B2/B3 |
| voice / voice-defense | active | 3 | F | Not migrated; live maintenance continuity blocked |

No attack or destructive probe was fired. There is no claimed successful migration,
confirmed new defense effect, or independent live acceptance. Validation details
and read-only reproduction commands are in
[the evidence notes](docs/migrations/dev-eks-20261024/README.md).

Retirement remains separately gated by [RETIREMENT-RUNBOOK.md](RETIREMENT-RUNBOOK.md).
