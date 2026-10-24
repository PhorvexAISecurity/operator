# Supervised retirement of the OLD dev-eks monolith

**NOT EXECUTED. BLOCKED by DECISION.md.** Milad/Claude own the live verification,
cutover acceptance and explicit destructive-retirement gate. This runbook does
not authorize any live command. Its write examples are for that supervised gate
only. Tenant scope and RBAC changes must be committed to operator-refactored and
reviewed/synced through GitOps; never repair them with ad-hoc kubectl.

Retire only `argocd/phorvex-stack` and the OLD
`phorvex-system/phorvex-phorvex` runtime and reviewed exclusive dependents.
**Never change `phorvex-system/operator-controller-manager`, its ServiceAccount,
RBAC, lease, CRDs, AMTDs or shared namespace.** Do not delete `phorvex-system` or
uninstall Helm release `phorvex`: Phoenix carries that same Helm release label.
Do not delete the split-service ApplicationSet or its child Applications.

## 1. Pin access and capture a fresh rollback baseline

Every operation, including reads, must use the explicit dev-eks context. The
gateway default was a different cluster during this investigation. This helper
quotes each remote argument before sending it over SSH:

```bash
phvx_k() {
  local phvx_remote
  printf -v phvx_remote '%q ' kubectl \
    --context=arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks \
    --request-timeout=30s "$@"
  ssh -o BatchMode=yes phorvex-gw "$phvx_remote"
}
umask 077
phvx_retirement_snapshot=$(mktemp -d /tmp/phvx-retirement.XXXXXX)
phvx_k get namespace kube-system -o json > "$phvx_retirement_snapshot/cluster.json"
phvx_k get phorvexpolicy -A -o json > "$phvx_retirement_snapshot/policies.json"
phvx_k get deployment -n phorvex-system -o json > "$phvx_retirement_snapshot/old-deployments.json"
phvx_k get deployment -n phorvex-staging -o json > "$phvx_retirement_snapshot/new-deployments.json"
phvx_k get pods -n phorvex-system -o json > "$phvx_retirement_snapshot/old-pods.json"
phvx_k get applications -n argocd -o json > "$phvx_retirement_snapshot/apps.json"
phvx_k get rolebindings,roles -A -o json > "$phvx_retirement_snapshot/namespaced-rbac.json"
phvx_k get clusterroles,clusterrolebindings -o json > "$phvx_retirement_snapshot/cluster-rbac.json"
phvx_k get leases -A -o json > "$phvx_retirement_snapshot/leases.json"
phvx_k get mutatingwebhookconfigurations,validatingwebhookconfigurations -o json > "$phvx_retirement_snapshot/webhooks.json"
phvx_k get validatingadmissionpolicies,validatingadmissionpolicybindings -o json > "$phvx_retirement_snapshot/admission-guards.json"
phvx_k get configmaps -n phorvex-system -o json > "$phvx_retirement_snapshot/old-configmaps.json"
phvx_k get pvc -n phorvex-system -o json > "$phvx_retirement_snapshot/old-pvcs.json"
```

Retry failed/partial reads; repeat the policy/deployment/binding inventory three
times and compare identities, generations, scope and runtime digests. Reconcile
new tenants rather than relying on the 2026-10-24 list. Keep the snapshot through
the rollback window. Back up audit/PVC data and protected-operation journals with
the established storage backup process; listing PVCs is not a backup. Preserve
credential references and approved recoverable credentials without committing
secret contents. Do not rotate credentials as part of retirement.

Record Phoenix's UID, desired/ready replicas, running image digest and lease holder.
The investigation observed UID `2ed0eeb9-7cf2-4f59-a35b-2324b9902b49` and image digest
`sha256:44f911592bff11cd9cfd5cdfe634f332c25eb02f6b46fd5409d421f26bd16c94`.
A legitimate intervening Phoenix rollout requires a refreshed baseline, not a
blind comparison with these historical values.

**Rollback preparation:** build and review a source-pinned restoration manifest
from the fresh *observed* deployment, stripping API-managed metadata/status. Pin
the actual container digest and preserve its flags, mounts, ServiceAccount,
credentials and storage. The old app's desired pin `6d581657...` differs from the
running `kv-drain-reset-0058a3ed...` image; Argo rollback/history alone is insufficient.
Store restoration configuration in the approved operator-refactored GitOps path.
Do not apply it yet. Independent review must verify the restore artifact before
any write below.

## 2. Clear the cutover and capability prerequisites — STOP if any is missing

Milad/Claude must sign off on all of these against live evidence:

- DECISION.md B1–B7 resolved, including an independently demonstrated atomic,
  fenced handoff and reverse handoff for all fresh mutations, recovery/maintenance,
  and hybrid/Phoenix work. No such mechanism was established by this PR.
- Each current policy is exclusively served by NEW after supervised per-tenant
  transfer; the old manager has no remaining execution or maintenance authority.
  Preserve modes, selectors, budgets, policy identities, allowed actions and
  working protection. Include both verification namespaces and both document-store
  policies. The demo's already-present overlap is resolved.
- New source-attributed decisions, per-target action capability and confirmed
  defense are at least the captured baseline. A shared ActionsSupported condition,
  zero recent actions, or Healthy/Synced status is insufficient. The m106 policy's
  Unknown capability remains unknown until a relevant target is verified.
- vLLM under-load KV-reset behavior, secure serving bindings, detector trust,
  EPSS/telemetry, endpoint-lease approvals and all feature-specific grants are
  verified in the actual replacement images. Voice and other protected-operation
  state have a verified recovery owner; no unaccounted pending/partial operation
  or serving path left closed is allowed at the handoff.
- costbench-opus / phorvex-catalogue-cpu grants, cost fixtures, old observer,
  console/catalogue profiles and old policy-application ownership have explicit
  retained owners or independently accepted retirement dispositions.

**Ordering for future GitOps:** first establish reviewed deployment controls and
the verified standby/fence mechanism; then adopt the AppProject into a reviewed
operator-refactored Argo bootstrap and sync its namespace destinations; then stage
the coordinated service/feature changes. The current root does not manage that
project; a one-off kubectl project edit is not an approved migration path.
Sync the manager, sensor and actuator only under that mechanism: their scope
handshakes must agree, and each currently uses Recreate. Sequentially restarting
services is not a no-gap migration plan. Do not merge the current all-tenant values
while main is auto-synced. Scope and RBAC removal/rollback use the same GitOps path.

If any prerequisite cannot be met, leave OLD running and return to Milad/Claude.
The remaining phases cannot make a failed cutover safe.

## 3. Move admission and shared dependencies before stopping OLD

These observed webhooks call the OLD manager's Service
`phorvex-system/phorvex-phorvex-webhook`:

| Webhook configuration | Failure policy | Function |
|---|---|---|
| phorvex-phorvex-policy-validator | Fail | PhorvexPolicy validation |
| phorvex-phorvex-protected-outcomes-stamp | Fail | SecurityEvent protected-outcome stamp |
| phorvex-phorvex-securityevent-stamp | Ignore | SecurityEvent identity stamp |

Deploy the reviewed replacement admission endpoint, certificate/trust and
non-disruptive availability configuration through GitOps. Verify it accepts valid
requests and rejects invalid/untrusted ones under the existing contract; preserve
fail-closed enforcement. Change the exact webhook service/CA references through
reviewed GitOps while the old endpoint is healthy; verify requests reach the new
endpoint and no webhook still depends on the old manager. Do not weaken
failurePolicy or remove a webhook to make shutdown succeed.

The new manager/sensor also require
`phorvex-system-phorvex-phorvex-se-creator-8acf73b8d0` as an external validating
admission policy/binding. Retain and rehome those guard objects and their ownership,
or deploy/verify the reviewed replacement before changing the new references.
Shared CRDs, detector-scope guards and retained AMTDs must survive. Any remaining
consumer of the old audit, admission, recovery or detector service blocks shutdown.
Do not repoint the old brain's service to an unverified new endpoint as a shortcut.

**Rollback:** restore the captured service/CA references while the old endpoint
is still healthy; verify enforcement. Keep both healthy endpoints until this
step is accepted. After old shutdown, restore its healthy endpoint first, without
restoring tenant execution authority, before reversing an admission reference.
That separate admission availability is itself a prerequisite of the gated plan.

## 4. Obtain the explicit retirement gate and park the old Argo app

Record Milad/Claude's approval with the accepted evidence, exact restored-runtime
manifest revision and the currently fenced execution owner. Before this point,
**no disable/scale/delete command in this runbook is authorized**.

Check `root` and any other ApplicationSet/parent cannot undo retirement. In the
baseline, root is pinned to the old repository and automated.enabled=false;
`phorvex-stack` itself still has automatic sync/self-heal enabled. A human-triggered
root sync can restore its old child spec. Preserve its approved state and remove
or rehome the old child declaration through the separately reviewed parent
configuration before eventual child deletion. Do not change unrelated root apps.

After the gate, this exact app-control change parks the old child and is reversible:

```bash
phvx_k patch application phorvex-stack -n argocd --type=merge \
  -p '{"spec":{"syncPolicy":{"automated":{"enabled":false,"prune":false,"selfHeal":false}}}}'
phvx_k get application phorvex-stack -n argocd -o json
```

Verify the disabled state persists across reconciliations and there is no running
sync/rollback operation. Retain the captured Application spec. Do not sync OLD to
"clean up" its existing OutOfSync/SyncError state.

**Rollback:** restore the reviewed captured app spec only after confirming its
source cannot re-enable old execution against an active NEW owner. Restore
execution authority through the verified reverse handoff, never by auto-sync alone.

## 5. Stop only the old brain after admission/recovery verification

Require a final live confirmation that NEW has every tenant, all old operations
have an accepted owner/terminal disposition, all old admission dependencies have
moved, and OLD is fenced. Then, under the same gate:

```bash
phvx_k scale deployment phorvex-phorvex -n phorvex-system --replicas=0
phvx_k get deployment phorvex-phorvex -n phorvex-system -o json
phvx_k get pods -n phorvex-system -o wide
phvx_k get deployment operator-controller-manager -n phorvex-system -o json
```

Wait for exactly that old manager pod to terminate and old authority/lease renewal
to cease. Cross-check NEW policy ticks and confirmed effect evidence throughout.
Compare Phoenix's UID/image/replicas/lease against the preflight baseline.
Do not scale the namespace, the console, the observer or Phoenix by selector.
Handle any old companion retirement only after its own dependencies are cleared.

**Rollback:** if NEW regresses, keep the old app parked. Restore the prepared old
runtime as a fenced standby from the reviewed GitOps restoration revision; verify
health, admission and state continuity; use the verified atomic reverse handoff
for each affected tenant. Only then resume its authorized execution. Simply
scaling the current unscoped old deployment to one would recreate split-brain.
A reviewed restore may ultimately set `phorvex-phorvex.spec.replicas=1`; that is
not an independently safe emergency command.

## 6. Observe, then remove obsolete tenant grants through GitOps

Maintain the independently agreed observation window across representative
reactive decisions and maintenance/recovery cycles. Choose the window from policy
intervals, operation deadlines, telemetry freshness and baseline threat coverage;
a fixed sleep does not prove safety. Compare each policy/target/action and the
operator-specific audits rather than trusting whichever stack last wrote status.

Only after NEW natively and exclusively owns the demo, with a confirmed native
rotate and verified rollback, may a reviewed operator-refactored GitOps cleanup
remove the exact `phvx93-rotate-eviction-proof` RoleBinding and Role from
`phorvex-staging-demo`. No such cleanup was done by this PR.

The split ApplicationSet has **prune=false**. Removing a namespace from values
leaves old Roles/RoleBindings. For approved removals, review the exact object
allowlist and execute a selective Argo resource prune through the established
GitOps deployment mechanism. Never prune all old app resources or broad labels.
Keep resource restoration manifests in the rollback revision; verify effective
permissions and every retained tenant immediately after each removal.

## 7. Retain the parked Application, or detach it without cascading

The safest reversible retirement point is OLD replicas=0, its app parked, and
all shared/rollback resources retained. The baseline old Application tracks 246
resources, including a policy CRD, admission guards, identity/cost fixtures and
storage dependencies. Its finalizer is `resources-finalizer.argocd.argoproj.io`.
**Deleting it normally can cascade through those resources.** Phoenix sharing a
Helm label is an additional reason to avoid release-wide cleanup.

If Milad/Claude explicitly approve deleting the Application *object*, first
verify the parent declaration will not recreate it. Back up its final current
spec and every retained resource's new owner. Then remove only the app finalizer,
with an exact-value precondition, and orphan its resources:

```bash
phvx_k patch application phorvex-stack -n argocd --type=json \
  -p '[{"op":"test","path":"/metadata/finalizers","value":["resources-finalizer.argocd.argoproj.io"]},{"op":"remove","path":"/metadata/finalizers"}]'
phvx_k delete application phorvex-stack -n argocd --cascade=orphan
```

If the finalizer differs, STOP and review it; do not broaden the patch. Verify
all retained objects, NEW defense and Phoenix again. Do not remove per-resource
finalizers or use a forced/cascading deletion. An orphaned app's resources still
need their reviewed replacement owners.

**Rollback:** recreate the captured Application with automated sync disabled and
without a cascading finalizer first, after checking parent ownership. Restore
approved source/ownership through GitOps; authority reversal still follows step 5.

## 8. Keep the rollback window reversible

Retain the old Deployment at zero, audit PVCs, needed credentials, journals,
webhook/guard rollback manifests and the runtime digest until Milad/Claude close
the rollback window. Do not delete data, shared CRDs, the namespace, Phoenix,
retained AMTDs, or old policy objects. Permanent storage/image/credential deletion
needs a separate disposal decision; it is outside this reversible runbook.

Completion requires NEW ownership and defense evidence for every current tenant,
no OLD manager pod/authority, independent admission and recovery continuity,
explicit ownership of retained resources, and an unchanged healthy Phoenix.
