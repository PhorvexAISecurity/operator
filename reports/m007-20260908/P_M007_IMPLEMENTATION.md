# PHORVEXSEC-214 / M-7

DEV Milad. Independent review requested from Hami. DEVOPS verifier assignment/approval pending. Base 074e9f887f62f974d8a5abbcbbb2f6868d56229b (PR135, M-47), upstream ea5d5ca / v0.4.96, chart 0.1.4, Kubernetes test API 1.33.0, controller-runtime 0.21.0. Stacked on 213 to retain its new owner-read permissions without conflicting contract expectations.

## Baseline and scope

Historical Pod patch, EndpointSlice writes, ServiceAccount/Secret markers were already removed at this baseline. Existing source-string tests guard them, but there was no supported Phorvex RBAC generation/check pipeline. The controller-gen commands in other vendored operators are not Phorvex's generator. The existing CRD command pins controller-gen 0.17.2.

Added tools/generate-native-rbac.sh, pinning controller-gen v0.17.2 with paths=./internal/actuator. Its generated namespaced Role is an **unbound review union** of routine and optional code-exec requirements. It must never replace/bind the routine installation Role. Existing manager ClusterRole and installation templates remain independently maintained. No claim that the full manager ClusterRole is generated or certified by this native-only check.

Added CI workflow native-rbac.yml on all PR bases and main. It reruns the pinned generator, compares the corresponding generated YAML, renders Helm with one tenant, and runs an independent normalized permission contract plus existing behavioral restitch regressions. Semantic checks expand the Cartesian product of resources and verbs, check namespace/Role scope and reject unsupported grants or lost necessary permissions. Built-in negative controls cover Pod patch, wildcard, cluster scope and missing update. These checks are a reviewed allowlist, not static analysis that detects every future API call.

Confirmed undergrant: GCOrphanedQuarantineNPs lists NetworkPolicies. Native markers already require list but the dedicated raw routine Role omitted it. Added namespaced list to raw/Helm routine roles. Helm's shared manager already had cluster read/list/watch, so this does not newly expand that identity's effective access. Raw dedicated actuator now receives the necessary local list permission. No handler or math change.

## Affected permission matrix

| Profile/resource | Verbs | Source justification |
|---|---|---|
| Routine core pods | get/list/update/delete | native ownership/mutations, warm-swap, route guards |
| Routine services | get/list/update | route/endpoint selector restitch and rollback, quarantine fallback |
| Routine apps ReplicaSet/Deployment/StatefulSet/DaemonSet | get | owner validation and selector reads |
| Routine core ReplicationController | get | M-47 owner validation |
| Routine batch jobs | get | quarantine owner selector |
| Routine networking NetworkPolicy | create/get/list/delete | quarantine, rollback and orphan GC |
| Optional core pods/ephemeralcontainers | update | native injection subresource, unbound by default in raw manifests |

Raw routine role binds phorvex-actuator in the substituted tenant namespace. Helm binds its namespaced routine roles to the release manager SA only in configured actuatorNamespaces. The shared manager's graph reads, Events, CRD status/watches and optional console privileges are separate. M-5 Lease RBAC is separate PR136. Corrected inaccurate marker header claiming a distinct minimal decision identity in every profile. No identity consolidation or console privilege redesign.

## Evidence

Predicted: regeneration stable, forbidden grants and missing required update detected, native routines retain permissions. Actual: tools/check-native-rbac.sh passes regeneration + rendered semantic checks + four intentional negative mutations + route success/refusal/compensation/rollback tests. Actuator package regression passes.

TestM007RestrictedRequests starts a real isolated envtest API with RBAC authorization. Admin creates only disposable fixtures and evaluates SubjectAccessReviews. Actual Pod GET/UPDATE and NetworkPolicy LIST use validated ServiceAccount impersonation with authenticated/serviceaccount/namespace groups. Pod label persistence is independently read back. Sensitive negatives use reviews, not Secret reads or destructive probes. Pod patch, Secret get, ServiceAccount delete, EndpointSlice update, optional ephemeralcontainers update and cross-namespace Pod update all denied. Raw log retained. This is isolated role evidence, not live deployment certification or all-handler coverage.

## Operational handoff

Inspect all actual RoleBindings/ClusterRoleBindings/aggregation for the deployed SA before claiming effective revocation. No unsupported historical grants were newly revoked by this PR. Preserve the optional code-exec split. Apply the corrected raw role per approved tenant namespace, or install the repackaged chart. Rollback must not revive historical broad markers/roles and must preserve list for any version running orphan GC. Controller and console permission unions need their own wider checks, not forced equality with native roles.

Independent security/DEV and DEVOPS review, actual deployment identity/binding inventory and upgrade/rollback evidence remain open. The implementer is not the sole approver. No deployment changed.
