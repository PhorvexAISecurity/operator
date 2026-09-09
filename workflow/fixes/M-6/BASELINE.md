# M6 initial operational baseline

Read-only snapshot: 2026-09-08T17:47:38.391409+00:00; context arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks.
Source baseline: 79c0370dd460a1d6400bc62346638655f64ae709 (main v0.4.97).
Kubernetes: v1.36.2-eks-bca9cf6.
Phorvex: image 0.4.97, digest sha256:e5ba82916f183e971a8cdc874103207124b26ed0f580f72650e35c4caf091502.
Earlier same-build audit observation reports embedded source c8c708145f2f425f0cee86d214671076ae1afcc0; provenance in evidence/baseline/source-pin.json. Re-pin at verification time.

Relevant code-exec VAP/binding: ABSENT. The only observed VAP and binding are phorvex-phorvex-e2e-detector (a different contract). The historical claim that the cluster has zero VAPs is stale; the relevant safeguard is still absent.

The committed codeexec-denylist.yaml targets PhorvexPolicy CREATE/UPDATE, whereas this supplied M6 ticket requires review of actual pods/ephemeralcontainers UPDATE payloads. Installing the existing object alone would not prove that contract.

Raw snapshot includes namespace labels, roles/bindings, cluster roles/bindings, policies and operator identities for the effective-permission and scope analysis. This is an inventory, not yet a completed authorization audit or enforcement proof. No mutations, impersonated allow/deny probes or ephemeral-container injections were performed. Complete request inventory, effective/indirect RBAC review and approved allow/deny matrix remain initial work.

Mostafa SEC-1/SEC-2/PO-1 are open. Claude owns the proposal and all implementation; Codex owns independent review and cluster verification. No baseline observation is a signed L3 PASS.

## Additional effective-grant finding (read-only, same snapshot)

The deployed operator principal is phorvex-system/phorvex-phorvex-manager, not the standalone manifest's phorvex-actuator. RoleBindings phorvex-actuation in litellm and vllm bind it to ClusterRole phorvex-actuation, whose rules grant pods/ephemeralcontainers get/create/update/patch as well as pods update/patch. Thus an unbound separate Role B does not establish absence of effective injection permissions, and pod object labels are not inherently installer-controlled. See roles/rolebindings/clusterroles in evidence/baseline/cluster.json. This is a direct-grant analysis, not a complete indirect-escalation audit.

## Authorization review confirmation — 2026-09-08 18:19 UTC

Read-only `kubectl auth can-i` reviews for the deployed manager SA, including standard service-account groups, return YES for update pods/ephemeralcontainers in vllm, patch pods/ephemeralcontainers in litellm, and update pods in vllm. They return NO for patch/update namespaces, update validatingadmissionpolicies, create clusterrolebindings, and update rolebindings in vllm. Exact commands and outcomes: evidence/baseline/authorization-review.json. This confirms authorization for the tested tuples, not admission acceptance or the absence of every indirect privilege path. No target resources were changed.
