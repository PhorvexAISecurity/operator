# Audit PVC availability and diagnostic access

The operator and console share one Pod and one ReadWriteOnce (RWO) audit PVC.
RWO limits attachment to one **node**, not one writer: a separate read-only
diagnostic Pod can retain the attachment and block the next Recreate rollout.
Do not create another Pod, Job or long-lived sleeper mounting this PVC.

Use the existing authenticated console's read-only views. If an investigation
requires file contents, export a bounded, authorized, redacted artifact through
the existing console container; do not mount the claim elsewhere. Routine health
diagnostics should record readiness, versions, events and attachment metadata,
not raw decision records, tokens or Secret contents.

## Three separate failure checks

1. Check the Deployment's available/ready replicas and the console Service's ready
   EndpointSlices. Empty ready endpoints explain the ingress 503; they do not
   identify why the Pod cannot start.
2. For `Multi-Attach`, list Pods in this namespace that reference the **exact**
   audit claim and inspect their nodes/owners. A read-only helper counts as a
   consumer. Delete only a specifically reviewed, explicitly authorized orphan
   instance with UID/resourceVersion preconditions and normal grace. Never delete
   the PVC, PV or VolumeAttachment or force-detach to clear this symptom.
3. A missing `ebs.csi.aws.com` entry in the target CSINode is a different fault.
   Inspect that node's EBS CSI DaemonSet readiness and sandbox/CNI events. CNI IP
   allocation failures can prevent the CSI node plugin from registering even when
   the Node itself is Ready. This admission guard does not repair CSI or CNI.

The EKS overlay places this shared Pod on `node-type: system` and explicitly
tolerates `CriticalAddonsOnly=true:NoSchedule`. It does not pin a hostname or
repair the database pool. Verify the selected pool has healthy CSI, enough
resources and nodes in the existing PVC's zone before changing placement.
The portable subchart leaves node placement unconstrained by default.

## Narrow admission guard

`phorvex.audit.volumeGuard.enabled` is off in the portable subchart and on in the
EKS umbrella (`phorvex.phorvex.audit.volumeGuard.enabled`). Enabling it requires
Kubernetes >=1.30, audit enabled and persistent audit storage; incompatible Helm
renders fail clearly. No manager/console webhook must be available to enforce it.

The native ValidatingAdmissionPolicy only matches CREATE of core/v1 Pods in the
release namespace that reference that release's audit claim. Other PVCs,
namespaces, Pod updates and subresources are unaffected. It requires the rendered
Deployment's ReplicaSet owner-reference shape, nonempty owner UID, service account,
application labels and manager container. Console-disabled installations work.
Policy/binding names include namespace and a hash of the complete release scope;
Argo sync waves install the policy before its Deny binding, before the Deployment.

This is an **accidental-outage guard, not authenticated controller ownership**.
Pod creators can forge owner references and labels; matching a prefix does not
prove a ReplicaSet exists or owns the request. RBAC and adversarial authorization
remain separate. Already existing helper Pods are not retroactively removed.

Before applying, review the two exact rendered guard objects, confirm their
cluster-scoped names do not collide, server-dry-run both, and test that the real
Deployment Pod template is admitted while a same-claim standalone helper is
rejected. Verify policy type-check warnings are empty. Do not apply an entire
rendered chart as an emergency workaround: unrelated TLS/Secret values may differ.
The chart-derived CEL tests run under `go -C phorvex test ./internal/auditguard`;
they require Helm (CI pins 3.16.4) and do not replace server-side dry runs.

## Recovery, rollback and remaining limits

Verify ready endpoints, operator/console versions, HTTP health and the same Bound
PVC after a rollout. Do not mark an old failed deployment job green by rerunning
release automation; that can create another release and invoke live E2E.

If this guard unexpectedly rejects the legitimate release Pod, stop and inspect
its exact validation message. An authorized rollback removes **only this newly
introduced binding first**, then its policy, after checking names/UIDs; preserve
the audit PVC and every workload. Record the temporary gap and fix/disable the
guard in GitOps desired state so reconciliation does not silently reintroduce it.
Do not weaken another release's policy or broaden cluster RBAC to bypass it.

One RWO-backed Pod with Recreate still has a planned restart window and a shared
operator/console failure domain. This change does not promise zero downtime,
replication, HA, or recovery from arbitrary node/storage/network failures. Separate
console replicas or external audit storage need a separate architecture decision.
