# PHORVEXSEC-213 / M47 — owner-safe native rotate

Baseline: `ea5d5cad4990365f55e61eddb3da2c6bfc2009a1` (v0.4.96), 2026-09-08. Review SHA and PR are in the submission attachment.

## Baseline and route

The baseline native rotate handler issues a Delete for an ownerless pod and claims `owner respawns clean`. The regression with the exact baseline handler overlaid fails by returning Emitted=true for the bare-pod case. See M47_BEFORE.log. This is executable local evidence, not a live customer deletion.

Production native mode is selected through PHORVEX_ACTUATOR=native. Hybrid/Phoenix rotate routes remain outside this handler's deletion guarantee. The native-only policy flag gates the new feasibility law, preserving other backends' mathematical/selection behavior. The normal controller entry point wires mgr.GetAPIReader to both ownership reads and the native boundary. The direct-client command entry points use their uncached client. An unconfigured native boundary reader refuses rotate.

## Delivered behavior

- Shared ownership validator is used by ingest/feasibility and independently by the native handler. Unknown, missing, non-controlling, mirror/static, stale-UID, terminating and unsupported owner states do not authorize native rotate.
- Supported local controller matrix: ReplicaSet, including a live non-paused Deployment parent, and ReplicationController. Desired replicas must be positive, reported replicas may not exceed desired during scale-down, and the pod must match the controller selector. StatefulSet, DaemonSet, Job and custom lifecycles are conservatively unsupported by this native rotate contract until their replacement semantics are validated. This does not claim those controllers never replace pods.
- Native decision requests carry the selected Pod UID. The handler reads current Pod and owner through the authoritative reader and refuses name reuse. Delete binds both Pod UID and resourceVersion, so changing ownerReferences on the same UID after the read invalidates the delete. No weaker retry or force deletion is introduced.
- A delete acknowledgement reports `Pod deletion requested; replacement unconfirmed`. NotFound/conflict/refusal are Emitted=false, not performed rotations. Handler notes survive dispatch and enter the trace's dispatch reason.
- Owner-facing rotation text no longer implies completed replacement. Rotate alone no longer sets the legacy AttackPrevented flag. Reviewed refusal categories reach the owner narrative without copying raw private/error text. Broader all-action outcome claims remain task 218.
- New owner reads use direct API reads to avoid initiating cluster-wide informer watches under a namespaced get grant. Chart and explicit routine Role add only namespaced get on Deployments and ReplicationControllers. Markers and their regression are synchronized, as is the vendored Helm subchart. No extra write authority is added.

## Verification and limits

M47_TARGETED.log contains the ownership/refusal/positive matrix, selected-identity check, native feasibility test, owner narrative tests and **real local kube-apiserver/etcd** integration test. The integration test mutates ownerReferences between validation and Delete and verifies that the API server's resourceVersion precondition rejects it, while an unchanged eligible positive control emits successfully. Envtest is not a workload controller cluster and does not prove actual replacement/readiness.

Full Go tests, go vet, pendingcheck, Helm lint and diff checks are reported in the accompanying evidence. The baseline overlay is reproducible by replacing only internal/actuator/handlers_k8s.go with that path from the baseline SHA and running TestM47OwnershipMatrix/bare.

Existing availability, stateful, dry-run, policy/tenant selection and kill-switch checks remain. This ticket does not close the general fresh safety re-gate task 225: ownership is refreshed, but unrelated predicates retain their existing contracts. A controller's state can change after its read, and deletion/replacement is not atomic. No guaranteed respawn, clean recovery, confirmed eviction, or mathematical coverage change is claimed.

Independent DEV/security review is requested. DEVOPS must still validate supported controller replacement/readiness and mirror refusal on disposable native-mode workloads, plus rollout/rollback behavior. The exact supported deployment and image digest must accompany that evidence. No production workload is mutated for this report. Keep final closure pending those sign-offs and deployment evidence.
