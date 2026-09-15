# Quarantine recovery

This procedure restores selected Pods from Phorvex quarantine. It does not assert that a workload is clean, reverse credential compromise, undo deleted or rotated state, or replay warm-swap, group, MIG, adapter, drain, or rotation actions. Those actions require their documented forward recovery or manual incident response.

1. Preserve the operator audit source, protected operation-journal ConfigMaps, policy objects, affected workload objects, and incident evidence. Back up the exact API objects before changing them. A restart can resume some recorded forward-recovery phases; it is not an undo.
2. Have DevOps engage the real `phorvex-killswitch` ConfigMap in the operator namespace by setting `data.engaged: "true"`. Confirm the running operator observes the hold, then wait for and independently verify that operations already in flight have drained. The ConfigMap blocks new actuation but cannot cancel a write that already crossed its mutation boundary. A missing, terminating, false, or unreadable ConfigMap does not authorize recovery apply. This CLI never creates, changes, or deletes the hold.
3. Investigate the incident and credential exposure. Rotate or revoke compromised credentials separately. Confirm each workload is clean enough to re-admit and record the human approval outside this command.
4. Inventory one policy scope. The default is read-only:

   ```sh
   phorvex-recovery --operator-namespace phorvex-system --namespace TENANT --policy POLICY --max-items 10
   ```

   Review receipt UID/resourceVersion/hash, policy and target UIDs, phase, supported operation, and every refusal/manual status. `--max-items` limits results in the exact policy scope; the authoritative paginated scans across operation-journal and MIG-recovery receipt labels share a separate fixed 1000-object ceiling and refuse incomplete, conflicting-label, or overflowing collections. MIG receipts are informational `manual` entries only and cannot enter a quarantine plan. Tenant Pod annotations are not recovery authority.
5. Create a small versioned plan in a new protected file, then review it:

   ```sh
   phorvex-recovery --operator-namespace phorvex-system --namespace TENANT --policy POLICY --max-items 10 --plan-out recovery-plan.json
   ```

   A plan is bound to the cluster and operator-namespace identities and exact receipt, policy, Pod, and NetworkPolicy observations. Its checksum detects accidental or unreviewed edits; it is not a signature, approval, or substitute for protected journal authority. Regenerate it after any stale-object, wrong-cluster, policy, UID, label, owner, receipt, or NetworkPolicy refusal. Never edit a plan.
6. Apply that exact plan and retain the result file:

   ```sh
   phorvex-recovery --operator-namespace phorvex-system --namespace TENANT --policy POLICY --max-items 10 --apply-plan recovery-plan.json --result-out recovery-result.jsonl
   ```

   Apply rechecks the hold and all bindings before each write and stops on the first failure. The result is bounded append-only JSONL: the first synced line records intent before effects and later synced lines retain cumulative progress, so preserve every complete line. Earlier items may already be restored. `partial-or-unknown` means preserve all evidence and inspect API state; do not automatically retry. A missing result file, incomplete final line, or output error after invocation means effects may have occurred and must be reconciled from earlier complete records, the protected journal, and live objects.
7. Verify the restored Pod identity, labels and owner, deletion of its exact quarantine NetworkPolicy and receipt, controller availability, service endpoints, and real application reachability. Keep refused, partial, and unknown items for individual investigation.
8. After incident acceptance and workload verification, have DevOps release the hold. Confirm normal actuation resumes. Command examples are operational instructions, not deployment, cluster-mutation, or hold-change authorization.

Keep protected-journal and audit backups according to the incident retention policy. If the cluster or operator namespace was rebuilt, receipts were restored from backup, or a plan is stale, establish current object provenance and create a new plan rather than carrying old authority forward.
