# PHORVEXSEC-249 / M048 — UID-bound quarantine policies

DEV implementation and independent source review, 2026-09-10. This report does not certify deployment, Kubernetes garbage collection or network containment.

## Result

A freshly authorized Pod with a reused name now receives a separate policy bound to its own UID. An old policy cannot silently select the previous incarnation or be repointed/deleted merely because its name matches. The new policy has an exact Pod owner reference and the handler verifies its selector against the current Pod labels.

The fix checks existing policy ownership and reconciles managed selector/spec drift through the real retry path. Management labels alone do not authorize adoption. Foreign/shared/ambiguous objects are refused. Correct retries report no new mutation. Accepted writes and subsequent errors remain visible through the existing result path.

PR: https://github.com/PhorvexSecurity/operator/pull/167

## Source and integration

Baseline: `4510b6adec6dbc3cca8105ee104c391aadcb536e`, combining PR150 `d2ce4aed6b9afd6553c6af8fb7be3077f21d1c0a` with main `7434376e164dc2610820ee15758c3084bba0c595`.
Implementation: `2543473928f14cf3cd14eff971684565a25b08f9`. Lifecycle core is `4ce47bb23804f8238bcc58687f88db16d6164408`; the final companion adds the required namespaced permission and its verification.

This PR is stacked on PR150 to preserve its existing controller/Service detach logic, uncached reader contract and partial-result propagation. Main's newer raw CoverageValue transport is also preserved. Source identity is not a deployed image or digest.

## Required permission companion

Managed reconciliation calls NetworkPolicy.Update. The existing routine actuator Role omitted that verb. The fix adds only `update` on NetworkPolicy to the existing opt-in namespaced Role in the source manifest, Helm chart, vendored chart and generated marker output. Scanner ClusterRole permissions and namespace opt-in remain unchanged. No shared RBAC was applied. The native mutation inventory is aligned without changing Phoenix/hybrid capability routing.

A restricted API-server fixture verifies old-role creation succeeds but drift repair is forbidden. The updated exact Role repairs the same policy, while patch operations, unrelated resources and another namespace remain denied. Source and vendored chart contents agree. Effective deployed permissions still require Hami verification.

## Migration and rollback

- Canonical policy names hash the complete Pod UID. Owner references preserve full Pod name and UID without requesting blockOwnerDeletion privileges.
- Existing version2 snapshots migrate only when the exact recorded legacy policy identity and management/target relationship can be verified. The canonical policy is created/read back before cleanup. A durable version3 checkpoint preserves both policy identities and the original detach restoration baseline across retries.
- Fresh authorized new-UID targets can be protected while an unproven old name-keyed policy remains untouched. Its inventory/cleanup limitation is reported explicitly. No adoption or bulk deletion is attempted.
- Manual cleanup checks the NetworkPolicy's own UID and resourceVersion. Old Pod UID is never substituted for policy UID.
- Explicit rollback keeps a released cleanup checkpoint until deletion succeeds. It refuses target/policy replacement and conflicting restore state. Existing versions that cannot read version3 snapshots are not safe automatic downgrade targets. Preserve/reconcile active records before downgrade.

Missing or invalid original recovery context remains an explicit refusal. Metadata retains the existing trust boundary and is not a new attestation system. The change does not introduce automatic quarantine inheritance or a new release policy.

## Verification

The independent baseline test first established successful quarantine, then reproduced failure on a new Pod UID with the same name. Head passes that test. Additional independent real-dispatch tests cover label-only foreign authority, copied selectors and a seeded historical old-UID policy alongside a fresh target.

Local Kubernetes API-server tests use real UIDs, resourceVersions and admission/defaulting. They cover long names, name reuse, managed repair/no-op, UID/RV delete conflicts with successful deletion control, legacy upgrade, durable migration/cleanup retry, concurrent release, and policy replacement during reconciliation. They do not run a garbage-collector controller, CNI or workload replacement controller.

Worker tests also cover ownership/spec collisions, AlreadyExists and write/readback failures, partial results, missing policies, snapshot corruption, migration crash windows, rollback and unchanged M038 selector behavior. See retained commands, logs and source files in the evidence ZIP. Independent review is by a separate agent acting as lead, not a claimed human Hami review.

Final required local preflight at `2543473928f14cf3cd14eff971684565a25b08f9` passed: Go build/test/vet and the selected Helm checks. The receipt is retained in the evidence ZIP. An initial broad run failed the existing `TestM013RealEventSink` permission-restoration assertion. That test passed separately without code changes, and the subsequent full required checks passed, including the final permission-companion source. The initial failure remains in the evidence and is not represented as a successful run.

## Remaining owners

Hami: verify the actual native route, deployed source/image digest, effective Pod/NetworkPolicy permissions, same-name recreation and real owner-GC with a positive dependent-deletion control, upgrade/rollback and any claimed traffic effect. A matching NetworkPolicy object alone does not prove containment.

M049/250 separately covers convergent detach repair and distinguishing stale same-UID requests across release. No general operation-generation guarantee or continuous repair cadence is claimed here.

The task remains open for review and operational verification. PR delivery is not task closure or deployment approval.
