# Signed lead plan: PR150 conflict resolution, round 2

User requests resolving conflicts of remaining PRs, not merging them. Lead root;
implementer review_143_150. Main pinned f0348b36e12d751a84ffdac1414c6ff6952d2ee1;
PR head pinned ccc0efe062e4eb1bad669a5c0d66105604b56e6e. Target main. Preserve all
integrated owner/emission lifecycle, identity/provenance, and newly merged M048
Pod-incarnation quarantine policy ownership/RBAC work on this PR, together with
main's audit-PVC guard, system pool/toleration, console history and current images.

Read-only merge-tree finds binary vendored phorvex-0.1.4.tgz and generated
workflow/fixes/INDEX.yaml conflicts. Source chart should combine cleanly; inspect
its RBAC and guard composition, regenerate archive from merged source (Helm3.16.4)
instead of selecting either binary. Reconcile index from union of underlying fix
records; preserve historical evidence byte-for-byte. Review auto-merged API types
and console server routing so PR's owner semantics and main's history endpoint
compose. Report contradictions instead of silently dropping either feature.

Normal merge of exact main pin. Validate both-parent ancestry, no markers,
chart extracted-content parity/CRD parity/actual EKS render with scope guard,
nodeSelector/toleration, image tags and preserved quarantine RBAC. Run focused
actuator/runner/console/audit/recon/decision and the new auditguard tests; check
frontend type compatibility (tsc if available). If full Go suite is run, use CI
x86-64 architecture to avoid known native ARM exact-float assertion, retaining
any failures honestly. Isolated KUBECONFIG=/dev/null, USE_EXISTING_CLUSTER=false.
No live cluster tests. Retain commands, pins, results and limits in this round
folder; do not overwrite previous reviews or fabricate renewed P3/L3 seals.

Commit normal merge with configured Git author, no AI trailers. Do not push,
change Draft/base state, merge GitHub PR or perform cluster mutation. Lead reviews
independently and publishes only accepted existing PR-branch updates.
Signed root, 2026-09-10.
