# Stage self-service repair verification

Question: can the user submit supported dynamic benchmark requests against current operator-refactored stage without stale source/policy configuration failures, while missing measurement stays explicit?

Scope: current61e836 isolated stage images, requested demo-api-defense and dedicated stage-bench-defense, jh benchmark services. Six-hour ceiling and unchanged4GiB disk reserve; existing resources only. No production action, physical workload mutation, policy-mode change or attack. Source/provenance mismatches and unsupported history cannot be waived.

See hypotheses.yaml and round-1/spec.md. Round1 contains sequential capture configuration, same-source runtime preparation, actual bot positivecontrols and exact original10day admission. All results retain requests, timestamps, source/image/UID, outputs and receipt hashes. Root owns live writes and mutation ledger. Stage-review independently reviews controls and cleanup. Automatic source reconciliation may read stage and update owned host state only; it cannot mutate shared-cluster configuration.

The historical fixture journal is never assigned to active demo. Native same-source study execution and any reviewed cross-source engine are distinct. Actual10day completion is not attainable from newly collected history; a scientifically correct blocked result satisfies only admission/reporting, not that study's outcome. Short positivecontrols are separately named.

Mutation ledger: fixes/BENCH-SELFSERVE/evidence/live/mutations.jsonl, with before/after and retained backups. Cleanup: retain intended capture/services/newjournals, removeonlyowned temporarycredentials/scratch whenunused, leaveunrelatedresources alone. No mainmerge.
