# Verification of the reported persisted-file rejection

Result: PASS — the bug is reproduced. This is not installed-repair acceptance.

## Test and falsifier

The reviewed metadata-only helper was registered before execution in the private campaign evidence at `pr323-rollout-0822/file-metadata/`; this intake was filed after its result. It inspected the six fixed files of the existing synthetic `v1run-5` through a read-only volume mount, without fsGroup or a Kubernetes token. It could not change their modes or content. A mismatch between current and retained content hashes would have falsified the unchanged-record premise. The exact helper UID was deleted and its absence confirmed.

The running PR323 console at e2ee943 returned functionalResult=null and an explicit private-file rejection. The sanitized [observations](../../campaigns/2026-09-23-catalogue-coverage/evidence/CONSOLE-PERSISTED-FILES/REPORT.md) bind its image/Pod identity, file metadata and unchanged content. The inferred Kubernetes fsGroup mechanism is distinguished from the directly observed0660 rejection; the historical chmod actor was not recovered.

## Independent source reproduction

Lead `codex-lead` used the actual WriteJob and WriteRuntimeConfig producers, verified their original0600 files load, then changed only mode to0660. An overlay of the deployed e2ee943 LoadJob/LoadRuntimeConfig implementations fails with `same-owner persisted job with fsGroup 0660 refused`. The worker repair passes the complete cataloguev1 package and vet. Commands, exit codes and log hashes are in [RESULT.json](evidence/RESULT.json); the reviewed dirty source is individually hashed in [source-hashes.json](evidence/source-hashes.json).

Positive controls: valid same-owner0600 and same-owner/intended-group0660 records both load on the repair. Negative controls reject unrelated ownership/group, public/special modes, symlinks, hardlinks, FIFOs, directories, oversized records and changed inode/link metadata. The nonblocking open is checked by a bounded FIFO regression.

No live catalogue execution, history rewrite, PVC chmod, shared deployment change or retry-debt clearance was performed. Installed repair verification must follow its own deployment; the original Voice partial result remains partial and unsafe.
