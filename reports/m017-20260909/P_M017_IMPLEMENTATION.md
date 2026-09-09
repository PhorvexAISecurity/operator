# PHORVEXSEC-220 / M-17 — partial writer correction

Base: 345c0ade12ac5b0d6ec71fe96c70cb9bc1d9cbac. Scope: RECORD writer and startup/shutdown ownership, unchanged decision/action policy. No Math changes.

## Verified baseline
Custom internal/audit/rotate.go, no Lumberjack/buffer library. Both Logger.Record and RecordOutcomeInventory discarded marshal/write failures. Rotation closed first, ignored all filesystem failures, and removed the live segment with zero backups. These are current-source findings, not newly reproduced historical live failures. runner calls Actuate before Record. cmd/main.go already falls back to logger-only on sink-open failure. That existing behavior is preserved, not cited as approval for a new crash-accounting policy.

## Delivered
Both record methods return failures and independently log them even when callers discard the return. A no-label phorvex_audit_persistence_errors_total counts observed failed record attempts, not all lost evidence. Writes check short counts, flush supported buffered sinks, then sync supported sinks. The production rotating file exposes Sync. Arbitrary io.Writer sinks without Sync do not receive a durability guarantee. Standard record kinds/JSON and readers are unchanged.

Rotation and writes share a process mutex. Enabled rotation rejects nonpositive backup counts before opening existing files. Unbounded mode remains capBytes<=0. Descending checked renames preserve count-based retention without first deleting the live file. File sync precedes rotation, directory sync follows rename/create, and errors stop further writes to the damaged writer until operator recovery/reopen. Partial writes are not followed by new records that conceal a damaged tail. Close combines sync/close/prior failure and is checked on normal main return. os.Exit/process death cannot run defers.

## Evidence
GOMAXPROCS=2 go -C phorvex test -p 2 ./internal/audit ./internal/runner ./cmd passes. New tests cover marshal, short-write, write, flush and sync failures, stage ordering, observed failure counter, zero/negative retention preserving original bytes, and actual filesystem rename failure with preserved live bytes and no blind retry. Existing bounded/unbounded rotation, schema/replay and tenant isolation tests pass.

## Deliberately open — do not close M-17
No approved mutation-pause ruling has been established here. The card explicitly marks that proposal as not approved. Durable pre-dispatch intent/result schema, attempt IDs, reader rollout, unmatched-intent recovery and the CONTROL admission gate remain pending that security/product decision. This PR does not close the crash gap. Recommendation for Mostafa/security: acknowledge durable intent before dispatch, pause new automatic mutations when required audit persistence fails, preserve possibly executed attempts as unresolved, never replay/rollback merely due to a missing result, and establish recovery verification before resumption.

Console internal/console/live.go and replay/schema tests still consume existing decision/inventory records. No new record kind is introduced or historical bytes repaired. Reader corruption diagnostics and crash-pair recovery belong to the explicit extension, not this writer-only delivery.

DEVOPS must verify actual image/build, storage mount/PVC persistence, permissions, and exactly one writer process per path. Helm co-locates console as a reader and supports audit PVC/ephemeral volume, which does not establish deployed storage or exclusive writers. No live cluster, process-crash, power-loss, node-loss, volume-loss, latency or throughput guarantee is claimed. Independent DEV/security review and isolated fault rig verification remain open. Retention remains configured backup count without age policy, not indefinite retention or tamper-proof logging. Oversized individual records may exceed the configured segment cap. A failed/interrupted rotation requires evidence-preserving operator inspection and reopening, not an automatic repair.
