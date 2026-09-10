# PHORVEXSEC-216 / M011

Source baseline: 345c0ade12ac5b0d6ec71fe96c70cb9bc1d9cbac. DEV: Milad. Independent DEV review requested from Hami. DEVOPS live verification remains required, not claimed complete.

## Preflight and scope

The original latch/selected-count defects were already corrected by task176. Current source uses a trailing EffectiveAntiOverRotationWindow and an in-memory Manager.emits ledger. The remaining source defects are: expiry only occurs after successful tenant processing, restart silently reports zero without history qualification, the ledger is keyed only by namespace/name, and Emitted=true plus an error is skipped before reporting. Status writes are unconditional.

Consumer inventory: Manager.emits and Status.MovesThisWindow/Actuated are reporting only. The decision engine spends its selected action costs in its existing internal optimizer flow. No solver, cost, lambda, feasibility or enforcement input reads the emission ledger. This correction does not redirect or reinterpret those inputs. No mathematical ruling is required for this isolated reporting change.

## Implemented contract

Retain the established trailing AntiOverRotationWindow, boundary (now-window, now]. Record emission acknowledgements at the actual returned actuator boundary, including Emitted with an error, separately from unchanged error handling, decision flags and intent/accounting updates. A normal result is observed once, outside all status retries.

Refresh only emission status before ingest and cadence gates on every base tick. Quiet/dry-run/killed policies and ingest failures therefore still age their observations. The writer does not change LastTickTime or decision totals during expiry. Progress is bounded by the running manager's base scheduling interval, API time and existing tick timeout, not an instantaneous guarantee while the manager is stopped.

History is scoped to policy UID, retains timestamps only within the active window, and is removed with the policy. A stale tick cannot overwrite a recreated policy or put observations into its ledger. Mode edits retain valid prior emissions. Memory scales with observed batches within the configured window and registered policies; no silent truncation is used.

The existing Conditions list carries EmissionHistory=True only after a complete locally observed window. Startup/restart, a widened window or clock regression starts an incomplete interval. While Unknown, counts are lower bounds, including zero, and Actuated=false is not proof of no earlier emission. Known positive observations remain visible. Observation assumes this is the authoritative elected runner; this is not cross-process history replication or fencing.

Status retries reread current objects, preserve other conditions and check UID. Equal desired status creates no extra write. Expiry-only writes use the status subresource and cannot re-actuate. Conditions keep their transition timestamp when their truth value does not change.

API/CRD descriptions and the packaged subchart document this qualification. Existing field names/types are unchanged. Consumers must read EmissionHistory and LastTickTime, especially across restart; the integer/boolean alone cannot represent complete historical knowledge.

## Validation

Runner, controller and API package tests pass. Existing staggered-expiry, selection-vs-emission, kill-switch/dry-run and conflict-retry tests remain passing. New clock-controlled tests cover quiet expiry at the exact boundary, restart uncertainty, expanded windows/clock regression, UID separation and stale-tick isolation, partial emitted-error through the actual actuator caller, no duplicate actuation, and unchanged expiry writes (counting both status PUT and PATCH). The caller's error decision remains unchanged while its reported emission is counted.

These are synthetic Go/fake-client tests. No live cluster or customer workload was changed. Independent code review, supported deployment/leader lifecycle verification, controlled emission/expiry evidence and operator rollout/rollback verification remain open. Deploy compatible readers before treating the newly qualified counts as complete. Rollback restores the earlier reporting limitations, not historical evidence.
