# K4 — distributed KV invalidation

Require a real disaggregated serving fabric and independently observable source
and destination workers. A local shim delegating to reset_prefix_cache cannot
satisfy the remote capability prerequisite.

Plant harmless identifiable test state, establish reads on each relevant worker,
then trigger the declared move. Verify source invalidation, destination/peer
behavior, continued serving, and that remote failures are not reported as full
success. Preserve worker identities and connector/version pins.

PASS requires the declared cross-worker postconditions and service budget. Record
local-only eviction as partial evidence with defense_outcome not_evaluated; do not
pass this full-path case. If transport is unwired, record BLOCKED with the observed
reason. Cleanup retires the test state and owned signals on every worker.
Historical reference: T49 proves local eviction only; remote behavior was deferred.
