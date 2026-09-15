# Native operation journal

Recoverable warm cutovers and quarantine cleanup use versioned ConfigMap receipts in
the configured operator namespace (`--operator-namespace`, default `POD_NAMESPACE`).
The chart grants the operator ServiceAccount namespaced create, list, get, update,
and delete permissions there. Tenant identities must not be granted write access
to that namespace or the `phorvex.ai/operation-journal` ConfigMaps. A deployment
that shares its operator namespace with a managed tenant namespace cannot start
these recoverable native operations.

Receipts bind the selecting PhorvexPolicy UID, target Pod UID, operation kind and
acknowledged phase. Warm cutovers also bind the exact old/new Pod pair; quarantine
binds the canonical NetworkPolicy UID only after an acknowledged policy write.
The model-shard tensor/pipeline-parallel group cutover has no scalar receipt and is
excluded from this recovery path; its ranks are never retired by a generic
double-leader cleanup.
Missing or invalid receipts prevent automatic retirement or garbage collection.
Uncertain operations remain in the journal for later review or safe retry. The
journal stores only identities and selected labels, never credentials or Pod specs.
Before creating a replacement warm shadow, the receipt stores its intended name
and Pod-spec digest. If Create succeeds but its UID cannot be bound to the receipt,
recovery retains the intent and refuses a second Create at that name. The existing
Pod needs independent administrative review; a matching name or spec is not
proof that the operator created it. Older Pod annotations and quarantine snapshots
without a protected receipt are likewise retained without automatic conversion
to operation authority.
An active quarantine retry verifies the canonical NetworkPolicy name and UID
against its protected receipt before mutation. If that exact policy is genuinely
absent, an authorized retry may create a new canonical policy and must bind its
acknowledged UID to the receipt before updating the Pod checkpoint. A same-name
replacement is refused. Legacy policy names and UIDs carried by a Pod snapshot
remain inventory only; retry does not delete those policies. Explicit rollback
keeps its historical snapshot and UID checks for re-admission and cleanup.
