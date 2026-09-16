# Quarantine capacity

Phorvex limits new retained or pending quarantines with
`--max-retained-quarantines-per-namespace`. The Helm value
`phorvex.maxRetainedQuarantinesPerNamespace` defaults to `1`; `0` disables new
quarantine admissions. The accepted range is 0 through 128. This is an
operator-owned namespace-wide bound shared by all policies and the native,
hybrid, and Phoenix routes.

This is a compatibility change for upgrades that omit the value: after one
retained or pending quarantine in a namespace, new Phorvex quarantine
admissions are refused until an operator completes conclusive reconciliation.

The decision inventory counts every Pod in the namespace carrying a native or
Phoenix quarantine marker, protected reservations in the operator namespace,
and UID-bound controlled Phoenix `SecurityEvent` objects. It scans the complete
namespace before applying tenant selectors. Existing population above the cap
is retained and causes additional quarantine to be refused. External actors and
controlled events created before the UID envelope was introduced are reported
as migration limits; Phorvex does not claim that they are absent.

Each admission is reserved in a ConfigMap labelled
`phorvex.ai/quarantine-capacity=v1` in the operator namespace before the first
effect. Records have no expiry. A successful or partial effect, a crash, an
ambiguous API response, and a lost acknowledgement all keep the slot. Removing
a Pod marker does not release it. Only a backend response explicitly proving
that no effect occurred releases its exact reservation automatically.

The count limit and storage limit are independent. The encoded ledger is capped
at 768 KiB and per-record effect references are bounded. Large individual
records or a full ledger refuse before a new effect; configuring 128 does not
promise that 128 arbitrarily large records will fit. An acknowledged effect whose
returned object list exceeds the record bound remains reserved as ambiguous,
while the full effect result remains in the action outcome.

There is deliberately no automatic cleanup for completed quarantine records.
No live administrative cleanup is part of normal reconciliation. Before using
the explicit administrative reconciliation operation, first quiesce every
Phorvex dispatch and Phoenix consumer that can act in the namespace so no
in-flight delayed write can race the proof. Then establish all of the following:

1. The ledger namespace UID and Pod UID match the intended historical objects.
2. The target Pod is conclusively absent, rather than replaced under the same
   name or temporarily unreadable.
3. For Phoenix, the bound `SecurityEvent` is absent or conclusively terminal;
   an event with an unknown create outcome is still pending.
4. No native quarantine object or delayed consumer work can still apply the
   operation.

Back up the ConfigMap, then update only the exact record with Kubernetes
resource-version compare-and-swap. Keep the ConfigMap identity and all other
records unchanged. A deleted and recreated ledger is a different authority and
is rejected by in-flight operations. If any identity or outcome is uncertain,
retain the record and investigate it individually.

Controlled Phoenix quarantine events carry the target Pod UID, namespace UID,
and operation ID. The Phoenix consumer reads those identities directly from the
API immediately before each effect and refuses a same-name replacement. Manual
and third-party Phoenix events keep their existing behavior and are outside this
admission guarantee.
