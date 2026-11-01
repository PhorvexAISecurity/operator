# Split capture relay component evidence

Author: bench-v3-worker. Component baseline: `cd3e48b819b7d9cf9f227a30dbcb5472b42181bc`.
The exact 19-file overlay and SHA-256 hashes are in `relay-component-inputs.json`.
This is component implementation evidence, not final integrated preflight or P3.

The remote manager now retains a lazy read-only snapshot relay. Both enabled
brain store construction and manager source assignment are wired. Additive
ListSnapshots and streaming ReadSnapshot RPCs use the existing brain listener,
transport identity and deadlines. An initially old or capture-disabled brain
returns an error; the same client/source recovers after an actual TCP server
replacement without restarting the manager. Capture defaults remain disabled.

Recorder process identity overrides only the snapshot header. Its source is the
embedded brain Git revision, image is the exact chart container image and marker
is `recorder-process`. Incoming manager policy fields remain unchanged. Existing
local recording keeps legacy identity when no explicit producer is configured.
The brain image gains a same-source `/brain-replay` companion. This component
does not contain the experimental endpoint-study or pre-cost candidate changes.

## Executed checks

* `proto-generation.txt` and status: checked-in pinned generator/linter completed
  with exit 0 at 23:14:12 UTC; only brain protobuf bindings changed.
* `worker-relay-chart-tests.txt`: 9 tests passed, including enabled/disabled
  brain chart configurations, actual immutable image environment binding, and
  conditional same-identity replay companion build instructions.
* `worker-relay-isolated-tests.txt` and its config/status: all three steps passed
  at 23:17:07 UTC using exact Go 1.26.3 with local toolchain mode. Six packages
  cover full brainclient, brainsvc, audittransport and cmd/brain suites; explicit
  producer-identity/replay regressions; and full service architecture checks.

The last run used a baseline Git archive with exactly the manifest overlay,
recorded in `relay-isolated-tree.json`. It excluded all uncommitted experimental
actionset, study and helper source. The real-producer test records a decision,
flushes the file store, lists and reads it through real gRPC and the existing
HTTP audit handler, verifies byte identity and SHA-256, and reproduces the
baseline exactly without changing owner state or calling decision gates.
The fixture transports use bufconn/plain local TCP and httptest; this is not a
claim of a live mTLS or Console authentication end-to-end test. Existing TLS
configuration and listeners are unchanged; live stage verification remains the
lead's obligation.

Negative controls cover disabled and old protocols, invalid filters/times and
digest paths, missing files, oversized index/snapshot/chunks, content corruption
on server and client, and the existing request deadline. A process-construction
test covers both enabled store registration and the default unavailable path.

## Retained first failure

`worker-relay-tests.txt`/status preserve the initial failed assertion. The generic
wire-parity fixture manually assigned a model label default of 0.4 while the new
capture request supplied an empty API spec. Replay correctly resolved label
weights from that empty spec, producing AssetValue mismatches (1.7/2.3 versus
1.3). The new real-producer fixture now derives policy label weights through the
actual API `Spec.AssetLabelWeights()` resolver and records the same nonempty
spec. The exact replay assertion and all transport controls remain intact; no
production replay logic or threshold was weakened.

An initial archive setup attempt used the system Python's unsupported tar
`filter` argument and stopped before tests. The isolated run was prepared with
the provisioned Python 3.12, whose data-filtered tar extraction succeeded.

No deployment, external message, historical reconstruction or endpoint-history
completeness claim was performed by this worker.
