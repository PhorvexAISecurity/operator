# Workload catalogue v3 — development suite

[`suite.json`](suite.json) selects nine implemented workload mechanisms through
15 explicit profiles. This is a development foundation for brain evaluation;
it is **not a completed live benchmark or a security-coverage certificate**.
Source tests, direct backend effects, installed-manager attribution, application
availability and security efficacy have separate acceptance records.

The full legacy catalogue remains available for assessment. Marker simulations,
unassessed entries and unavailable hardware do not become demonstrated coverage
by appearing in a registration list. These profiles select only the workload
controls below and never select the legacy `d-phorvex` defender that starts extra
controllers or installs shared CRDs.

| Boundary | Profile IDs | What the result can establish |
|---|---|---|
| HTTP process state | `http-session-baseline-timer` | Synthetic session survives no action or is lost after independently observed replacement; a fresh session works. |
| Durable checkpoint | `checkpoint-local-baseline-timer` | Acknowledged progress and later durable readback on an exact owned volume, including interruptions and unverified recovery. |
| Voice transport | `voice-stream-baseline-timer` | Numbered synthetic WebSocket frames, end marker, established-session interruption and fresh-session recovery. |
| NATS JetStream | `nats-no-action`, `nats-member-restart`, `nats-quorum-pause` | Actual publish/consumer acknowledgements and stored-message hashes around no action, one non-client restart, or bounded two-member quorum loss with same-ID reconciliation. |
| Installed Phorvex | `manager-session-no-action`, `manager-session-blind-timer`, `manager-session-installed` | Matched process-state/request observations with a separately attributable installed decision, refusal or action. |
| Ordinary GPU cache | `gpu-prefix-cache-reset-no-action`, `gpu-prefix-cache-reset-direct` | Actual inference/cache observations; direct logical reset, miss/repopulation and busy refusal, followed by eight exact normal-length completions and an idle metrics sample. |
| Ordinary GPU drain | `gpu-request-drain-no-action`, `gpu-request-drain-direct` | Actual engine admission, one late-selected authenticated unfinished SSE anchor bound to an aborted engine request, explicit unknown background IDs, fresh quiescence observations and reopening. |
| Native route rotation | `native-route-rotate` | Production `NativeActuator` route-rotate selector rekey, exact EndpointSlice membership, bounded HTTP identities and protected rollback. |
| Native endpoint rotation | `native-endpoint-rotate` | Production `NativeActuator` endpoint-rotate selector rekey, exact EndpointSlice membership, bounded HTTP identities and protected rollback. |

Voice covers the transport and state boundary found in the running service; it
does not make paid speech or LLM calls. The NATS quorum profile retains a bounded single publish attempt while member 0 remains connected and members 1 and 2 are paused, then reconciles the exact message ID after recovery. It does not establish client or leader failover. GPU controls use ordinary hardware and real
OPT-125m inference. They do not demonstrate MIG, physical memory erasure,
cross-tenant isolation, voice draining or attacker mitigation.
The drain control does not attribute every queued client to an engine request:
queued requests can be aborted before vLLM emits an SSE ID. It retains all
eight client lifecycles and every engine disposition, but claims only the exact
pre-observed anchor. `fullCohortAttributed` remains false whenever any snapshot
ID lacks client attribution.

## Running a reviewed profile

The manifest is a selection and measurement contract, **not a harness config**.
It intentionally contains no live credentials, reusable runtime UIDs or cluster
mutation command. A profile needs a fresh, reviewed target configuration and
fixture package. Reusing an old namespace/Pod/volume identity is not preparation.

1. Build the harness from the reviewed source commit and retain its commit,
   source-tree, binary hash and toolchain. Check `harness -list` against the exact
   `scenarioFilter` and `defenderFilter` in the selected profile.
2. Prepare the declared owned fixtures. Capture exact runtime identities,
   capability and source/digest evidence, the bounded workload schedule,
   resource limits, failure stops and cleanup authority. External GPU/storage
   fixtures require their own provisioning and cleanup supervisor; selecting a
   profile does not create them. For the installed arm, bind the existing
   manager and authenticated audit/material reader; do not start a controller.
   GPU objects belong to the external fixture supervisor: use its dedicated
   `fixture.phorvex.ai/run` label and retained creation identities. Do not mark
   its Pod, controller or Service `r6th.io/owned=true`; that label grants ordinary
   harness cleanup ownership and the GPU scenario rejects it on these objects.
3. Put the selected profile's exact filters and `trialsPerArm` into the reviewed
   config. Apply its `requiredConfigValues`; dotted keys describe nested config
   fields. GPU profiles require `expectedNamespaceUID` to equal the exact
   `gpuFunctionalFixture.namespaceUID` before any client or scenario operation.
   Supply the fixture-specific identities and private file paths. Keep
   one fresh output directory per profile invocation. Do not use `-resume` to
   combine profiles or fixture modes.
4. Run the ordinary arm through the reviewed bounded supervisor. The underlying
   command uses the existing CLI:

   ```sh
   ./harness -config /absolute/path/to/reviewed-target.json \
     -negative-control=false -adaptive=false
   ```

5. Retain the manifest/configuration hashes, per-trial metrics, producer receipts,
   unknown and failed observations, critical dependency checks, process exit and
   exact cleanup evidence. A successful exit is not an independent live review.
   Do not start another profile over unresolved fixture residue.

See the [installed-manager contract](../../INSTALLED_MANAGER_CATALOGUE.md) and
[NATS evidence schema](../../NATS_JETSTREAM_CATALOGUE_SCHEMA.md). GPU backend
producer contracts are in [`guardrail`](../../guardrail); bare vLLM without the
required reviewed protocol extensions is unavailable for those controls.

## Comparing brain changes

The full comparison is no action, the applicable timer/static baseline, and
installed Phorvex under the same source-pinned fixture, offered workload, warmup,
observation horizon and outcome definitions. The installed session profiles are
the current route for that attributable chain. The other direct controls are
building blocks; calling a backend from a scenario does not test brain selection.

Both NATS and GPU direct-control modes deliberately use `d-nomtd`: there is no
separate defender selecting their internal protocol action. Group their rows by
**profile ID and explicit fixture mode**, not only `(scenario, defender)`. Never
pool a direct intervention with its no-action observations. GPU profiles with
different request counts or observation horizons are unmatched functional checks;
they cannot establish comparative latency, availability, cost or brain improvement.

Report request/session/state outcomes, typed unavailability, latency/recovery,
observed operation counts and measured resource cost in their actual units.
Keep non-selection, refusal, failure and missing observations visible. No-action
can be a correct outcome under availability or budget constraints. A selected
operation needs independent completion/effect evidence; a dispatch receipt alone
is insufficient. Benign controls produce no security percentages or monetary ROI.

The profile trial counts are bounded functional-control defaults, not statistical
power claims. Before a performance verdict, freeze a suite revision and declare
repetitions from observed variance, preserve all trials and report uncertainty.
Keep a held-out evaluation set when tuning the brain. Changes to the fixture,
actuator, catalogue or load schedule require a new comparison rather than being
silently credited to a brain change.

Each entry's `sourceSHA256` hashes the exact bytes of its scenario source file.
It detects changes to that file; it is not a hash of all imported dependencies.
Full commit, module-tree and binary pins remain required for every comparison.

## Acceptance and remaining scope

Consult the [campaign scope and acceptance records](../../../../workflow/campaigns/2026-09-20-post25-live/catalogue/SCOPE-AND-COVERAGE.md)
and its per-round evidence for current results and limitations. This source
manifest contains no historical success constants and grants no live PASS.
Missing capability is unavailable, not zero cost or successful defense. The
larger actuator/workload matrix, vulnerability applicability, enabled network
enforcement and remaining installed chains remain explicit work; this curated
suite does not claim to cover every supported handler or every real-world stack.

## Collecting retained runs offline

`catalogue-collector` reads only an explicit local run index. It does not scan
output directories, run the harness, contact Kubernetes, or call a network
service. Paths in the index are relative to that index, and every suite,
configuration, harness, source, and metrics identity is explicit and hashed.
For a local synthetic example:

```sh
go run ./cmd/catalogue-collector \
  -index catalogue/v3/examples/run-index.json \
  -json /tmp/catalogue-functional.json \
  -markdown /tmp/catalogue-functional.md
```

The example is deliberately opaque and reports
`UNSUPPORTED_MEASUREMENT_SCHEMA`; it demonstrates retention without inventing a
measurement. The decoded families are the three `manager-session-*` profiles
and the `nats-no-action`, `nats-member-restart`, and `nats-quorum-pause`
profiles. The manager-session decoder reconstructs the retained base64 segment receipt, checks
its hashes and flattened observations, and reports HTTP 200 session presence,
HTTP 404 no-session responses with per-Pod counts, typed unknowns, Pod identities, action/effect fields,
and every inter-segment gap separately. A 404 is not counted as a successful
session read, and sampled windows are not described as continuous availability.

The NATS decoder requires an explicit `natsIdentity` authority in each run-index
record. It binds the retained receipt to the supplied mode, nonce, node, three
Pod/PVC/PV/store identities, storage class, connected member, and initial server
identities. It then checks the raw receipt digest, three-replica stream and
consumer state, PubAck and consumer ACK sequences, stored payload hashes,
single-delivery/no-redelivery state, and source-described action counts.
Restart receipts must retain workload, volume, and store identity across one
changed child process. Quorum receipts must bind both paused members and their
nanosecond observation bracket, keep an initially acknowledged publication
separate from a timeout-unknown publication, reconcile only the same message ID,
and end with exact A/X/Y sequences 1/2/3. Unknown is not reported as loss. These
identities remain supplied run-index pins; the collector checks consistency but
does not claim independent live resolution.

An index may declare a run `missing` or `failed` with a reason, which keeps it in
the trial denominator. `available` files with a wrong hash, duplicate JSON key,
unknown profile, selection mismatch, conflicting profile reuse, partial receipt,
inconsistent flattened evidence, NATS identity/protocol disagreement, or
replayed metrics bytes are rejected. A benign row qualifies only with the exact
unscored disposition and no security or financial derivation; older scored NATS
rows remain visible as invalid even when their raw protocol receipt can be
reconstructed. External review state and
reference are copied as supplied metadata; the collector does not grant live
acceptance. Source, harness, and configuration hashes are supplied pins too;
the collector checks referenced suite and metrics bytes but does not
independently establish binary lineage. Reports always state
`COMPARISON_NOT_ESTABLISHED` until a separately reviewed comparison contract is
implemented.
