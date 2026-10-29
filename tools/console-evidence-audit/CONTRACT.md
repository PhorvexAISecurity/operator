# Audit-ready evidence contract v1

The authoritative input is a bundle with schema
`phorvex.console-evidence-audit.bundle.v1`:

```json
{
  "schema": "phorvex.console-evidence-audit.bundle.v1",
  "campaign_id": "catalogue-192-...",
  "exported_at": "2026-10-29T12:10:00Z",
  "expected_runs": [
    {"catalogue_id": "T1610", "run_id": "immutable-run-id"}
  ],
  "records": [
    {"schema": "phorvex.console-evidence-audit.record.v1"}
  ]
}
```

For the production campaign, `expected_runs` must contain 192 unique catalogue
IDs and exactly one immutable run ID for each. Passing `--expected-count 192`
makes that cardinality an explicit campaign gate. A record for another run is
not substituted for the expected run.

All timestamps are timezone-aware ISO-8601 values. All payload hashes are
lowercase SHA-256. JSON payload hashes use UTF-8 over canonical JSON with sorted
object keys, no insignificant whitespace, and no NaN/Infinity. The executable's
`sha256_value()` is the reference implementation.

## Record gates

Each `phorvex.console-evidence-audit.record.v1` has top-level
`catalogue_id`, `run_id`, `family`, and `expected_action`. Every stage repeats
the exact `catalogue_id` and `run_id`; omission is BLOCKED and mismatch is
INVALID.

| Stage | Required proof |
| --- | --- |
| `run` | `started_at < finished_at`, both no later than the audit clock |
| `trigger` | `evidence_kind=runtime-config`, `mode=reactive` |
| `policy` | separate `evidence_kind=runtime-config`, `mode=active`; `active\|dryRun` is never accepted as a trigger mode |
| `signal` | runtime observation, `observed=true`, event and target UIDs, creation/observation timestamps in the run window, and age within the verifier ceiling |
| `decision` | same event and target UIDs, decision ID, later timestamp, exact expected action, `selected=true`, and `feasible=true` |
| `actuator` | `evidence_kind=accepted-receipt`, same decision ID/action, receipt ID, `status=accepted`, and later timestamp; `dispatch_outcome=emitted` alone earns no credit |
| `oracle` | recognized family-specific kind, structured two-sided observations whose before/after relation is independently checked, and observation after receipt acceptance |
| `prometheus` | complete, error-free metric set containing query hash plus independently hashed baseline, final, and raw Prometheus API payloads with numeric samples |
| `postflight` | top-level `postflight_clean=true` plus a consistent runtime health proof after the oracle, nested `clean=true`, and an inventory hash; Console fixture cleanup is not postflight health |

The baseline precedes signal creation. The final capture follows the physical
oracle. The raw range capture follows final and its sample timestamps cover both
baseline and final. A query, labels, deltas, screenshot, or producer summary
without the raw response payload is insufficient.

See [fixtures/strict-valid.json](fixtures/strict-valid.json) for the complete,
executable fixture.

## Persisted Console runtime inputs

The verifier also consumes the runtime's durable
`phorvex.attack-catalogue-run.v1` `catalogue-run.json` envelope directly. Its
top-level `runID`, `catalogueID`, `triggerMode`, and `executionMode` must exactly
match the nested `phorvex.attack-catalogue-result.v1` fields. Standalone legacy
`catalogue-result.json` documents and `/api/runs/evidence` responses remain
accepted for backward compatibility. Trigger mode maps only to `trigger.mode`;
execution mode maps only to `policy.mode`.

Native runtime evidence is normalized without upgrading it. The current runtime
record does not persist the family on the result envelope, signal/decision/receipt
timestamps, event and target bindings on the decision, a durable receipt ID, the
audit-ready two-sided observation list, a separate postflight health inventory,
or raw Prometheus response bodies and hashes. Those fields remain BLOCKED or
INVALID as appropriate; `validated=true`, `receiptObserved=true`, cleanup flags,
parsed metric samples, or a `DEFENDED` verdict do not substitute for them. See
[`persisted-runtime-incomplete.json`](fixtures/persisted-runtime-incomplete.json)
for the exact native shape and its fail-closed test.

## Family oracle registry

The v1 registry is deliberately closed for the 192-case catalogue. A new family
requires a verifier change and tests; an unknown family cannot pass.

| Family | Oracle kind | Required structured observations |
| --- | --- | --- |
| `agent-action` | `app-action-denied-two-sided` | abusive action allowed→blocked; benign action and peer unchanged |
| `controller-stop` | `controller-stopped-availability` | target running→stopped; availability true |
| `credential` | `credential-revoked-two-sided` | attacked credential authenticated→denied; benign credential remains authenticated |
| `datastore` | `datastore-restored-readback` | datastore changed; legitimate read unchanged |
| `identity-sa-rotate` | `service-account-rotated-credential-replay` | SA UID changed; old credential authenticated→denied; Pod UID unchanged |
| `image` | `image-rollback-runtime` | image digest changed; availability true |
| `network-edge` | `network-edge-blocked-two-sided` | forbidden edge reached→blocked; legitimate edge and target Pod UID unchanged |
| `node-recycle` | `node-replaced-two-sided` | target Pod UID changed; peer node unchanged; availability true |
| `pod-rotate` | `pod-uid-replaced-availability` | target Pod UID changed; sibling Pod UID unchanged; availability true |
| `quarantine` | `pod-quarantined-network` | forbidden edge reached→blocked; legitimate edge and target Pod UID unchanged |
| `sensitive-output` | `sensitive-output-blocked-two-sided` | sensitive output disclosed→blocked; benign output unchanged |
| `serving-kv` | `key-reset-two-sided` | compromised key changed; benign key unchanged; serving Pods consistent |
| `serving-rate` | `abusive-rate-throttled-two-sided` | abusive request admitted→throttled; legitimate request unchanged |

Each named observation is an object containing `name`, `before`, `after`,
`passed=true`, and `observed_at`. The verifier evaluates the relation itself;
`oracle.passed=true` and observation `passed=true` cannot conceal a wrong
before/after transition.

## Screenshot attachment contract

Every run produces a deterministic binding:

```text
binding_id = sha256("v1\\0" + catalogue_id + "\\0" + run_id + "\\0" + evidence_sha256)
```

`screenshot-bindings.json` preallocates `console` and `grafana` slots with
deterministic filenames. A later collector may fill only `captured_at` and the
PNG's lowercase SHA-256, preserving `catalogue_id`, `run_id`, `evidence_sha256`,
and `binding_id`. Screenshot capture time should fall inside the retained run's
review interval. A screenshot is an attachment for human navigation: the
manifest and every binding state `source_of_truth=false`, and the verifier does
not read screenshots when calculating PASS.

## Core-runtime integration assumptions

The verifier assumes the evidence exporter, not the browser, will eventually
provide the audit-ready fields:

1. Console assigns an immutable run ID before launch and persists that ID plus
   the exact catalogue ID on signal, decision, actuator receipt, physical
   oracle, Prometheus, and postflight records.
2. Trigger mode (`reactive`) and policy safety mode (`active|dryRun`) are emitted
   as separate typed fields.
3. The actuator exposes a durable acceptance receipt distinct from manager
   dispatch/emission.
4. Each family exports raw before/after physical observations using the closed
   v1 names, including a benign/sibling/availability side where required.
5. The Prometheus exporter retains unmodified baseline, final, and range-query
   response bodies, query text, capture times, and hashes. It does not
   reconstruct raw proof from rendered Grafana values.
6. Postflight exports a separate clean inventory hash after teardown/oracle
   completion. Case cleanup flags are not treated as cluster-health proof.
7. Exported source JSON is a point-in-time snapshot. API use is optional and
   read-only; no validation step needs to launch a case or mutate a cluster.
