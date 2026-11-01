# Math Lab: decision snapshots and offline replay

This covers the operator side of the Math/OR Benchmark Lab (tickets C, D and F, replay MVP). The lab dashboard consumes it from `benchmark/`.

For the explicit offline V2/V3 candidate export and observed endpoint study,
see [Endpoint study through the brain](ENDPOINT_STUDY.md). Default replay remains
the legacy baseline/parameter path.

## What it does

1. **Capture.** The operator can record the decision ticks of policies on an allowlist. Each record is an immutable, content-addressed snapshot of everything the production `CoverageEngine` reads to make one tick's decision.
2. **Replay.** `brain-replay` is built into the operator image from the same source revision. It restores a snapshot into a fresh in-memory engine and re-runs the unmodified production decision. It does this first for the recorded baseline, then once per hypothetical parameter value ("arm").
3. **Attribution.** For every enabled (asset, action) pair, replay reports which gate produced the first veto. Downstream gates are reported as not evaluated. Pure counterfactual diagnostics are labelled separately and never counted as what production ran.

Nothing in this path changes a production decision, writes to the cluster or dispatches an action.

## Capture contract

| Item | Behaviour |
|---|---|
| Enable | `--math-lab-capture-policies=ns/name,...` (Helm `phorvex.mathLab.capturePolicies`). Empty, the default, records nothing. There is no wildcard. |
| Storage | `--math-lab-capture-dir`, on the audit volume. A bounded store (`--math-lab-capture-max-bytes`, default 1 GiB) evicts the oldest snapshots first. Files are `<sha256>.pxms`, written atomically and verified on read. |
| Hot path | Inputs are copied immediately before `DecideChecked`, and the raw decisions immediately after. The audited decisions are copied after dispatch. Compression and disk I/O run on one background writer. The queue never blocks: if it is full, or a snapshot exceeds `--math-lab-capture-max-snapshot-bytes`, the snapshot is dropped and counted. |
| Failure | A store or configuration error disables capture with an error log. The operator keeps running. |
| Metrics | `phorvex_mathlab_snapshots_total{result}`, `phorvex_mathlab_capture_seconds`, `phorvex_mathlab_snapshot_uncompressed_bytes`, `phorvex_mathlab_store_{bytes,files,evicted_total,write_failures_total}`. Production first-veto attribution is `phorvex_candidates_gated_total{tenant,action,first_gate}`, a bounded label set. |
| Transport | `GET /v1/math-lab/snapshots[?policyUID,namespace,policy,since,until,limit]` and `GET /v1/math-lab/snapshots/{digest}`, on the existing mTLS audit listener. The only client is the console. The console relays both as `GET /api/math-lab/snapshots?namespace=` and `GET /api/math-lab/snapshot?namespace=&digest=`, read-only and scoped to one granted namespace. A digest whose snapshot belongs to another namespace is reported as absent. The console stores nothing. |

### Snapshot contents (`math-lab.snapshot.v1`)

**Uncompressed JSON header.** This is the identity and join key, used for listing without decoding:

- capture and decision instants, the source SHA and the brain image;
- tick, policy UID and generation, owner;
- the parameter-set manifest hash and the policy-overrides hash;
- the **process configuration**: the decision-relevant effective flags and their hash, so a flag change alters identity even when the policy hash does not;
- the engine's own recon profile and context provider, the GPU envelope and the economics mode;
- the assets in evaluation order, the selected set, and the production error.

**Gob payload (gzip):**

- the configured `PhorvexPolicySpec`, as JSON;
- the effective `model.Policy`. Its label-weight function is rebuilt from the spec at replay time.
- the ordered `[]*model.WorkloadView`. Order decides tie-breaks.
- `decision.OwnerState`, which holds:
  - the cost bucket: RLS θ/P/ff/primed/updates/frozen, the conformal residual window, and runtime λ;
  - `BucketMeta` and the creation counter;
  - the calibration freeze;
  - the kill-chain stage-clock slots and the conjugate prior.
- every **capability** and **failure-cooldown** verdict that production requested in that tick. These collaborators make SSAR calls and live API reads, so replay answers from the recorded verdicts and never calls them.
- the raw production decisions. When the tick reached the audit write, the payload also holds the post-dispatch decisions, with dry-run, kill-switch and dispatch-outcome stamps.

## Replay contract (`brain-replay`)

```
brain-replay -version
brain-replay -inspect  -snapshots DIR -out inspect.jsonl          # configured vs operator-resolved effective values + learned state
brain-replay -snapshots DIR -arms arms.json -out results.jsonl [-summary summary.json] [-allow-cross-version]
```

`arms.json` is a JSON array. The first arm is the baseline, with no overrides. Overridable parameters for this MVP:

| param_id | Field | Domain | Notes |
|---|---|---|---|
| `P-OBJ-003` | `disruptionAversion` (β) | `[0,10]` or `unset` | `unset` keeps the policy's own mode (legacy runtime λ live today). A value on a `costPreferences` policy is an `INVALID_ARM`, because the two are mutually exclusive. |
| `P-FEA-006` | `costCeiling` (c̄, gate G9) | `(0,1000]` | Hypothetical; replay only. |
| `P-FEA-005` | `spec.budget.proactiveFloor` (T_cad), in whole seconds | `[1,604800]` | Coupled: the operator derives both the hygiene cadence (G6 `proactive-cadence`) and the exposure-pressure horizon (T_exp: context exposure, recon belief, hazard pressure) from this one spec field, so the arm sets both. A recorded policy whose horizon differs from its floor is an `INVALID_ARM`. Moves backed by a fresh trusted event bypass the cadence law. |

NaN, ±Inf, out-of-domain values, unknown parameters and duplicates are refused before anything runs. `brain-replay -version` lists the parameters the build can override (`overridableParameters`), so a caller can refuse a sweep the deployed build cannot run; a build without that field supports only `P-OBJ-003` and `P-FEA-006`.

**Per (snapshot, arm) result statuses:**

| Status | Meaning |
|---|---|
| `OK` | The arm replayed completely. |
| `UNREPLAYABLE` | Missing replay-critical input (named), a verdict production never recorded, a baseline that did not reproduce, or a snapshot from another source revision (`VERSION_MISMATCH`, unless `-allow-cross-version`, which flags `cross_version`). |
| `INVALID_ARM` | The arm cannot apply to this policy. |
| `ERROR` | The replay itself failed. |

The baseline result carries `baseline_check`. It holds an exact comparison of every replayed decision and full trace against the recorded production decisions. Both sides are normalized through the same codec, and the first differing JSON path is reported. The **only** excluded field is `ScopedOutcomes`, a reporting-only cohort report keyed by process lifetime that selection never reads.

**Rows emitted per arm:**

- **decisions:** action, selection, a no-op reason from a closed set, attack-backed, common-weight coverage, expected and robust cost, and gain. The dispatch status is `COUNTERFACTUAL_NOT_DISPATCHED` for every arm. Baseline dispatch evidence is reported separately.
- **candidates:** the first-veto gate with its reason, admission, scoring and gain, and a G9 category: `G9_PASS`, `G9_SOLE_VETO_VERIFIED`, `G9_MULTI_VETO_VERIFIED`, `G9_WOULD_PASS_AFTER_EARLIER_VETO` or `G9_UNKNOWN_OTHER_GATES`.
- **gates (`math-lab.gate.v1`):** one row per pair × gate, plus one per feasibility law.
- **costs (`math-lab.cost.v1`):** the expected terms only. The realized value is always `NOT_OBSERVED` in replay.
- **funnel:** disjoint population counts.

### Gate identifiers

These are the per-candidate gates, in generator order. Every exclusion names exactly one.

| ID | Gate | Diagnostic when not reached |
|---|---|---|
| G0-recon-absent | Asset-level: a non-finite recon input minted no fact | — |
| G1-policy-binding | Bound observation identity/epoch | UNKNOWN |
| G2-unsupported-action | `identity-rotate` | UNKNOWN |
| G3-quarantine-capacity | Namespace quarantine bound | UNKNOWN |
| G4-capability | Opt-out, installability, cover, capability, code-exec, RBAC, failure cooldown | UNKNOWN (impure) |
| G5-shared-resources | Shared resource capacity | UNKNOWN |
| G6-feasibility | Hard laws. Each law is reported, with `SKIPPED_UNUSABLE` when its telemetry is unusable and `NOT_APPLICABLE` when the law is not configured. | Pure, per law |
| G7-cost-nan | Fail-conservative cost category | Pure |
| G8-objective-pricing | Set-level economics validity. It never excludes a single candidate. | — |
| G9-chi-ceiling | CHi > c̄ | Pure |

The actual statuses follow the generator's short-circuit exactly. A gate before the first veto actually **passed**. Gates after it are `NOT_EVALUATED`. A pure diagnostic is `counterfactual_only` and is never an actual pass.

Per-law G6 rows are evaluated on the view as the generator read it, carrying the tick's event-evidence stamp. On the raw recorded view an event-backed move would show a `proactive-cadence` failure the generator never applied, and a later law's real veto would lose its attribution.

## What replay can and cannot claim

- It establishes **immediate decision sensitivity** on recorded states: which candidates are admitted, what is selected, and the estimated objective. It does **not** establish realized defense, SLO impact or future-state effects. After an arm diverges, the recorded next state no longer follows from that arm. Those claims need paired sandbox episodes (ticket F, later phase).
- Replay never observes realized cost, so expected-versus-measured cost truth (M-D07) needs the separate realized-cost join.
- A parameter that changes which capability or cooldown queries production makes, for example the enabled actions, cannot be replayed from recorded verdicts. Such arms come back `UNREPLAYABLE` and name the missing verdicts.

## Verification

All tests are in-tree and run in CI. They map to the shared acceptance matrix as follows:

| Test | Acceptance |
|---|---|
| `decision.TestRestoredOwnerStateReplaysProductionTickByteForByte` (6-tick history: trained RLS, conformal window, λ movement, stage transitions; serialized state) | R-01 |
| `mathlab.TestBaselineReplayReproducesProductionExactlyAndDeterministically` | R-01, R-03 |
| `mathlab.TestBaselineComparisonDetectsATamperedProductionRecord` (1e-9 change is detected and named) | R-01 positive control |
| `mathlab.TestIncompleteSnapshotIsUnreplayable` (missing owner state; lost verdicts) | R-02 |
| `mathlab.TestBetaArmChangesOnlyObjectivePricing` | R-04 |
| `mathlab.TestCostCeilingArmAdmitsOnlyVerifiedSoleG9Vetoes` | G-01, R-05, R-07 |
| `mathlab.TestEarlierVetoNeverCountsAsG9` | G-02, G-03 |
| `mathlab.TestUnusableTelemetryIsNotAPass` | G-04 |
| `mathlab.TestInvalidArmsAreRefused` | V-04 |
| `mathlab.TestBucketCreationTickReproduces` (first tick after a start, on an advancing clock) | R-01 |
| `mathlab.TestProactiveFloorArmMovesCadenceAndExposureHorizon` (coupled roles; event-backed bypass; decoupled policy refused) | R-05, R-07 |
| `decision.TestShadowAssemblyAfterRestoreMatchesProductionCandidates` (owner state untouched; gate views carry the production evidence stamp) | D gate attribution |
| `runner.TestMathLabCaptureIsNonInterferingAndReplaysTheRunnerTick` (audited decisions byte-identical with capture on and off; the runner tick replays exactly) | C "no selection changes", D "no production decisions change" |
| `cmd/brain-replay.TestReplayCommandReproducesAndRefusesForeignRevisions` | V-01 (version mismatch), inspection |
| `audittransport.TestMathLabEndpointsAreReadOnlyBoundedAndContentAddressed` | read-only transport |
| `actionset.TestEveryGeneratedExclusionNamesItsGate` (AST guard) | D gate attribution completeness |

### Optional cost-input evidence (observability prerequisite)

The manager flag `--math-lab-capture-cost-evidence` defaults to `false`. When
explicitly enabled it attaches `phorvex.endpoint-cost-evidence.v1` to the capture
request. Existing policy allowlisting and snapshot storage remain required. In
remote mode, enable the new flag on the **manager** and the existing
`--math-lab-capture-policies=namespace/name` and storage flags on the **brain**.
This proposal does not change chart defaults or activate collection in a cluster.
The manager, brain, and sensor (when remote) must all run compatible code; older
components can omit the additive fields, and old snapshots keep them absent.

`model.Pod.WorkloadSpec` records an exact UID-checked controller `spec.replicas`
observation with resource version, generation, and sensor observation time. A
Deployment is resolved through its ReplicaSet; standalone ReplicaSets,
StatefulSets and ReplicationControllers can also supply already-observed replica specs. The
evidence helper never issues additional API reads: it sees only the existing
snapshot owner cache after the existing rotation and stateful-rotation producers.
Objects they do not read, such as direct-Deployment owners, remain
`owner-object-not-observed`. Cache identity includes type, GVK and object key. Zero is a known
value. Missing readers, stale or ambiguous identities and unsupported controllers
remain unknown. In particular, Phoenix observations that do not request owner
resolution keep `owner-reader-unavailable`; enabling this flag does not broaden
sensor API reads. Existing `DesiredReplicas` and admission behavior are unchanged.

Inspection exposes `endpoint_cost_evidence` and `endpoint_cost_missing`. The
optional envelope contains at most 256 workload observations and 2,000 matching
ledger observations, bounded to 1 MiB. Truncation and attribution gaps are explicit.
Ledger export is an immutable copy filtered by exact policy owner and namespace;
rows preserve their observation ID, emitted/censored/completed status and known
pod/workload UIDs. `process_observed_since` is this ledger instance's creation time,
not a promise of uninterrupted monitoring. History is in-memory and
`history_complete` remains false, including after restart.

The exported ledger source is **replica-readiness**: its duration runs from
actuation to observed replacement Pod readiness. The current EndpointSlice
producer records point membership, without durable, move-attributed transition
intervals. Therefore `endpoint_loss_status` is always `unavailable` and
`admission_ledger_status` is `not-authoritative` for this producer. These records
cannot activate endpoint pricing, reconstruct an authoritative endpoint budget,
or supply a complete paired V2/V3 dataset. Accepted endpoint availability targets
and move-attributed endpoint-loss intervals require a separate producer. Old
snapshots report `endpoint_cost_evidence:not-recorded` while legacy replay still
works; no historical observations are invented.
