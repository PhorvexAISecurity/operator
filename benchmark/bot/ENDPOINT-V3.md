# Endpoint V2/V3: recorded brain replay and synthetic reference

`endpoint-v3-recorded.json` compares explicit V2/V3 selection through the reviewed, source-pinned **brain-replay** engine on actual stage snapshots. `endpoint-v3-synthetic.json` exercises the same pure Go cost kernel on synthetic fixtures. The latter is a reference calculation, not a stage brain result.

The kernel lives in `phorvex/internal/cost/endpoint`; its standalone fixture CLI is `phorvex/cmd/endpoint-v3`. `benchmark/endpointv3/build.py` builds that command and records a v2 source inventory, compiler and binary hash. Ship the named source files with the release. The bot checks every source and binary hash before synthetic execution.

## Required observed inputs

A stage observer journal must bind the exact context, stage namespace, brain image/source, policy UID, workload UID and Service/Pod/controller lineage. Continuous EndpointSlice observations measure **watch-observed Service ready backends**, not application outage. Watch gaps, restarts without continuous coverage, ambiguous moves and failed durable writes cannot establish complete history.

Candidate exports come from the real source-pinned brain pipeline using `--export-study-candidates`. Every tick preserves its original snapshot digest, capture source, actual exporter source, full non-cost candidate/gate evidence and exact baseline result. A final selected-action list is not a complete candidate universe. Initial endpoint studies require a single workload UID and B=1; unsupported scope is rejected.

The isolated calibration fixture records real controlled rotations and observed endpoint intervals. These are calibration moves, not counterfactual brain arm executions. Study SLO target, window, lambda lookback and worth threshold are explicit experimental settings. They do not become an accepted production SLO or authoritative admission ledger.

Normalize from actual journal and candidate exports:

```sh
python3 -m benchmark.stage.normalize \
  --journal /absolute/stage-observations.sqlite \
  --candidates /absolute/candidates.jsonl \
  --output-dir /absolute/normalized \
  --slo-target 0.9 --window 600 --lookback 600 --worth-threshold 0 \
  --install-data-dir /home/hami/phorvex-benchmark/stage-data
```

These 600-second settings are a short study request, not the original 30-day specification. The collector must actually cover the complete requested window before every selected tick. A longer window requires that much observed history and verified storage/runtime readiness. Only a `READY` normalization can be installed. The manifest binds journal/export evidence, source/image/policy identities, snapshot digests, retained history and study settings. The old arbitrary JSON installation command is intentionally refused.

## Request file

```json
{
  "schema": "phorvex-bench.endpoint-study.v1",
  "title": "Observed stage V2 versus V3, 600-second study window",
  "policy": "phorvex-staging-demo/stage-bench-defense",
  "ticks": 64,
  "dataset": "recorded",
  "config": {"lookback": 600},
  "study": {"slo_target": 0.9, "window": 600, "worth_threshold": 0}
}
```

Use the actual pinned calibration policy if it differs from this example. Download [the 600-second stage request](templates/endpoint-v3-stage-600s.json) or [the original 30-day W / 1-day L request](templates/endpoint-v3-original-30d-pending.json). Both are also sent by `/templates`. The original request requires its entire continuous 30-day history to be observed and retained, plus verified capacity to store and process it within the allowed time. The 30-day capability is not yet validated; running the shorter request does not complete the original requirement.

The optional strict `study` object accepts `slo_target` (strictly between 0 and 1), `window` (1–2,592,000 seconds) and `worth_threshold` (nonnegative). `config.lookback` controls L (1–2,592,000 seconds); it defaults to 86,400 seconds when omitted. Other bounded lambda settings (`min`, `max`, `eta`, `g_max`, `max_dt`, `delta`) can also be varied. Unknown keys and invalid values are rejected before queueing.

Overrides apply to an immutable per-run copy. Changed SLO settings remain `accepted=false` and `study_assumption=true`. Facts, gates, UIDs, move intervals, duration samples, containment and ledger authority remain exactly as recorded. Both W and L must fit the continuous observed history for every selected tick. Expansion beyond installed defaults additionally requires the producer's explicit all-moves/all-samples/untrimmed-interval retention contract and sealed per-tick evidence. Missing coverage produces `BLOCKED` with requested and available seconds before either arm runs. Collect and normalize again to extend the available history; a request cannot create it.

`dataset-manifest.json` preserves the original normalization provenance. `study-settings.json` and the result record original settings, requested overrides, effective per-tick settings, retained coverage and the original trace hash. The installed dataset is never modified.

The periodic stage sync and `benchmark/worker/endpoint_refresh.py` publish fresh qualified trace generations. Each request reads one immutable generation and freezes its exact snapshots before replay. Refresh preserves the last good manifest when source changes or observed history is insufficient, with the current reason in `mathlab/endpoint-refresh/NAMESPACE/POLICY.status.json`. Results retain the selected generation's actual source and interval; retained older data is not relabelled as fresh. Managed-cache pruning waits for readers to finish copying and never deletes frozen experiment directories.

If capture is from merged main and the study engine is a reviewed candidate, the normalizer preserves both `snapshot_source_revision` and the actual candidate `source_revision`. Install the candidate engine and local base through `stage_cli.py install-study-engine` as described in the bot README. The bot first replays the image control and local base on the exact same frozen snapshot cohort, requires every baseline to reproduce, then invokes the candidate's typed mode with explicit cross-version permission. Reports remain observational and do not claim the candidate was deployed.

## Results and refusals

The output includes each candidate's grounded V, E, rho, gates/refusals, available budget, lambda state/update, J and selection. Both arms receive identical real inputs and independent study state. V2 ranks by V; V3 ranks by the explicit J equation. At lambda's floor, tie-breaking matches V2. Containment remains separate from ordinary priced ranking.

`BLOCKED` identifies missing/unqualified evidence before claiming comparable ticks. `PARTIAL` preserves per-tick refusals. Forecast costs are separated from actual calibration measurements; counterfactual realized costs and verified effects remain null. A changed-choice rate is not an improvement score. The History picker reference workflow is documented in STUDIES.md and remains a separately labelled reference model.

`budget.acting_admission = BLOCKED: offline experiment` is expected even for a successful comparison: replay grants no physical actuation authority. The result's top-level `state`, comparable count and missing reasons determine whether the benchmark completed.
