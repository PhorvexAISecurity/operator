# Math/OR Benchmark Lab

The Math Lab is part of the benchmark dashboard. It lets OR/Math pick one Brain parameter, replay the **same recorded production ticks** with different values on the unmodified decision engine, compare against the recorded control, plot the result and export the raw evidence. Engineering does not have to change code for each experiment.

```
Parameters → New experiment → Preflight → Replay → Compare / plot → Export
```

It is **replay-only**. Nothing in the lab can change a production setting or dispatch an action. Replay measures how the decision engine responds on recorded states. It does not measure defense rates, SLO outcomes or future-state effects; those need paired sandbox episodes, which are a later phase.

## Pieces

| Piece | Where | What it does |
|---|---|---|
| Parameter registry | `mathlab/registry/parameter_registry.json` | 246 quantities: the 198 from the audit plus 48 found at `085a9fae`. Each has its class, protection, couplings, metrics, source location and replay knob definition. `ALL_MATH_PARAMETERS.refreshed.csv` is the same content as a table. `docs/math-lab/PHASE0_DELTA_REPORT.md` explains every change since the audit. |
| Snapshot capture | operator (`--math-lab-capture-policies`) | Records allowlisted policies' decision ticks. Contract: `docs/math-lab/SNAPSHOT_AND_REPLAY.md`. |
| `brain-replay` | inside the operator image | Offline replay and `-inspect`. The worker extracts it from ECR by the deployed image digest and checks its embedded source SHA. |
| Worker | `worker/mathlab/`, `worker/mathlab_cli.py` | Sync, binary extraction, preflight, cohort freeze, replay, analysis, exports. |
| API | `apps/api/src/mathlab.ts` | `/api/math/*`, as described below. Runs one Math Lab job at a time. Interrupted work is marked `INTERRUPTED` and is never re-run automatically. |
| Web | `apps/web/src/app/mathlab.tsx`, `charts.tsx` | Parameter catalogue, experiment builder, experiments, results. |

## API

All routes require a dashboard session. None can write to the cluster.

| Route | Purpose |
|---|---|
| `GET /api/math/registry?policy=ns/name` | The registry, with configured versus operator-resolved effective values taken from the newest recorded tick. |
| `GET /api/math/policies` | Capture policies (`MATHLAB_POLICIES`, default `vllm/vllm-defense`), corpus status, and the replay binary identity. |
| `POST /api/math/sync` `{policy}` | Pull recorded ticks through the Console relay, resolve the deployed `brain-replay`, and inspect the newest tick. |
| `GET /api/math/jobs/:id` | Sync job progress. |
| `POST /api/math/experiments/preflight` | Validate a design. Returns the checks and machine-readable errors (`error_code`, `field`, `reason`, `evidence_ref`, `retryable`). |
| `POST /api/math/experiments` | Create and queue an experiment. Only accepted after a passing preflight. |
| `GET /api/math/experiments[/:id[/metrics\|/plots\|/artifacts/:name]]` | List, detail, tidy metric rows, plot data and evidence. |

### Experiment request (`math-lab.experiment.v1`)

```json
{ "title": "Cost-ceiling (G9) binding sweep", "mode": "REPLAY", "parameter_id": "P-FEA-006", "policy": "vllm/vllm-defense",
  "arms": [{"arm_id": "control", "value_source": "RECORDED_EFFECTIVE"}, {"arm_id": "c1_8", "value": 1.8}],
  "cohort": {"max_snapshots": 500}, "hypothesis": "…", "primary_metric_id": "M-P04",
  "secondary_metric_ids": ["M-P21"], "safety_metric_ids": ["M-D06"] }
```

- **Knobs:** only registry `EXPERIMENT_KNOB` parameters can be varied. Today these are:
  - `P-OBJ-003` (β, with `{"unset": true}` allowed);
  - `P-FEA-006` (cost ceiling);
  - `P-FEA-005` (proactive floor, in whole seconds). It sets the hygiene cadence and the exposure horizon together, as the operator derives both from `spec.budget.proactiveFloor`. It needs an operator release whose `brain-replay -version` lists it (PR #452) and a cohort recorded by that release.
- **Rejected values:** non-finite, out-of-domain and duplicate values, unknown fields, `SANDBOX` mode, and β on a `costPreferences` policy.

### Preflight checks

- the replay-binary source SHA must equal the source SHA of every snapshot in the cohort (`VERSION_PIN`);
- the replay binary must list the knob in `overridableParameters` (`KNOB_UNSUPPORTED_BY_REPLAY_BINARY`); a build without that list supports only `P-OBJ-003` and `P-FEA-006`;
- the cohort must be non-empty and every snapshot must be complete;
- the cohort must be uniform: source, policy UID, process config, parameter manifest, policy overrides, economics mode;
- protected-parameter warning;
- statements that security outcomes are unavailable and that nothing writes to production.

### Experiment statuses

| Status | Meaning |
|---|---|
| `COMPLETE` | Every tick's baseline reproduced exactly and every arm replayed. |
| `PARTIAL` | Some ticks were excluded; they are counted and named in the result. |
| `INVALID` | No tick was usable. |
| `PREFLIGHT_FAILED`, `FAILED`, `INTERRUPTED` | The run stopped at that point. |

## How results are computed

- **Matched ticks only.** A tick enters a comparison only if the control replay reproduced production byte-for-byte and the arm replayed `OK` on the same recorded state.
- **Comparison status:**
  - `MATCHED_REPLAY`: all ticks come from the deployed image's binary on one source revision.
  - `OBSERVATIONAL`: anything else, such as a locally supplied binary or a cross-version cohort.
- **Common valuation.** Arms are compared on arm-independent quantities: gate admission, selected sets, and the coverage of the selected set valued with the **control's** fact weights. Each arm's own objective value is reported (M-P18) but is not comparable across differently priced arms.
- **Intervals.** All are deterministic, with seed 20261009 and 2000 resamples:
  - Wilson intervals for tick-level proportions;
  - a cluster bootstrap by tick for asset- and pair-level ratios;
  - a paired bootstrap over matched ticks for arm-versus-control differences.

  No p-values are reported; the intervals are descriptive.
- **Missing is never zero.** A ratio with a zero denominator is `UNAVAILABLE`. In replay, M-S01 (verified defense) and M-D02…M-D09 (observed disruption) are always `UNAVAILABLE`, with the reason recorded.

### Metric catalogue

The catalogue is in `worker/mathlab/analysis.py`, `METRIC_CATALOG`.

| ID | Metric | Kind |
|---|---|---|
| M-P21 | Changed-decision share | PROCESS |
| M-P22 | Useful-feasible-opportunity share | PROCESS |
| M-P23 | Unassessed-gate share | PROCESS |
| M-P03 | First-veto share per gate G0…G9 | PROCESS |
| M-P04 | CHi-ceiling exclusion share | PROCESS |
| M-P19 / M-P19R | No-op under attack, and no-op reason shares | PROCESS |
| M-P06 | Action mix | PROCESS |
| M-P02 | Budget saturation | PROCESS |
| M-P18 | Estimated objective | ESTIMATED_MODEL |
| M-P24 | Recorded production dispatch funnel (control only) | OBSERVATIONAL |
| M-P25 … M-P30 | Proposed IDs; definitions in the catalogue | — |

M-P25 … M-P30 are flagged `metric_proposed`. They cover common-weight predicted coverage, selected moves, feasible candidates per asset-tick, estimated disruption cost of selected moves, replay compute time, and the share of enabled pairs first-vetoed by each G6 hard law (M-P30, one row per law, with a 0 for a law that vetoes nothing in that arm).

## Evidence (per experiment, also in `evidence.zip`)

| File | Contents |
|---|---|
| `experiment_manifest.json` | Immutable identity: binary SHA and image digest, cohort digest list and hash, registry hash, arms, learner-state protocol, limitations. |
| `sweep_results.csv` | One row per arm × metric (× dimension), with numerator, denominator, n, interval method, status and population. |
| `candidate_gate_trace.csv` | One row per enabled (asset, action) pair × gate, including per-law feasibility rows, actual status and labelled counterfactual diagnostics. |
| `decision_funnel.csv`, `candidates.csv`, `cost_truth.csv` | Per-asset decisions and no-op reasons, first-veto attribution and G9 category, and expected cost terms. Realized cost is `NOT_OBSERVED` in replay. |
| `Phorvex_Math_Lab_Results.xlsx` | The same tables as an Excel workbook. |
| `plots/*.svg` and `plots.json` | The plots and their data. |
| `report.md` | A short report for OR review. |
| `replay.jsonl` | The authoritative raw replay output. |

## Operations

- **Capture prerequisite:** the operator release must include `brain-replay` and `--math-lab-capture-policies`, which come from operator PR #448.
- **Where it runs:** the worker uses the jump host's existing read-only `kubectl`, its Console E2E identity, and `aws ecr` read access.
- **Data:** stored under `DATA_DIR/mathlab/`: snapshots, inspections, `bin/<image-digest>/`, experiments and jobs. Deploys preserve it.
- **Local development:** set `MATHLAB_LOCAL_BINARY=/path/to/brain-replay` to use a locally built binary. Results are then always `OBSERVATIONAL`.

## Acceptance coverage

- **Operator side** (V-01, R-01…R-07, G-01…G-04, capture non-interference): see `docs/math-lab/SNAPSHOT_AND_REPLAY.md`.
- **Lab side:**
  - `worker/mathlab/test_mathlab.py` covers matched-population rules, UNAVAILABLE-not-zero, funnel conservation, dispatch-funnel scope, preflight refusals (V-04), version pin (V-01), β/costPreferences conflict, the configured-versus-effective overlay (V-02), and that only the two knobs are editable.
  - `apps/api/test/mathlab.test.ts` covers strict request validation, real preflight fail-closed behavior, interrupted experiments never re-running, and artifact traversal and symlink refusal.
  - **UI-01 (end to end):** checked on 24 recorded fixture ticks × 6 arms through the UI. Every baseline reproduced exactly, and the results, plots and ZIP were produced.
  - **UI-02:** no "safe" or "recommended" label exists anywhere. Unavailable safety evidence is shown as unavailable.
