# Declarative Cost and History studies

All bot requests now use `operator-refactored` and stage namespaces. `/param` runs the actual pinned stage replay locally; `/bench` compares actual brain builds. This document describes the separate **reference** Cost/History runner. For the integrated recorded V2/V3 brain study use [ENDPOINT-V3.md](ENDPOINT-V3.md).

Recorded reference traces require an installed stage pin, matching source revision and policy UID manifest. Inline uploaded traces must be synthetic. The import command binds the trace to that pin; it does not prove physical measurements or create absent history. Fresh observation cannot establish a 24-hour or 30-day history. Keep the requested window explicit and collect it before interpreting the associated results.

Upload a `phorvex-bench.study.v1` JSON request to run configured reference algorithms
without asking an LLM to generate code. A study supports 1–8 named arms, 1–16
recorded seeds, a shared chronological trace, and up to 100,000 candidate rows
across all arms/seeds. `/bench` and `/param` keep their existing behavior.

This implements an **offline reference-model experiment**, not the production
consolidated model. It does not actuate, deploy, create new verifier contracts,
reconstruct missing evidence or certify the Go brain. `COMPLETE` means the requested
reference experiment completed with adequate inputs; it does not mean that a
proposal passed production rollout gates.

## Start with an executable example

Use `/templates`, then upload one of:

* `study-cost-synthetic.json`: dimensionless legacy cost versus endpoint-second cost,
  with the same deterministic B=1 selector. Values with different units are kept separate.
* `study-history-synthetic.json`: deterministic, entropy, score-only stochastic and
  history-weighted selectors; three seeds; explicit synthetic acknowledgements.
* `study-history-recorded.json`: the same four selectors on a normalized recorded
  dataset. Returns `NEEDS_DATA` with an explanation until that dataset exists.

All synthetic examples are labelled in the request, result, report and manifest.
They demonstrate computation and history behavior, not observed security outcomes.
Send the file with `/validate` as its caption first, then without that caption to
execute. `/study` explains the feature. JSON can also be placed in a UTF-8 `.txt`
file; do not wrap it in `[bench]` or mix it with legacy sections.

The same engine runs locally, requiring only Python's standard library:

```sh
python3 benchmark/bot/study.py benchmark/bot/templates/study-history-synthetic.json --out /tmp/history-study
```

Exit codes: 0 COMPLETE; 3 PARTIAL/NEEDS_DATA/CANCELLED; 2 invalid configuration or I/O.
Use a fresh output directory for each local run. Telegram creates private job directories.

## Request contract

The examples are complete inputs, not placeholders. Change `arms`, their settings,
`seeds`, `history` and trace content to define an experiment. Unknown fields,
duplicate JSON keys, nonfinite numbers, bad identities, duplicate ticks and
resource-limit violations are rejected before queueing. JSON uploads are limited
to 2 MiB. There are no user-supplied commands, executable expressions or file paths.

Top-level fields:

| Field | Meaning |
|---|---|
| `schema` | Exactly `phorvex-bench.study.v1` |
| `title`, `policy` | Study label and namespace/name |
| `seeds` | Unique integer seeds; paired random values are keyed by seed and tick |
| `arms` | Named cost/selector configurations; first arm is the comparison reference |
| `history` | `mode`: `observed` or `simulated-starts`; positive `window_seconds` |
| `trace` | Inline `phorvex-bench.study-trace.v1` input |
| `dataset` | Alternative to `trace`: exactly `recorded` |

All algorithms use **B=1**. Comparison arms are independent; seeds and histories are
reset for each arm/run. Reordering the arms does not change an arm's draws.

Cost choices:

* `provided`: consume authoritative `c` and `rho` in endpoint-seconds from each
  candidate. Useful for isolating selector changes on a fixed external estimator.
* `legacy`: require explicit `norm_weight`, `flow_weight`, `ceiling`; consume
  recorded `norm`, `flow`, `chi`. This is a supplied-term reference, not a new RLS
  implementation or proof that those terms reproduce the deployed brain.
* `endpoint-v1`: defaults `delta` to the proposal's 30 seconds; computes class
  priors, cold/max-sample and calibrated order-statistic duration bounds, one-sided
  95% failure bounds, standard reservations and quarantine hold/closing-rotate
  accounting. `T_rb=T_upper` is explicitly marked a stand-in. Censored samples are
  `null`, never zero. `k=0` avoids `0*Infinity`; unavailable bounds refuse admission.

Selector choices:

* `deterministic`: maximum J with stable candidate-id tie handling.
* `entropy`: explicit positive `tau`, nonnegative `epsilon`, and a positive
  `entropy_prior` for every eligible candidate. Finds the largest feasible
  temperature up to tau. Missing fact-derived priors are not replaced with uniform.
* `history`: explicit `epsilon`, `score_scale`, `eta_pair`, `eta_action`, `eta_fact`,
  `kappa_pair`, `kappa_action`, `q_ref`, `x0`, `a0`. These are study settings, not
  approved production defaults. Implements v1.1 missed-opportunity weights,
  verified-fact novelty/anticipation, history-weighted best-score ties, and the
  expected-regret mixture. `epsilon=0` explicitly excludes nonmaximal choices.

Each arm defaults `lambda_eff` to zero and `coverage_guard` to true. Lambda is an
explicit study input, not the old move-count controller or a newly implemented
adaptive lambda controller. `coverage_guard:false` is an offline ablation of the
supplied guard verdict. It cannot disable actual production gates.

## Trace producer responsibilities

Legacy `.pxms` replay output does not contain all consolidated-budget/history/fact
inputs. The tool intentionally does not invent a conversion. An evidence producer
must supply a normalized trace, with the original source commit and independently
derived gate/ledger values. The examples show the exact JSON shape; validation is
implemented in `study_schema.py`.

Trace fields: `schema`, `evidence` (`recorded`/`synthetic`), `source_revision` (full
40-character SHA for recorded evidence), `history_complete_from` (epoch seconds or
null), ordered `events`, ordered `ticks`. Timestamps are numeric UTC epoch seconds.

Each tick carries a unique `id`, `at`, `workload_uid`, `selection`
(`optional`/`mandatory`/`noop`), `randomization_authorized`, and `candidates`.
Mandatory selection names `mandatory_candidate`. It remains deterministic and
unpriced, and cannot bypass cost or non-cost admission. Unauthorized optional
randomization falls back to deterministic selection. An authoritative NOOP stays NOOP.

Candidates carry a stable `id`, `pod_uid`, `generation`, `action`, authoritative
incremental `value`, `non_cost_admitted`, and `guard_admitted`. The producer must
apply mode restrictions, singleton/last-endpoint rules, quorum, cooldown, stale
state, anti-neglect due reservations, feasibility, validated-effect eligibility and
all non-cost gates before setting these flags. **A true flag is an input assertion,
not evidence that this harness independently ran the gate.** Do not use a legacy
G9 veto as `non_cost_admitted:false` when studying replacement cost admission.

`budget` contains `r`, `used`, `held` from authoritative accounting, so
`R_left=r-used-held`. The producer derives r from the selected SLO/window/replica
definition. A missing ledger is not initialized to zero. Zero is permitted when
explicitly supported by evidence or declared synthetic. A missing required cost
or budget input invalidates the tick, rather than silently dropping a competitor.

`cost` holds inputs required by the chosen cost models. Endpoint-v1 uses `class`
(`stateless`, `gpu`, `stateful`, `unknown`), integer `k`, newest eligible `samples`
(up to 200; right-censored entries null), and `overdue` count. The producer applies
workload/action/window and suspect-lineage filtering. For quarantine it supplies
`sample_action:"rotate"` and `hold_cap`; samples must describe the closing rotate.
The no-endpoint exception is represented by k=0. Realized kv-reset charge is not
inferred from its reservation.

For fact preferences, `facts` contains unique active fact-instance identifiers and
`weight`, `origin` (enrollment/last verified time), `deadline`, `required`, `validated`.
Generation is part of a fact id. Unknown effects receive no verification credit.
Only required, validated facts contribute to Q. Existing fact clocks and guard
verdicts remain authoritative; this engine does not create new 24-hour obligations.

## History and evidence semantics

Observed mode consumes chronological events:

* `opportunity`: `id`, `at`, `tick_id`, `workload_uid`, `pod_uid`, `generation`,
  `action`. This is a true optional opportunity after gates and scheduling guard,
  not a stale retry or an inferred opportunity between snapshots.
* `execution_start`: same pair identity, unique `id`/`at`, and `opportunity_id`
  referencing an earlier event. A dispatch without acknowledgement is not a start.
* `verified`: unique `id`, `at`, `workload_uid`, `fact_id`. Emit only a matching
  verified invalidation, never merely a successful dispatch.

F/S count events inside the rolling history window. Pair counters reset with pod
identity/generation; action-level counters persist within the workload. Action F
counts at most one opportunity for the action kind per tick, even with multiple
eligible pods. Duplicate opportunities/acknowledgements are rejected. Events after
the current timestamp cannot influence selection.

The completeness marker must cover the history lookback. Missing required history
or fact inputs invokes `PICKER_UNAVAILABLE` and a deterministic fallback, with
`PARTIAL` status. Do not mark missing evidence as a known-empty store. Observed
starts update observed history; counterfactual draws never do. This remains
observational after choices diverge.

`simulated-starts` is available **only for explicitly synthetic traces**. Every
optional candidate supplies boolean `simulated_start`. Selecting a candidate with
true creates a synthetic acknowledgement for that arm; false leaves S unchanged.
This is useful for picker-history logic tests. It does not simulate future workload
states, duration learning, reservations/settlement, recovery or verified coverage.
Budgets remain exogenous; summed selected reservations are not actual spend.

Install recorded evidence using an operator-side command, after the producer has
provided and checked the trace:

```sh
python3 benchmark/bot/study_data.py /path/to/normalized-trace.json --data-dir /path/to/data --policy phorvex-staging-demo/demo-api-defense
```

The import validates and atomically installs a private file at
`mathlab/study-traces/phorvex-staging-demo/demo-api-defense.json`. The bot only reads this fixed dataset
namespace. A study freezes the resolved input and hashes it into its evidence ZIP;
future dataset replacements cannot change an already completed run's evidence.

## Outputs and interpretation

Telegram returns HTML, metrics CSV, result JSON and an evidence ZIP containing:

* original/resolved request, full trace, source/implementation hashes and manifest;
* per-candidate JSONL and CSV including cost units, admission/refusal, scores,
  F/S/A/Q/h, q/r_star/p and selection;
* per-tick choices, reasons, random draw, expected and realized **score** regret;
* per-arm/per-seed counts and paired changed-decision comparisons.

Candidate CSV columns are discovered from emitted rows, so one cost model's fields
do not hide another's. Nonfinite bounds round-trip as explicit strings. HTML is
escaped and spreadsheet formula prefixes are neutralized.

`NEEDS_DATA` reports missing data; `PARTIAL` reports incomplete ticks or fallback;
`CANCELLED` preserves partial evidence. Verified counterfactual coverage and realized
cost remain null with reasons. Several seeds are reported individually; they are
not a confidence interval over deployment outcomes. A real 24-hour coverage study
still needs suitable authoritative evidence or isolated execution plus warm-up.

Large arbitrary model redesigns still require implementation/review; this format
does not execute formulas or programs supplied in a document. Extend the registered
reference algorithms and their tests to support a genuinely new algorithm. A
declined `/bench` now returns sanitized planner diagnostics instead of requiring
server access just to see which context files were omitted.
