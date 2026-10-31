# Paired endpoint-cost V2/V3 studies

Upload `templates/endpoint-v3-synthetic.json` to exercise the **offline Go reference** on 64 explicitly synthetic ticks. Both arms execute, share the same immutable inputs and new cost/admission rules, and use B=1. V2 ranks by grounded V; V3 ranks by `V - lambda_s * E / R`. Lambda evolves from the supplied measured-move evidence, never from its own hypothetical picks. This does not activate the production V3 brain.

Upload `templates/endpoint-v3-recorded.json` for qualified recorded inputs. `/validate` checks structure only. If the dataset is missing, execution inspects the pinned deployed snapshots and returns **BLOCKED**, an exact input checklist, HTML, JSON, CSV and ZIP. No model generation or Go compilation is attempted for this input failure. The original reviewed `PHORVEX_V3_NEW_COST_LAMBDA_GREEDY_BENCH.txt` routes to this same preflight by an exact whitespace-normalized prompt hash. Editing its algorithm makes it an ordinary code benchmark; use the versioned JSON contract for registered studies.

The legacy snapshot corpus does **not** contain the required move-attributed endpoint intervals or a complete candidate export under the new cost gate. Observed pod count is not `spec.replicas`; replica-readiness impact is not endpoint loss. No algorithm can recover those historical observations from absent fields. An optional future snapshot capture envelope can expose actual controller observations and replica history while still reporting these missing fields; it is not itself a complete V3 trace producer.

## Runtime and evidence

Build the standard-library-only runner with Go 1.23 or newer:

```sh
python3 benchmark/endpointv3/build.py
```

`ENDPOINT_GO` may select an installed Go executable. The build disables dependency downloads, records the compiler, and binds all Go source files and `go.mod` to the binary in `BUILD.json`. Ship `benchmark/endpointv3/` alongside `benchmark/bot/`. Generated `bin/` and `BUILD.json` are release artifacts, not committed binaries. The bot verifies source inventory and binary hashes before running a study. Run `go test ./...` in the module and `python3 -m unittest discover -s benchmark/bot` after building; the Python suite includes actual Go execution when the binary is present.

The fixture has a labelled synthetic burn rate of 2, ordinary 30-second ticks, default lambda starting at its floor, and close-valued GPU/stateless candidates. Different choices emerge from the update equation; no lambda is forced to create a difference. A zero-spend control must remain at the floor and produce zero changed choices. These are numerical validation results, not measured production improvements.

Outputs include every candidate's V, E, rho and refusal, budget R/used/held, lambda previous/next/effective, S/b/g/dt, durable-write result, picks and changed-choice counts. Lambda floor/ceiling status is in JSON. ZIP includes request, trace, build identity, execution log, per-controller durable state and file hashes. Counterfactual realized charges and verified facts remain null. Counts and forecast sums include only comparable ticks. `PARTIAL` and `BLOCKED` retain exact missing reasons and never become a successful zero-effect result.

## Recorded trace contract

`benchmark/endpointv3/types.go` defines `phorvex-bench.endpoint-trace.v1`. Each timestamp must represent a coherent snapshot with:

- Immutable workload/policy identities and the actual historical workload `spec.replicas`.
- An accepted SLO or explicitly declared study-only SLO; acting admission remains blocked in this offline runner.
- Measured endpoint-loss intervals attributable to move IDs, revisions and open/settled state, with known coverage of both SLO and lambda windows. Latest revisions replace older revisions; conflicting identities, stale open accrual and overlapping attribution fail closed.
- Complete candidates from a pinned producer, actual grounded fact-to-actuator/provenance weights, all non-cost gate verdicts, original containment priority and V-worth threshold. Exporting only previously selected candidates is insufficient. Multi-workload candidates within a single policy tick require a joined producer/contract extension and are currently rejected.
- Known duration history partitioned by workload UID/action, with censoring, overdue and suspect lineage. Known zero observations uses documented class priors; unknown history is unavailable. Quarantine uses rotate samples and explicit hold cap. Unsupported actuator bounds remain refused.

An operator can install a qualified trace only after checking its producer and provenance:

```sh
python3 benchmark/bot/endpoint_study.py /path/to/qualified-trace.json \
  --data-dir /path/to/data --policy vllm/vllm-defense \
  --producer 'audited producer revision and evidence reference'
```

Installation records a source SHA, policy and trace hash in a manifest. A hash establishes integrity, not truth of self-declared measurements. Telegram inline traces are accepted only as synthetic evidence; users cannot upload a JSON file and silently promote it to recorded production data. The last N chronological ticks are used, with fresh independent study state on every job.

The request prose contains an ordering ambiguity: it says low E must not override higher V but also explicitly requires maximizing J and supplies an example selecting lower V at nonzero price. This reference follows the explicit J equation and controlled example. At the floor it uses V, then lower E, then stable ID, exactly as V2. No priced-worth, entropy or history selector is added.
