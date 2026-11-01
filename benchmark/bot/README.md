# Stage brain benchmark bot

The bot benchmarks **operator-refactored** using recorded decision ticks from a stage namespace. Each recorded run binds the brain image digest, source commit, replay binary hash, policy UID and snapshot hashes. The old `operator` clone and production/vllm corpus are not valid inputs for this bot.

The default policy is `phorvex-staging-demo/demo-api-defense`. `/policies` lists the configured stage allowlist and installed pins. Requests retain their exact policy; the bot never substitutes the separate `stage-bench-defense` dryRun fixture. Experimental arms run offline: predicted choices and forecast costs are not executed defenses or measured counterfactual outcomes.

## Choose a request

| Request | Execution and evidence |
|---|---|
| `/param P-FEA-006 1.2 1.5 ticks=64` | The actual stage replay binary executes the recorded control and each registered parameter override locally. |
| `/bench ticks=64 <precise code change>` | Tests the actual base and candidate code, builds both with the captured toolchain, then compares image control, local base and candidate on the same frozen stage cohort. |
| `endpoint-v3-recorded.json` | Uses real stage snapshots and qualified observer inputs in the reviewed brain study engine; validates the deployed control and local base first. |
| `endpoint-v3-stage-600s.json` | Explicit 600-second W/L stage study with configurable SLO and worth threshold; requires complete observed history. |
| `endpoint-v3-original-30d-pending.json` | Original 30-day W / 1-day L request; requires complete retained history and verified storage/runtime readiness. The 30-day capability is not yet validated. |
| `endpoint-v3-10d.txt` | Declarative exact requested demo policy, 64 ticks, sync:false, W=10 days/L=1 day, s=.999. Missing active-policy attribution or retained history returns BLOCKED. |
| `endpoint-v3-fixture-600s.txt` | A separate explicit dryRun fixture control. It requires its own current source and complete 600-second measured history; it does not satisfy the 10-day request. |
| `endpoint-v3-synthetic.json` | Executes the shared Go cost kernel on labelled synthetic fixtures; a numerical reference test. |
| `study-*.json` | Configurable Cost/History **reference algorithms**, arms and seeds. These are not the production History picker. Missing real ledgers remain `NEEDS_DATA`. |

Use `/templates` for valid files and `/guide` for English HTML/PDF. Persian guides are also shipped in [HTML](guide-fa.html) and [PDF](guide-fa.pdf). Send a file without a caption to run it. `/validate` reports syntax validity separately from read-only runtime readiness: requested policy, live source/image/UID, capture, available/fresh ticks and required endpoint history. Apart from receiving the attached request itself, it does not sync snapshots/source, repin, queue, call a model or execute replay. Execution repeats the checks and still requires exact baseline reproduction and the applicable tests. Missing prerequisites produce `BLOCKED` artifacts; malformed requests and genuine test/internal failures remain errors. `/check` reports configuration, disk and model access; `/status`, `/runs` and `/cancel` track work. Owner-only `/invite` creates a one-use invitation.

For arbitrary supported V2/V3 settings use `[endpoint]` TXT/Markdown or endpoint JSON. Set independent `study.window` (W) and `config.lookback` (L) in seconds, `study.slo_target`, optional `study.worth_threshold`, and bounded `config.min/max/eta/g_max/max_dt/delta`. Unknown, duplicate or malformed keys are rejected. If min/max change without eta, eta is derived as `ln(max/min)/3600`; an explicit eta is preserved. `sync:false` prevents request downloads but never skips identity checks. Only the two exact previously reviewed V3 prose hashes receive compatibility conversion; their original bytes, conversion contract and normalized settings are retained. Edited prose remains a generic code request and is never silently interpreted as a different algorithm.

The registry at `benchmark/mathlab/registry/parameter_registry.json` lists supported replay knobs and domains. All such knobs can be selected by ID; unknown or non-overridable parameters are rejected. For a new formula or unregistered algorithm, use a scoped code request with concrete equations, input fields, invariants and tests. A model decline is reported with its reason and is not a successful benchmark.

## Stage installation

Keep secrets in the private `config/bot.env` described by [the example](deploy/bot.env.example). Set `BOT_REPO` to an `operator-refactored` clone containing the exact stage source, `MATHLAB_DATA_DIR` to a separate stage directory, and `BOT_DEFAULT_POLICY` to the stage capture policy. The bot's owner/member state can stay in its existing private state directory. `DASHBOARD_*` no longer selects the replay service; `/param` and sync use the stage runtime directly.

The staging service values retain both policy capture entries, the existing bounded PVC, manager cost observations and a separate read-only Console binding across image releases. The Console's additive grant preserves the current catalogue's operator grants. Applying those values is an operator action; uploaded requests never change the cluster. Capture of an active policy does not create attributed endpoint history. Its actual image and source must be verified after rollout. Then, from the benchmark host:

For recurring reconciliation, use the reviewed [stage service examples](../worker/deploy/README.md). The bounded reconciler observes the actual stage source, fetches that exact repository source, extracts its image-native replay without Docker, and verifies every selected baseline before atomically publishing a pin. It preserves historical pins/cohorts and serializes source changes against running jobs. It cannot enable cluster capture or supply missing endpoint history. A source/policy/workload change starts a new observer segment; the old history is never relabelled. Its default allowlist contains only the two named stage policies:

```sh
PYTHONPATH=benchmark/worker:. python3 benchmark/worker/stage_reconcile.py \
  --data /home/hami/phorvex-benchmark/stage-data \
  --repo /home/hami/phorvex-benchmark/operator-refactored \
  --ticks 64 --timeout 900 --max-work-bytes 268435456 --max-corpus-bytes 2147483648
```

The following explicit manual pin/sync commands remain available for operator setup:

```sh
python3 benchmark/worker/stage_cli.py pin \
  --data /home/hami/phorvex-benchmark/stage-data \
  --repo /home/hami/phorvex-benchmark/operator-refactored \
  --context arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks \
  --policy phorvex-staging-demo/demo-api-defense \
  --console-account staging-brain-benchmark
python3 benchmark/worker/stage_cli.py sync \
  --data /home/hami/phorvex-benchmark/stage-data \
  --repo /home/hami/phorvex-benchmark/operator-refactored
python3 benchmark/worker/stage_cli.py readiness --verify-replay \
  --data /home/hami/phorvex-benchmark/stage-data \
  --repo /home/hami/phorvex-benchmark/operator-refactored
```

`pin` resolves the actual ready brain container, checks the current ReplicaSet and complete rollout, and executes its version command to verify embedded source. It extracts a content-verified replay binary from the same image. For an older split brain image lacking the companion executable, `--companion-deployment staging-phorvex` permits the same-source staging manager image; that producer and the actual brain digest remain separately recorded.

`sync` checks the running source/digest and policy UID again. It mints a 10-minute Console identity token and opens an owned loopback port-forward to the pinned stage Console. The token is not logged or persisted. Ambient production Console URLs/tokens are ignored. The existing Console grant must permit read access to the exact stage tenant.

Stage acceptance requires snapshot headers produced by the actual recorder process: `captureIdentitySource=recorder-process`, the embedded brain SHA and the exact immutable `brainImage` from the installed pin. Sync, inspection and cohort sampling filter those identities before choosing ticks. Old manager-stamped snapshots and records from another digest remain historical even when their SHA matches; they cannot inherit the new image's provenance. Capture fresh data after installing the recorder-aware stage release.

Sync scans a bounded number of oldest-first index pages and saves source-scoped continuation, so old-image pages cannot permanently hide current data. Capture-time boundaries are inclusive; equal-time rows are never silently skipped. An index boundary beyond the API's 5,000-row limit is reported as `pagination_blocked` instead of being treated as complete.

`DATA_AVAILABLE` means matching snapshots exist. `READY` requires `--verify-replay` to reproduce every checked baseline exactly. Recreated policies, mixed sources, tampered binaries, absent capture, incomplete rollouts and unreplayable inputs produce explicit failures. Every actual experiment rechecks its own full cohort; readiness of one sample is not a guarantee for another request.

Build the synthetic reference runner with `benchmark/endpointv3/build.py` and ship its manifest, binary and the source inventory it names. Install the bot with [deploy/install.sh](deploy/install.sh); it runs exact stage baseline readiness before restarting the service. The installer leaves the old dashboard and data in place.

## Recorded endpoint V2/V3

See [ENDPOINT-V3.md](ENDPOINT-V3.md). The stage observer and normalizer produce UID-bound observed ready-backend intervals, duration evidence and a complete candidate export from the actual brain pipeline. An arbitrary uploaded trace cannot become recorded evidence.

When the actual image-native replay exposes paired-study and candidate-export capabilities, reconciliation can install a same-source native lane after measured exact baseline equivalence. This is not a cross-source review approval. Every requested study still validates its own frozen cohort and measured history. Missing or changed binaries, capabilities, generation bindings or evidence block readiness.

A typed study engine from a different source remains an explicitly reviewed experimental lane. Install that candidate and its exact local base with independent review evidence:

```sh
python3 benchmark/worker/stage_cli.py install-study-engine \
  --data /home/hami/phorvex-benchmark/stage-data \
  --repo /home/hami/phorvex-benchmark/operator-refactored \
  --study-binary /absolute/reviewed/brain-replay \
  --study-source FULL_CANDIDATE_SHA \
  --base-binary /absolute/base/brain-replay \
  --review-evidence /absolute/source-pinned-review.json \
  --review-evidence /absolute/source-tests.log
```

The JSON receipt has schema `phorvex-bench.study-engine-review.v1`, `result: PASS`, a nonempty `reviewer`, exact `source_revision` and `base_source`, `candidate_binary_sha256` and `base_binary_sha256`, plus `evidence_sha256` listing the SHA-256 hashes of the other supplied evidence files. The reviewer produces this receipt after reviewing the actual tested source and binaries; the CLI does not infer approval from prose. Stale or mismatched receipts are rejected.

The engine's actual source is retained. Cross-version replay requires exact image-control and local-base reproduction, then runs with an explicit cross-version flag and is labelled observational. No source SHA is relabelled and no candidate is deployed by a benchmark request.

## Reading results

A completed comparison reports actual comparable tick counts, unchanged/changed choices and per-candidate cost/gate details. Zero changes can be a valid result. `PARTIAL`, `BLOCKED`, `NEEDS_DATA` and invalid baseline states retain their reasons and never become a successful zero-effect result. Missing actual cost or verified effect is `null`, not zero.

Each report preserves the request, source/image identities, policy UID, frozen snapshot hashes, arm/build/test provenance and measurement limitations. Cost and History reference results remain labelled reference results. A fresh observer cannot supply a 30-day history. The original request requires continuous retained history and verified capacity to store and process it within the allowed time; the 30-day capability is not yet validated. Use an explicitly declared short study window only when its data and processing requirements are met.

Validation records from earlier releases in [VALIDATION.md](VALIDATION.md) are historical and do not prove the current stage deployment. Source tests: run the bot suite and worker suite with the installed dependencies; build the shared Go reference first to include its execution tests. Stage live evidence must be collected separately.
