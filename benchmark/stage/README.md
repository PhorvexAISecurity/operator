# Source-pinned stage endpoint evidence

This collector supplies observed inputs to the actual `brain-replay` study.
The candidate set, security values and non-cost gates come from the reviewed
brain source. The collector contributes Service endpoint membership and a
durable, explicitly labelled calibration history. It does not select actions,
change the production cost model, or claim application availability.

The initial supported scope is one Deployment UID, one exact Service selector,
one `dryRun` policy with `B=1`, and a dedicated stage fixture. `fixture.yaml`
uses `phorvex-staging-demo/stage-bench-*` resources and three replicas. Review
and apply it separately. The observer refuses an active policy, changed UID,
changed selector, unrelated rollout, ambiguous move, or unexplained endpoint
loss. A pod UID may appear in multiple EndpointSlices/addresses; it is counted
once as a logical Service backend.

## Capture

Run commands from a reviewed checkout of `operator-refactored`. The context is
always explicit. `SOURCE` is the actual captured brain source and `DIGEST` its
resolved running image digest; obtain both from the deployment identity check,
never infer them from the latest Git branch.

```sh
python3 -m benchmark.stage.observe discover \
  --context "$CONTEXT" --namespace phorvex-staging-demo \
  --policy stage-bench-defense --deployment stage-bench-api \
  --service stage-bench-api --source "$SOURCE" --image-digest "$DIGEST" \
  --output /private/stage-observer/scope.json

python3 -m benchmark.stage.observe watch \
  --scope /private/stage-observer/scope.json \
  --journal /private/stage-observer/evidence.db --seconds 1800
```

The watch command only reads Kubernetes resources. Initial lists and subsequent
raw watches retain exact resource versions, object UIDs and controller lineage.
Every append is serialized and committed with SQLite `synchronous=FULL`; its
hash includes the preceding record. The clock is the collector's serialized
UTC observation clock. These are observed control-plane readiness intervals,
not measured request outages or exact server-side transition times.

API events/bookmarks seal a continuous observation segment. Timer checkpoints
prove process liveness only and never extend API coverage. A tick is eligible
only after every watch has advanced beyond that tick; later bookmarks provide
coverage evidence without supplying later object state. A disconnected/error
watch, a missing event/bookmark for 180 seconds, failed durable write, or clock
regression ends qualified collection. A new session cannot bridge the gap.

For persistent capture, adapt `stage-observer.service.example` to the reviewed
checkout and private state paths. An automatic restart records a new session
and a real coverage gap. The default journal capacity is 256 MiB with plain
encoding. For a new persistent journal, select the reviewed compressed format
and its explicit capacity:

```sh
python3 -m benchmark.stage.observe watch \
  --scope /private/stage-observer/scope.json \
  --journal /private/stage-observer/compressed-evidence.db \
  --seconds 31536000 --encoding zlib-v1 --max-bytes 4294967296
```

`--max-bytes` is an accounted encoded-byte limit: 1 MiB..2 GiB for `plain-v1`,
or 1 MiB..4 GiB for `zlib-v1`. Encoding and capacity are immutable. Existing
plain journals remain readable without rewriting events, adding encoding or
compressed counters, or recompressing history. Starting a compressed journal
starts a new observation segment; it never bridges an earlier gap. The
collector stops when full; it does not
delete history and then claim completeness. Archive the complete journal and
create a new named scope/journal for a new segment. Monitor available disk and
the `status` command. Do not copy a live SQLite file without its WAL; use
SQLite's backup API or stop the collector before archiving all files.

Compressed journals store one lossless level-1 zlib stream per canonical UTF-8
event. The hash chain still covers the exact decoded event, scope, order and
serialized clock. Each decoded event has a hard 4 MiB limit; truncated streams,
trailing bytes, multiple streams, invalid UTF-8 and noncanonical JSON are
rejected. Encoded and decoded byte counters include a fixed 128-byte allowance
per event and are updated in the same transaction as the event. Opening the
journal verifies both counters against all stored rows and the decoded hash
chain. Plain journals retain their original logical counter; an ancient plain
journal with no transactional counter stays readable, but cannot be appended
to without starting a new journal.

SQLite pages, WAL and other benchmark data consume additional disk. Creation
and each append preserve at least 4 GiB free on the journal's filesystem, with
an additional allowance for the pending write; this guard cannot guarantee
space against unrelated concurrent writers. `observe status` includes both
accounted counters, actual DB/WAL/SHM sizes, free disk, reserve and measured
verification time. Its rate-based capacity/disk headroom estimates are labelled
estimates and are separate from observed history coverage; changed event rates,
WAL amplification or other users can exhaust storage sooner.

Normalization uses two streaming passes over one
frozen SQLite read snapshot, with the cutoff sequence/hash recorded in its
manifest. Concurrent capture cannot mix those passes. Opening/verifying a long
journal and validating a calibration intent still require a complete linear
decoded scan. Every scan defaults to a 120-second runtime limit; a timeout
produces no completeness result. `--scan-timeout` on observation commands or
`STAGE_JOURNAL_SCAN_TIMEOUT_SECONDS` for all Journal consumers can explicitly
set 1..1800 seconds. The refresher's total runtime budget remains a separate
bound. Measure representative scan runtime before choosing longer windows;
long intent scans can also delay concurrent observation writers. Schedule
calibrations accordingly and monitor observer health.

Collection duration supports up to 366 days, and raw watches request that
duration without a client-imposed hourly disconnect. The API server or network
may still close a watch. A one-day/30-day history is available only when an
actual complete segment covers those windows and retained capacity is
sufficient. This implementation does not promise uninterrupted 30-day capture
or claim proven continuity across a reconnect. Short declared study windows
can be used immediately after enough continuous observation exists.

## One physical calibration

Keep the watcher running. Verify all three fixture pods are ready. This command
performs one physical Pod deletion; use only the dedicated fixture and the
authorized stage experiment:

```sh
python3 -m benchmark.stage.observe rotate \
  --journal /private/stage-observer/evidence.db --pod EXACT_CURRENT_POD_NAME \
  --reservation 159 --deadline-seconds 120
```

`159` is the explicit cold stateless study reservation with the documented
43-second prior and 30-second watchdog, not a measured duration. The command
persists intent before issuing an HTTP DELETE with the exact Pod UID as a
precondition through a temporary localhost Kubernetes proxy. It retains the
real API acknowledgement. A simultaneous second intent is rejected in the
same database transaction. The known other baseline endpoints must remain
ready; loss of another pod is never credited to the intended move.

The observation joins the intended target to exactly one same-controller
replacement. The measured interval is its isolated ready-backend deficit;
duration runs from durable intent to acknowledged replacement readiness.
Open-to-settled state transfers the same move identity once. Uncertain or
interrupted moves remain censored and cannot supply a measured duration.
The operation is labelled `controlled-stage-calibration`, never a brain-issued
move or a counterfactual V2/V3 outcome. The ledger is shadow evidence and grants
no acting admission authority.

## Normalize a frozen brain cohort

Use the reviewed brain binary's `--export-study-candidates` against the exact
frozen snapshot cohort. Each export must reproduce its recorded legacy
baseline. The export carries the snapshot digest, actual capture source,
candidate-engine source, policy UID, exact spec replicas and source-owned
candidate fields. A reviewed cross-version replay must explicitly report both
source SHAs and its observational status.

An example short experiment uses `s=.9`, `W=600s`, `L=600s`, and `theta=0`.
Those are explicit study assumptions, not an accepted tenant SLO. With three
replicas its budget is 180 endpoint-seconds. Wait for the full 600-second
continuous history before the first tick in the selected cohort; leave the
observer running until its API watermarks cover the cohort's final tick.

```sh
python3 -m benchmark.stage.normalize \
  --journal /private/stage-observer/evidence.db \
  --candidates /private/run/candidates.jsonl --output-dir /private/run/normalized \
  --slo-target .9 --window 600 --lookback 600 --worth-threshold 0 \
  --install-data-dir /private/stage-data
```

The normalizer preserves candidate facts, values, gates, class, action and
containment from the engine. It fills only qualified endpoint/history inputs
and explicit study settings. It rejects a different source/cohort/policy,
incomplete candidates or a baseline mismatch. `trace.json` and
`normalization.json` explain readiness; an incomplete trace is never installed.
An otherwise eligible quarantine also requires an explicitly configured finite,
nonnegative `hold_cap`; zero is an explicit budget refusal and this collector
never invents a missing cap. A known non-cost
veto or the existing worth rejection can make pricing unnecessary. The initial
live fixture is rotate-only; unsupported action bounds remain unavailable.
The installed manifest binds the trace hash, image, both source SHAs, ordered
snapshot digests, candidate-export hashes and journal evidence.

The bot must use the manifest's frozen snapshot cohort and the pinned actual
brain study binary. Custom study settings may change W/L only within genuinely
retained continuous evidence; they cannot create missing history.
The standalone `endpoint-v3` CLI is a synthetic/reference control using the
same pure kernel; its result alone is not a recorded brain benchmark.
Counterfactual realized charges and verified effects remain unavailable.

## Refresh the installed dataset

After stage pinning, reviewed study-engine installation and continuous
observation, run the read-only refresh command periodically:

```sh
python3 benchmark/worker/endpoint_refresh.py \
  --data /private/stage-data --repo /opt/operator-refactored \
  --policy phorvex-staging-demo/stage-bench-defense \
  --journal /private/stage-observer/evidence.db \
  --slo-target .9 --window 600 --lookback 600 --worth-threshold 0 \
  --ticks 64 --timeout 900
```

The command synchronizes actual image/UID/source-matched snapshots, selects
the newest requested ticks inside one continuous observed segment, freezes
and verifies their bytes, verifies both the captured-image and reviewed local
base replay, and exports the candidate set with its true study-engine source.
One frozen SQLite prefix covers both selection and normalization. Later API
bookmarks seal earlier ticks without applying future object state to them.
The running image, policy UID, installed pin and reviewed engine are checked
again immediately before publication.

Each qualified trace is an immutable content-addressed generation. The bot
reads one atomic `POLICY.manifest.json` pointer first, then the named generation
and its hash. A failed refresh preserves the last good pointer; its current
reason and phase are written to `mathlab/endpoint-refresh/NAMESPACE/POLICY.status.json`.
An old dataset is still historical: the status file identifies whether the
latest refresh succeeded. Missing windows remain unavailable.

Default bounds are 64 ticks (maximum 256), 900 seconds (maximum 1800), 512 MiB
temporary work, 512 MiB immutable generations per policy and 2 GiB snapshot
cache per policy. API observation seals must be no older than 600 seconds
by default (`--max-observation-age`, bounded to 60..3600 seconds).
The snapshot cache retains the newest 256 managed snapshots plus the current
manifest cohort. Only snapshots downloaded by this refresh path with the exact
current source, image, policy UID and recorder-process stamp are eligible for
pruning. A shared policy lock protects consumers until their verified run copy
is complete; pruning and pointer publication hold its exclusive counterpart.
Unowned and older-source files count against the capacity but are preserved;
if they fill the cache, move them only through an explicit archival procedure.
Generations are never removed while readers may hold them;
an exhausted generation quota requires explicit archival during a reader
maintenance window. Journals, frozen run cohorts and results have separate
retention and are never removed by refresh. A process supervisor may invoke
this command every few minutes; overlapping refreshes for one policy are
rejected by a local lock. A source/image change requires a new verified pin
and a new genuine observation segment before publication can resume.

## Verification and cleanup

```sh
python3 -m unittest benchmark.stage.test_evidence benchmark.stage.test_observe benchmark.stage.test_storage
python3 -m benchmark.stage.observe status --journal /private/stage-observer/evidence.db
```

Tests use realistic Kubernetes producer objects and a real localhost HTTP
DELETE transport. They cover exact UID preconditions, unrelated readiness
loss, restart/watch gaps, missing acknowledgements, write failure, concurrency,
as-of evidence, history completeness, source binding and single charging.
They do not replace the independently recorded live stage controls.

Stop the observer before cleanup and retain its journal, scope, frozen
snapshots, normalized trace, reports and source identities. Remove only the
four owned resources from `fixture.yaml` if the persistent benchmark fixture
is no longer needed. Removing a fixture does not erase benchmark evidence.
