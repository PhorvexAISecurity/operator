# Manager OOMKilled source investigation — 2026-09-17

## Scope and conclusion

This is a bounded source/evidence review of the manager built from `673db9f3f2dfa9cca4e62a772c49cd416eec1227` and the same relevant paths in Tier 13 source `54b7c3ae676ae132e928da738bc14c3e82712a34`. It does **not** establish a memory leak or a product cause. The September 17 evidence proves one manager container ran from `2026-09-17T12:46:43Z` until it was `OOMKilled` with exit 137 at `2026-09-17T19:18:20Z`, under a `256Mi` memory limit. Fresh September 18 evidence proves the last termination of a different Tier 13 manager Pod was also `OOMKilled`/137 after running from `12:03:23Z` to `19:35:03Z` under the same limit. Neither capture contains a pre-kill RSS/working-set series, Go heap profile, cgroup memory event breakdown, informer object counts, or allocation profile.

The highest-priority source candidates are:

1. the already-open M-137 default controller-runtime informer cache, whose retained size follows cluster object/cardinality and has no configured namespace/type scope here;
2. the shadow calibration runtime's seven-day, cardinality-dependent history of fleet samples and per-policy-tick optimizer comparisons;
3. high transient allocation and serialization pressure from full colocation assessments on every decision.

Only (1) is already represented by a canonical issue. Candidate (2) is time-windowed rather than an infinite lifetime leak, but has no count/byte ceiling within that window. Candidate (3) is source-evident allocation volume, not retained history. None can be named as the cause from this single OOM.

Tier 13 source `54b7c3ae676ae132e928da738bc14c3e82712a34` is byte-identical to `673db9f3` in the relevant calibration, audit, metrics, colocation and manager-construction paths. Latest main `4c31ae289797f1c5e71bb957d5fbaf6a965ba787` changes only release metadata beyond `54b7c3ae` in this comparison. Tier 13's M64/M29 changes therefore do not repair or newly introduce these candidate seams. M64 was absent from the September 17 image and present in the September 18 image, while the candidate paths stayed unchanged; that coexistence still does not assign cause to M64.

## Retained evidence

- `live/20260917T202143Z/manager-restart.json` records the exact terminated/running states and exit reason.
- `live/20260917T202143Z/pods.json` confirms the restarted manager was Ready with restart count 1 and container limit `256Mi`.
- `live/20260917T202143Z/deployments.json` confirms the deployed arguments: base interval `10s`, calibration shadow enabled, sample interval `5m`, refresh interval `30m`, lookback `168h`, and the same `256Mi` limit. No `GOMEMLIMIT` or `GOGC` override is present. That absence is diagnostic context, not a recommendation to change the limit.
- `live/20260917T202143Z/manager-previous.json` is only the last 100,000 bytes: 27 lines over 10 seconds immediately before termination. It contains 16 colocation assessments averaging 6,108 bytes, 10 tick summaries, and a calibration refresh reporting `assets=100`, `nodes=8`, `rotations=1`.
- `live/20260917T202143Z/manager-initial.json` is from the restarted process: its last 200 lines span 53 seconds and total 742,422 bytes. All are audit output: 118 colocation assessments averaging 6,152 bytes and 82 tick summaries. This shows sustained record/allocation volume after restart; it does not show retained heap.
- `live/20260918T223312Z/pods.json` records a different Pod UID (`fbf5d8e4-b7e7-4b23-97c7-b893a6d97e17`) running image `0.4.129` / digest `8825048b…`, source `54b7c3ae`, Ready with restart count 3. Its captured **last** termination is independently `OOMKilled`/137 at `19:35:03Z` after starting at `12:03:23Z`, again under `256Mi`. The other two restart causes are unavailable and are not classified as OOMs.
- `live/20260918T223312Z/manager-initial.json` shows the same high-volume path after that restart: 645,745 bytes across 200 lines in 47 seconds, including 102 colocation assessments averaging 6,066 bytes, 70 tick summaries and 28 maintenance records. This strengthens recurrence of allocation/output pressure, not a retained-heap conclusion.

## Candidate 1: default informer cache — already M-137

`phorvex/cmd/main.go:361-372` constructs `ctrl.Manager` with default cache options: no `DefaultNamespaces`, `ByObject`, transform, or other cache scope is configured. `CollectSnapshot` uses the manager's cache-backed client for cluster-wide Pods, Namespaces, NetworkPolicies, RBAC, policies, nodes, PDBs and Services (`phorvex/internal/ingest/kube.go:137-287`). Informers retain their current object sets for the manager lifetime; the snapshot projections are transient but the underlying informer objects are not.

This is the exact memory-scale exposure already recorded in `workflow/issues/entries/M-137.md:20-23`: an unscoped O(cluster) in-memory cache with no measured scale envelope. The OOM is relevant live evidence for that issue's missing envelope, but it does not prove the cache caused this event. Do not file a duplicate issue from this report.

## Candidate 2: shadow calibration history

`phorvex/internal/calib/runtime.go:129-143` retains `samples`, `rotations`, `pending` comparisons and the latest full `RefreshResult`. `ObserveValidation` appends one `SelectionComparison` at `runtime.go:184-196`. The production caller is `phorvex/internal/runner/manager.go:1941-1950`, after each policy tick for which a shadow view/decision is available. Each comparison retains production/shadow selection slices and two `[]DecisionScore` slices.

At each five-minute sample, `runtime.go:227-255` moves all pending comparisons into a `CadenceSample` and retains samples for the configured seven-day lookback. At each 30-minute refresh, `runtime.go:262-279` copies the sample headers, flattens all retained optimizer comparisons into a second slice for `latest`, and evaluates the full history. Old samples are pruned by time, so this is not an infinite lifetime leak. There is no count or byte bound for samples, comparisons, assets, scores, or rotations inside the lookback. Its steady-state memory therefore scales with policy count, protected assets, tick frequency and action/decision count.

With nine deployed policies and a ten-second base interval, the configured path can admit roughly 21,000 policy-tick comparisons during the observed 6.5-hour process lifetime if every tick has shadow evidence. That is an envelope calculation, not an observed count: the retained evidence does not expose `len(samples)`, `len(pending)`, `len(latest.Comparisons)` or their bytes. The final refresh's `assets=100`/`nodes=8` shows this runtime was active at nontrivial cardinality, while `rotations=1` makes rotation history alone an unlikely explanation.

No canonical issue found in the targeted issue-entry review owns this calibration-memory contract. M-98 concerns calibration/objective semantics, not retained runtime history. A future issue, if warranted by measurement, should describe a bounded-window/cardinality problem rather than call it a leak.

## Candidate 3: colocation assessment allocation pressure

`phorvex/internal/runner/colocation.go:14-38` rebuilds a policy-to-pod membership map with nested policy/pod iteration for each policy tick. `recordColocation` then calls `recon.AssessColocation` for each decision (`colocation.go:41-62`). `phorvex/internal/recon/colocation.go:34-91` scans the pod inventory, allocates neighbor/witness collections, copies policy/event details, and sorts them. `internal/audit/colocation.go` serializes the complete assessment to the structured logger.

The retained log sizes above confirm this path was producing about 6 KiB per assessment and more than 700 KiB of structured output in under a minute after restart. This is a plausible source of sustained allocation rate and GC pressure at a low memory limit, especially alongside cache and calibration live data. The source does not retain these assessment objects: `audit.Logger` writes synchronously and contains no in-process record queue/history. Persistent audit rotation is a disk concern already covered by M-154, not this heap question. Thus this report does not call the colocation logger a leak.

## Lower-priority stores reviewed

- Exposure clocks and intent maps are pruned by owner against each tick's live Pod set (`internal/exposure/clock.go`, `internal/exposure/intent.go`).
- Action-failure feedback has an explicit 4,096-record cap and owner/Pod pruning (`internal/runner/action_failures.go`).
- Manager policy, lifecycle, epoch, emitted-history and published-tenant state has explicit removal/drain cleanup (`internal/runner/manager.go:530-885`).
- The disruption ledger is time-retained for 30 days rather than count-capped (`internal/slo/ledger.go`), but the live refresh reported only one rotation. It remains a theoretical rate/cardinality seam, not a leading candidate for this event.
- The authorization TTL cache does not delete expired namespace/verb keys (`internal/authz/ssar.go`), and some cumulative Prometheus vectors naturally retain label combinations. The evidence shows nine stable policy namespaces and no churn/cardinality measurement, so neither has event-specific support here.
- Pending rotation records can remain while recovery is unresolved, but the observed single rotation gives no basis for attributing material memory to them.

## Evidence needed to distinguish the candidates

A source fix is not justified by this record alone. The discriminating evidence is a time-correlated series over at least one process lifetime for container working set/RSS, `go_memstats_heap_alloc_bytes`, heap objects and GC cycles, joined to informer object counts and explicit calibration sizes (`samples`, `pending`, retained comparisons/assets/rotations). A heap profile near the rising edge would distinguish informer objects, calibration history and transient JSON/colocation allocations. A bounded offline soak at the deployed 100-asset/9-policy cadence can then compare the same workload with calibration and colocation recording independently controlled, without mutating live workloads.

Until those measurements exist, the defensible statements are: two captured last terminations on different manager Pods/builds were OOMKilled under 256Mi; the other recorded restarts have unknown causes; M-137's missing memory envelope is operationally relevant; calibration has a separate count-unbounded-within-168h retention contract; and colocation logging creates high allocation/output volume. Limit changes, leak claims and causal repair should not be inferred from this evidence.
