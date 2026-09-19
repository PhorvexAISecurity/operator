# Calibration retention investigation — September19

Source tested: `f8d3106e1eea9f2db4027a17b1fb744926ab5592`. All calibration production files are byte-identical to deployed Tier13 `54b7c3ae`; Tier14 does not change this subsystem. Go1.26.3; single process, isolated test overlay, no cluster access.

## Measured result

The real calibration Runtime retains caller-supplied comparison scores across its default seven-day history. A synthetic 100-asset/eight-node fixture, nine policy comparisons per ten seconds, five-minute samples and thirty-minute refreshes admitted21,060 comparisons across6.5 simulated hours. Every default refresh/cadence path ran. These are declared experiment cardinalities, not measured production comparison counts. Production-style exact-capacity score slices were used.

| Scores per comparison side | Retained heap delta at1h | At3h | At6.5h |
| --- | ---: | ---: | ---: |
| 0 | 1.24 MiB | 3.60 MiB | 7.60 MiB |
| 4 | 3.41 MiB | 10.12 MiB | 21.73 MiB |
| 12 | 8.55 MiB | 25.55 MiB | 55.16 MiB |

The12-score case retained approximately55MiB above its initial heap. Heap profiles attribute the live allocations to score arrays/keys supplied by the fixture and the runtime's history/refresh copies. This proves a relevant source retention cost, not the cause of a256Mi container OOM. Informer cache, actual decision cardinality, allocator/GC transients, process overhead and container memory still need a real lifetime profile. No recommended resource limit or leak cause is inferred.

## Independently reproduced expired-reference defect

After an eight-day quiet gap, ObserveSnapshot logically drops all old comparisons and refreshes Latest to zero comparisons. However, the in-place samples compaction leaves expired comparison slices referenced beyond len(samples) in its retained backing array. In the12-score experiment54,441,112 bytes above baseline remained after logical expiry. Clearing only the unused tail in this diagnostic fixture returned heap near baseline. This diagnostic is not a committed repair.

A separate small actual-runtime counterexample, with a positive before-expiry control and no memory-stat threshold, fails as intended: `expired comparison references remain reachable in Runtime.samples backing array: got100 want0`. Raw output is `expired-reference-red.log` (package0.022s). This is a source-confirmed expiry-retention defect, distinct from the already-open M137 informer cache scope problem. It cannot explain the observed6–8-hour OOM by itself because those histories had not yet reached the seven-day cutoff. The larger count/cardinality budget and the narrower stale-tail repair need separate contract decisions; do not solve memory pressure by silently removing scientific evidence.

## Reproduction and limits

`retention_probe_test.go` is supplied with Go's overlay mechanism; repository code was unchanged. The measured suite passed in0.528s. The explicit expiry-release invariant failed as expected. Raw logs, profiles and an inuse-space pprof summary are retained privately. An earlier run used append-grown score arrays; that run is preserved in superseded-append-allocation and excluded from the table because production allocates exact-capacity arrays.

Next: deduplicate/file the precise expiry finding with positive/negative tests; define bounded calibration history and evidence-export behavior before any larger retention redesign. Obtain deployed heap/cardinality evidence for OOM attribution. DevOps retains all resource/deployment ownership.
