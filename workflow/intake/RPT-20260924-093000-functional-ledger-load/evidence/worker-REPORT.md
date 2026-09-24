# Fixed-suite retained-ledger admission reproduction

On 2026-09-24, a private Go overlay added only `TestFunctionalLaunchRefusesUnknownRetainedRunState` to the actual `phorvex/internal/console` package. No product source, cluster resource or provider was changed. The test configures an existing valid `AuthUnauth` fixed-suite profile and an inert local worker, writes a malformed `run-events.jsonl`, then calls `NewRunManager` and the real `StartFunctional`. It expects admission to refuse without allocating a run ID or changing the retained ledger.

At source worktree head `bd4f62f84ee2a13c5fe8e7a44c83ee1bac1987ae`, `runs_catalogue_v1.go` SHA-256 `cbccea9b43d3d8417a5e5f97c2fdcf50d7bfce6e73f1dbc345cd471aea3560dc` and `runs.go` SHA-256 `5b1fed6362c2998ac5a0445c7e6fb2ba9ff6861e2a3ed7b9df51f6ce5709cb9a`, the expectation failed: `rm.loadErr` was set, yet `StartFunctional` returned `v1run-1` with no error, incremented sequence, added a run and appended to the malformed ledger. This is a genuine admission regression on an unknown retained-state source, not a simulated final `UnsafeToRetry` bit. Raw expected-RED output is `baseline.log` (SHA-256 `3bb834fe63e4ee1ffa31427039782eab858ddd8f5aeb1deca717f2dc67da29ff`, exit 1).

Command, from `/home/mehrdad/operator-catalogue-nats-response/phorvex`, with `GOMAXPROCS=2 GOFLAGS=-p=1` and a private `TMPDIR`:

```text
/home/mehrdad/.local/share/phorvex-tools/go1.26.1/go/bin/go test -overlay /home/mehrdad/operator/.git/phorvex-workflow/catalogue-coverage-20260923/reconciliation/load-error-repro/overlay.json ./internal/console -run '^TestFunctionalLaunchRefusesUnknownRetainedRunState$' -count=1
```

The overlay maps a nonexistent package test path to the adjacent private `functional_load_error_test.go` (SHA-256 `b874f5fd242b1c74823b95dc89ddea83e54345f09dd13b7c0f3e1c2a823ee058`). `overlay.json` SHA-256 is `b59d68a6973de2da137b79e7f7a169669b05f6f50a4dac9db2806b60c8b09f1c`. The inert worker exits immediately and has no cluster/provider access; this test proves admission, not any deployed workload effect.

Narrow repair candidate: under the `RunManager` lock in `StartFunctional`, refuse `rm.loadErr != nil` before checking the possibly incomplete `rm.runs` map or allocating/persisting a new run. Keep the separate healthy retained-unsafe status refusal control and add this exact malformed-ledger producer test. A Voice transcript cleanup reconciliation must also preserve the original failed result and use a separate audited attempt receipt; the load-error repair alone does not clear the historical `v1run-5` retry gate.
