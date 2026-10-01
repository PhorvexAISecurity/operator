# Parallel vs serial live-attack benchmark

One armed Live attack per app, fired through the Console on `phorvex-dev-eks` in
two modes, to measure the effect of concurrency (PR #410 allows concurrent runs
across apps; the Console serializes same-app runs). Attack set: vLLM `kvcache`,
Voice `ai2-agent-memory-contamination`, LiteLLM `ai2-query-extraction`, and
`crm` / `mcp` / `nats` footholds.

| Report | Files |
| --- | --- |
| Serial (one at a time, in order) | [serial.html](serial.html), [serial.csv](serial.csv) |
| Parallel (all apps at once) | [parallel.html](parallel.html), [parallel.csv](parallel.csv) |

## Headline

| | Serial | Parallel |
| --- | --- | --- |
| Total wall-clock | **665 s** | **314 s** (~2.1× faster) |
| Attacks | 6 | 6 (all start at t=0, overlapping) |

## Honest findings

- **Concurrency cuts total wall-clock ~2×**, but it is bounded by the slowest
  single attack, not the sum.
- **Served-model attacks run slower under contention.** vLLM, Voice and LiteLLM
  all hit the same vLLM backend; in parallel they took longer, and LiteLLM
  exceeded its 300 s budget without reaching a terminal result (`UNKNOWN`),
  whereas serially it reached `DEFENDED` in ~161 s. So parallel firing is faster
  overall but can degrade per-attack latency and even the verdict for
  backend-sharing attacks — raise their budgets for parallel runs.
- **`crm` foothold is rejected** in both modes: *"namespace crm is outside this
  identity's tenant scope"* — the Console E2E identity (`phorvex-phorvex-console-e2e`)
  is not granted the `crm` tenant. Firing CRM from the Console needs that grant.
- **Voice memory is variable** (UNKNOWN / LANDED across runs); see the
  voice/pgv2 diagnosis in `test_coverage/`.

## Reproduce

`benchmark_runner.py <serial|parallel> <out.jsonl>` runs on the cluster jump host
over one shared Console port-forward (independent per-fire port-forwards collide,
which invalidates a naive parallel run). `make_bench_report.py <in.jsonl> <mode>
<out_dir>` renders the HTML timeline + CSV.
