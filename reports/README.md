# Parallel vs serial live-attack benchmark — all armed attacks

Every armed Live attack was fired through the Console on `phorvex-dev-eks` against
its own app, in two execution modes, to measure concurrency (PR #410 allows
concurrent runs across apps; the Console serializes same-app runs). 20 armed
attacks across 6 apps (vLLM 9, Voice 5, LiteLLM 3, and mcp/nats/document-store
footholds). `crm` is not included because the Console E2E identity is not scoped
to the `crm` tenant (its foothold is rejected).

| Report | Files |
| --- | --- |
| Serial — one at a time, in order | [serial.html](serial.html), [serial.csv](serial.csv) |
| Parallel — apps concurrent, same-app serialized | [parallel.html](parallel.html), [parallel.csv](parallel.csv) |

Each HTML has KPIs, a Gantt-style execution timeline, a summary table, and a full
per-attack brain pipeline (fire → attack executed → SecurityEvent → brain decision
→ actuation → post-action check → verdict). The CSVs carry the raw rows.

## Headline

| | Serial | Parallel |
| --- | --- | --- |
| Attacks | 20 | 20 |
| Total wall-clock | **1687 s (~28 min)** | **682 s (~11 min)** — ~2.47× faster |
| Defended / protected | 4 | 4 |

In parallel, all 6 apps start at t=0; within each app the attacks run back-to-back.
The 9-attack vLLM chain is the critical path, so parallel wall-clock ≈ the vLLM
chain time, not the sum of all 20.

## Verdicts (identical in both modes)

| App | Attack | Verdict | Actuator |
| --- | --- | --- | --- |
| vLLM | poison | **DEFENDED** | adapter-rotate |
| vLLM | endpoint-lease-revoke | **PROTECTED** | (prior revocation revalidated) |
| vLLM | kvcache | mechanism (effect-only) | kv-reset (steered) |
| vLLM | endpoint-rotate | mechanism (effect-unverified) | — |
| vLLM | model-shard-replace / warm-swap | mechanism (synthetic, no oracle) | kv-reset (steered) |
| vLLM | request-drain / guardrail-rotate | inconclusive | — |
| vLLM / Voice / LiteLLM / mcp / nats / document-store | foothold | fired (manager disposition) | rotate / quarantine |
| Voice | ai2-agent-memory-contamination | LANDED (variable run-to-run) | voice-memory-note-revoke |
| Voice | mcp-tool-poisoning / excessive-agency / system-prompt-leakage | did not land / UNKNOWN | — (pgv2 pre-empts; see test_coverage) |
| LiteLLM | ai2-unbounded-consumption | **DEFENDED** | litellm-client-revoke |
| LiteLLM | ai2-query-extraction | **DEFENDED** | litellm-client-revoke |

## Brain parameters per attack

Each per-attack card now records the brain's decision parameters, mapped to the
post-stable math spec:

- **One-step objective** (parsed from the decision trace): `strict gain`,
  `fullValue S`, `ECost`, `lambda`, `hazard`, `pHold`, `stage`, plus `value at risk`,
  `savings`, `covered facts`, `economics version`, and uptime before/dip/after.
  Example (vLLM poison): S=16.65, ECost=0.16, λ=0.04, pHold=0.82, strict gain=16.64,
  stage=prompt-inject-persist→lateral.
- **Decision identity & dispatch**: `decision action`, `selected`, `feasible`,
  `actuated`, `kill switch`, `trust`, `mutation`, `dispatch outcome`, `event rule`,
  `decisionId`, `tickId`, `policyUid`, `brain image`, `git sha` (and, for voice/litellm,
  the probe's `selected action`, `decisionId`, `dispatch path`).
- **Admissible-set evaluation (the Runtime Math Gate)**: the full candidate table —
  every action with its status (`selected` / `candidate` / `infeasible` / `not-enabled`
  / `no-cover` / `ineligible`) and the exclusion reason (e.g. `pdb: disruptionsAllowed=0`,
  `recon-cover: action invalidates no facts`).

Key parameters are also columns in the CSVs (`lambda`, `pHold`, `strictGain`,
`fullValue_S`, `ECost`, `hazard`, `stage`, `valueAtRisk`, `feasible`, `killSwitch`,
`decisionId`, `tickId`, `gitSha`, `candidatesEvaluated`, …).

The full objective math + 23-candidate trace is emitted by the vLLM decision attacks
(kvcache, poison, endpoint-rotate, model-shard-replace, warm-swap) in both modes; the
voice/LiteLLM attacks carry their decision in their probe (selected action + decision
id + dispatch path); endpoint-lease (PROTECTED) revalidates a prior decision and raises
no new one; footholds record a manager disposition only.

## Honest findings

- Parallel cuts total wall-clock ~2.5×, bounded by the slowest **app chain** (vLLM),
  not the slowest single attack.
- Served-model attacks (vLLM/Voice/LiteLLM) contend for the same vLLM backend, so a
  few run slower under concurrency; outcomes were otherwise stable across modes.
- Voice agency/output/mcp do not land because the pgv2 guardrail pre-empts the
  injection or the model declines — the guardrail working, not a Phorvex failure
  (full diagnosis in `test_coverage/`).
- The `crm` foothold is rejected in both modes (Console identity lacks the `crm`
  tenant grant).

## Reproduce

`benchmark_runner.py <serial|parallel> <out.jsonl>` runs on the jump host over one
self-healing shared Console port-forward (independent per-fire port-forwards
collide and invalidate a naive parallel run). `make_bench_report.py <in.jsonl>
<mode> <out_dir>` renders the HTML + CSV.
