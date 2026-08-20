# PHORVEXSEC-130 — 65-minute live shadow-calibration soak

Run date: 2026-08-20

PR: `PhorvexSecurity/operator#58`

Collector commit: `6894146` (`cmd/calib-soak`)

Integrated branch head before evidence commit: `99f30ef`

## Result

The read-only live collector completed a 65-minute PHVX-74 shadow run against EKS
`phorvex-dev-eks`. It exercised the 5, 15, 30 and 60-minute walk-forward candidates while
production scoring remained unchanged.

Final raw result:

- observation interval: `2026-08-20T16:25:37Z` through `2026-08-20T17:30:37Z` (`65m`);
- `1059` tenant-level optimizer comparisons across `369` decision
  timestamps;
- production-vs-shadow selection changes: `0`;
- availability violations: `0`;
- SLO violations: `0`;
- final fleet snapshot: `70` eligible assets on `5` nodes;
- measured co-residency P95 scale: `8`;
- measured joint dispersion P95 cap: `6.91242`;
- ready-delay outcomes: `0`, therefore the active reference correctly remained
  `400s`, `source=fallback_default`, reason `no eligible rotations`.

The final exporter snapshot was generated at `2026-08-20T17:27:17.762983974Z`; optimizer rows span
`2026-08-20T16:25:47.772012293Z` through `2026-08-20T17:27:07.763044829Z`.

No learned value entered the production decision path. The collector forced in-memory policy copies
to dry-run, engaged the static kill switch, and wrapped the Kubernetes client with a local write-deny
implementation. Its executable SHA-256 was
`0366f0bdc68e8c0eca60f0fc27daff70b7927ce5b1dcd627c822becc85faf0d0`.

## Cadence walk-forward result

| Candidate | Windows | Optimizer comparisons | Worst at-ceiling ratio | Max selection-change ratio | Availability/SLO violations | Clears all gates |
|---:|---:|---:|---:|---:|---:|---:|
| 5m | 12 | 1059 | 5.7143% | 0% | 0 / 0 | no |
| 15m | 4 | 880 | 5.7143% | 0% | 0 / 0 | no |
| 30m | 2 | 617 | 5.7143% | 0% | 0 / 0 | no |
| 60m | 1 | 82 | 5.7143% | 0% | 0 / 0 | no |

The cadence rows are strictly walk-forward: each scale is fitted from observations before the
boundary and evaluated afterward. `ClearsThreshold=false` is expected when a required validation
dimension has no observations; zero ready comparisons are not silently treated as a passing zero.

## Reproducibility

Cluster:

```text
AWS account: 753556437180
region: us-east-2
context: arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks
policies loaded: 4
```

Command configuration:

```text
calib-soak
  --duration=65m
  --sample=5m
  --refresh=5m
  --base-interval=10s
  --epss-cache=epss-cache-generated.json
  --out=out
```

Safety boundaries:

1. all loaded policy copies were forced to `ModeDryRun`;
2. `KillSwitch.Static=true` prevented actuation;
3. client `Create`, `Update`, `Delete`, `DeleteAllOf`, `Patch` and non-status subresource writes
   returned `errReadOnly` locally;
4. status writes were acknowledged and discarded locally;
5. the audit stream recorded `mode=dryRun`, `killSwitch=true` throughout.

The audit contained 1115 tick summaries and all 1115 carried those two safety fields. There was one
error at exactly `17:30:37Z`: the outer 65-minute context cancelled an ingest call during shutdown.
The process then completed the final export and exited successfully; no mid-run collector error or
actuation was recorded.

`go test ./...` passed on branch head `99f30ef` after merging current `main`. PR #58 retains reviewer
`hamihoriyat` and assignee `Milad93R`.

## Evidence files

The adjacent directory contains the unmodified final exporter outputs:

- `co-residency.csv/json`;
- `dispersion.csv/json`;
- `joint-percentile-sweep.csv/json`;
- `ready-delay.csv/json`;
- `optimizer-comparisons.csv/json`;
- `cadence-sweep.csv/json`;
- `evidence-manifest.json`; and
- `SHA256SUMS`.

## Honest remaining blocker

The run observed zero eligible rotations because production's kill switch was engaged and this tool
is intentionally incapable of actuation. Consequently the task's minimum of 100 eligible ready-delay
outcomes is not satisfied and no ready-delay percentile is identifiable.

Forcing 100 production rotations to manufacture this dataset would contradict the task's zero
availability/SLO-violation requirement. The collection path is no longer a manual implementation
gap: `cmd/calib-soak` is committed, and PR #58 wires the same runtime into the operator. The remaining
input requires PR #58 to be deployed and real eligible rotations to occur within the seven-day
lookback. Until then, `ReadyDelayReference=400s` with explicit fallback is the only valid result.
