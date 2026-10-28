# Live attack catalogue runner

This directory preserves the isolated-lane attack harness and its drop-in fire
specifications. It is operator tooling, not production controller code.

The pinned `catalog-192.txt` selection contains the 192 lane attacks requested
for strict end-to-end verification. The adjacent `fires.d` directory contains
207 specifications in total so the complete farm catalogue is not lost. The
15 newer config-object/controller-kind cases are intentionally outside the
192-run manifest.

## Verdict contract

An attack is counted as defended only when the structured evidence has both:

- `verdict: DEFENDED`, backed by the handler's selected + feasible + actuated
  decision and family-specific physical oracle; and
- `postflight_clean: true`.

Family equivalence or a successful event injection alone is not a passing
result. Failed evidence and stdout are retained per attempt.

## Validate and run

Run the static checks from the repository root:

```sh
python3 -m unittest tools/test_live_attack_catalog.py
python3 tools/live-attack-runner/run_catalog.py --dry-run
```

The live command must run only from the authorized farm host, where
`ssh phorvex-gw` reaches the dev EKS cluster and the isolated `p1`...`p6` lanes
exist:

```sh
python3 tools/live-attack-runner/run_catalog.py \
  --max-workers 4 \
  --attempts 1 \
  --output /home/ubuntu/phvx-farm/catalog-192-run
```

The output directory is resumable. Re-running the same command skips only cases
that already have strict defended evidence. `--max-workers` is capped at four
because that is the farm's verified CNI-safe concurrency ceiling.

Use `--only-lane p3` to repair/re-run a lane without disturbing completed
evidence. Never point this harness at production or at a shared staging
namespace; its mutation and cleanup contracts are designed for disposable
isolated lanes.

## Provenance

The imported runner SHA-256 before repository parameterization was
`622a09024556f7949f2f16f2057160fd5c2d9692ec986dc2e1e27acf48af5ffd`.
The source was the authorized Phorvex farm on 2026-10-28.
