# PHORVEXSEC-114 (PHVX-23) — item 3 and guard addendum

Updated: 2026-08-20 · Branch `fix/phvx-23-work-guard-calibration` · PR #55

This addendum records why item 3 changed from a relaxation request to direct measurement. The
complete current result, runtime matrix, raw artifacts, commands, and status semantics are in:

`reports/phvx-23-20260810/PHORVEXSEC-114-exact-optimality-report.md`

## Item 3

The ticket assumed brute force could not reach 76 assets. That assumption was caused by the old
flat 18-asset cap, not by the B=1 computation. Direct exact checks now complete at 76 assets for
B=1 and B=2. In the six-run 2026-08-20 matrix:

| case | P50 | P95=max | gap |
|---|---:|---:|---:|
| n=76, k=2, B=1 | 0.281ms | 0.836ms | 0 |
| n=76, k=2, B=2 | 16.698ms | 21.165ms | 0 |

The fixtures are deterministic synthetic workloads at production scale, not live-pod replays.

## Guard correction

The previous work estimate counted each candidate set as O(1) and continued descending the search
tree after B picks were already spent. It admitted measured overruns while claiming they were
inside a 500ms budget. Commit `a15bda9` scales estimated work by B and prunes the exhausted subtree;
an independent exhaustive search proves the prune is output-identical.

The active cap is `300_000`. Commit `47ee2ed` strengthens the earlier 1.5s CI ceiling with a normal-
build subprocess matrix whose expected production rows must complete inside the actual 500ms
ruling. A case with 1,640,774,404 estimated units is skipped in about 0.2–0.4ms; the same case with
the guard disabled is killed at the 500ms deadline and reports `timeout`.

Raw files:

- `exact-runtime-raw.csv`
- `exact-runtime-raw.jsonl`
- `exact-runtime-summary.csv`
- `exact-runtime-summary.json`
- `exact-runtime-manifest.json`

All live under `reports/phvx-23-20260810/exact-runtime-20260820/`. Non-completed rows omit numeric
ratio and gap; no skipped or timed-out check can be read as completed gap 0.
