# Phoenix / Phorvex -- Dollars, Schwartau & Attack-Reusability View

Pure post-processing over the SAME extended Metric schema (ZERO re-execution). ROI($) is recomputed from the swappable knobs; Schwartau P = the arm's rotation interval, D/R = measured time-to-action; attack-reusability anchors replay-success to the static baseline.

## Swappable $ inputs (clearly-labeled defaults)

- **gpuCount** = 8 (a single DGX-class node)
- **dollarsPerGpuHour** = $2.50 (cloud H100-class list-ish placeholder; SWAP for your contract rate)
- **gpuOverheadPercent** = 0.015 (midpoint of R6's stated 1-2% overhead)
- **avoidedBreachValueDollars** = $4880000 (industry-avg breach-cost placeholder; SWAP)
- **horizonYears** = 1.0
- Derived **GPU-overhead $/yr saved** = gpuCount*$/hr*8760*overhead = **$2628**

## Per-arm dollars / Schwartau / reusability

| Scenario | Defender | Disrupt% | MTDEffect | Trigger | SecPerCost($) | DefenseCost$/yr | Schwartau P/D/R (s) | P>D+R | Replay succ | ReuseRedux% | CapPending |
|---|---|---|---|---|---|---|---|---|---|---|---|
| b-recon-lifetime | d-blind-12s | 100% | - | - | $585600 | $8 | 12/12.0/12.0 | false | 0 | 0% | false |
| b-recon-lifetime | d-blind-30s | 0% | - | - | $0 | $8 | 30/0.0/0.0 | true | 0 | 0% | false |
| b-recon-lifetime | d-blind-3s | 100% | - | - | $585600 | $8 | 3/3.0/3.0 | false | 0 | 0% | false |
| b-recon-lifetime | d-blind-60s | 0% | - | - | $0 | $8 | 60/0.0/0.0 | true | 0 | 0% | false |
| b-recon-lifetime | d-blind-6s | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| b-recon-lifetime | d-blind-9s | 100% | - | - | $585600 | $8 | 9/9.0/9.0 | false | 0 | 0% | false |
| b-recon-lifetime | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| b-recon-lifetime | d-phorvex | 100% | - | - | $585600 | $8 | 0/5.0/5.0 | false | 0 | 0% | false |
| b-recon-lifetime | d-r6blindtimer | 100% | - | - | $585600 | $8 | 15/15.0/15.0 | false | 0 | 0% | false |
| c1-heldout-cve | d-blind-12s | 100% | - | MISSING-TRIGGER:detector-absent | $585600 | $8 | 12/ABSENT/12.0 | false | 0 | 0% | false |
| c1-heldout-cve | d-blind-30s | 0% | - | MISSING-TRIGGER:detector-absent | $0 | $8 | 30/ABSENT/0.0 | false | 0 | 0% | false |
| c1-heldout-cve | d-blind-3s | 100% | - | MISSING-TRIGGER:detector-absent | $585600 | $8 | 3/ABSENT/2.9 | false | 0 | 0% | false |
| c1-heldout-cve | d-blind-60s | 0% | - | MISSING-TRIGGER:detector-absent | $0 | $8 | 60/ABSENT/0.0 | false | 0 | 0% | false |
| c1-heldout-cve | d-blind-6s | 100% | - | MISSING-TRIGGER:detector-absent | $585600 | $8 | 6/ABSENT/6.0 | false | 0 | 0% | false |
| c1-heldout-cve | d-blind-9s | 100% | - | MISSING-TRIGGER:detector-absent | $585600 | $8 | 9/ABSENT/7.7 | false | 0 | 0% | false |
| c1-heldout-cve | d-nomtd | 0% | - | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| c1-heldout-cve | d-phorvex | 100% | - | MISSING-TRIGGER:detector-absent | $585600 | $8 | 0/ABSENT/5.0 | false | 0 | 0% | false |
| c1-heldout-cve | d-r6blindtimer | 100% | - | MISSING-TRIGGER:detector-absent | $585600 | $8 | 15/ABSENT/15.0 | false | 0 | 0% | false |
| c2-stateful-training | d-blind-12s | 100% | - | - | $585600 | $8 | 12/12.0/12.0 | false | 0 | 0% | false |
| c2-stateful-training | d-blind-30s | 0% | - | - | $0 | $8 | 30/0.0/0.0 | true | 0 | 0% | false |
| c2-stateful-training | d-blind-3s | 100% | - | - | $585600 | $8 | 3/3.1/3.1 | false | 0 | 0% | false |
| c2-stateful-training | d-blind-60s | 0% | - | - | $0 | $8 | 60/0.0/0.0 | true | 0 | 0% | false |
| c2-stateful-training | d-blind-6s | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c2-stateful-training | d-blind-9s | 100% | - | - | $585600 | $8 | 9/9.0/9.0 | false | 0 | 0% | false |
| c2-stateful-training | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-stateful-training | d-phorvex | 100% | - | - | $585600 | $8 | 0/5.0/5.0 | false | 0 | 0% | false |
| c2-stateful-training | d-r6blindtimer | 100% | - | - | $585600 | $8 | 15/15.0/15.0 | false | 0 | 0% | false |
| e-dilution-n9 | d-blind-12s | 100% | - | - | $610000 | $8 | 12/0.0/0.0 | true | 0 | 0% | false |
| e-dilution-n9 | d-blind-30s | 0% | - | - | $0 | $8 | 30/0.0/0.0 | true | 0 | 0% | false |
| e-dilution-n9 | d-blind-3s | 100% | - | - | $610000 | $8 | 3/0.0/0.0 | true | 0 | 0% | false |
| e-dilution-n9 | d-blind-60s | 0% | - | - | $0 | $8 | 60/0.0/0.0 | true | 0 | 0% | false |
| e-dilution-n9 | d-blind-6s | 100% | - | - | $610000 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| e-dilution-n9 | d-blind-9s | 100% | - | - | $610000 | $8 | 9/0.0/0.0 | true | 0 | 0% | false |
| e-dilution-n9 | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| e-dilution-n9 | d-phorvex | 33% | - | - | $168276 | $10 | 0/7.1/7.1 | false | 0 | 0% | false |
| e-dilution-n9 | d-r6blindtimer | 100% | - | - | $610000 | $8 | 15/0.0/0.0 | true | 0 | 0% | false |

## Hypotheses H1 / H2 / H3 (PHORVEX Part 9 -- defined transparently from the rotation-vs-static thesis; no pre-registered doc exists in the repo)

- **H1 (Dwell-bound)**: rotating arms' mean persistence-disruption = 100% (95% CI [100, 100]) vs static 0%. PASS iff CI lower-bound > 0 -> **PASS**.
- **H2 (In-request invariance)**: 1/4 rotating-arm rows are attributed detector-absent/receiver-only (MTD-CANNOT-HELP in-request). PASS iff in-request disruption brackets 0 AND attribution is detector-absent/receiver-only/capability-pending -> **PASS** (the honest negative the AI-MTD-AUDIT predicts).
- **H3 (Trigger-gated neutralization + reuse)**: for trigger-supplied scenarios, d-fullphoenix persistence-disruption = 0% (CI [0, 0]); rotating-arm reuse-reduction mean = 0%. PASS iff fullphoenix CI>0 AND reuse-reduction>0 -> **FAIL**.

**Phorvex column (d-phorvex-slot): TO-BE-FILLED** -- the slot arm currently skips-with-note; the real Phorvex defender drops in later as one file and these H1/H2/H3 rows fill its comparison column with zero harness changes.

Every number above is recomputed from the raw metrics (DisruptionVsOracle, TimeToActionSeconds, DefensiveActions) + the swappable $ knobs -- no re-run.
