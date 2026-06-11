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
| ai1-prompt-injection-apt | d-fullphoenix | 0% | - | - | $0 | $8 | 15/0.0/0.0 | true | 0 | 0% | false |
| ai1-prompt-injection-apt | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai1-prompt-injection-apt | d-phorvex | 100% | - | - | $585600 | $8 | 0/5.0/5.0 | false | 0 | 0% | false |
| ai1-prompt-injection-apt | d-r6blindtimer | 0% | - | - | $0 | $8 | 15/0.0/0.0 | true | 0 | 0% | false |
| ai1-prompt-injection-apt | d-randomequal | 33% | - | - | $203333 | $8 | 15/2.3/2.3 | true | 0 | 0% | false |
| ai1-prompt-injection-apt | d-reactive-only | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-escape-persist-apt | d-fullphoenix | 0% | - | - | $0 | $8 | 15/0.0/0.0 | true | 0 | 0% | false |
| c1-escape-persist-apt | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-escape-persist-apt | d-phorvex | 100% | - | - | $585600 | $8 | 0/5.0/5.0 | false | 0 | 0% | false |
| c1-escape-persist-apt | d-r6blindtimer | 0% | - | - | $0 | $8 | 15/0.0/0.0 | true | 0 | 0% | false |
| c1-escape-persist-apt | d-randomequal | 67% | - | - | $406667 | $8 | 15/0.7/0.7 | true | 0 | 0% | false |
| c1-escape-persist-apt | d-reactive-only | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-imds-theft-apt | d-fullphoenix | 0% | - | - | $0 | $8 | 15/0.0/0.0 | true | 0 | 0% | false |
| c3-imds-theft-apt | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-imds-theft-apt | d-phorvex | 100% | - | - | $585600 | $8 | 0/5.0/5.0 | false | 0 | 0% | false |
| c3-imds-theft-apt | d-r6blindtimer | 0% | - | - | $0 | $8 | 15/0.0/0.0 | true | 0 | 0% | false |
| c3-imds-theft-apt | d-randomequal | 0% | - | - | $0 | $8 | 15/0.0/0.0 | true | 0 | 0% | false |
| c3-imds-theft-apt | d-reactive-only | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |

## Hypotheses H1 / H2 / H3 (PHORVEX Part 9 -- defined transparently from the rotation-vs-static thesis; no pre-registered doc exists in the repo)

- **H1 (Dwell-bound)**: rotating arms' mean persistence-disruption = 11% (95% CI [0, 31]) vs static 0%. PASS iff CI lower-bound > 0 -> **FAIL**.
- **H2 (In-request invariance)**: 0/9 rotating-arm rows are attributed detector-absent/receiver-only (MTD-CANNOT-HELP in-request). PASS iff in-request disruption brackets 0 AND attribution is detector-absent/receiver-only/capability-pending -> **FAIL** (the honest negative the AI-MTD-AUDIT predicts).
- **H3 (Trigger-gated neutralization + reuse)**: for trigger-supplied scenarios, d-fullphoenix persistence-disruption = 0% (CI [0, 0]); rotating-arm reuse-reduction mean = 0%. PASS iff fullphoenix CI>0 AND reuse-reduction>0 -> **FAIL**.

**Phorvex column (d-phorvex-slot): TO-BE-FILLED** -- the slot arm currently skips-with-note; the real Phorvex defender drops in later as one file and these H1/H2/H3 rows fill its comparison column with zero harness changes.

Every number above is recomputed from the raw metrics (DisruptionVsOracle, TimeToActionSeconds, DefensiveActions) + the swappable $ knobs -- no re-run.
