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
| c1-c2-exfil | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-c2-exfil | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-c2-exfil | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-c2-exfil | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-c2-exfil | d-randomequal | 0% | - | - | $0 | $8 | 6/0.4/0.4 | true | 0 | 0% | false |
| c1-credtheft-rbac | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-credtheft-rbac | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-credtheft-rbac | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-credtheft-rbac | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-credtheft-rbac | d-randomequal | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-escape-persist | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-escape-persist | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-escape-persist | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-escape-persist | d-r6blindtimer | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c1-escape-persist | d-randomequal | 57% | - | - | $334629 | $8 | 6/1.3/1.3 | true | 0 | 0% | false |
| c1-lateral | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-lateral | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-lateral | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-lateral | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-lateral | d-randomequal | 0% | - | - | $0 | $8 | 6/0.9/0.9 | true | 0 | 0% | false |
| c1-stealth-dweller | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c1-stealth-dweller | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-stealth-dweller | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c1-stealth-dweller | d-r6blindtimer | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c1-stealth-dweller | d-randomequal | 71% | - | - | $418286 | $8 | 6/2.2/2.2 | true | 0 | 0% | false |
| c2-c2-disrupt | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c2-c2-disrupt | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-c2-disrupt | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-c2-disrupt | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c2-c2-disrupt | d-randomequal | 33% | - | - | $195200 | $8 | 6/2.3/2.3 | true | 0 | 0% | false |
| c2-dwell-rotation | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c2-dwell-rotation | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-dwell-rotation | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-dwell-rotation | d-r6blindtimer | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c2-dwell-rotation | d-randomequal | 81% | - | - | $455824 | $9 | 6/2.8/2.8 | true | 0 | 0% | false |
| c2-lateral-disrupt | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c2-lateral-disrupt | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-lateral-disrupt | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-lateral-disrupt | d-r6blindtimer | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c2-lateral-disrupt | d-randomequal | 52% | - | - | $306743 | $8 | 6/1.7/1.7 | true | 0 | 0% | false |
| c2-persistence-evict | d-fullphoenix | 100% | - | - | $585600 | $8 | 6/0.1/0.1 | true | 0 | 0% | false |
| c2-persistence-evict | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-persistence-evict | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-persistence-evict | d-r6blindtimer | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c2-persistence-evict | d-randomequal | 67% | - | - | $390400 | $8 | 6/2.0/2.0 | true | 0 | 0% | false |
| c2-recon-window | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c2-recon-window | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-recon-window | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-recon-window | d-r6blindtimer | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c2-recon-window | d-randomequal | 76% | - | - | $446171 | $8 | 6/2.7/2.7 | true | 0 | 0% | false |
| c2-supplychain-foothold | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c2-supplychain-foothold | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-supplychain-foothold | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c2-supplychain-foothold | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c2-supplychain-foothold | d-randomequal | 24% | - | - | $139429 | $8 | 6/2.2/2.2 | true | 0 | 0% | false |
| c3-admission-bypass | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-admission-bypass | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-admission-bypass | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-admission-bypass | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-admission-bypass | d-randomequal | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-cicd | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-cicd | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-cicd | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-cicd | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-cicd | d-randomequal | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-cryptomining | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-cryptomining | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-cryptomining | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-cryptomining | d-r6blindtimer | 100% | - | - | $585600 | $8 | 6/6.0/6.0 | false | 0 | 0% | false |
| c3-cryptomining | d-randomequal | 62% | - | - | $362514 | $8 | 6/2.4/2.4 | true | 0 | 0% | false |
| c3-imds-theft | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-imds-theft | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-imds-theft | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-imds-theft | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-imds-theft | d-randomequal | 24% | - | - | $145238 | $8 | 6/0.3/0.3 | true | 0 | 0% | false |
| c3-secrets-sprawl | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-secrets-sprawl | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-secrets-sprawl | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-secrets-sprawl | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-secrets-sprawl | d-randomequal | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-sidecar-inject | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-sidecar-inject | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-sidecar-inject | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-sidecar-inject | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-sidecar-inject | d-randomequal | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-supplychain | d-fullphoenix | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-supplychain | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-supplychain | d-phorvex-slot | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| c3-supplychain | d-r6blindtimer | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |
| c3-supplychain | d-randomequal | 0% | - | - | $0 | $8 | 6/0.0/0.0 | true | 0 | 0% | false |

## Hypotheses H1 / H2 / H3 (PHORVEX Part 9 -- defined transparently from the rotation-vs-static thesis; no pre-registered doc exists in the repo)

- **H1 (Dwell-bound)**: rotating arms' mean persistence-disruption = 25% (95% CI [14, 36]) vs static 0%. PASS iff CI lower-bound > 0 -> **PASS**.
- **H2 (In-request invariance)**: 0/54 rotating-arm rows are attributed detector-absent/receiver-only (MTD-CANNOT-HELP in-request). PASS iff in-request disruption brackets 0 AND attribution is detector-absent/receiver-only/capability-pending -> **FAIL** (the honest negative the AI-MTD-AUDIT predicts).
- **H3 (Trigger-gated neutralization + reuse)**: for trigger-supplied scenarios, d-fullphoenix persistence-disruption = 0% (CI [0, 0]); rotating-arm reuse-reduction mean = 0%. PASS iff fullphoenix CI>0 AND reuse-reduction>0 -> **FAIL**.

**Phorvex column (d-phorvex-slot): TO-BE-FILLED** -- the slot arm currently skips-with-note; the real Phorvex defender drops in later as one file and these H1/H2/H3 rows fill its comparison column with zero harness changes.

Every number above is recomputed from the raw metrics (DisruptionVsOracle, TimeToActionSeconds, DefensiveActions) + the swappable $ knobs -- no re-run.
