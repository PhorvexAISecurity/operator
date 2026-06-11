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
| ai1-inference-manipulation | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 3 | 0% | false |
| ai1-inference-manipulation | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/5.0 | false | 3 | 0% | false |
| ai1-llm-jacking | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai1-llm-jacking | d-phorvex | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai1-model-theft | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 3 | 0% | false |
| ai1-model-theft | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/5.0 | false | 3 | 0% | false |
| ai1-pillar03-panic-mutation | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai1-pillar03-panic-mutation | d-phorvex | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai1-prompt-injection | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai1-prompt-injection | d-phorvex | 100% | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | $585600 | $8 | 0/ABSENT/5.2 | false | 0 | 0% | false |
| ai2-agent-excessive-agency | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-agent-excessive-agency | d-phorvex | 100% | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | $585600 | $8 | 0/ABSENT/5.0 | false | 0 | 0% | false |
| ai2-agent-injection-to-persistence | d-nomtd | 0% | MTD-CANNOT-HELP | harness-injected | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-agent-injection-to-persistence | d-phorvex | 100% | MTD-BOUNDS-ONLY | harness-injected | $585600 | $8 | 0/ABSENT/5.0 | false | 0 | 0% | false |
| ai2-agent-memory-contamination | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-agent-memory-contamination | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/5.0 | false | 0 | 0% | false |
| ai2-agent-rogue-tool-persistence | d-nomtd | 0% | MTD-CANNOT-HELP | harness-injected | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-agent-rogue-tool-persistence | d-phorvex | 0% | MTD-CANNOT-HELP | harness-injected | $0 | $8 | 0/ABSENT/0.5 | false | 0 | 0% | false |
| ai2-co-location-cross-tenant | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai2-co-location-cross-tenant | d-phorvex | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai2-data-model-poisoning | d-nomtd | 0% | MTD-CANNOT-HELP | harness-injected | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-data-model-poisoning | d-phorvex | 0% | MTD-CANNOT-HELP | harness-injected | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-embedding-store-tampering | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-embedding-store-tampering | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-embedding-vector-weakness | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-embedding-vector-weakness | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-excessive-agency | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-excessive-agency | d-phorvex | 100% | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | $585600 | $8 | 0/ABSENT/5.5 | false | 0 | 0% | false |
| ai2-gpu-side-channel | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai2-gpu-side-channel | d-phorvex | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai2-kvcache-poisoning-cross-session-leak | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai2-kvcache-poisoning-cross-session-leak | d-phorvex | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai2-malicious-model-artifact | d-nomtd | 0% | MTD-CANNOT-HELP | harness-injected | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-malicious-model-artifact | d-phorvex | 100% | MTD-BOUNDS-ONLY | harness-injected | $457500 | $11 | 0/ABSENT/14.0 | false | 0 | 0% | false |
| ai2-mcp-rogue-server | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 3 | 0% | false |
| ai2-mcp-rogue-server | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/5.0 | false | 3 | 0% | false |
| ai2-mcp-tool-poisoning | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-mcp-tool-poisoning | d-phorvex | 100% | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | $585600 | $8 | 0/ABSENT/5.0 | false | 0 | 0% | false |
| ai2-mcp-tool-response-injection | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-mcp-tool-response-injection | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $9 | 0/ABSENT/3.8 | false | 0 | 0% | false |
| ai2-poisoned-model-registry | d-nomtd | 0% | MTD-CANNOT-HELP | harness-injected | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-poisoned-model-registry | d-phorvex | 0% | MTD-CANNOT-HELP | harness-injected | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-query-extraction | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 3 | 0% | false |
| ai2-query-extraction | d-phorvex | 0% | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/5.0 | false | 1 | 67% | false |
| ai2-rag-retrieval-poisoning | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-rag-retrieval-poisoning | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-sensitive-info-disclosure | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 3 | 0% | false |
| ai2-sensitive-info-disclosure | d-phorvex | 100% | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | $585600 | $8 | 0/ABSENT/5.0 | false | 0 | 100% | false |
| ai2-system-prompt-leakage | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 3 | 0% | false |
| ai2-system-prompt-leakage | d-phorvex | 100% | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | $585600 | $8 | 0/ABSENT/5.0 | false | 0 | 100% | false |
| ai2-tampered-inference-base-image | d-nomtd | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-tampered-inference-base-image | d-phorvex | 0% | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | $0 | $8 | 0/ABSENT/0.0 | false | 0 | 0% | false |
| ai2-unbounded-consumption | d-nomtd | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |
| ai2-unbounded-consumption | d-phorvex | 0% | - | - | $0 | $8 | 0/0.0/0.0 | false | 0 | 0% | false |

## Hypotheses H1 / H2 / H3 (PHORVEX Part 9 -- defined transparently from the rotation-vs-static thesis; no pre-registered doc exists in the repo)

- **H1 (Dwell-bound)**: rotating arms' mean persistence-disruption = 0% (95% CI [0, 0]) vs static 0%. PASS iff CI lower-bound > 0 -> **FAIL**.
- **H2 (In-request invariance)**: 0/0 rotating-arm rows are attributed detector-absent/receiver-only (MTD-CANNOT-HELP in-request). PASS iff in-request disruption brackets 0 AND attribution is detector-absent/receiver-only/capability-pending -> **FAIL** (the honest negative the AI-MTD-AUDIT predicts).
- **H3 (Trigger-gated neutralization + reuse)**: for trigger-supplied scenarios, d-fullphoenix persistence-disruption = 0% (CI [0, 0]); rotating-arm reuse-reduction mean = 0%. PASS iff fullphoenix CI>0 AND reuse-reduction>0 -> **FAIL**.

**Phorvex column (d-phorvex-slot): TO-BE-FILLED** -- the slot arm currently skips-with-note; the real Phorvex defender drops in later as one file and these H1/H2/H3 rows fill its comparison column with zero harness changes.

Every number above is recomputed from the raw metrics (DisruptionVsOracle, TimeToActionSeconds, DefensiveActions) + the swappable $ knobs -- no re-run.
