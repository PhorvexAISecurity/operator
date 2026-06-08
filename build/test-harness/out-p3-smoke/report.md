# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-fullphoenix | 2 | 0% [0,0] | 100% | 9.2 [8.5,9.9] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-nomtd | 2 | 0% [0,0] | 100% | 9.3 [9.0,9.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-phorvex | 2 | 100% [100,100] | 0% | 9.0 [8.6,9.5] | 2.5 [-29.3,34.3] | 1.00 | 0.88 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-r6blindtimer | 2 | 100% [100,100] | 0% | 9.1 [8.0,10.2] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-randomequal | 2 | 100% [100,100] | 0% | 9.2 [8.7,9.8] | 5.0 [-20.4,30.4] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-reactive-only | 2 | 0% [0,0] | 100% | 9.2 [9.1,9.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-fullphoenix | 2 | 0% [0,0] | 100% | 12.5 [12.3,12.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-nomtd | 2 | 0% [0,0] | 100% | 12.7 [10.6,14.8] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-phorvex | 2 | 100% [100,100] | 0% | 9.2 [-31.7,50.1] | 4.5 [-52.7,61.7] | 1.00 | 0.88 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-r6blindtimer | 2 | 100% [100,100] | 0% | 6.1 [4.9,7.3] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-randomequal | 2 | 100% [100,100] | 0% | 9.3 [-30.2,48.8] | 1.5 [-17.6,20.6] | 0.62 | 0.50 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-reactive-only | 2 | 0% [0,0] | 100% | 12.5 [12.1,12.8] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-fullphoenix | 2 | 0% [0,0] | 100% | 7.1 [7.1,7.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-nomtd | 2 | 0% [0,0] | 100% | 7.1 [7.0,7.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-phorvex | 2 | 100% [100,100] | 0% | 7.0 [6.6,7.5] | 2.5 [-29.3,34.3] | 1.00 | 0.88 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-r6blindtimer | 2 | 100% [100,100] | 0% | 7.1 [6.3,7.8] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-randomequal | 2 | 100% [100,100] | 0% | 7.1 [7.0,7.1] | 4.0 [-21.4,29.4] | 0.62 | 0.38 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-reactive-only | 2 | 0% [0,0] | 100% | 7.1 [6.8,7.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **c1-heldout-cve** [R6CannotRespond]: held-out CVE foothold alive=true (no detector event); detection-free eviction=false
- **c1-llm-adaptive** [R6Partial]: adaptive re-strike foothold alive=true (deterministic LLM-adversary timing into predicted lull)
- **c1-stealth-dweller** [R6Partial]: stealth dweller alive=true with 0 SecurityEvents (zero-detection survival=true)

Every number above traces to a raw log + command via provenance.json.
