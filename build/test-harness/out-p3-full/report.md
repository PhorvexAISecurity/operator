# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 12.5 [12.4,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 12.5 [12.4,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-phorvex | 21 | 100% [100,100] | 0% | 5.2 [5.1,5.2] | 5.0 [4.9,5.1] | 1.00 | 0.75 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 12.5 [12.4,12.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-randomequal | 21 | 52% [29,76] | 48% | 7.7 [5.6,9.8] | 2.8 [1.3,4.4] | 0.52 | 0.85 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-reactive-only | 21 | 0% [0,0] | 100% | 12.5 [12.4,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 20.4 [20.4,20.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 20.4 [20.4,20.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-phorvex | 21 | 100% [100,100] | 0% | 5.6 [5.5,5.7] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-r6blindtimer | 21 | 100% [100,100] | 0% | 15.3 [15.2,15.3] | 15.0 [15.0,15.0] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-randomequal | 21 | 71% [50,93] | 29% | 12.1 [8.8,15.4] | 5.9 [3.1,8.7] | 0.71 | 0.82 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-reactive-only | 21 | 0% [0,0] | 100% | 20.4 [20.4,20.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 12.5 [12.5,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 12.4 [12.4,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-phorvex | 21 | 100% [100,100] | 0% | 52.7 [52.7,52.8] | 5.0 [4.9,5.1] | 1.00 | 0.75 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 12.5 [12.4,12.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-randomequal | 21 | 38% [15,61] | 62% | 12.9 [12.5,13.3] | 2.5 [0.8,4.1] | 0.25 | 0.80 | 0 |
| c1-llm-adaptive | ClassicChain | R6Partial | d-reactive-only | 21 | 0% [0,0] | 100% | 12.5 [12.4,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 20.3 [20.2,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-phorvex | 21 | 100% [100,100] | 0% | 5.7 [5.6,5.7] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 15.2 [15.2,15.2] | 15.0 [15.0,15.0] | 1.00 | 0.75 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-randomequal | 21 | 76% [56,96] | 24% | 11.2 [7.9,14.5] | 6.2 [3.4,9.1] | 0.76 | 0.81 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-reactive-only | 21 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-fullphoenix | 21 | 100% [100,100] | 0% | 46.4 [46.4,46.5] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-nomtd | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-phorvex | 21 | 90% [77,100] | 10% | 42.8 [37.7,48.0] | 5.0 [5.0,5.0] | 0.90 | 0.74 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-randomequal | 21 | 29% [7,50] | 71% | 6.1 [6.1,6.1] | 0.6 [0.1,1.1] | 0.26 | 0.92 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-reactive-only | 21 | 100% [100,100] | 0% | 46.4 [46.4,46.5] | 0.0 [-0.1,0.1] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-fullphoenix | 21 | 100% [100,100] | 0% | 41.0 [41.0,41.1] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-phorvex | 21 | 100% [100,100] | 0% | 46.0 [45.9,46.0] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 16.8 [16.7,17.0] | 15.0 [15.0,15.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-randomequal | 21 | 76% [56,96] | 24% | 13.0 [10.0,16.0] | 6.8 [3.8,9.7] | 0.74 | 0.80 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-reactive-only | 21 | 100% [100,100] | 0% | 41.0 [41.0,41.0] | 0.1 [-0.0,0.2] | 1.00 | 0.75 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **c1-fast-attacker** [R6CannotRespond]: fast attacker (objective 9s): [survival=12.4s] [evicted=false] [objective-achieved=true] [blind-too-late=true] [fast-attacker=true]
- **c1-heldout-cve** [R6CannotRespond]: held-out CVE foothold (no detector event) [survival=20.3s] [evicted=false] detection-free-eviction=false [zero-day=true]
- **c1-llm-adaptive** [R6Partial]: adaptive re-strike foothold alive=true (deterministic LLM-adversary timing into predicted lull)
- **c1-stealth-dweller** [R6Partial]: stealth dweller [survival=20.3s] [evicted=false] with 0 detection events (zero-detection survival=true) [stealth=true]
- **c2-persistence-evict** [R6Covers]: post-detection: backdoor alive=true, old pod replaced=false
- **c2-stateful-training** [R6Partial]: stateful training job: foothold-alive=true [survival=20.3s] [evicted=false] [work-preserved=true] [harm=none] [arm-action=none] [infeasible-rotate=false] [feasible-alt=false] [lead-demo=true]

Every number above traces to a raw log + command via provenance.json.
