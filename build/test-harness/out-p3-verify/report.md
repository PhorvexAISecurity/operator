# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-fullphoenix | 1 | 0% [0,0] | 100% | 12.5 [12.5,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-nomtd | 1 | 0% [0,0] | 100% | 12.5 [12.5,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-phorvex | 1 | 100% [100,100] | 0% | 5.1 [5.1,5.1] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-r6blindtimer | 1 | 0% [0,0] | 100% | 12.4 [12.4,12.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-randomequal | 1 | 100% [100,100] | 0% | 7.9 [7.9,7.9] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| c1-fast-attacker | ClassicChain | R6CannotRespond | d-reactive-only | 1 | 0% [0,0] | 100% | 12.5 [12.5,12.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-fullphoenix | 1 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-nomtd | 1 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-phorvex | 1 | 100% [100,100] | 0% | 5.6 [5.6,5.6] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-r6blindtimer | - | SKIP: scenario setup failed: no running pod fo... | - | - | - | - | - | - |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-randomequal | 1 | 100% [100,100] | 0% | 9.0 [9.0,9.0] | 8.0 [8.0,8.0] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-reactive-only | 1 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-fullphoenix | 1 | 100% [100,100] | 0% | 25.9 [25.9,25.9] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-nomtd | 1 | 0% [0,0] | 100% | 20.2 [20.2,20.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-phorvex | 1 | 100% [100,100] | 0% | 30.9 [30.9,30.9] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-r6blindtimer | - | SKIP: scenario setup failed: no running pod fo... | - | - | - | - | - | - |
| c2-stateful-training | R6Claimed | R6Partial | d-randomequal | 1 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-reactive-only | 1 | 100% [100,100] | 0% | 25.9 [25.9,25.9] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **c1-fast-attacker** [R6CannotRespond]: fast attacker (objective 9s): [survival=12.4s] [evicted=false] [objective-achieved=true] [blind-too-late=true] [fast-attacker=true]
- **c1-heldout-cve** [R6CannotRespond]: held-out CVE foothold (no detector event) [survival=20.2s] [evicted=false] detection-free-eviction=false [zero-day=true]
- **c2-stateful-training** [R6Partial]: stateful training job: foothold-alive=true [survival=20.1s] [evicted=false] [work-preserved=true] [harm=none] [arm-action=none] [infeasible-rotate=false] [feasible-alt=false] [lead-demo=true]

Every number above traces to a raw log + command via provenance.json.
