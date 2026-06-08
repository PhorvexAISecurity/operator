# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| b-recon-lifetime | ClassicChain | R6Partial | d-blind-12s | 21 | 100% [100,100] | 0% | 12.2 [12.2,12.2] | 12.0 [12.0,12.0] | 1.00 | 0.75 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-blind-30s | 21 | 0% [0,0] | 100% | 20.2 [20.2,20.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-blind-3s | 21 | 100% [100,100] | 0% | 3.1 [3.1,3.1] | 3.0 [3.0,3.0] | 1.00 | 0.75 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-blind-60s | 21 | 0% [0,0] | 100% | 20.2 [20.2,20.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-blind-6s | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-blind-9s | 21 | 100% [100,100] | 0% | 9.1 [9.1,9.1] | 9.0 [9.0,9.0] | 1.00 | 0.75 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 20.2 [20.2,20.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-phorvex | 21 | 100% [100,100] | 0% | 5.1 [5.1,5.2] | 5.0 [4.9,5.1] | 1.00 | 0.75 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 15.2 [15.2,15.2] | 15.0 [15.0,15.0] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-blind-12s | 21 | 100% [100,100] | 0% | 12.5 [12.4,12.5] | 12.0 [12.0,12.0] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-blind-30s | 21 | 0% [0,0] | 100% | 20.3 [20.3,20.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-blind-3s | 21 | 100% [100,100] | 0% | 3.5 [3.4,3.5] | 2.9 [2.6,3.2] | 1.00 | 0.76 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-blind-60s | 21 | 0% [0,0] | 100% | 20.3 [20.3,20.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-blind-6s | 21 | 100% [100,100] | 0% | 6.3 [6.3,6.3] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-blind-9s | 21 | 100% [100,100] | 0% | 9.1 [9.0,9.1] | 7.7 [6.2,9.2] | 1.00 | 0.79 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 20.4 [20.3,20.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-phorvex | 21 | 100% [100,100] | 0% | 5.1 [5.1,5.1] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-r6blindtimer | 21 | 100% [100,100] | 0% | 15.2 [15.2,15.3] | 15.0 [15.0,15.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-blind-12s | 21 | 100% [100,100] | 0% | 13.8 [13.6,14.0] | 12.0 [12.0,12.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-blind-30s | 21 | 0% [0,0] | 100% | 20.5 [20.3,20.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-blind-3s | 21 | 100% [100,100] | 0% | 4.7 [4.5,4.9] | 3.1 [3.0,3.2] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-blind-60s | 21 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-blind-6s | 21 | 100% [100,100] | 0% | 7.8 [7.6,7.9] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-blind-9s | 21 | 100% [100,100] | 0% | 10.9 [10.7,11.0] | 9.0 [9.0,9.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 20.5 [20.3,20.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-phorvex | 21 | 100% [100,100] | 0% | 46.0 [45.9,46.0] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 16.8 [16.6,17.0] | 15.0 [15.0,15.0] | 1.00 | 0.75 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-blind-12s | 21 | 100% [100,100] | 0% | 12.4 [12.4,12.4] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-blind-30s | 21 | 0% [0,0] | 100% | 20.2 [20.2,20.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-blind-3s | 21 | 100% [100,100] | 0% | 3.1 [3.1,3.1] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-blind-60s | 21 | 0% [0,0] | 100% | 20.2 [20.2,20.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-blind-6s | 21 | 100% [100,100] | 0% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-blind-9s | 21 | 100% [100,100] | 0% | 9.4 [9.3,9.4] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 20.3 [20.2,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-phorvex | 21 | 33% [11,55] | 67% | 19.2 [18.6,19.9] | 7.1 [4.7,9.4] | 0.07 | 0.33 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 15.4 [15.4,15.4] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **b-recon-lifetime** [R6Partial]: recon-validity: identity 0b75d0e1 stayed usable 20.2s [recon-valid=20.2s] [recon-invalidated=false] [recon-lifetime=true]
- **c1-heldout-cve** [R6CannotRespond]: held-out CVE foothold (no detector event) [survival=20.3s] [evicted=false] detection-free-eviction=false [zero-day=true]
- **c2-stateful-training** [R6Partial]: stateful training job: foothold-alive=true [survival=20.3s] [evicted=false] [work-preserved=true] [harm=none] [arm-action=none] [infeasible-rotate=false] [feasible-alt=false] [lead-demo=true]
- **e-dilution-n9** [R6Partial]: dilution fleet N=9: at-risk recon valid 20.2s [recon-valid=20.2s] [recon-invalidated=false] [fleet-size=9] [dilution=true]

Every number above traces to a raw log + command via provenance.json.
