# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| c2-stateful-training | R6Claimed | R6Partial | d-nomtd | 6 | 0% [0,0] | 100% | 20.4 [20.3,20.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-phorvex | 6 | 100% [100,100] | 0% | 20.4 [20.3,20.4] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| c2-stateful-training | R6Claimed | R6Partial | d-r6blindtimer | 6 | 100% [100,100] | 0% | 16.6 [16.2,17.1] | 15.0 [15.0,15.0] | 1.00 | 0.75 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **c2-stateful-training** [R6Partial]: stateful training job: foothold-alive=true [survival=20.4s] [evicted=false] [work-preserved=true] [harm=none] [arm-action=none] [infeasible-rotate=false] [feasible-alt=false] [lead-demo=true]

Every number above traces to a raw log + command via provenance.json.
