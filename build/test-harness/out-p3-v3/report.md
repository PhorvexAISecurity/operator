# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-nomtd | 1 | 0% [0,0] | 100% | 20.6 [20.6,20.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-phorvex | 1 | 100% [100,100] | 0% | 5.1 [5.1,5.1] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| c1-heldout-cve | ClassicChain | R6CannotRespond | d-r6blindtimer | 1 | 100% [100,100] | 0% | 15.3 [15.3,15.3] | 15.0 [15.0,15.0] | 1.00 | 0.75 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **c1-heldout-cve** [R6CannotRespond]: held-out CVE foothold (no detector event) [survival=20.5s] [evicted=false] detection-free-eviction=false [zero-day=true]

Every number above traces to a raw log + command via provenance.json.
