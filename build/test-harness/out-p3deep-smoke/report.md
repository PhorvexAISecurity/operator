# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| b-recon-lifetime | ClassicChain | R6Partial | d-blind-30s | 1 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-blind-6s | 1 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| b-recon-lifetime | ClassicChain | R6Partial | d-nomtd | 1 | 0% [0,0] | 100% | 20.3 [20.3,20.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-blind-30s | 1 | 0% [0,0] | 100% | 20.2 [20.2,20.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-blind-6s | 1 | 100% [100,100] | 0% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 1.00 | 1.00 | 0 |
| e-dilution-n9 | ClassicChain | R6Partial | d-nomtd | 1 | 0% [0,0] | 100% | 20.2 [20.2,20.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **b-recon-lifetime** [R6Partial]: recon-validity: identity 87e4226d stayed usable 20.2s [recon-valid=20.2s] [recon-invalidated=false] [recon-lifetime=true]
- **e-dilution-n9** [R6Partial]: dilution fleet N=9: at-risk recon valid 20.2s [recon-valid=20.2s] [recon-invalidated=false] [fleet-size=9] [dilution=true]

Every number above traces to a raw log + command via provenance.json.
