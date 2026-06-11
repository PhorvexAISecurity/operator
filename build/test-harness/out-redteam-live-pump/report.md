# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| apt-lambda-pump-live | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 31.4 [28.0,34.8] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| apt-lambda-pump-live | R6Claimed | R6Covers | d-phorvex | 3 | 100% [100,100] | 0% | 72.3 [68.3,76.4] | 41.0 [-2.3,84.3] | 0.06 | 0.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **apt-lambda-pump-live** [R6Covers]: live actuation: footholdRotated=false backdoorAlive=true under 8 internal decoys

Every number above traces to a raw log + command via provenance.json.
