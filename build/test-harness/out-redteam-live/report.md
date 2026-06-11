# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| apt-dispersion-steer-live | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 21.8 [20.4,23.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| apt-dispersion-steer-live | R6Claimed | R6Covers | d-phorvex | 3 | 100% [100,100] | 0% | 63.7 [58.6,68.8] | 46.3 [-10.2,102.8] | 0.07 | 0.00 | 0 |
| apt-dispersion-steer-live | R6Claimed | R6Covers | d-phorvex-vuln-steer | 3 | 100% [100,100] | 0% | 63.8 [58.5,69.1] | 38.3 [-11.7,88.4] | 0.07 | 0.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **apt-dispersion-steer-live** [R6Covers]: live actuation: footholdRotated=false backdoorAlive=true under 3 restricted decoys

Every number above traces to a raw log + command via provenance.json.
