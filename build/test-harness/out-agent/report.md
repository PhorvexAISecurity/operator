# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ai1-model-theft-agent | R6Claimed | R6Partial | d-nomtd | 2 | 0% [0,0] | 100% | 13.1 [13.0,13.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-escape-persist-agent | R6Claimed | R6Partial | d-nomtd | 2 | 0% [0,0] | 100% | 13.0 [12.9,13.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft-agent | R6Claimed | R6Partial | d-nomtd | 2 | 0% [0,0] | 100% | 13.2 [13.1,13.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **ai1-model-theft-agent** [R6Partial]: ai1-model-theft-agent [ai]: attacker foothold retained past the defender's response = true
- **c1-escape-persist-agent** [R6Partial]: c1-escape-persist-agent [k8s]: attacker foothold retained past the defender's response = true
- **c3-imds-theft-agent** [R6Partial]: c3-imds-theft-agent [k8s]: attacker foothold retained past the defender's response = true

Every number above traces to a raw log + command via provenance.json.
