# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ai1-prompt-injection-apt | R6Claimed | R6Partial | d-fullphoenix | 3 | 0% [0,0] | 100% | 10.2 [10.2,10.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-prompt-injection-apt | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 10.3 [10.2,10.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-prompt-injection-apt | R6Claimed | R6Partial | d-phorvex | 3 | 100% [100,100] | 0% | 5.1 [5.1,5.2] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| ai1-prompt-injection-apt | R6Claimed | R6Partial | d-r6blindtimer | 3 | 0% [0,0] | 100% | 10.2 [10.1,10.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-prompt-injection-apt | R6Claimed | R6Partial | d-randomequal | 3 | 33% [0,100] | 67% | 9.1 [4.3,13.8] | 2.3 [-7.7,12.4] | 0.33 | 0.92 | 0 |
| ai1-prompt-injection-apt | R6Claimed | R6Partial | d-reactive-only | 3 | 0% [0,0] | 100% | 10.2 [10.1,10.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-escape-persist-apt | R6Claimed | R6Partial | d-fullphoenix | 3 | 0% [0,0] | 100% | 10.3 [10.1,10.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-escape-persist-apt | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 10.2 [10.1,10.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-escape-persist-apt | R6Claimed | R6Partial | d-phorvex | 3 | 100% [100,100] | 0% | 5.1 [5.1,5.2] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c1-escape-persist-apt | R6Claimed | R6Partial | d-r6blindtimer | 3 | 0% [0,0] | 100% | 10.3 [10.2,10.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-escape-persist-apt | R6Claimed | R6Partial | d-randomequal | 3 | 67% [0,100] | 33% | 6.1 [-3.8,16.0] | 0.7 [-2.2,3.5] | 0.67 | 0.92 | 0 |
| c1-escape-persist-apt | R6Claimed | R6Partial | d-reactive-only | 3 | 0% [0,0] | 100% | 10.2 [10.1,10.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft-apt | R6Claimed | R6Partial | d-fullphoenix | 3 | 0% [0,0] | 100% | 10.2 [10.1,10.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft-apt | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 10.2 [10.1,10.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft-apt | R6Claimed | R6Partial | d-phorvex | 3 | 100% [100,100] | 0% | 5.1 [5.0,5.2] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| c3-imds-theft-apt | R6Claimed | R6Partial | d-r6blindtimer | 3 | 0% [0,0] | 100% | 10.2 [10.2,10.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft-apt | R6Claimed | R6Partial | d-randomequal | 3 | 0% [0,0] | 100% | 10.2 [10.1,10.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft-apt | R6Claimed | R6Partial | d-reactive-only | 3 | 0% [0,0] | 100% | 10.3 [9.9,10.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **ai1-prompt-injection-apt** [R6Partial]: realistic campaign "Indirect prompt-injection escalating to durable control (real RAG/agen" [ai]: foothold retained past defender response = true
- **c1-escape-persist-apt** [R6Partial]: realistic campaign "Container-breakout-to-host-persistence" [k8s]: foothold retained past defender response = true
- **c3-imds-theft-apt** [R6Partial]: realistic campaign "A Capital-One/ScarletEel-class IMDS-to-cloud-takeover" [both]: foothold retained past defender response = true

Every number above traces to a raw log + command via provenance.json.
