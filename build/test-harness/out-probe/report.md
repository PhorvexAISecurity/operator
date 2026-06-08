# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| c2-persistence-evict | R6Claimed | R6Covers | d-fullphoenix | - | SKIP: kubectl apply CRDs failed: exit status 1... | - | - | - | - | - | - |
| c2-persistence-evict | R6Claimed | R6Covers | d-nomtd | 2 | 0% [0,0] | 100% | 6.2 [5.2,7.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c2-persistence-evict | R6Claimed | R6Covers | d-r6blindtimer | 2 | 100% [100,100] | 0% | 6.1 [6.0,6.2] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-randomequal | 2 | 50% [0,100] | 50% | 6.1 [6.0,6.3] | 1.0 [-11.7,13.7] | 0.50 | 0.88 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **c2-persistence-evict** [R6Covers]: post-detection: backdoor alive=true, old pod replaced=false

Every number above traces to a raw log + command via provenance.json.
