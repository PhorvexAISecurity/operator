# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ai1-model-theft | R6Claimed | R6Partial | d-fullphoenix | 2 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-model-theft | R6Claimed | R6Partial | d-nomtd | 2 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-fullphoenix | 2 | 100% [100,100] | 0% | 4.2 [4.1,4.4] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-nomtd | 2 | 0% [0,0] | 100% | 4.2 [4.1,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## AI split-oracle & MEASURED MTD-effect (Pass-B)

MTDEffect is MEASURED per arm from the oracle + persistence outcome (never assumed). Trigger attribution carries the audit honesty so a missing-trigger result is not read as a Phoenix failure. See report-dollars.md for ROI($)/Schwartau/reusability + H1/H2/H3.

| Scenario | Defender | SplitOracle | MTDEffect | TriggerAttribution | CapPending |
|---|---|---|---|---|---|
| ai1-model-theft | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-model-theft | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-poisoned-model-registry | d-fullphoenix | persistence | MTD-NEUTRALIZES | harness-injected | false |
| ai2-poisoned-model-registry | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |

## Honest R6 grounding

- **ai1-model-theft** [R6Partial]: extracted=true digest=sha256:r6thmockweights; external endpoint stable-after-rotation=true (audit #3 backend-only)
- **ai2-poisoned-model-registry** [R6Covers]: poisoned model served=true; served digest after drift=sha256:r6thpoisonedmodel golden-restored=false (signing=provenance not benignity)

Every number above traces to a raw log + command via provenance.json.
