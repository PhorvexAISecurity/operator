# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ai1-prompt-injection | R6Claimed | R6Partial | d-fullphoenix | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-prompt-injection | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-prompt-injection | R6Claimed | R6Partial | d-phorvex | 3 | 100% [100,100] | 0% | 6.1 [6.1,6.2] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-fullphoenix | 3 | 100% [100,100] | 0% | 6.1 [6.1,6.2] | 0.3 [-1.1,1.8] | 1.00 | 0.75 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-phorvex | 3 | 100% [100,100] | 0% | 6.1 [6.1,6.2] | 5.0 [5.0,5.0] | 1.00 | 0.75 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-fullphoenix | 3 | 100% [100,100] | 0% | 4.0 [4.0,4.0] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 4.0 [4.0,4.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-phorvex | 3 | 0% [0,0] | 100% | 4.0 [4.0,4.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-fullphoenix | 3 | 100% [100,100] | 0% | 4.2 [4.2,4.3] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-phorvex | 3 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-fullphoenix | 3 | 100% [100,100] | 0% | 46.3 [46.3,46.4] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 6.1 [6.0,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-phorvex | 3 | 100% [100,100] | 0% | 47.7 [41.9,53.4] | 14.3 [-0.8,29.5] | 0.12 | 0.00 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-fullphoenix | 3 | 100% [100,100] | 0% | 4.2 [4.1,4.3] | 0.3 [-1.1,1.8] | 1.00 | 0.75 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 4.2 [4.1,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-phorvex | 3 | 0% [0,0] | 100% | 4.2 [4.1,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## AI split-oracle & MEASURED MTD-effect (Pass-B)

MTDEffect is MEASURED per arm from the oracle + persistence outcome (never assumed). Trigger attribution carries the audit honesty so a missing-trigger result is not read as a Phoenix failure. See report-dollars.md for ROI($)/Schwartau/reusability + H1/H2/H3.

| Scenario | Defender | SplitOracle | MTDEffect | TriggerAttribution | CapPending |
|---|---|---|---|---|---|
| ai1-prompt-injection | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-prompt-injection | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-prompt-injection | d-phorvex | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-injection-to-persistence | d-fullphoenix | persistence | MTD-BOUNDS-ONLY | harness-injected | false |
| ai2-agent-injection-to-persistence | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-injection-to-persistence | d-phorvex | persistence | MTD-BOUNDS-ONLY | harness-injected | false |
| ai2-agent-rogue-tool-persistence | d-fullphoenix | persistence | MTD-BOUNDS-ONLY | harness-injected | false |
| ai2-agent-rogue-tool-persistence | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-rogue-tool-persistence | d-phorvex | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-data-model-poisoning | d-fullphoenix | persistence | MTD-NEUTRALIZES | harness-injected | false |
| ai2-data-model-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-data-model-poisoning | d-phorvex | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-malicious-model-artifact | d-fullphoenix | persistence | MTD-BOUNDS-ONLY | harness-injected | false |
| ai2-malicious-model-artifact | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-malicious-model-artifact | d-phorvex | persistence | MTD-BOUNDS-ONLY | harness-injected | false |
| ai2-poisoned-model-registry | d-fullphoenix | persistence | MTD-NEUTRALIZES | harness-injected | false |
| ai2-poisoned-model-registry | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-poisoned-model-registry | d-phorvex | persistence | MTD-CANNOT-HELP | harness-injected | false |

## Honest R6 grounding

- **ai1-prompt-injection** [R6Partial]: in-request injection fired=true; session override survived rotation=true (rotation bounds session)
- **ai2-agent-injection-to-persistence** [R6Covers]: injection planted persistence=true; backdoor evicted (gone=false, old UID replaced=false)
- **ai2-agent-rogue-tool-persistence** [R6Covers]: rogue tool registered+called=true; rogue tool survived regenerate=true
- **ai2-data-model-poisoning** [R6Covers]: in-request poison loaded=true; served digest after drift=sha256:r6thpoisonedmodel golden-restored=false
- **ai2-malicious-model-artifact** [R6Covers]: payload exec=true; loader foothold evicted (old UID replaced=false)
- **ai2-poisoned-model-registry** [R6Covers]: poisoned model served=true; served digest after drift=sha256:r6thpoisonedmodel golden-restored=false (signing=provenance not benignity)

Every number above traces to a raw log + command via provenance.json.
