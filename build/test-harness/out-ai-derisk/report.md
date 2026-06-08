# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ai1-prompt-injection | R6Claimed | R6Partial | d-nomtd | 2 | 0% [0,0] | 100% | 6.2 [5.9,6.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-nomtd | 2 | 0% [0,0] | 100% | 6.2 [6.1,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-tool-poisoning | ModernUnsupported | R6Partial | d-nomtd | 2 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-nomtd | 2 | 0% [0,0] | 100% | 4.2 [4.1,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-rag-retrieval-poisoning | ModernUnsupported | R6CannotRespond | d-nomtd | 2 | 0% [0,0] | 100% | 6.2 [6.1,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## AI split-oracle & MEASURED MTD-effect (Pass-B)

MTDEffect is MEASURED per arm from the oracle + persistence outcome (never assumed). Trigger attribution carries the audit honesty so a missing-trigger result is not read as a Phoenix failure. See report-dollars.md for ROI($)/Schwartau/reusability + H1/H2/H3.

| Scenario | Defender | SplitOracle | MTDEffect | TriggerAttribution | CapPending |
|---|---|---|---|---|---|
| ai1-prompt-injection | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-injection-to-persistence | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-mcp-tool-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-poisoned-model-registry | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-rag-retrieval-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |

## Honest R6 grounding

- **ai1-prompt-injection** [R6Partial]: in-request injection fired=true; session override survived rotation=true (rotation bounds session)
- **ai2-agent-injection-to-persistence** [R6Covers]: injection planted persistence=true; backdoor evicted (gone=false, old UID replaced=false)
- **ai2-mcp-tool-poisoning** [R6Partial]: poisoned tool description executed=true; poisoned tool survived rotation=true
- **ai2-poisoned-model-registry** [R6Covers]: poisoned model served=true; served digest after drift=sha256:r6thpoisonedmodel golden-restored=false (signing=provenance not benignity)
- **ai2-rag-retrieval-poisoning** [R6CannotRespond]: poisoned doc retrieved+acted=true; poisoned doc persisted in corpus after rotation=true (data-plane differentiator)

Every number above traces to a raw log + command via provenance.json.
