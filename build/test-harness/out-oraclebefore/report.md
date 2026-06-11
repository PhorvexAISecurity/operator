# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ai1-inference-manipulation | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-inference-manipulation | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.1 [6.1,6.2] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai1-llm-jacking | R6Claimed | R6Partial | d-nomtd | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai1-llm-jacking | R6Claimed | R6Partial | d-phorvex | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai1-model-theft | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-model-theft | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai1-pillar03-panic-mutation | R6Claimed | R6Covers | d-nomtd | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai1-pillar03-panic-mutation | R6Claimed | R6Covers | d-phorvex | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai1-prompt-injection | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-prompt-injection | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai2-agent-excessive-agency | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-excessive-agency | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai2-agent-memory-contamination | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-memory-contamination | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.0 [6.0,6.1] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 4.0 [4.0,4.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-phorvex | 3 | 0% [0,0] | 100% | 4.0 [4.0,4.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-co-location-cross-tenant | ModernUnsupported | R6Partial | d-nomtd | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai2-co-location-cross-tenant | ModernUnsupported | R6Partial | d-phorvex | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-phorvex | 3 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-store-tampering | ModernUnsupported | R6CannotRespond | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-store-tampering | ModernUnsupported | R6CannotRespond | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-vector-weakness | ModernUnsupported | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-vector-weakness | ModernUnsupported | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-excessive-agency | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-excessive-agency | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai2-gpu-side-channel | ModernUnsupported | R6CannotRespond | d-nomtd | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai2-gpu-side-channel | ModernUnsupported | R6CannotRespond | d-phorvex | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai2-kvcache-poisoning-cross-session-leak | ModernUnsupported | R6CannotRespond | d-nomtd | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai2-kvcache-poisoning-cross-session-leak | ModernUnsupported | R6CannotRespond | d-phorvex | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-phorvex | 3 | 100% [100,100] | 0% | 47.7 [42.0,53.4] | 27.7 [12.5,42.8] | 0.12 | 0.00 | 0 |
| ai2-mcp-rogue-server | ModernUnsupported | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-rogue-server | ModernUnsupported | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 5.3 [3.9,6.8] | 0.00 | 0.75 | 0 |
| ai2-mcp-tool-poisoning | ModernUnsupported | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-tool-poisoning | ModernUnsupported | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai2-mcp-tool-response-injection | ModernUnsupported | R6CannotRespond | d-nomtd | 3 | 0% [0,0] | 100% | 6.1 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-tool-response-injection | ModernUnsupported | R6CannotRespond | d-phorvex | 3 | 0% [0,0] | 100% | 6.7 [4.2,9.3] | 2.3 [0.9,3.8] | 0.00 | 0.50 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-nomtd | 3 | 0% [0,0] | 100% | 4.2 [4.1,4.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-phorvex | 3 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-query-extraction | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.1 [6.0,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-query-extraction | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.0 [6.0,6.1] | 1.7 [-5.5,8.8] | 0.00 | 0.92 | 0 |
| ai2-rag-retrieval-poisoning | ModernUnsupported | R6CannotRespond | d-nomtd | 1 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-rag-retrieval-poisoning | ModernUnsupported | R6CannotRespond | d-phorvex | 2 | 0% [0,0] | 100% | 6.2 [6.2,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-sensitive-info-disclosure | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-sensitive-info-disclosure | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai2-system-prompt-leakage | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-system-prompt-leakage | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.2 [6.1,6.2] | 5.0 [5.0,5.0] | 0.00 | 0.75 | 0 |
| ai2-tampered-inference-base-image | ModernUnsupported | R6Partial | d-nomtd | 3 | 0% [0,0] | 100% | 7.8 [6.3,9.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-tampered-inference-base-image | ModernUnsupported | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 8.1 [8.1,8.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-unbounded-consumption | R6Claimed | R6Partial | d-nomtd | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |
| ai2-unbounded-consumption | R6Claimed | R6Partial | d-phorvex | - | SKIP: cluster lacks required capabilities [Cap... | - | - | - | - | - | - |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## AI split-oracle & MEASURED MTD-effect (Pass-B)

MTDEffect is MEASURED per arm from the oracle + persistence outcome (never assumed). Trigger attribution carries the audit honesty so a missing-trigger result is not read as a Phoenix failure. See report-dollars.md for ROI($)/Schwartau/reusability + H1/H2/H3.

| Scenario | Defender | SplitOracle | MTDEffect | TriggerAttribution | CapPending |
|---|---|---|---|---|---|
| ai1-inference-manipulation | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-inference-manipulation | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-model-theft | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-model-theft | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-prompt-injection | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-prompt-injection | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-excessive-agency | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-excessive-agency | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-injection-to-persistence | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-injection-to-persistence | d-phorvex | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-memory-contamination | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-memory-contamination | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-rogue-tool-persistence | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-rogue-tool-persistence | d-phorvex | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-data-model-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-data-model-poisoning | d-phorvex | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-embedding-store-tampering | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-store-tampering | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-vector-weakness | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-vector-weakness | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-excessive-agency | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-excessive-agency | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-malicious-model-artifact | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-malicious-model-artifact | d-phorvex | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-mcp-rogue-server | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-rogue-server | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-poisoning | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-response-injection | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-response-injection | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-poisoned-model-registry | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-poisoned-model-registry | d-phorvex | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-query-extraction | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-query-extraction | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-rag-retrieval-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-rag-retrieval-poisoning | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-sensitive-info-disclosure | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-sensitive-info-disclosure | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-system-prompt-leakage | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-system-prompt-leakage | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-tampered-inference-base-image | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-tampered-inference-base-image | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |

## Honest R6 grounding

- **ai1-inference-manipulation** [R6Partial]: in-request output tampered=true; static path intercept-able after rotation=true (URL/path rotation absent)
- **ai1-llm-jacking** [R6Partial]: 
- **ai1-model-theft** [R6Partial]: extracted=true digest=sha256:r6thmockweights; external endpoint stable-after-rotation=true (audit #3 backend-only)
- **ai1-pillar03-panic-mutation** [R6Covers]: 
- **ai1-prompt-injection** [R6Partial]: in-request injection fired=true; session override survived rotation=true (rotation bounds session)
- **ai2-agent-excessive-agency** [R6Partial]: deputy action executed=true; deputy capability survived rotation=true
- **ai2-agent-injection-to-persistence** [R6Covers]: injection planted persistence=true; backdoor evicted (gone=false, old UID replaced=false)
- **ai2-agent-memory-contamination** [R6Partial]: in-session contamination=true; crossed into new session after rotation=true
- **ai2-agent-rogue-tool-persistence** [R6Covers]: rogue tool registered+called=true; rogue tool survived regenerate=true
- **ai2-co-location-cross-tenant** [R6Partial]: 
- **ai2-data-model-poisoning** [R6Covers]: in-request poison loaded=true; served digest after drift=sha256:r6thpoisonedmodel golden-restored=false
- **ai2-embedding-store-tampering** [R6CannotRespond]: tampered vector returned=true; tampered vector survived rotation=true (data-plane store)
- **ai2-embedding-vector-weakness** [R6Partial]: in-request cross-context leak=true; tampered vector survived rotation=true (data-plane store outside pod rotation)
- **ai2-excessive-agency** [R6Partial]: over-privileged action executed=true; foothold survived rotation=true
- **ai2-gpu-side-channel** [R6CannotRespond]: 
- **ai2-kvcache-poisoning-cross-session-leak** [R6CannotRespond]: 
- **ai2-malicious-model-artifact** [R6Covers]: payload exec=true; loader foothold evicted (old UID replaced=false)
- **ai2-mcp-rogue-server** [R6Partial]: agent reached rogue server=true; rogue binding survived rotation=true
- **ai2-mcp-tool-poisoning** [R6Partial]: poisoned tool description executed=true; poisoned tool survived rotation=true
- **ai2-mcp-tool-response-injection** [R6CannotRespond]: injected response steered model=true; directive persisted in memory across rotation=true
- **ai2-poisoned-model-registry** [R6Covers]: poisoned model served=true; served digest after drift=sha256:r6thpoisonedmodel golden-restored=false (signing=provenance not benignity)
- **ai2-query-extraction** [R6Partial]: replica extracted=true (fidelity 8); held-session replays=3/3 after rotation
- **ai2-rag-retrieval-poisoning** [R6CannotRespond]: poisoned doc retrieved+acted=true; poisoned doc persisted in corpus after rotation=true (data-plane differentiator)
- **ai2-sensitive-info-disclosure** [R6Partial]: in-request disclosure=true; leaked secret replay-valid after rotation=true
- **ai2-system-prompt-leakage** [R6Partial]: in-request prompt leak=true; extracted credential replay-valid after rotation=true
- **ai2-tampered-inference-base-image** [R6Partial]: tampered layer ran=true; tamper re-appears after rotation=true (same ref re-pulled)
- **ai2-unbounded-consumption** [R6Partial]: 

Every number above traces to a raw log + command via provenance.json.
