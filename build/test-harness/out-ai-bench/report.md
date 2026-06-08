# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ai1-inference-manipulation | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-inference-manipulation | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-inference-manipulation | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai1-inference-manipulation | R6Claimed | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 6.0 [6.0,6.0] | 0.00 | 0.75 | 0 |
| ai1-inference-manipulation | R6Claimed | R6Partial | d-randomequal | 21 | 0% [0,0] | 100% | 6.2 [6.1,6.3] | 1.9 [1.0,2.8] | 0.00 | 0.76 | 0 |
| ai1-model-theft | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-model-theft | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-model-theft | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai1-model-theft | R6Claimed | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-model-theft | R6Claimed | R6Partial | d-randomequal | 21 | 0% [0,0] | 100% | 6.0 [6.0,6.1] | 1.7 [0.8,2.6] | 0.00 | 0.80 | 0 |
| ai1-prompt-injection | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-prompt-injection | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-prompt-injection | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai1-prompt-injection | R6Claimed | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| ai1-prompt-injection | R6Claimed | R6Partial | d-randomequal | 21 | 52% [29,76] | 48% | 6.2 [6.1,6.3] | 1.4 [0.6,2.2] | 0.37 | 0.79 | 0 |
| ai2-agent-excessive-agency | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-excessive-agency | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-excessive-agency | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-agent-excessive-agency | R6Claimed | R6Partial | d-r6blindtimer | 21 | 95% [85,100] | 5% | 6.2 [6.1,6.3] | 5.7 [5.1,6.3] | 0.95 | 0.76 | 0 |
| ai2-agent-excessive-agency | R6Claimed | R6Partial | d-randomequal | 21 | 62% [39,85] | 38% | 6.2 [6.1,6.3] | 1.4 [0.6,2.2] | 0.52 | 0.79 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [-0.1,0.1] | 0.00 | 0.75 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.2 [6.1,6.2] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| ai2-agent-injection-to-persistence | R6Claimed | R6Covers | d-randomequal | 21 | 67% [45,89] | 33% | 6.2 [6.1,6.2] | 1.8 [1.0,2.7] | 0.46 | 0.71 | 0 |
| ai2-agent-memory-contamination | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-memory-contamination | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-memory-contamination | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-agent-memory-contamination | R6Claimed | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.0 [6.0,6.0] | 0.3 [-0.3,0.9] | 0.00 | 0.99 | 0 |
| ai2-agent-memory-contamination | R6Claimed | R6Partial | d-randomequal | 21 | 0% [0,0] | 100% | 6.0 [6.0,6.1] | 1.9 [1.1,2.7] | 0.00 | 0.75 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-fullphoenix | 21 | 100% [100,100] | 0% | 4.0 [4.0,4.0] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-nomtd | 21 | 0% [0,0] | 100% | 4.0 [4.0,4.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-r6blindtimer | 21 | 0% [0,0] | 100% | 4.0 [4.0,4.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-agent-rogue-tool-persistence | R6Claimed | R6Covers | d-randomequal | 21 | 0% [0,0] | 100% | 4.1 [4.0,4.1] | 0.9 [0.3,1.5] | 0.00 | 0.87 | 0 |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-fullphoenix | 21 | 100% [100,100] | 0% | 4.3 [4.3,4.3] | 0.1 [-0.0,0.3] | 1.00 | 0.75 | 0 |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-nomtd | 21 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-r6blindtimer | 21 | 0% [0,0] | 100% | 4.2 [4.2,4.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-data-model-poisoning | R6Claimed | R6Covers | d-randomequal | 21 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-store-tampering | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-store-tampering | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-store-tampering | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-embedding-store-tampering | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-store-tampering | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-vector-weakness | ModernUnsupported | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-vector-weakness | ModernUnsupported | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-vector-weakness | ModernUnsupported | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-embedding-vector-weakness | ModernUnsupported | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-embedding-vector-weakness | ModernUnsupported | R6Partial | d-randomequal | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-excessive-agency | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.3 [6.1,6.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-excessive-agency | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-excessive-agency | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-excessive-agency | R6Claimed | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| ai2-excessive-agency | R6Claimed | R6Partial | d-randomequal | 21 | 67% [45,89] | 33% | 6.2 [6.1,6.3] | 2.0 [1.0,2.9] | 0.57 | 0.79 | 0 |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-fullphoenix | 21 | 100% [100,100] | 0% | 6.0 [6.0,6.0] | 0.0 [0.0,0.0] | 1.00 | 0.75 | 0 |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-nomtd | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-r6blindtimer | 21 | 71% [50,93] | 29% | 6.0 [6.0,6.1] | 2.0 [0.7,3.3] | 0.71 | 0.92 | 0 |
| ai2-malicious-model-artifact | R6Claimed | R6Covers | d-randomequal | 21 | 67% [45,89] | 33% | 6.1 [6.0,6.1] | 1.9 [1.0,2.7] | 0.54 | 0.75 | 0 |
| ai2-mcp-rogue-server | ModernUnsupported | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-rogue-server | ModernUnsupported | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-rogue-server | ModernUnsupported | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-mcp-rogue-server | ModernUnsupported | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 6.0 [5.9,6.1] | 0.00 | 0.75 | 0 |
| ai2-mcp-rogue-server | ModernUnsupported | R6Partial | d-randomequal | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.2] | 2.0 [1.1,2.8] | 0.00 | 0.74 | 0 |
| ai2-mcp-tool-poisoning | ModernUnsupported | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-tool-poisoning | ModernUnsupported | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-tool-poisoning | ModernUnsupported | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-mcp-tool-poisoning | ModernUnsupported | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.2 [6.0,6.4] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| ai2-mcp-tool-poisoning | ModernUnsupported | R6Partial | d-randomequal | 21 | 67% [45,89] | 33% | 6.1 [6.1,6.2] | 1.6 [0.8,2.4] | 0.51 | 0.74 | 0 |
| ai2-mcp-tool-response-injection | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-tool-response-injection | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-mcp-tool-response-injection | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-mcp-tool-response-injection | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 0.00 | 0.75 | 0 |
| ai2-mcp-tool-response-injection | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 6.2 [6.1,6.3] | 1.7 [0.9,2.6] | 0.00 | 0.73 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-fullphoenix | 21 | 100% [100,100] | 0% | 4.2 [4.2,4.3] | 0.1 [-0.0,0.2] | 1.00 | 0.75 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-nomtd | 21 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-r6blindtimer | 21 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-poisoned-model-registry | R6Claimed | R6Covers | d-randomequal | 21 | 0% [0,0] | 100% | 4.2 [4.2,4.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-query-extraction | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-query-extraction | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-query-extraction | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-query-extraction | R6Claimed | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 5.4 [4.6,6.3] | 0.00 | 0.77 | 0 |
| ai2-query-extraction | R6Claimed | R6Partial | d-randomequal | 21 | 0% [0,0] | 100% | 6.1 [6.0,6.2] | 1.6 [0.8,2.5] | 0.00 | 0.77 | 0 |
| ai2-rag-retrieval-poisoning | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-rag-retrieval-poisoning | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-rag-retrieval-poisoning | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-rag-retrieval-poisoning | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-rag-retrieval-poisoning | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-sensitive-info-disclosure | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-sensitive-info-disclosure | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-sensitive-info-disclosure | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-sensitive-info-disclosure | R6Claimed | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| ai2-sensitive-info-disclosure | R6Claimed | R6Partial | d-randomequal | 21 | 57% [34,80] | 43% | 6.2 [6.1,6.2] | 1.8 [0.8,2.7] | 0.44 | 0.77 | 0 |
| ai2-system-prompt-leakage | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-system-prompt-leakage | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.1,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-system-prompt-leakage | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-system-prompt-leakage | R6Claimed | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| ai2-system-prompt-leakage | R6Claimed | R6Partial | d-randomequal | 21 | 71% [50,93] | 29% | 6.2 [6.1,6.3] | 2.2 [1.2,3.2] | 0.61 | 0.76 | 0 |
| ai2-tampered-inference-base-image | ModernUnsupported | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 7.9 [7.8,8.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-tampered-inference-base-image | ModernUnsupported | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 8.0 [7.8,8.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai2-tampered-inference-base-image | ModernUnsupported | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| ai2-tampered-inference-base-image | ModernUnsupported | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 8.0 [7.8,8.2] | 6.0 [6.0,6.0] | 0.00 | 0.75 | 0 |
| ai2-tampered-inference-base-image | ModernUnsupported | R6Partial | d-randomequal | 21 | 19% [1,37] | 81% | 27.5 [14.6,40.3] | 2.5 [1.5,3.4] | 0.08 | 0.57 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## AI split-oracle & MEASURED MTD-effect (Pass-B)

MTDEffect is MEASURED per arm from the oracle + persistence outcome (never assumed). Trigger attribution carries the audit honesty so a missing-trigger result is not read as a Phoenix failure. See report-dollars.md for ROI($)/Schwartau/reusability + H1/H2/H3.

| Scenario | Defender | SplitOracle | MTDEffect | TriggerAttribution | CapPending |
|---|---|---|---|---|---|
| ai1-inference-manipulation | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-inference-manipulation | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-inference-manipulation | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-inference-manipulation | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-model-theft | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-model-theft | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-model-theft | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-model-theft | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-prompt-injection | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-prompt-injection | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-prompt-injection | d-r6blindtimer | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai1-prompt-injection | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-excessive-agency | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-excessive-agency | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-excessive-agency | d-r6blindtimer | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-excessive-agency | d-randomequal | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-injection-to-persistence | d-fullphoenix | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-injection-to-persistence | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-injection-to-persistence | d-r6blindtimer | persistence | MTD-BOUNDS-ONLY | harness-injected | false |
| ai2-agent-injection-to-persistence | d-randomequal | persistence | MTD-BOUNDS-ONLY | harness-injected | false |
| ai2-agent-memory-contamination | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-memory-contamination | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-memory-contamination | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-memory-contamination | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-agent-rogue-tool-persistence | d-fullphoenix | persistence | MTD-NEUTRALIZES | harness-injected | false |
| ai2-agent-rogue-tool-persistence | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-rogue-tool-persistence | d-r6blindtimer | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-agent-rogue-tool-persistence | d-randomequal | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-data-model-poisoning | d-fullphoenix | persistence | MTD-NEUTRALIZES | harness-injected | false |
| ai2-data-model-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-data-model-poisoning | d-r6blindtimer | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-data-model-poisoning | d-randomequal | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-embedding-store-tampering | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-store-tampering | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-store-tampering | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-store-tampering | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-vector-weakness | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-vector-weakness | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-vector-weakness | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-embedding-vector-weakness | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-excessive-agency | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-excessive-agency | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-excessive-agency | d-r6blindtimer | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-excessive-agency | d-randomequal | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-malicious-model-artifact | d-fullphoenix | persistence | MTD-NEUTRALIZES | harness-injected | false |
| ai2-malicious-model-artifact | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-malicious-model-artifact | d-r6blindtimer | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-malicious-model-artifact | d-randomequal | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-mcp-rogue-server | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-rogue-server | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-rogue-server | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-rogue-server | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-poisoning | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-poisoning | d-r6blindtimer | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-poisoning | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-response-injection | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-response-injection | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-response-injection | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-mcp-tool-response-injection | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-poisoned-model-registry | d-fullphoenix | persistence | MTD-NEUTRALIZES | harness-injected | false |
| ai2-poisoned-model-registry | d-nomtd | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-poisoned-model-registry | d-r6blindtimer | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-poisoned-model-registry | d-randomequal | persistence | MTD-CANNOT-HELP | harness-injected | false |
| ai2-query-extraction | d-fullphoenix | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-query-extraction | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-query-extraction | d-r6blindtimer | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-query-extraction | d-randomequal | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-rag-retrieval-poisoning | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-rag-retrieval-poisoning | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-rag-retrieval-poisoning | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-rag-retrieval-poisoning | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-sensitive-info-disclosure | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-sensitive-info-disclosure | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-sensitive-info-disclosure | d-r6blindtimer | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-sensitive-info-disclosure | d-randomequal | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-system-prompt-leakage | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-system-prompt-leakage | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-system-prompt-leakage | d-r6blindtimer | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-system-prompt-leakage | d-randomequal | persistence | MTD-BOUNDS-ONLY | MISSING-TRIGGER:detector-absent | false |
| ai2-tampered-inference-base-image | d-fullphoenix | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-tampered-inference-base-image | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-tampered-inference-base-image | d-r6blindtimer | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai2-tampered-inference-base-image | d-randomequal | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |

## Honest R6 grounding

- **ai1-model-theft** [R6Partial]: extracted=true digest=sha256:r6thmockweights; external endpoint stable-after-rotation=true (audit #3 backend-only)
- **ai1-prompt-injection** [R6Partial]: in-request injection fired=true; session override survived rotation=true (rotation bounds session)
- **ai2-poisoned-model-registry** [R6Covers]: poisoned model served=true; served digest after drift=sha256:r6thpoisonedmodel golden-restored=false (signing=provenance not benignity)
- **ai2-query-extraction** [R6Partial]: replica extracted=true (fidelity 8); held-session replays=3/3 after rotation
- **ai1-inference-manipulation** [R6Partial]: in-request output tampered=true; static path intercept-able after rotation=true (URL/path rotation absent)
- **ai2-agent-excessive-agency** [R6Partial]: deputy action executed=true; deputy capability survived rotation=true
- **ai2-agent-injection-to-persistence** [R6Covers]: injection planted persistence=true; backdoor evicted (gone=false, old UID replaced=false)
- **ai2-agent-memory-contamination** [R6Partial]: in-session contamination=true; crossed into new session after rotation=true
- **ai2-agent-rogue-tool-persistence** [R6Covers]: rogue tool registered+called=true; rogue tool survived regenerate=true
- **ai2-data-model-poisoning** [R6Covers]: in-request poison loaded=true; served digest after drift=sha256:r6thpoisonedmodel golden-restored=false
- **ai2-embedding-store-tampering** [R6CannotRespond]: tampered vector returned=true; tampered vector survived rotation=true (data-plane store)
- **ai2-embedding-vector-weakness** [R6Partial]: in-request cross-context leak=true; tampered vector survived rotation=true (data-plane store outside pod rotation)
- **ai2-excessive-agency** [R6Partial]: over-privileged action executed=true; foothold survived rotation=true
- **ai2-malicious-model-artifact** [R6Covers]: payload exec=true; loader foothold evicted (old UID replaced=false)
- **ai2-mcp-rogue-server** [R6Partial]: agent reached rogue server=true; rogue binding survived rotation=true
- **ai2-mcp-tool-poisoning** [R6Partial]: poisoned tool description executed=true; poisoned tool survived rotation=true
- **ai2-mcp-tool-response-injection** [R6CannotRespond]: injected response steered model=true; directive persisted in memory across rotation=true
- **ai2-rag-retrieval-poisoning** [R6CannotRespond]: poisoned doc retrieved+acted=true; poisoned doc persisted in corpus after rotation=true (data-plane differentiator)
- **ai2-sensitive-info-disclosure** [R6Partial]: in-request disclosure=true; leaked secret replay-valid after rotation=true
- **ai2-system-prompt-leakage** [R6Partial]: in-request prompt leak=true; extracted credential replay-valid after rotation=true
- **ai2-tampered-inference-base-image** [R6Partial]: tampered layer ran=true; tamper re-appears after rotation=true (same ref re-pulled)

Every number above traces to a raw log + command via provenance.json.
