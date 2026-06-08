# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| c1-c2-exfil | ClassicChain | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 2.1 [2.1,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-c2-exfil | ClassicChain | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-c2-exfil | ClassicChain | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c1-c2-exfil | ClassicChain | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-c2-exfil | ClassicChain | R6Partial | d-randomequal | 21 | 0% [0,0] | 100% | 2.1 [2.1,2.1] | 0.4 [0.2,0.7] | 0.00 | 0.90 | 0 |
| c1-credtheft-rbac | ClassicChain | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 0.1 [0.1,0.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-credtheft-rbac | ClassicChain | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 0.1 [0.1,0.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-credtheft-rbac | ClassicChain | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c1-credtheft-rbac | ClassicChain | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 0.1 [0.1,0.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-credtheft-rbac | ClassicChain | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 0.1 [0.1,0.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-escape-persist | ClassicChain | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 8.1 [8.1,8.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-escape-persist | ClassicChain | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 8.2 [8.1,8.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-escape-persist | ClassicChain | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c1-escape-persist | ClassicChain | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c1-escape-persist | ClassicChain | R6Partial | d-randomequal | 21 | 57% [34,80] | 43% | 7.0 [6.5,7.5] | 1.3 [0.6,2.0] | 0.40 | 0.76 | 0 |
| c1-lateral | ClassicChain | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 3.2 [3.2,3.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-lateral | ClassicChain | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 3.2 [3.2,3.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-lateral | ClassicChain | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c1-lateral | ClassicChain | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 3.2 [3.2,3.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-lateral | ClassicChain | R6Partial | d-randomequal | 21 | 0% [0,0] | 100% | 3.2 [3.1,3.3] | 0.9 [0.4,1.4] | 0.00 | 0.82 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 7.1 [7.1,7.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 7.1 [7.1,7.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c1-stealth-dweller | ClassicChain | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 7.1 [7.1,7.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c1-stealth-dweller | ClassicChain | R6Partial | d-randomequal | 21 | 71% [50,93] | 29% | 7.1 [7.1,7.2] | 2.2 [1.2,3.3] | 0.51 | 0.68 | 0 |
| c2-c2-disrupt | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 7.1 [7.1,7.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-c2-disrupt | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 7.2 [7.1,7.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-c2-disrupt | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c2-c2-disrupt | R6Claimed | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 7.1 [7.1,7.2] | 6.0 [6.0,6.0] | 0.00 | 0.75 | 0 |
| c2-c2-disrupt | R6Claimed | R6Partial | d-randomequal | 21 | 33% [11,55] | 67% | 6.6 [6.3,6.9] | 2.3 [1.3,3.2] | 0.24 | 0.74 | 0 |
| c2-dwell-rotation | R6Claimed | R6Covers | d-fullphoenix | 21 | 0% [0,0] | 100% | 8.1 [8.1,8.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-dwell-rotation | R6Claimed | R6Covers | d-nomtd | 21 | 0% [0,0] | 100% | 8.1 [8.1,8.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-dwell-rotation | R6Claimed | R6Covers | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c2-dwell-rotation | R6Claimed | R6Covers | d-r6blindtimer | 21 | 100% [100,100] | 0% | 8.2 [8.2,8.2] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c2-dwell-rotation | R6Claimed | R6Covers | d-randomequal | 21 | 81% [63,99] | 19% | 8.1 [8.1,8.2] | 2.8 [1.6,4.0] | 0.54 | 0.60 | 0 |
| c2-lateral-disrupt | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-lateral-disrupt | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 6.2 [6.2,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-lateral-disrupt | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c2-lateral-disrupt | R6Claimed | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c2-lateral-disrupt | R6Claimed | R6Partial | d-randomequal | 21 | 52% [29,76] | 48% | 6.1 [6.0,6.2] | 1.7 [0.7,2.6] | 0.39 | 0.79 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-fullphoenix | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 0.1 [-0.0,0.2] | 1.00 | 0.75 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-nomtd | 21 | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c2-persistence-evict | R6Claimed | R6Covers | d-r6blindtimer | 21 | 100% [100,100] | 0% | 6.1 [6.1,6.1] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c2-persistence-evict | R6Claimed | R6Covers | d-randomequal | 21 | 67% [45,89] | 33% | 6.2 [6.1,6.3] | 2.0 [1.1,3.0] | 0.56 | 0.77 | 0 |
| c2-recon-window | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 8.0 [8.0,8.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-recon-window | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 8.0 [8.0,8.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-recon-window | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c2-recon-window | R6Claimed | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 8.0 [8.0,8.0] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c2-recon-window | R6Claimed | R6Partial | d-randomequal | 21 | 76% [56,96] | 24% | 8.0 [8.0,8.1] | 2.7 [1.5,3.9] | 0.59 | 0.69 | 0 |
| c2-supplychain-foothold | R6Claimed | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 8.1 [8.1,8.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-supplychain-foothold | R6Claimed | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 8.2 [8.1,8.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c2-supplychain-foothold | R6Claimed | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c2-supplychain-foothold | R6Claimed | R6Partial | d-r6blindtimer | 21 | 0% [0,0] | 100% | 8.2 [8.2,8.2] | 6.0 [6.0,6.0] | 0.00 | 0.75 | 0 |
| c2-supplychain-foothold | R6Claimed | R6Partial | d-randomequal | 21 | 24% [4,44] | 76% | 8.1 [8.1,8.2] | 2.2 [1.2,3.1] | 0.13 | 0.68 | 0 |
| c3-admission-bypass | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 3.5 [3.5,3.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-admission-bypass | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 3.3 [3.2,3.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-admission-bypass | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c3-admission-bypass | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 3.2 [3.1,3.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-admission-bypass | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 3.3 [3.1,3.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-cicd | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 4.5 [4.4,4.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-cicd | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 4.2 [4.1,4.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-cicd | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c3-cicd | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 4.3 [4.1,4.5] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-cicd | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 4.3 [4.2,4.4] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-cryptomining | ModernUnsupported | R6Partial | d-fullphoenix | 21 | 0% [0,0] | 100% | 8.1 [8.1,8.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-cryptomining | ModernUnsupported | R6Partial | d-nomtd | 21 | 0% [0,0] | 100% | 8.1 [8.1,8.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-cryptomining | ModernUnsupported | R6Partial | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c3-cryptomining | ModernUnsupported | R6Partial | d-r6blindtimer | 21 | 100% [100,100] | 0% | 8.2 [8.1,8.2] | 6.0 [6.0,6.0] | 1.00 | 0.75 | 0 |
| c3-cryptomining | ModernUnsupported | R6Partial | d-randomequal | 21 | 62% [39,85] | 38% | 8.1 [8.1,8.1] | 2.4 [1.3,3.5] | 0.37 | 0.65 | 0 |
| c3-imds-theft | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c3-imds-theft | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 2.1 [2.1,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-imds-theft | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 24% [4,44] | 76% | 2.1 [2.1,2.1] | 0.3 [0.1,0.6] | 0.24 | 0.93 | 0 |
| c3-secrets-sprawl | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 2.1 [2.1,2.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-secrets-sprawl | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 2.2 [2.2,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-secrets-sprawl | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c3-secrets-sprawl | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-secrets-sprawl | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-sidecar-inject | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 4.6 [4.5,4.7] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-sidecar-inject | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 4.6 [4.4,4.8] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-sidecar-inject | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c3-sidecar-inject | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 4.8 [4.6,4.9] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-sidecar-inject | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 4.4 [4.3,4.6] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-supplychain | ModernUnsupported | R6CannotRespond | d-fullphoenix | 21 | 0% [0,0] | 100% | 5.0 [4.9,5.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-supplychain | ModernUnsupported | R6CannotRespond | d-nomtd | 21 | 0% [0,0] | 100% | 4.9 [4.8,5.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-supplychain | ModernUnsupported | R6CannotRespond | d-phorvex-slot | - | SKIP: PhorvexSlot is a registered stub (proves... | - | - | - | - | - | - |
| c3-supplychain | ModernUnsupported | R6CannotRespond | d-r6blindtimer | 21 | 0% [0,0] | 100% | 4.8 [4.6,5.0] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| c3-supplychain | ModernUnsupported | R6CannotRespond | d-randomequal | 21 | 0% [0,0] | 100% | 4.9 [4.7,5.1] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## Honest R6 grounding

- **c1-c2-exfil** [R6Partial]: mock sink counted 4096/4096 bytes exfiltrated
- **c1-credtheft-rbac** [R6CannotRespond]: stolen SA token used against API: authorized=true (HTTP 200, listed 1 pods with stolen identity)
- **c1-escape-persist** [R6Partial]: backdoor alive after dwell=true; survived forced restart=false
- **c1-lateral** [R6Partial]: command-in-B marker present=true in c1lat-dst
- **c1-stealth-dweller** [R6Partial]: stealth dweller alive=true with 0 SecurityEvents (zero-detection survival=true)
- **c2-c2-disrupt** [R6Partial]: beacon delivered ~55 bytes (>=K=true), source identity stable=true
- **c2-dwell-rotation** [R6Covers]: foothold dwell out-lived window=true (measured ~8s vs window 8s)
- **c2-lateral-disrupt** [R6Partial]: in-flight command completed in B before rotation=true
- **c2-persistence-evict** [R6Covers]: post-detection: backdoor alive=true, old pod replaced=false
- **c2-recon-window** [R6Partial]: recon map (ip=10.244.0.34 uid=2931241f-0983-4703-8611-84253e26f951) still valid after interval=true
- **c2-supplychain-foothold** [R6Partial]: malicious-image foothold marker present after interval=true in c2sc-target
- **c3-admission-bypass** [R6CannotRespond]: policy-violating pod admitted+Running and exercised privileged context=true
- **c3-cicd** [R6CannotRespond]: injected pipeline step tampered artifact=true
- **c3-cryptomining** [R6Partial]: miner accrued 9/5 CPU-seconds before rotation
- **c3-imds-theft** [R6CannotRespond]: stolen FAKE cloud cred authorized by mock cloud API=true
- **c3-secrets-sprawl** [R6CannotRespond]: leaked secret read + used against mock sink authorized=true
- **c3-sidecar-inject** [R6CannotRespond]: injected sidecar read shared volume + wrote proof=true
- **c3-supplychain** [R6CannotRespond]: tampered image payload ran=true in c3sc-victim (rotation re-pulls same poisoned image)

Every number above traces to a raw log + command via provenance.json.
