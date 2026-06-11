# Phoenix / Phorvex Attack-Harness Report

Confidence level: 95%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).

## Detected cluster capabilities

- **CapGPU**: no node advertises nvidia.com/gpu — GPU scenarios skip-with-note
- **CapMIG**: no MIG resources/labels — MIG scenarios skip-with-note
- **CapMultiNode**: single schedulable node — multi-node scenarios skip-with-note

## Per-arm results (scenario x defender)

| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ai1-inference-manipulation | R6Claimed | R6Partial | d-nomtd | 3 | 0% [0,0] | 67% | 6.1 [5.9,6.3] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |
| ai1-inference-manipulation | R6Claimed | R6Partial | d-phorvex | 3 | 0% [0,0] | 100% | 6.1 [6.1,6.2] | 0.0 [0.0,0.0] | 0.00 | 1.00 | 0 |

## Controls

- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.
- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).

## AI split-oracle & MEASURED MTD-effect (Pass-B)

MTDEffect is MEASURED per arm from the oracle + persistence outcome (never assumed). Trigger attribution carries the audit honesty so a missing-trigger result is not read as a Phoenix failure. See report-dollars.md for ROI($)/Schwartau/reusability + H1/H2/H3.

| Scenario | Defender | SplitOracle | MTDEffect | TriggerAttribution | CapPending |
|---|---|---|---|---|---|
| ai1-inference-manipulation | d-nomtd | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |
| ai1-inference-manipulation | d-phorvex | persistence | MTD-CANNOT-HELP | MISSING-TRIGGER:detector-absent | false |

## Honest R6 grounding

- **ai1-inference-manipulation** [R6Partial]: in-request output tampered=true; static path intercept-able after rotation=true (URL/path rotation absent)

Every number above traces to a raw log + command via provenance.json.
