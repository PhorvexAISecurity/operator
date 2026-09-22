# Root-cause deduplication

## Search terms and anatomy locus

Protected serving journal, nonterminal receipt, dispatching, outcome-unknown, KV reset, KV migrate invalidate, preselection capability, dispatch replay guard. The decisive source is `phorvex/internal/actuator/serving_effect_journal.go` and `NativeActuator.SupportsAction`.

## Candidate comparison

M-064 owns crash-safe serving-effect receipts, effect-domain slots, terminal phases, and no-blind-replay recovery. The incident is not a new transport or scoring mechanism: its retained M-064 receipt correctly stops dispatch but had no matching preselection capability gate. The stock vLLM empty-200 confirmation gap remains separate deployment/source-contract debt and is not repaired here.

## Determination

`DUPLICATE`

- Existing issue: M-064
- Rationale: this is the missing selection-side consumer of the same protected receipt authority and domain model. The fix leaves M-064 dispatch and recovery semantics intact.
