# Root-cause deduplication

## Search and mechanism

Compared `adapter`, `SecurityEvent`, `phorvex.attack.adapter`, creator and Pod-UID observation contracts against current issue entries and ingest source. Actual installed detector hash 5f37421809b883b537ffd3a913e223f56c7ae918a6b87430e7fa206db53012a8 emits `lora.unauthorized_adapter` without adapter-name or target-pod-uid annotations. Real consumer reproduction rejects observation binding even when API identity/time and trusted creator are supplied. Correcting all three fields produces the positive control.

## Candidate comparison

- M-95 addresses attacker-steerable Pod annotations. Its consumer fix requires authenticated, scoped observations. This finding concerns the deployed trusted producer never satisfying that interface; weakening M-95 would be incorrect.
- M-94 concerns self-declared source trust. This new failure persists with trusted creator identity, so creator trust repair cannot fix it.
- M-153 concerns event-type dominance/scoring. The event here never forms the required adapter observation; score adjustment does not supply target identity or adapter identity.
- M-2 concerns policy enum/schema drift, not the SecurityEvent producer envelope.
- Search-ranked M-144/M-136/M-140/M-142 overlap general event or decision terms but do not contain this installed producer contract defect.

## Determination

NEW. Version the producer, bind inventory to the exact serving Pod lifetime and emit the canonical authenticated event contract. Preserve consumer defenses. Source compatibility does not establish live detection, dispatch or mitigation; those remain separate acceptance controls.
