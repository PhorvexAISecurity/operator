# T0-C L3 · record-size band (D-4 "≤ +5%") · Skeptic measurement · 2026-09-04

Method: compact JSON bytes (`json.dumps(separators=(',',':'))`) so pretty-printing on disk cannot
inflate either side. v2 references = the two records we hold from before the change (vllm @0.4.74,
voice @0.4.73). v3 = the exported slice `01-post-deploy-0.4.80-17082b7.jsonl` (2,002 records).
Comparison is **same pod, same fact count** — the only like-for-like available since the pre-0.4.80
corpus rotated out of the PVC.

| pod | facts | v2 bytes | v3 median bytes (n) | Δ |
|---|---|---|---|---|
| vllm/vllm-* | 122 | 61,609 | 77,601 (59) | **+26.0%** |
| voice/voice-bot-* | 118 | 64,043 | 80,430 (241) | **+25.6%** |

Where the bytes are (vllm): per-fact 465 → 574 B (+109 B/fact × 122 = +13.3 KB) from
`coveringActions`, `coveredRound{present,value}`, `decompositionAvailable`; `actionStatus` 15 rows
= +1.5 KB; candidates +0.6 KB (CHi quad, sloGateResult, scored). Facts are 80% of every record.

K3's fleet-mean numbers (v2 "15-20 KB" / v3 83 KB, ×4-5) were a composition + pretty-print artifact;
the controlled delta is **+26%**, five times the declared band. K3's "schema adds only ~2-4 KB ≈ +5%"
counts the actionStatus rows and forgets the per-fact additions on ~120-fact records.

**Ruling input:** every byte added is ticket-mandated (§8 `coveringActions`, `decompositionAvailable`;
03 B.2 `coveredRound`). A trim would violate the ticket. The prediction was wrong, the record is not.
Consequence is retention depth (~4.7 h → ~half at 0.4.80 rates, K3 step 6) — a PVC-cap decision.
