# T1-C — L3 LIVE VERDICT: **PASS**

**When:** 2026-09-05, ~17:36–18:34 UTC (K3, Skeptic)
**Deployed under test:** brain image `phorvex:0.4.84`, gitSHA `4522076…` (= merge of PR #112 T1-C `33a9935`, along with #111/#113)
**Corpus:** retained audit window 14:37:34→~18:30 UTC, 100% v0.4.84 (13–15k records/scan). Evidence: `01-joint-corpus-scans.txt`, `02-foothold-capture-0.4.84.txt`.

## The intended collapse — SUCCESS, not regression

`phase × phaseReason` fleet-wide:

| phase | phaseReason | records | where |
|---|---|---|---|
| Warm | `warm-no-app-signal` | 13,343 | ci-reports, crm, document-store, litellm, mcp, nats, voice — **100% of every uninstrumented namespace** |
| Warm | `busy-measured` | 616 | vllm (measured traffic) |
| Idle | `idle-measured` | 142–152 | vllm only |

The M-142 defect (fleet priced Idle under arbitrary load because `Present` was universally true) is gone: absence now reads as Warm-by-absence with an honest reason string, never as a measured zero.

## Positive control (2b): instrumented idle stays Idle

`vllm/vllm-77997646c9-nhzv4`: 152 Idle records, **all with `requestRate.present=true`, value = 0.000000 ≤ 0.001** — measured-idle, honestly Idle. The same pod flips to `Warm/busy-measured` (616 records) when measured traffic arrives. The measured/assumed split lives exactly where designed: in `phaseReason`, with the enum unchanged.

## Cost effect: the 0.15 → 0.7 rise is live in real selection

- Rotate candidate rows on Warm-by-absence pods: **`cFlow = 0.70`** (the Warm switching-table entry; Idle = 0.15, table unchanged — P2), composite `expectedCost = 0.82 = 0.4·cNorm(1.0) + 0.6·cFlow(0.7)` — exact.
- Not just recorded — **used**: the brain's own actuation fingerprint for the 18:33 foothold rotate reads `strict gain 6.22 > 0 (fullValue=6.22 ECost=0.82 …)`. The Warm-phase cost flowed into a real, correctly-priced actuation.

## Phantom fan-out: eliminated

`residual = 0.0000` on **all 14,104 reqRate-absent records** (and on all 799 reqRate-present ones — calm fleet). The §A-documented phantom (real ConnCount × absent-zero ReqRate fabricating a lateral-probing residual on uninstrumented pods) reads exactly zero now: each little's-law term gates on its own signal's `Usable()`.

## SLO honesty

`inputs.sloHeadroom = {present: false}` on **100% of records, all namespaces** — headroom is recorded absent (no silent 1.0 in the record); the top-level effective value stays permissive 1.0 per P-NO-FREEZE, with the skip counted by `phorvex_slo_gate_skipped_total` (metric endpoint not separately scraped — record-level contract verified). Note: even vllm's latency signal is absent fleet-wide at this Prometheus — honest absence is the correct read.

## Not run

- **2c (kill a Prometheus scrape target):** exceeds the read-only standing rule; deferred. The behavior it would demonstrate (scrape failure → `phorvex_scrape_failures_total` + best-effort telemetry + no Idle flip) is the same code path as the verified absence handling.

**Conclusion:** absence is typed, priced, and recorded honestly; the fleet reads Warm-by-absence; the one instrumented pod proves measured-idle still reads Idle. **T1-C: L3 PASS.**

## Mutation ledger

Same joint session as T1-B's verdict (reader pod, one sanctioned foothold + clear, proxy kill, reader deleted); nothing T1-C-specific beyond read-only scans.
