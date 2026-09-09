# 06 — Live verification (L3) · T0-C (B-5/R-2/R-9) · part 2 — D-4 amendment APPROVED by owner (Mehrdad, 2026-09-04 ~19:15Z)

**Deployed under test:** image `phorvex:0.4.80`, gitSHA `17082b7fbcf436bde72723996fcbbe149fe3bfff`
(PR #104 merge; contains T0-C merge `098ab89` + #103; does NOT contain #106/#110).
**Window:** full retained corpus on the audit PVC, scanned twice (17:53Z: 15,159 records;
18:11Z: 12,988 records — rotation shrank the window between scans, see M-154). 100% of records
on the deployed SHA are `phorvex.decision-trace.v3`.

## L3 band results (02 §B.9)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Structure: 100% v3, 15 canonical `actionStatus` rows, closed enums, vllm signature | **PASS** — 12,988/12,988 v3; 15/15 rows canonical on every record; zero enum violations; vllm 817 records: 13×`not-enabled` + 2×(`infeasible/feasibility` or `candidate/reactive-only`, `scored=false`) | `evidence/live-l3/l3-verdict-0.4.80.txt` |
| 2 | Independent reconstruction (Skeptic's validator, `--strict-v3`) | **PASS** — 2,002/2,002 PASS, 0 FAIL, 0 UNDECIDABLE on the frozen slice (newest 2,000 + both selected) | `evidence/live/01-post-deploy-0.4.80-17082b7.jsonl`; `evidence/live/02-validator-strict-v3-0.4.80.md` |
| 3 | Selection-unchanged | **CONFOUNDED** — deployed build ≥ 0.4.79 carries #104 (M-141 EPSS lookup) which moves weights independently of T0-C. Distribution as measured: 2 selected of 12,988 (0.015%), both `rotate` on `voice` (baseline 0.4.74/75: 5/20,044 = 0.025%, all rotate on voice). The Class-A claim rests on the offline frozen-corpus trace-on/off equivalence test (05, E1/E3 + fixture battery), not on live comparison | `evidence/live-l3/l3-verdict-0.4.80.txt` addendum |
| 4 | Record size ≤ +5% (D-4) | **FAILED PREDICTION — amended declaration APPROVED by owner (Mehrdad, 2026-09-04)**. D-4 is amended to: +26% on ~120-fact records, mechanism as measured, retention consequence = M-154. Controlled same-pod same-fact-count measurement (Skeptic, `evidence/live/03-size-band-measurement.md`): vllm 122 facts 61,609 → 77,601 B (**+26.0%**, n=59); voice 118 facts 64,043 → 80,430 B (**+25.6%**, n=241). Mechanism: +109 B/fact (`coveringActions`, `coveredRound`, `decompositionAvailable`) × ~120 facts ≈ +13 KB; `actionStatus` +1.5 KB; candidates +0.6 KB. Every added byte is ticket-mandated (§8, 03 B.2) — no trim possible without breaching the ticket. Consequence: audit history depth roughly halved at the current PVC cap → filed as **M-154** | register M-154 |
| 5 | `sloHeadroom` / `leakage` / ceiling / cmv | **PASS** — `sloHeadroom present:false` 12,988/12,988 (no policy sets p99Ms, as predicted); `leakage` = `{present:false}` on 12,988/12,988; `costCeiling` > 0 and `costModelVersion` non-empty on 12,988/12,988 | `evidence/live-l3/l3-verdict-0.4.80.txt` addendum |
| 6 | Ledger | **PASS** — reader pods l3/l3b/l3c/l3d/l3e/l3f, all read-only mounts, all deleted in-session; one write op: force-delete of own evicted pod l3b (was blocking the brain's RWO failover — accepted by Skeptic) | bus 295 §step 6, bus 298 |

## Incidents during verification (affect the corpus, not the verdict)

- **Node flap 17:29Z:** brain node `ip-172-27-12-51` went NotReady; brain down ~18 min
  (17:28–17:46Z) on RWO force-detach; recovered on `ip-172-27-12-248`, later moved to
  `ip-172-27-12-138` (further node churn — spot-style recycling; two reader pods, l3e and the
  first l3 attempt, died with their nodes). Record gap 17:28–17:46Z. Old node still NotReady —
  infra item, not Phorvex.
- **Rotation evicted the pre-0.4.80 corpus** mid-verification (M-154): the window is
  0.4.80-only, which is why every record checked is on the deployed SHA.

## Status

**LIVE-VERIFIED.** Checks 1, 2, 5, 6 PASS as measured; check 3 confounded by #104 (Class-A
rests on the offline trace-on/off equivalence suite); check 4 (D-4) failed as predicted and is
closed by the owner's approval of the amended declaration (+26% on ~120-fact records,
mechanism stated, retention consequence filed as M-154) — Mehrdad, 2026-09-04.

**T0-C: CLOSED** — with one carried exception: the CI-stage half of B-5 (validator gate in CI)
stays open per hami. Register flips: R-2 → closed, R-9 → closed, B-5 → closed-minus-CI-stage;
the 9 follow-up deviations from 05 are noted on the relevant entries.
