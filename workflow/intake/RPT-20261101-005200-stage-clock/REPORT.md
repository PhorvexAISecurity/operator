# Fractional decision-clock rejection in the new stage refresher

Observed during this campaign at source348c1c7a64256e945f10077b3eb8e2a6cca107ea: a real captured decision at2026-11-01T00:06:31.717543556Z exported by the true Go engine at1793491591.7175436 was compared with a Python whole-second timestamp1793491591. The refresh stopped CANDIDATE_EXPORT_DECISION_CLOCK_MISMATCH after exact baselines. This is a harness parsing defect, not an invalid recorder clock.

Corrected within the active BENCH-STAGE fix at3e11f4e7ca8424c31a387b53e04942a18ee7d977; independent Go IEEE bit controls and realfailed-cohort reproduction support the repair. Subsequent actual300and600second refreshes are READY64. No strict equality check was relaxed. Evidence authority: fixes/BENCH-STAGE/evidence/peer-review/r9-clock and live/refresh-300 plus live/final-observed-controls. This retrospective intake retains a campaign-discovered implementation defect; it does not create an additional product fix.
