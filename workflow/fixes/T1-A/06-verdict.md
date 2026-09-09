# 06 — Verdict · T1-A (Skeptic)

**Verdict: CLOSED — LIVE-VERIFIED, with one coverage admission (M-149).**
Base/commit: `57790cb` (PR #98, merged `35c1206`) · deployed image `phorvex:0.4.74` · verdict date 2026-09-03.

## Part 1 — offline (pre-PR; signed 2026-09-02)

Documented in `02-critique.md` (blind derivation §A, written before reading `01-proposal.md`) and
`03-decision.md`; offline evidence (L0 red→green, L1 battery, fixture (e) the declared M-25 arm-2
downgrade) in `05-evidence.md`; verifier `verify.sh` exit 0. Skeptic sign-off: STATUS → AGREED,
2026-09-02.

## Part 2 — live (post-deploy; this section)

FIX_LOOP §5: a verdict is valid only with the blind derivation (part 1, §A) **and** one of
attack-failed / attack-succeeded / coverage admission. This verdict rests on **attack-failed**
for the no-change surface and a **coverage admission** for the gate's active path.

**Attack that failed.** Declared delta (03-decision): on this fleet, selections/actuations
unchanged, belief-layer labels only, trace gains `leakage` with honest-absent semantics, zero
AI-GPU-stage records steady-state. Post-deploy scan of 4,978 decision records over the first
~75 min of 0.4.74 (`evidence/live/01`): stage distribution recon 4,976 / exploit 2 /
model-theft 0 / gpu-side-channel 0; all 263 vllm records uniform `(leakage.absent, sm.absent,
vram.absent, rarity 1, coRes 2, recon)`; structural golden diff pre-vs-post shows the **only**
schema change is the added `leakage` key and no presence-flag flips. No deviation from the
declaration found anywhere I could measure.

**Coverage admission (§5(3)).** The gate's active path — SMOccupancy measured, gate
fires/doesn't on real activity — is not live-testable on this fleet: DCP profiling is not
enabled on the T4s (`DCGM_FI_PROF_SM_ACTIVE` zero series; dcgm-exporter DaemonSet unpatched;
the enabling patch is human-gated). Residual risk accepted and recorded on register entry
M-149; the active path is covered by the merged offline fixtures (leakage_gate_test.go,
leakage_record_test.go, leakage_trace_test.go — in the permanent suite via PR #98). Live
discrimination evidence must be collected if/when DCP is enabled; M-149 stays open until then.

**Definition of done (§4 LIVE-VERIFIED → CLOSED), four parts:**
1. Skeptic verdict — this document. ✓
2. Register updated — R-8 row flipped to CLOSED with this cycle's reference; M-149 admission
   appended. ✓
3. Verification tests merged into the permanent suite — three test files, merged in PR #98. ✓
4. Version re-stamp — all part-2 evidence cites deployed `0.4.74` / trace gitSHA `35c12069`;
   the baseline it diffs against cites `0.4.72` / `ad4d3b8`. Consistent. ✓

Signed: the Skeptic (K3 seat), 2026-09-03. Proposer was offline for part 2; the verdict is the
Skeptic's artifact per FIX_LOOP §2.

## Proposer review of part 2 (2026-09-03, after the fact)

Re-verified independently: `57790cb` ∈ ancestors of `v0.4.74`; live record `gitSHA` = PR #98 merge,
`brainImage` = `0.4.74`; `inputs.leakage` honest-absent; register R-8/M-149 edits present; no record
file committed. **Closure accepted.** Deviation (no battery-wide L2 byte diff) accepted by ruling:
on a one-ModelID fleet the battery cannot exercise the gate, so it carries no discriminating power
beyond the 263-record uniformity; the ≥2-model topologies are the merged fixtures a–e. The missing
L2 battery is recorded as a Phase-0 program gap (bus 267), required before the first
selection-changing cycle.
