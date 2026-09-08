# T1-M023 — L3 live verification: watch phase

**Date:** 2026-09-07 · **Verifier:** K3 (live_verifier) · **Result so far: NON_DISCRIMINATING — watcher deployed**
**Observed deployment:** `phorvex:0.4.95` (embedded gitSHA `743a9d46b840`; M-23
merge `809d80c` is an ancestor). M-23 code live since 0.4.93, 15:52Z (~2.5h window).

## What was checked
1. **Full-corpus emission scan** (0.4.93 + 0.4.94 + 0.4.95, ~13.3k decision
   records, 15:52–18:15Z): **zero rotate-family emissions** (`selected` records
   for rotate, guardrail-rotate, request-drain, quarantine, endpoint-rotate,
   route-rotate, identity-rotate, adapter-rotate). No bursts — but vacuously:
   there is no selection pressure.
2. **Guard reachability**: on 0.4.95, `rotate`/`route-rotate` reach
   `candidate`/`feasible=true` only in `litellm` (466 rows each) and are never
   selected (calm fleet, netGain negative). Elsewhere rotates are
   availability-vetoed (`ready=1-1 < minAvailable=2`, 233 rows) or ineligible.
   The anti-over-rotation guard is therefore **not reachable** in this window —
   the pre-fix V2 bursts (8 rotate/90s across 3 pods) occurred under attack
   pressure.

## Disposition (human decision 2026-09-07)
Defer-with-watch: no attack/pressure trigger authorized now. A watcher is
deployed on the jump host (`/tmp/m23_watch_loop.sh`, 5-min cadence, reader pod
`audit-scan-k3-l3` extended to 48h, auto-recreate on the brain's node):
- logs every rotate-family emission with build pin and per-(pod,action) gap;
- flags `SPACING-VIOLATION` on any gap < 85s (window 90s);
- re-emission after the window constitutes the positive control.
Log: jump host `/tmp/m23_watch.log`; state `/tmp/m23_state.txt`.

## Verdict criteria when emissions occur
- **PASS**: every per-(pod,action) inter-emission gap ≥ ~85s AND at least one
  re-emission after the window (guard throttles, then releases).
- **FAIL**: any gap < 85s on a post-M-23 build (burst = guard not binding).

**Status: L3 PENDING (watch phase).** Offline L0–L2 + RED gates remain the
binding evidence until a discriminating live window occurs.
