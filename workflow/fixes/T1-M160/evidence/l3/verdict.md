# T1-M160 — L3 live verification verdict (T1-E re-L3)

**Date:** 2026-09-07 · **Verifier:** K3 (live_verifier) · **Result: PASS**
**Observed deployment:** `phorvex:0.4.96` — embedded gitSHA `a13b83af3b2d`
(= `a13b83a`, head under release tag `v0.4.96` @ `ea5d5ca`; M-160 merge `c081616` /
head `281abce` is an ancestor). Rollout 21:50:14Z; verified window 21:50–22:15Z
(1,927 decision records). Deploy detected by watcher at 21:54:49Z.

## Criterion-by-criterion (the 5 M-160 acceptance criteria)

1. **rotate/quarantine no-rbac → 0 fleet-wide — PASS.**
   Zero `no-rbac` exclusions for `rotate` and `quarantine` across all 1,927 records
   on 0.4.96. Pre-fix baseline on 0.4.95: `rotate` in `nats` alone had 969 no-rbac
   exclusions (`denied /pods:delete in nats`) — all gone. Phoenix-routed actions now
   authorize against `amtd.r6security.com/securityevents:create`, which the operator
   holds cluster-wide.
2. **Native true-positives survive — PASS.**
   `kv-reset` no-rbac in `vllm-prod` (98 rows; condition message:
   `no-rbac: denied /pods:update in vllm-prod`) and `route-rotate` no-rbac in
   `litellm-prod` (194 rows). Both are native actions with genuine denials — the
   no-rbac leg still bites where it should.
3. **rbacUnknown=0 — PASS with one environmental observation.**
   50 rows (50 actionStatus + 50 candidate) carried `rbacUnknown=true`, ALL inside a
   single ~2-minute window (22:00:53–22:02:54Z). Brain logs root-cause it to a
   **cluster-wide API stall**: every tenant's AMTD update and all Prometheus queries
   failed `context deadline exceeded` in the same window; tick durations spiked to
   ~21s. SSAR checks timed out with everything else. The designed **fail-open**
   behaved correctly: no false exclusions during the window, self-recovered after.
   Zero unknowns before or after on 0.4.96, and zero across the entire 0.4.95 window.
   Not an M-160 regression — the fail-open path was exercised live and held.
4. **vllm-prod kv-reset no-rbac / voice-prod True — PASS.**
   Conditions: `vllm-prod/vllm-prod-defense` False with
   `kv-reset unsupported on 1/1 assets (no-rbac: denied /pods:update in vllm-prod)`;
   `voice-prod/voice-prod-defense` True (`all enabled actions have matching
   capabilities`). Exactly as predicted.
5. **Rotate candidacy restored in voice/nats — PASS.**
   `rotate` candidate rows on 0.4.96: `voice` 300, `voice-prod` 300 (both were
   no-rbac-excluded pre-fix), plus `litellm` 130 / `litellm-prod` 198. In `nats`,
   rotate is no longer RBAC-excluded — it is now availability-vetoed
   (`ready=1-1|2-1 < minAvailable=2`, 261 rows), a pre-existing feasibility
   constraint unrelated to M-160.

## Verdict

**L3 PASS — all five criteria met on the observed 0.4.96 deployment.**
M-160 closes the T1-E criterion-6 failure. The no-rbac leg in `ActionsSupported`
(via `CapableAndAuthorized`) reports native denials accurately and no longer
mis-gates Phoenix-routed actuation.
