# T1-M028 — L3 live verification verdict

**Date:** 2026-09-08 · **Verifier:** K3 (live_verifier) · **Result: PASS (core claims live-verified; two criteria fleet-masked, marked below)**
**Observed deployment:** `phorvex:0.4.97` — embedded gitSHA `c8c708145f2f` (= `c8c7081` under
release tag `v0.4.97` @ `79c0370`; M-28 commit `aaf01e0` is an ancestor). Live since 14:20:59Z;
verified window 14:20–17:20Z (11,884 decision records, ~7× T_cad).

## Criterion-by-criterion

1. **Zero-event cadence ≤ 1/T_cad — PASS.** Zero kv-reset emissions fleet-wide across the whole
   0.4.97 window (zero SecurityEvents existed). The cap is not merely latent: **~950
   `proactive-cadence` vetoes** fired on 12 voice-bot pods (rotate, podIdentity clock), exact
   grammar `proactive-cadence: podIdentity hygiene-reset <ago> ago < floor=15m0s (no evidence)`,
   10s-tick cadence, each pod vetoed ~70–83× = precisely its first 15 min of life.
2. **Reactive positive control — NON_DISCRIMINATING (fleet-masked, cap not implicated).**
   Injected a trusted SecurityEvent (`k3-l3-m028-probe`, anomaly/high/falco → voice-bot-vg9p5,
   lived 17:11:50–17:18:52Z ≈ 42 ticks). The brain ingested it (31 log refs) but no move fired:
   rotate on the target is **availability-vetoed** (`ready=1-1 < minAvailable=2`; pod v5fs8 stuck
   ContainerCreating since 15:29Z) and selection reported `reactive-only: no direct foothold`.
   The cadence cap was never the blocker. Note: kv-reset specifically cannot be demonstrated
   anywhere tonight (vllm-prod: no-rbac true-positive; litellm: no-cover; vllm: not-enabled).
   Reactive path remains covered in-tree by `TestCapUntouchedByReactivePath` + the stamp test.
3. **Hygiene resumes — PASS (natural experiment, no probe needed).** voice-bot-5252f: created
   15:30Z → rotate vetoed 81× by proactive-cadence while within the floor → at 16:13:08Z (age 43m,
   past floor, prov=1.0) rotate **selected** (`selected_strict_positive_gain`), dispatch emitted,
   pod actually rotated (successor vg9p5 created the same second). The full intended lifecycle,
   version-tagged, zero events.
4. **Gap-#1 live (physics-pinned zero-event pod must show the veto) — NON_DISCRIMINATING
   (fleet-masked), mechanism proven in-tree.** Every AI pod's enabled actions are currently
   vetoed UPSTREAM of the cadence cap (vllm: availability; vllm-prod: no-rbac + availability;
   litellm-prod route-rotate: no-rbac), so the cap's veto cannot surface on an aiClassified pod
   tonight. The mechanism chain is guarded non-vacuously:
   `TestAssembleSetStampsHasEventEvidenceOntoView` (physics-only pod → aiClassified fires, broad
   HasEvidence=true, HasEventEvidence=false — with the P3-2 non-vacuousness pin) +
   `TestCapFiresWhenOnlyPhysicsClassifiedNoEvent`. Live, the veto grammar is confirmed firing on
   zero-event pods (criterion 1).
5. **TTFT — PASS.** 3× HTTP 200 from inside the cluster, total latency 0.21–0.26s
   (max_tokens=1; served model id is `Qwen/Qwen2.5-7B-Instruct-AWQ` — the `Qwen/` prefix is
   required). Availability healthy during the zero-event window.
6. **Veto scope — PASS.** Every proactive-cadence veto in the corpus carries the `(no evidence)`
   reason (the law's only veto branch); zero events existed during the veto windows; the single
   selection (5252f) was past-floor prov=1. No evidence-bearing asset was capped.

## Notes
- The M-23 watcher missed the 16:13 rotate (its reader pod was down 12:43–15:03Z and it only
  scans the active file). Corpus scan caught it. Watcher limitation noted for M-23's verdict.
- Probe footprint: one SecurityEvent created + deleted (7m02s). No pods harmed; cluster clean.

## Verdict
**L3 PASS.** The ticket's primary claim — evidence-less hygiene motion is floored at T_cad and the
~110s churn is gone — is live-verified on 0.4.97, with the veto mechanism observed firing ~950× and
the release-to-hygiene transition observed end-to-end. Criteria 2 and 4 are fleet-masked tonight
(NOT cap-blocked); both are guarded non-vacuously in-tree. Recommend a standing discriminating
probe (auto event-injection on the next young voice-bot generation) to close 2/4 live when fleet
conditions allow — boss's call.
