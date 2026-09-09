# L3 — Post-deploy live verification · T1-A · 2026-09-03 ~15:05–15:15 UTC (Skeptic, Claude offline)

Base/commit under test: `57790cb` (the only commit of PR #98), merged as `35c1206`, released `v0.4.74`.
`git merge-base --is-ancestor 57790cb v0.4.74` → YES.

## 1. The fix is up

    kubectl -n phorvex-system get deploy phorvex-phorvex -o jsonpath=containers[*].image
    → phorvex:0.4.74, phorvex-console:0.4.74        (baseline 2026-09-02 was 0.4.72)

    brain pod phorvex-phorvex-57d6fbcd78-s22jx, startTime 2026-09-03T13:54:43Z,
    node ip-172-27-12-250.us-east-2.compute.internal, 0 restarts.

    Post-deploy vllm decision record (02-vllm-decision-record-0.4.74.json):
      decisionTrace.brainImage = …/phorvex:0.4.74
      decisionTrace.gitSHA     = 35c1206908ef11ffeee4d8414b9fd9feae7741dd   (= the PR #98 merge)

## 2. Zero AI-GPU-stage records (no-change assertion) — PASS

Reader pod `audit-scan-k3` (python:3.11-slim) on the brain node, PVC `phorvex-phorvex-audit` at /audit.
Window: all `phorvex.audit.v2` decision records with time ≥ 2026-09-03T13:54:43Z, scanned across
live.jsonl.2 (tail) + live.jsonl.1 + live.jsonl.

    post-deploy decision records: 4,978  (~75 min)
    stage distribution:  recon 4,976 · exploit 2
    model-theft:       0
    gpu-side-channel:  0

Matches the declared delta (03-decision): on this fleet the gate is dark on both sides of the fix —
pre-fix because ModelRarity = 1.0 (M-151), post-fix because SMOccupancy is honest-absent (M-149).
Per M-149 this pass is **vacuous as discrimination evidence**; it is a no-regression assertion only.

## 3. The new `leakage` trace field — honest-absent semantics live — PASS

263 vllm-namespace records post-deploy, uniform tuple
(leakage.present, smOccupancy.present, vramFraction.present, modelRarity, coResidency, stage):

    (False, False, False, 1, 2, 'recon') -> 263   (no exceptions)

`inputs.leakage = {present:false, value:0}` on every record — present in the schema, absent as a
measurement, exactly the specified behavior when `SMSource == ""`. `vramFraction` remains
`{present:false}` — M-152 (stampGPU drops VRAMPresent) is still open and was not in T1-A scope.

## 4. Golden structural diff, one vllm record pre vs post — PASS

05-vllm-decision-record-0.4.72.json (baseline) vs 02-vllm-decision-record-0.4.74.json (this dir),
recursive key-set walk:

    keys only in pre : NONE
    keys only in post: .decisionTrace.inputs.leakage{,.present,.value}
    presence-flag flips on existing inputs: NONE
    stage/reason identical: recon / "noop: no candidate won strict gain > 0"; selected=false, action=noop

The declared "no record change except the new absent `leakage` field" holds byte-structurally.

## 5. DCP / PROF_SM_ACTIVE status — NOT enabled → coverage admission on M-149

Brain's Prometheus (monitoring/kube-prom-stack-kube-prome-prometheus), 2026-09-03 ~15:12 UTC:

    count(DCGM_FI_PROF_SM_ACTIVE)        → []      (zero series — unchanged from baseline)
    count(DCGM_FI_DEV_FB_USED)           → 1
    count({__name__=~"DCGM_FI_PROF.*"})  → 2       (PCIe RX/TX only — unchanged)

dcgm-exporter DaemonSet unchanged: image 3.3.9-3.6.1-ubuntu22.04, no args, env only
DCGM_EXPORTER_KUBERNETES / DCGM_EXPORTER_LISTEN, no collectors CSV volume. The DCP-enabling patch
remains human-gated and has not been applied. vllm pod vllm-77997646c9-nhzv4 (2d21h, 0 restarts)
on the T4 node ip-172-27-12-137.

Consequence: the gate's ACTIVE path (SM present → fire / not-fire on real activity) has no live
coverage on this fleet. It is verified only by the merged offline fixtures
(killchain/leakage_gate_test.go incl. fixture (e) the declared M-25 arm-2 downgrade,
killchain/leakage_record_test.go, decision/leakage_trace_test.go). Recorded as a coverage
admission on M-149 per FIX_LOOP §5(3).
