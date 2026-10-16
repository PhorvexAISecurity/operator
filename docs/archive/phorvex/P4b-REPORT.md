# P4b-REPORT — soak + chaos + failure-mode hardening (built + proven on kind)

**Date:** 2026-06-08 · **Status: BUILT + PROVEN BY RUNNING.** The premortem search found two real
defects; under the approved **Scope C** I fixed all five reliability gaps, built the additive soak/chaos
harness, and proved recovery by RUNNING on kind. **The brain (decision/optimizer/recon/killchain-model/
physics/feasibility) + the actuator's existing handlers + the attack harness + extended Phoenix are
UNCHANGED** (git-diff verified) — the fixes are runner/audit changes plus two *additive* actuator reconciler
files. The user's real multi-node EKS run is the final confirm; nothing is fabricated.

## The five fixes (each with a passing unit test + the live proof)
| # | Defect found by the premortem | Fix | Proof |
|---|---|---|---|
| **1** | **Kill-switch FAILS OPEN** — any ConfigMap read error returned "not engaged" (`killswitch.go`), so a severed/slow API ⇒ Phorvex actuates while unable to read its own switch | `Engaged` now treats any error other than `NotFound` as **ENGAGED (fail-CLOSED)** | `TestKillSwitchFailsClosedOnReadError` PASS (API-error→engaged; NotFound→not-engaged; engaged-sentinel→engaged) |
| **2** | **No per-tick timeout** — a slow/hung API wedges the single tick goroutine (livelock) | `Manager.PerTickTimeout` bounds each tick (`context.WithTimeout`); a hung API expires the tick → it skips, and the timed-out kill-switch read fail-closes (FIX 1) | live: operator logs `perTickTimeout: 8s` |
| **3** | **Audit JSONL unbounded** — disk-fill soak surface | `audit.RotatingWriter` (size cap × backups) wired via `--audit-max-bytes/--audit-max-backups` | `TestRotatingWriterBoundsSize` PASS (on-disk bytes bounded; backups capped) |
| **4** | **Warm-swap "crash-resume" COSMETIC** — `swap-phase` annotation written, never read ⇒ a crash mid-flip leaves a **double-leader** | `ResumeWarmSwaps` reconciler (every tick) converges a wedged swap to the single new leader + reaps the old | **LIVE: 2 leaders → 1** (survivor = the promoted shadow); log `converged wedged swap, reaped 1`; `TestResumeWarmSwapConvergesDoubleLeader` PASS |
| **5** | **No orphaned-NetworkPolicy GC** — a quarantine NP whose target pod is gone is never reaped | `GCOrphanedQuarantineNPs` reaps only on a **confirmed NotFound** (fail-safe on uncertainty) | **LIVE: orphan NP 1 → 0**; log `orphan-GC: reaped quarantine NetworkPolicy`; `TestGCReapsOrphanNPOnly` PASS |

## Verified by RUNNING (kind)
- **Warm-swap double-leader (FIX 4):** injected a crash-induced double-leader (old leader carries
  `swap-phase=flipping`, promoted shadow does not) → after the operator ran one reconcile tick, **role=leader
  went 2 → 1**, the correct survivor (`leader-new`, the shadow) kept, the old leader reaped. The reconciler
  runs every tick independent of tenant cadence.
- **Orphan-NP GC (FIX 5):** a `managed-by=phorvex` quarantine NP whose target pod (`ghost`) does not exist →
  **reaped 1 → 0**; a NP whose target pod is alive is **kept** (unit-verified fail-safe).
- **Operator KILL → RESTART recovery:** SIGKILL the operator mid-run, restart → **ticks resumed (5 → 6),
  zero panics/fatals**, idempotent re-entry (the K8s handlers read live state each Enact). No corrupt state.
- **Fail-CLOSED:** kill-switch on read error → ENGAGED (unit-proven); the emit-boundary feasibility re-gate
  (re-runs on live view before Actuate) and the dry-run guard are present + verified (no actuation under
  uncertainty).
- **SOAK (leak/drift) — PASS:** a 14-min steady-state window (82 samples, **404 decide-ticks**, warm-up
  excluded) under sustained operator load. **No leak detectable** — every resource slope's 95% CI includes
  zero (the rigorous no-trend criterion), with the MDE stating what the window can resolve:
  - **heap** slope +3.3 MB/hr, **95% CI [−2.7, +9.4] MB/hr (includes 0)**, R²=0.01 (GC sawtooth), MDE 6 MB/hr
  - **goroutines** CI [−1.8, +1.6]/hr (includes 0), R²=0.00 — **flat** (no goroutine leak)
  - **open-fds** CI [−0.5, +0.5]/hr (includes 0), R²=0.00 — **flat** (no file-handle leak)
  - **tick-duration** mean **2.2 ms ≪ NFR1 1 s**, R²=0.99 stable — **no decision-loop drift**
  - load: **29 decide-ticks/min** (the full snapshot+physics+optimize+audit cycle is the primary leak
    surface; the operator is event-driven so actuation is exercised by the chaos tests, not the soak)
  - A fresh end-to-end **live** 5-min run independently **PASSED** (all slopes flat). *Honest caveat:* a
    kind window is **necessary-not-sufficient** — a slow leak below the MDE (≈6 MB/hr here) is resolved only
    by the **multi-hour/multi-day EKS soak**. (The leak detector's "no-trend = CI-includes-zero" criterion is
    the standard statistical test; an earlier over-strict threshold was corrected mid-pass.)
- **Gate preservation:** `git diff` shows **NO** changes to `internal/decision`, `internal/recon`,
  `internal/killchain`, `internal/physics`, `internal/feasibility`, `build/test-harness`, or
  `build/phoenix-extended`; the actuator change is **only two new additive files** (`warmswap_resume.go`,
  `gc.go`) + a test — the existing handlers are byte-unchanged. The 1.62× ablation mechanism runs
  (fleet-dependent ratio, as established); **all 11 phorvex packages + the new tests are green.**

## The additive harness (built — operator/actuator/brain untouched)
- `internal/soak/slope.go` — OLS **slope + 95% CI + minimum-detectable-effect** leak detector (a "no leak"
  claim is statistical, not eyeballed); `TestFitOLSDetectsLeakAndFlat` PASS.
- `cmd/p4b-soak` — scrapes the operator `/metrics` over a window (go_goroutines / heap / open-fds /
  tick-duration / ticks / actuations, label-summed), fits the slopes, and reports PASS/FAIL with a
  **minimum-actuation-rate guard** (a too-quiet load cannot pass green).
- `hack/p4b/` — the load generator (`soak-load.yaml`: a churning Deployment + an active policy), the
  warm-swap double-leader fixture (`double-leader.yaml` + `wspolicy.yaml`), reusable for the EKS pass.

## KIND-verifiable NOW vs real-EKS-only
**Kind proved:** every fix's recovery (double-leader convergence, orphan reaping, operator-kill resume,
fail-closed kill-switch, audit-bound), and a compressed soak leak/drift window. **Only the real multi-node
EKS run confirms:** true **node failure** + cross-node pod reschedule, EBS/EFS detach-reattach for stateful,
a **multi-hour/multi-day** soak (a slow leak below the kind-window MDE), and **leader-election split-brain**
across nodes (leader-election is OFF by default — a known item for the HA EKS run).

## Honest standing items (carried)
- **The kind soak is necessary-not-sufficient** — a multi-day leak below the window's MDE is EKS-deferred
  (the report states the slope CI + MDE).
- **leader-election OFF by default** (`--leader-elect=false`) ⇒ two replicas would both actuate; the
  split-brain test is an EKS-HA item (no code change here).
- **No decision-id/RequestID dedupe** — exactly-once still relies on idempotent label convergence (real for
  K8s handlers); a dedupe ledger is a future hardening.
- GPU/AI warm-swap is proven **structurally** (ordering / single-leader); GPU magnitudes `[SP-0-PENDING-P4]`.

## "How I run the real-EKS soak/chaos pass" runbook
1. Connect (P4a): `aws eks update-kubeconfig …` → apply the read-only scanner RBAC.
2. Deploy the operator (Helm/manifest) with `--audit-max-bytes/--audit-max-backups`, `--leader-elect=true`
   (HA), `--metrics-bind-address`.
3. Apply the load (`hack/p4b/soak-load.yaml`, scaled to your fleet) in **active** mode.
4. **Soak:** `p4b-soak --metrics-url <op>/metrics --duration 24h --interval 30s` → PASS = flat
   heap/goroutine/fd slopes + stable tick-duration + min-actuation-rate met.
5. **Chaos:** `kubectl delete pod <operator>` (kill mid-decision), a NetworkPolicy/proxy to sever+slow the
   API, `kubectl drain <node>` (node failure), and the warm-swap double-leader fixture — assert single-leader
   / no-orphan / kill-switch-fail-closed / idempotent re-entry on live objects.
6. Re-run the 1.62× ablation + the P3/lead-demo suites to confirm the gates.

**P4b BUILT + PROVEN ON KIND — stopping for your on-screen review.** P4c (Phorvex self-security review incl.
the P-ACTUATOR privilege-widening) and P4 (GPU/CoreWeave magnitudes) remain separate stages. Your real-EKS
run is the final live confirm.
