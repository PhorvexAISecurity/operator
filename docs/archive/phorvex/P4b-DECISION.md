# P4b-DECISION — soak + chaos + failure-mode harness (design for approval)

**Date:** 2026-06-07 · **Status: DESIGN — STOP for approval. Build nothing yet.** A persona-panel +
**premortem** search (3 code-readers → 10 world-class personas with adversarial scoring; 11 of 13 agents
returned, recovered from the journal after 2 personas failed to emit — the recovered set is fully
representative). The search did its job: beyond designing the harness, it **found real production defects** a
chaos pass would expose. Panel scores converged high (catches-premortem 9, threshold-rigor 8–9, fail-closed
8–9, both-products 8, gate-preservation 9–10).

> **HEADLINE (the premortem paid off — two real defects, verified at source):**
> 1. **The kill-switch FAILS OPEN on a read error.** `killswitch.go:44-46` returns `false` ("not engaged")
>    whenever the ConfigMap `Get` fails for ANY reason — API hiccup, RBAC, timeout, slow API. **Under a
>    severed/slow API the kill-switch reads as DISENGAGED and actuation PROCEEDS** — the exact opposite of
>    "uncertain ⇒ do not actuate." For an autonomous actuator this is the highest-severity fail-closed
>    violation.
> 2. **The warm-swap "crash-resume" is COSMETIC.** The persisted `phorvex.ai/swap-phase="flipping"`
>    annotation is **written but never read** (grep confirms zero readers). A crash in the window *after* the
>    shadow is promoted to `role=leader` but *before* the old leader is relabeled/deleted leaves a transient
>    **double-leader** (the Service routes to both); nothing scans for `swap-phase=flipping`/`role=retiring`
>    to converge it. The comment "crash-resume + idempotent dedupe" overstates the code.
>
> Plus: **no decision-id/RequestID dedupe** (exactly-once relies entirely on idempotent label convergence);
> **no per-tick context timeout** (a slow/hung API blocks the single tick goroutine — livelock surface);
> **audit JSONL is unbounded** (no rotation — disk-fill soak surface); **no orphaned-NetworkPolicy GC**;
> **leader-election OFF by default** (`--leader-elect=false` ⇒ two replicas both actuate — split-brain).

## What is ALREADY solid (verified — the harness will confirm these PASS)
- **Emit-boundary feasibility re-gate** — feasibility is re-run on the *live* view immediately before
  Actuate (action-agnostic, ignores the cached bool) → genuine fail-closed; plus the **dry-run guard**
  (runner + handler belt-and-suspenders, `errDryRunGuard`).
- **K8s handler idempotency is real** — each Enact reads live K8s state (rotate UID-precondition; quarantine
  `already-quarantined` label-guard; ephemeral-container name-key) → **safe idempotent re-entry** across a
  restart.
- **Rollback snapshots are READ on rollback** — quarantine/identity/route/endpoint restore from the
  `phorvex.ai/*-snapshot` annotation → real compensation.
- **Kill-switch re-read fresh each tick** (survives a restart — *except* the fail-open-on-error bug above).
- **Metric cardinality bound** (`ResetTenant` prevents a series leak); **NeutralPhysics/honest-absent
  telemetry** (no fabrication when Prometheus is down).

## A — SOAK (sustained load, MEASURED thresholds — no guesses)
Deploy the **UNCHANGED** operator on kind (native actuator, `--audit-json` on tmpfs, a stub `--prometheus-url`),
`--base-interval` compressed to **1–2 s** to pack ticks, against a **churn load generator** (M tenants × P
pods, labels flipped so top-B keeps selecting → a *steady actuation rate*). Run ≥4–6 h compressed
(~10k–20k ticks). **Detectors (additive monitor, regression not eyeball):**
- **Leak:** OLS regression **slope + 95% CI** on heap/goroutines/file-handles (`/metrics` + `/debug/pprof` +
  process fd count); PASS = slope CI upper bound below a **measured-baseline** drift floor, and the report
  states the **minimum-detectable-effect** for the window (a flat short slope is *necessary, not sufficient*;
  multi-day confirmation is EKS-deferred).
- **Drift:** tick-duration creep (NFR1 < 1 s), `lastTick` stall, decision-distribution drift (does sustained
  RLS/belief/exposure-clock state shift the decisions?).
- **Audit growth:** bytes/decision rate → projected disk-fill time (exposes the unbounded-append gap).
- **Anti-false-pass:** assert a **minimum** `actuations_total` + `decisions_total` rate (a too-quiet load
  makes every slope flat → false PASS); the SRE + statistician personas both flagged this.

## B — CHAOS / FAULT INJECTION (out-of-process; operator/actuator/harness UNCHANGED)
Each fault repeated **N ≥ 20–30** for a Bernoulli recovery-rate CI; **every assertion reads LIVE K8s objects
+ metrics, never log text** (log-only assertions are a false-pass vector). Injectors: `kubectl delete pod`,
a tiny **API-proxy** for sever + latency, Prometheus restart.
| Fault | Correct-recovery assertion (on live objects) |
|---|---|
| **operator SIGKILL mid-decision** | restart Ready ≤ 1 base-interval; **no duplicate actuation** (`actuations_total` delta ≤ B); idempotent re-entry; tick-1 burst ≤ Σ per-tenant B (`lastTick` zeroed) |
| **kill target pod mid-actuation** | no orphaned quarantine NP; rotate converges (idempotent); no stuck state |
| **kill operator mid-WARM-SWAP** (event-driven hook on `swap-phase=flipping`, **200 ms** EndpointSlice sampling) | **single `role=leader`** post-convergence; no strand (`SwapBlockedNoReadyShadow` ⇒ old leader serves) — **this is the test that exposes the double-leader gap** |
| **sever + restore API** | **kill-switch must read ENGAGED/skip** (exposes the fail-open bug); no actuation on uncertainty; clean reconnect |
| **slow API server** (latency proxy) | tick does not wedge; **exposes the missing per-tick timeout** |
| **Prometheus restart** | telemetry honest-absent → NeutralPhysics; decisions byte-identical (hash the JSONL) |

## C — FAILURE-MODE MATRIX (failure → expected fail-closed → measured actual)
operator crash · actuation mid-flight · API loss · telemetry loss · kill-switch during fault · budget
exhaustion · split-brain (leader-election). Each row: **expected = fail-CLOSED** (uncertain ⇒ no actuate),
**measured = live-object assertion over N runs with a recovery-rate CI**. The matrix will show **2 expected
FAILs against the current code** (kill-switch fail-open under API loss; double-leader under mid-flip crash) —
honest, not hidden.

## D — BOTH PRODUCTS
K8s actuations real. **AI/GPU warm-swap crash-resume tested STRUCTURALLY** — kill mid-`flipping`, assert
re-flip-to-alive-leader / no double-leader / no strand (the headline chaos test); mig-rebind/kv-reset fault
behavior. GPU magnitudes `[SP-0-PENDING-P4]` (kind has no GPU; the state-machine *ordering* is what's proven).

## E — FAIL-CLOSED PROOFS (positive + negative control each)
emit-boundary re-gate (mutate live state between decide+actuate → assert no actuation); dry-run (assert
`actuations_total == 0` while decisions flow); no-telemetry (hash decision JSONL == the no-telemetry
baseline); GPU fail-closed (handler returns fail-closed, pod untouched). Each paired with a **negative
control** (a case that *should* actuate does) so a PASS isn't just "nothing happened."

## KIND-verifiable NOW vs real-EKS-only
**Kind:** the compressed soak (leak/drift slopes + MDE), every fault injection + recovery assertion, the
structural warm-swap double-leader test, all fail-closed proofs, the two exposed defects. **Real EKS only:**
true **node failure** + cross-node pod reschedule, EBS/EFS detach-reattach for stateful, **multi-day** soak
(a slow leak below the kind-window MDE), and **leader-election split-brain** across nodes under real load.

## Requirement-coverage map
A soak (slope+CI+MDE, min-load) · B chaos (N≥20, live-object asserts, event-driven mid-flip) · C matrix
(fail-closed expected, measured actual, honest FAILs) · D both-products (warm-swap structural, GPU pending) ·
E honest (kind-vs-EKS) · ineligibility: **no fabricated numbers** (every recovery is a measured rate with a
CI), **no AWS creds** (kind + the user's EKS run), **not K8s-only** (AI crash-resume structural), **fail-closed
verified** (positive+negative controls). ✅ all covered.

## Gate preservation
The harness is **ADDITIVE** (new `test/soak`, `test/chaos`, a load generator, a metrics-slope analyzer, an
API latency/sever proxy — all out-of-process). It touches **no** decision/optimizer/recon/killchain/actuator/
Phoenix/attack-harness code. The 1.62× / P3 / lead-demo gates are preserved by construction + re-run as a
post-check.

## Honest risks
- **The soak proves *necessary-not-sufficient* on kind** — a multi-day leak below the window MDE is
  EKS-deferred (stated with the slope CI width).
- **The mid-flip crash window is microseconds** — a periodic SIGKILL misses it; an **event-driven** fault
  hook (gated on the `swap-phase` annotation) is required to land in it (else false PASS).
- **The two exposed defects mean Phorvex does NOT currently recover correctly** for (a) API-loss + kill-switch
  and (b) mid-flip crash. Honest P4b outcome.

---

## ⚠ THE SCOPE DECISION (your call — this is why I'm stopping)
The harness is purely additive and exposes the defects. But **"production-trustworthy" (the stated P4b goal)
requires that Phorvex actually fail-closed and converge** — and right now it does not, for two faults. The
fixes are small and targeted, but some touch files in your "unchanged" list:

- **IN-SCOPE reliability fixes (touch `internal/runner` + `internal/audit` — NOT brain/optimizer/recon/
  killchain-model/actuator/Phoenix/attack-harness):** (1) **kill-switch → fail-CLOSED** on read error (treat a
  Get error as engaged/skip-this-tick); (2) a **per-tick context timeout** (slow-API can't wedge the loop);
  (3) **audit-log rotation/cap**. These make Phorvex genuinely fail-closed + leak-bounded.
- **ACTUATOR-TOUCHING fixes (touch `internal/actuator` — which you listed as UNCHANGED, so explicit approval
  needed):** (4) a **warm-swap resume reconciler** that converges a wedged `flipping`/double-leader; (5) an
  **orphaned-NetworkPolicy GC**.

None of these change the *decision logic* (optimizer/physics/recon stay byte-identical; the 1.62×/P3/lead-demo
gates re-verify). They are reliability hardening — arguably the substance of P4b.

## Recommendation
**APPROVE the additive soak/chaos harness (Step 2) — it builds + proves on kind regardless.** Then choose the
fix scope:
- **(A) Expose-only:** ship the harness; the two defects are documented `[KNOWN-FAILING → fix follow-up]`;
  brain/actuator/runner strictly untouched. *Honest, but P4b's "it recovers" is FALSE for those two faults.*
- **(B) Expose + fix the in-scope reliability bugs** (kill-switch fail-closed, tick timeout, audit rotation —
  runner/audit only) — my recommendation; closes the highest-severity defect (an actuator that ignores its
  own kill-switch under API loss).
- **(C) Expose + fix all five** (also the actuator warm-swap reconciler + orphan-NP GC) — fully
  production-trustworthy; requires touching `internal/actuator` (the explicit approval).

**STOP — awaiting (1) approval to build the harness and (2) your fix-scope choice (A / B / C) before Step 2.**
brain/optimizer/recon/killchain-model + Phoenix + attack-harness stay UNCHANGED under all options.
