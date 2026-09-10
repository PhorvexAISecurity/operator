# Phorvex — Runtime Validation & Self-Security Report

**Date:** 2026-08-20 · **Target:** live EKS demo cluster (vLLM tenant: Qwen2.5-7B-Instruct-AWQ on T4, guardrail sidecar, warm stand-in) · **Method:** everything below was executed live against the running brain (`phorvex:0.4.37`) and the model-serving stack. Nothing in this document is a static-analysis claim; every behavioral statement has a captured artifact (decision records, event objects, API receipts, probe outputs) in `runtime-audit/evidence/`.

This report complements the static audits. It covers the three areas the static work could not: **runtime/dynamic behavior**, **Phorvex's own security posture**, and **the full actuator pipeline as a closed loop**.

---

## 1. The headline: the loop closes with zero human-in-the-loop signals

We built and deployed two real, running detectors and watched the full pipeline — **sense → signal → decide → actuate → verify → stand down** — execute twice, for two different attack classes, with no hand-fired events and no policy edits.

### 1.1 Closed loop A — poisoned LoRA supply chain → `adapter-rotate`

**The detector** (`detector-adapter-inv`, a ~120-line Python Deployment with a least-privilege ServiceAccount): polls the serving engine's `/v1/models`, diffs loaded LoRA adapters against the expected set (empty), and on an unexpected adapter does both halves of the detection contract — stamps the pod marker the brain's recon consumes, and emits a `SecurityEvent` (`source=adapter-inventory-detector`, `type=lora.unauthorized_adapter`, critical). When the inventory is clean it removes its own signal.

**The attack** was launched from an unrelated workload (the CRM pod — a pod with no business relationship to the model server), over the plain cluster network, with no credentials:

```
POST /v1/load_lora_adapter  (from crm pod, via Service)  -> 200   (80MB crafted adapter "evil" hot-loaded)
poison probe through the adapter                          -> corrupted output served
```

**The loop, verbatim from the logs:**

| t (UTC) | stage | evidence |
|---|---|---|
| 18:04:50 | detector observes `['evil']`, flags marker + creates SecurityEvent | `UNEXPECTED adapter(s) ['evil'] on vllm/vllm-65b5489974-vgqqs — flagging` / `SecurityEvent adapter-inv-evil-…: create -> 201` |
| 18:05:09 | brain selects **adapter-rotate** (19s later) | `"action":"adapter-rotate","selected":true,"attribution":[{"source":"cover:adapterIntegrity","contribution":11.37}],"cost":0.03,"perDollar":379.03` |
| ~18:05:10 | actuator evicts the adapter, clears the marker, stamps epoch | handler receipt: `adapter-epoch=47083019`, marker gone |
| 18:05:20 | detector's next poll sees clean inventory → deletes its own SecurityEvent | `inventory clean — clearing signal` / `delete -> 200` |

**Effect verification (the part that makes this more than a selection demo):**
- probe through the adapter after the move → `HTTP 404 (adapter gone)` — the poison is verifiably out of the serving path;
- base model still serving normally;
- **pod UID unchanged** (`bc1a6549-…` before and after) — surgical, zero restart, zero downtime;
- the brain's own decision record notes the comparison: *"R6's blind timer would DELETE this pod on schedule; Phorvex used adapter-rotate instead — the workload keeps serving."*

### 1.2 Closed loop B — prefix-cache occupancy oracle → `kv-reset`, with measured effect

**The detector** (`detector-kv-canary`): plants a unique ~3,200-token nonce prefix into the engine's prefix cache, then re-probes it. Warm (fast) re-probe = planted attacker-observable state is still resident → emit `SecurityEvent` (`type=PromptInjection`, critical, the steering contract the brain maps to KV-session coverage). Cold re-probe = the flush worked → delete the event and retire.

**The trace:**

| t (UTC) | stage | evidence |
|---|---|---|
| 18:11:16 | plant + cold reference | `cold-ref=2.79s` |
| 18:11:28 | re-probe: **0.05s** → 55x gap = cache-resident → SecurityEvent created (201) | `CACHE-HIT (resident)` |
| 18:12:59 | brain selects **kv-reset** | `"action":"kv-reset","selected":true,"attribution":[{"source":"cover:session","contribution":3.79}]` |
| 18:13:02 | detector re-probe: **2.91s = cold** — the flush is *measured*, not assumed → deletes its events (200) | `canary cold — cache flushed; closing signal` |
| after | pod UID unchanged; `kv-reset-epoch` bumped 47085396 → 47085795 | receipts |

This is the answer to "we need to see the whole pipeline, the loop": the pipeline is **engine state → detector → SecurityEvent → fact minting → feasibility/SLO gates → selection → handler → engine admin call → independent re-measurement → signal retirement**. Both runs show every stage with timestamps, and — critically — the *verification* stage closes the loop: today Phorvex's brain trusts handler success; these detectors demonstrate the effect-verification pattern that should become a first-class stage (actuate → re-measure → confirm invalidation → close).

### 1.3 What the detectors taught us (engineering notes for the detection module)

These are real lessons from writing detectors against the live system:

1. **Active canaries re-plant what they probe.** vLLM caches every request's prefix, so a canary re-probe that finds the cache flushed *re-creates the resident state it is testing for*. A continuous "is it still there?" canary is self-defeating and, worse, keeps its SecurityEvent permanently live — which drives the brain to re-fire every anti-over-rotation window (we watched exactly this churn start). Production semantics must be **one-shot with retirement** (flag → on cold, close and never probe that canary again) or **passive** (metrics/audit-based). Our shipped detector now implements one-shot retirement.
2. **Detectors must own their signal lifecycle.** Each detector creates and deletes only its own events (by source). The brain currently has no event TTL/expiry — a detector that crashes leaves a live event behind and the brain will keep reacting to it. Signal expiry is a brain-side gap worth fixing (see findings table, R6).
3. **Failed observation ≠ clean observation.** The detectors treat a failed poll as *unknown* and never flap signals on errors. This matters: a detector that clears its event on a failed read would tell the brain "attack over" precisely when it's blind.
4. **Least-privilege detector RBAC is cheap.** Each detector runs under its own ServiceAccount: namespace-scoped `pods get/list[/patch]`, plus a shared ClusterRole for `securityevents create/delete/get/list` and nothing else. The pattern is a template for the detector plane.

---

## 2. Phorvex's own security — audited live

The static audits treated the brain as the defender. This section treats it as part of the attack surface. Four findings, three of them **live-confirmed**.

### R1 — CRITICAL: no admission control on `PhorvexPolicy` (live-confirmed)

A policy with `maxMovesPerTick: 1000000`, `antiOverRotationWindow: "0s"`, `proactiveFloor: "0s"`, `tickInterval: "1s"`, `minAvailableReplicas: 0`, zeroed cost weights, and `reactiveOnly: false` was **accepted** — first via server-side dry-run, then via a live apply scoped to an empty tenant, where the brain began ingesting and ticking it (`"policy accepted"`, `Ready: Ticking`). The CRD schema has **no bounds on any knob** (only `mode` has an enum); there is no validating webhook.

Anyone with policy-write can turn the protection system into a cluster-wide churn machine: 1-second ticks, unlimited moves per tick, no availability floor, no cost brake. **Fix:** CEL validation rules in the CRD (bounds on every numeric/duration knob) + a validating webhook; treat policy writes as a privileged control-plane operation (see R3).

### R2 — HIGH: the model-server admin plane is unauthenticated and unsegmented (live-confirmed)

From the **CRM pod** — an arbitrary workload with no relationship to the model stack — over the cluster network, with no credentials:

```
GET  /health                 -> 200
GET  /v1/models              -> 200   (full model inventory)
POST /reset_prefix_cache     -> 200   (KV cache flushed — the exact effect the kv-reset actuator exists to control)
POST /v1/load_lora_adapter   -> 200   (the B1 attack: hot-loaded an 80MB adapter into the serving path)
```

There are **no NetworkPolicies in the vllm namespace at all**. Consequences, concretely: any compromised pod can (a) flush the KV cache at will — a free availability attack, and a way to *erase evidence* of cache-side attacks; (b) load adapters if LoRA is enabled — the poisoned-adapter supply-chain attack requires zero privileges; (c) enumerate the served models. The brain's surgical actuators drive a control plane that every workload in the cluster shares. **Fix:** default-deny NetworkPolicy with an allowlist (gateway, brain, detectors); vLLM API-key/mTLS on admin routes; consider binding admin routes to a separate, unexposed port.

### R3 — HIGH: the brain can rewrite its own constraints (RBAC)

The brain's ClusterRole (`phorvex-phorvex-manager-role`) grants:
- `phorvexpolicies: update, patch` (+ status, + finalizers) — **the brain can edit the policy objects that constrain it** (budgets, windows, enabled actions). A compromised brain loosens its own leash;
- `pods/exec: create` cluster-wide — arbitrary command execution in any pod;
- `securityevents: delete` — can erase the trigger stream, including other detectors' signals.

Some of this is motivated (exec for ephemeral-debug workflows, policy/status for status writes), but the write scopes are far wider than the need. **Fix:** split the role — status-writer (policy/status only), actuator (namespace-scoped actuation role already exists and is well-shaped), event reader (get/list/watch, no delete); drop cluster-wide pods/exec or scope it to ephemeral containers in enrolled namespaces.

Additional hygiene item: a leftover test fixture Role (`costprobe-runner` in `phorvex-cost-validate-vllm`) holds `*` on everything in that namespace, including policy objects. Delete or scope it.

**What checked out:** the brain's pod runs `runAsNonRoot`, `allowPrivilegeEscalation: false`, all capabilities dropped. The kill-switch ConfigMap is *not* writable by the brain (read-only via its role) — the brain cannot un-kill itself. Its own self-annotation events (`source=PhorvexController`) are explicitly excluded from ingest, so the brain does not train on its own actuation noise. SecurityEvent creation is limited to admin planes and the (new) detector roles.

### R4 — Kill-switch: **works**, receipts below

Engaging the sentinel ConfigMap stopped all actuation within one tick (10s):

```
epoch before engage:        47090360
engaged for 120s:           decisions keep logging (by design), epoch UNCHANGED 47090360   <- zero actuation
policy status during:       killSwitchEngaged=true                                          <- honest status
disengaged +130s:           epoch 47092522                                                  <- actuation resumed
```

The decide-and-log-but-don't-act design means the audit trail continues during a freeze — exactly right for forensics. This is the availability story's keystone control, and it holds.

---

## 3. Availability & SLA behavior — what the brain does when things go wrong

### R5 — HIGH (SLA): standing `kv-reset` churn with zero attack signals (live, pre-existing)

While instrumenting the cluster we found the brain has been flushing the vLLM pod's KV cache **every ~110 seconds, around the clock, including before any of today's activity** (~5 moves per 10 minutes in every bucket sampled). Every decision record shows the same shape:

```
"action":"kv-reset","selected":true, "stage":"model-theft","hazard":1,"pHold":1,
"attribution":[{"source":"cover:session","contribution":3.79}]
```

There are **no SecurityEvents targeting that pod** (verified directly). The belief system permanently classifies a model-serving pod as under active model-theft attack at maximum confidence (pHold = 1.00) with zero evidence — the AI-stage classifier marks the pod "attacked" by virtue of being a model server, that classification feeds the evidence gate, and the reactive path then justifies a flush every time the 90-second anti-over-rotation window expires. (This is the live, production-posture instance of the belief-lifecycle findings in the math-validation report — the classifier-override and evidence-tautology issues compounding.)

On a real deployment this is a self-inflicted SLA wound: the prefix cache never accumulates, so TTFT for repeated-context workloads never improves — the protection tool is quietly taxing the very latency SLO it is supposed to protect. It also desensitizes operators: when everything is always "critical," nothing is. **Fix:** (a) the belief fixes from the math report — the AI stage classifier must not assert evidence, and stage/belief must decay without fresh signals; (b) a per-action proactive cadence cap so hygiene moves can't ride the anti-over-rotation window; (c) a low-cost "quiet" indicator in status when a move was hygiene rather than event-driven, so churn is visible as churn.

### R6 — Prometheus outage: silent degradation (live)

With the brain's Prometheus scaled to zero for 100+ seconds, the brain produced **zero operator-visible warnings** — no error logs, no status condition, nothing — while continuing to decide. Combined with the known static behavior (failed scrapes read as real zeros rather than as absent), the brain cannot distinguish "telemetry is down" from "the cluster is idle," and it doesn't say so. For an SLA-critical controller this is the dangerous direction: silent bad data is worse than a loud failure. **Fix:** surface scrape-failure as a status condition + metric; treat sustained signal failure as *unknown* (honest-absent) everywhere, which the physics layer partially does but the ingest layer does not.

### R7 — Guardrail tier false-positives on a benign probe (live)

The active guardrail variant (pgv2) blocked the benign canary prompt *"Reply with exactly the words SYSTEM NOMINAL and nothing else."* with `injection-score=1.000` — a full-confidence false positive on an instruction-shaped but harmless request. The two-variant guardrail tier is the strongest demo asset from the attack campaign, but as currently tuned the aggressive variant over-blocks; in production this is an availability cost paid by legitimate users. **Fix:** threshold calibration per variant + a shadow/observe mode before blocking; this also argues for the guardrail-rotate actuator remaining cheap, since variant personalities will need to change as classifiers are re-tuned.

### R8 — Detector silence (the zero-day posture): the brain keeps moving — with a caveat

With all detectors silent, the brain does not stop: proactive hygiene motion continues (that is the design — protection must not depend on detection, and zero-days emit no events). The caveat is R5: today the proactive/belief path over-fires, so "detectors down" currently means "churn continues." Once the belief fixes land, the intended posture — calm, cadence-capped hygiene when silent, sharp surgical response when detectors fire — is demonstrably achievable: both closed loops in §1 show the sharp mode, and the kill-switch (R4) bounds the worst case.

---

## 4. Findings summary

| # | sev | finding | status | fix in one line |
|---|---|---|---|---|
| R1 | CRITICAL | no admission control on PhorvexPolicy (any values accepted) | live-confirmed | CEL bounds in CRD + validating webhook |
| R2 | HIGH | vLLM admin plane unauthenticated, no NetworkPolicy | live-confirmed (POST 200 from arbitrary pod) | default-deny netpol + admin auth |
| R3 | HIGH | brain can rewrite its own policy / exec anywhere / delete events | RBAC-confirmed | split roles; drop policy write + pods/exec + event delete |
| R4 | — | kill-switch stops actuation within one tick, honest status | **verified working** | — |
| R5 | HIGH (SLA) | standing kv-reset churn (~110s cadence) on zero evidence; belief pinned at model-theft/pHold=1 | live, pre-existing | belief decay + evidence-gate fix + proactive cadence cap |
| R6 | MEDIUM | Prometheus outage is silent; zero-as-real persists | live (absence of any warning) | scrape-failure condition + honest-absent in ingest |
| R7 | MEDIUM | guardrail pgv2 blocks benign instruction-shaped probes (score 1.000) | live-confirmed | threshold calibration + observe mode |
| R8 | — | detector-silence posture: motion continues without detection | verified (see R5 caveat) | lands once R5 fixed |
| — | LOW | leftover star-permission test Role (`costprobe-runner`) | RBAC-confirmed | delete/scope |

Detector-side lessons (§1.3) are folded into the detection-module design: one-shot/retire semantics for active canaries, detector-owned signal lifecycle, unknown≠clean on failed polls, least-privilege detector RBAC template.

## 5. What this proves, and what remains

**Now proven live, end-to-end:** a detector emitting only a SecurityEvent (+ the documented pod marker for adapter-integrity) steers the brain to the correct surgical actuator; the actuator's effect is independently measurable in the serving path (adapter 404s; canary TTFT 0.05s→2.91s); workloads survive (UID unchanged in both loops); signals retire cleanly; the kill-switch halts actuation within one tick.

**Still open (next workstream candidates):**
1. **Effect-verification as a brain-internal stage** — today verification is external (the detectors did it). The brain should re-measure post-actuation and record confirmed/unconfirmed in the audit line (this also closes the epistemic hole the math audit flagged around self-scored success).
2. **Security hardening tickets**: R1–R3 are the minimum set before any shared-cluster story.
3. **Belief fixes** (R5) — the top SLA item.
4. **Soak + P/D-disaggregation runtime fixture** — the one actuator family with no live runtime evidence remains the disaggregated-KV path; the code-level work is done, the cluster fixture is the next build.
5. Event TTL/expiry in the brain (crash-safe signal lifecycle; §1.3 lesson 2).

*Artifacts: raw logs, decision records, event YAML, and probe outputs under `build/test-harness/runtime-audit/evidence/` (per-run directories `px-b1`, `px-b2`, `px-batch-a*`, `px-batch-c`). Detector sources: `runtime-audit/detector.py`, `runtime-audit/kv_detector.py`. Both detectors are still deployed in the `vllm` namespace, dormant and clean.*
