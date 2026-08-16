# PHORVEXSEC-98 (PHVX-10c) — Verify the RLS calibrator is actually learning in production

Date: 2026-08-11 · audited 2026-08-12 · Branch `feat/phvx-10c-rls-match-rate`
Stacked on PHORVEXSEC-84 / PR #19 (`feat/phvx-2-rls-offswitch`).

## Headline: it is not learning, and the reason is not the one the ticket expected

Measured on `phorvex-dev-eks` over a **10 h 21 m** window:

```
2360 decisions   ->   ALL kv-reset
   0 rotations
   0 matched      0 censored      0 abandoned
```

The match rate is **0 / 0** — not a low ratio. The calibrator is not failing to pair rotations with
replacements; **it is receiving no input at all**, because only a `rotate` trains the rotation cost
model and the engine has not selected one in ten hours.

This rules out the ticket's stated suspicion — *"high attempts with near-zero matches"* — on this
fleet. That failure mode would have produced a large `abandoned` or `censored` count. There is
nothing to match.

## 1. Why the distinction matters

The ticket asked for the match rate rather than just `Primed()` because "why not" has several
answers with different fixes. Those are now separate series:

| outcome | meaning | what it would imply |
|---|---|---|
| `matched` | a replacement pod was found; θ trained on a real measurement | working |
| `censored` | nothing became Ready inside the window; trains at the censored maximum | replacements are slow or never arrive |
| `abandoned` | the **original** UID was still alive when the window expired | the actuation never took effect — an **emit-path** failure, not a cost-model one |

Collapsing these into a single counter would have hidden exactly the difference the ticket is
asking about. `0/0` is a fourth answer again, and it is only legible because attempts are counted
separately from successes.

## 2. What was added

Per tenant, on the existing `/metrics` endpoint:

```
phorvex_rls_rotation_observations_total{tenant,outcome}   matched | censored | abandoned
phorvex_rls_rotations_pending{tenant}                     current backlog
phorvex_rls_primed{tenant}                                1 = has left the shipped prior
phorvex_rls_updates_total{tenant}                         observations folded in
```

**Metrics, not the audit record**, as the ticket specifies — the audit output is an unversioned
contract owned by PHVX-27.

`RLS.Updates()` was added alongside `Primed()`. `Primed()` is a boolean and cannot distinguish one
lucky match from genuine calibration; the count can. Both are in-process and reset on operator
restart, which is deliberately visible: a calibrator that never survives long enough to prime looks
identical to one that never matches unless the reset is observable.

## 3. Counting discipline

Outcomes are recorded **once per rotation leaving the pending set**, not once per tick it is
examined. `TestOutcomeIsCountedOncePerRotationNotPerTick` asserts this: three ticks over an
unresolved rotation must produce zero outcomes, the resolving tick produces exactly one, and later
ticks must not count it again.

Without that, `matched / total` would measure tick cadence rather than matching success — the ratio
would drift while nothing changed.

The audit also found a gauge-lifecycle edge: after a tenant's pending queue drained,
`phorvex_rls_rotations_pending` retained its last nonzero sample because only tenants still present
in the queue were updated. The manager now publishes an explicit zero for previously seen tenants
when their queue drains. `TestPendingGaugeReturnsToZeroWhenQueueDrains` locks that correction.

## 4. Ticket checklist

| item | status |
|---|---|
| Instrument the match rate, per tenant | ✅ three outcomes, separate series |
| Expose `Primed()` and the per-tenant observation count, via metrics | ✅ `phorvex_rls_primed`, `phorvex_rls_updates_total` |
| Check production and record the result per tenant | ✅ §Headline — 2360 decisions, 0 rotations, 0/0 match rate |
| If unprimed, establish why before changing anything | ✅ cause identified: **no rotations**, not matching failure. Nothing changed in the decision path |
| Remove the stale `[SP-0-PENDING-P4a]` marker | ✅ already absent from the tree (verified) |
| Verify safety rails exist (clamp, rate cap, revert-to-prior) | ✅ delivered under PHORVEXSEC-84 / PR #19: output clamp existed; a per-observation θ bound and a documented off-switch were added there |
| Add the convergence test | ✅ `cost/p1cost_test.go:25` converges toward the observed 0.05; `TestRateLimitStillConverges` (PR #19) pins that the rate cap does not block it |

## 5. The finding underneath the finding

`kv-reset` never trains the rotation cost model. On a fleet whose traffic is almost entirely
AI-serving workloads, `kv-reset` is the cheap correct answer nearly every tick — so the cost model
for `rotate` will stay at the shipped prior indefinitely, on this fleet, by design rather than by
defect.

That matches the earlier PHORVEXSEC-84 measurement from a different window: of 1025 decisions, 1020
were `kv-reset` on the `vllm` tenant, and the only calibrated cost seen came from `pxtest`, which had
5 rotations.

**Consequence worth stating plainly:** `θ` for rotation is an assumption on every tenant that does
not rotate, and the prior `[0.15, 0.85, 0.55, 0, 0.45, 0.20]` has no cited derivation. The counters
now make that visible instead of leaving it to be inferred arithmetically from decision costs, which
is how PHORVEXSEC-84 had to establish it.

## 6. Not claimed

- **The metrics have not been observed in production.** This revision is not deployed; the production
  numbers in §Headline were reconstructed from the live operator's audit log, which records the same
  events the counters increment on. The counters themselves are proven by unit tests against the real
  `observeReadyRotations` path.
- No decision-path behaviour was changed. This adds observation only.
- A tenant that never rotates will now publish `phorvex_rls_primed = 0` permanently. That is correct
  and is the point, but it should not be alerted on without the rotation count beside it.
