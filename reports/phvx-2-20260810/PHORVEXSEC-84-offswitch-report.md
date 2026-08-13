# PHORVEXSEC-84 (PHVX-2) — step 3, the off-switch — completion report

Date: 2026-08-10 · Branch `feat/phvx-2-rls-offswitch` · Commit `3d5308f`
Completes the last open item. Steps 1, 2, 4 and 5 were verified earlier
(`PHORVEXSEC-84-live-verification.md`), including live proof that θ really does adapt.

## What was missing

The ticket's "Done when" reads: *"θ demonstrably adapts to measured costs, **with a documented
off-switch**."* The first half was proven on `phorvex-dev-eks`. The second half did not exist —
`grep -inE "revert|disable|freeze|kill"` across `internal/cost` returned nothing, and the engine-wide
`KillSwitch` gates **actuation**, not learning.

There was an *accidental* off-switch: RLS state is in-process, so restarting the operator resets θ.
That is not a control. It is undocumented, all-or-nothing across every tenant, and requires bouncing
the defence to use.

## What shipped

**1. `RLS.SetFrozen` — revert, not pause.** Freezing restores the shipped prior instead of holding the
last learned value, so the result is the documented nil-data behaviour rather than a snapshot of
whatever the operator just stopped trusting. Unfreezing resumes *from the prior*; the discarded
calibration is not restored. That is deliberate and asserted, because a control that quietly brings
back a distrusted model is not a safety control.

**2. A bound on how far one observation may move θ.** `Predict` already clamped the **output**;
nothing bounded the **parameter**. Measured with the guard removed:

```
one absurd observation -> theta[0] moves 497.04 in a single update
```

A pod that took 300 s to become Ready because its node was draining is, at this layer,
indistinguishable from a genuinely expensive rotation — and RLS's forgetting factor is designed to
follow the new level, so the outlier sticks until many clean samples walk it back. `maxThetaStep` is
0.25, a quarter of the largest prior weight, and `TestRateLimitStillConverges` pins that a real trend
still converges to the observed value. It is a rate limit, not a correctness bound.

**3. A runtime switch that needs no restart.** Read every tick from the `costCalibration` key of the
same sentinel ConfigMap the actuation kill-switch already uses:

```yaml
kubectl -n phorvex-system patch configmap phorvex-killswitch \
  --type merge -p '{"data":{"costCalibration":"off"}}'
```

A CLI flag would have been the easier option and the wrong one: a flag needs a restart, and a restart
already wipes the state, so the flag would only be a slower version of the accident.

Two asymmetries against `KillSwitch.Engaged`, both deliberate:

- **Separate key.** Freezing actuation and freezing learning are different decisions. An operator may
  want the defence to stop moving while the cost model keeps observing, or the reverse.
- **A read failure does NOT fail closed.** `Engaged` fails closed because acting on an unreadable
  kill-switch is dangerous. Here the dangerous direction is inverted — freezing discards every
  tenant's calibration — so an unreadable sentinel holds the current state instead.

## Per-tenant subtlety

The RLS is per tenant and buckets are created lazily, so a switch applied only to existing buckets
would silently miss the next tenant the engine sees. `SetCostCalibrationFrozen` records the flag and
applies it at bucket creation. It is also idempotent, which matters because it runs every tick and
freezing has a side effect: without that, an already-frozen learner would be re-reverted forever.

## Tests

| test | pins |
|---|---|
| `TestFreezeRevertsToPrior` | frozen `Predict` returns the prior **exactly** — fails without the revert with `0.055` against `1.15` |
| `TestFrozenLearnerIgnoresObservations` | 100 updates move nothing while frozen |
| `TestUnfreezingResumesFromThePrior` | the discarded estimate is not restored |
| `TestSingleObservationCannotSwingTheta` | one sample cannot exceed the cap — fails without it at **497.04** |
| `TestRateLimitStillConverges` | the cap does not disable learning |
| `TestFreezeAppliesToTenantsCreatedLater` | a tenant first seen after the freeze does not start learning |
| `TestFreezeIsIdempotent` | setting the switch to its current value is a no-op |

Full suite green apart from `TestScenariosExport`, which fails on `main` too (`bin/scenarios-instances.jsonl`
is a generated fixture absent from this checkout).

## Ticket status

| step | status |
|---|---|
| 1. confirm caller count | ✅ verified earlier |
| 2. wire into the post-action feedback path | ✅ verified earlier |
| 3. safety rails (clamp / rate cap / revert-to-prior) | ✅ **this change** |
| 4. convergence test | ✅ existed |
| 5. remove `[SP-0-PENDING-P4a]` | ✅ existed |

**PHORVEXSEC-84 can be closed** once this merges.

## Not claimed

- **Not exercised on the live cluster.** The sentinel key has not been flipped on `phorvex-dev-eks`;
  doing so would freeze calibration on a running defence and needs the team's agreement. The mechanism
  is proven by tests against the real `Update`/`Predict`/`costFor` paths.
- The learner is still **unobservable from outside** — `Primed()` and now `Frozen()` are exposed in no
  metric or endpoint, so "is calibration on?" still cannot be answered without reading decision costs
  arithmetically. That is PHORVEXSEC-98's scope, not this ticket's.
- `maxThetaStep = 0.25` is a judgement, not a derivation. It belongs in the constants registry
  (PHVX-24) alongside the other unvalidated values.
