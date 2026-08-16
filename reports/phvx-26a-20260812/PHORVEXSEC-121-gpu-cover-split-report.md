# PHORVEXSEC-121 (PHVX-26a) — split the GPU cover — report

Date: 2026-08-12 · Branch `fix/phvx-26a-gpu-cover-split`
Implements the math resolution recorded on the ticket. Also closes the math items of **PHORVEXSEC-117**.

## The defect

`mig-rebind` and `warm-swap` held **byte-identical** cover: `{gpuColocation, sideChannel}`.

Two consequences, both invisible to the objective:

1. The optimizer cannot tell them apart, so it always takes the cheaper one and the other can never
   be selected on merit — however different their real physical effects are.
2. Both grants asserted more than either action performs.

## The soundness condition applied

> A fact may belong to `CoverByAction[a]` only if **every successful execution of `a` invalidates
> it.** There is no probabilistic or expected-cover reading in this model.

Applying it:

| action | grant | why |
|---|---|---|
| `mig-rebind` | `{gpuContentionChannel}` only, **and only on a pod with a MIG device** | repartitioning destroys the mapped GI/CI structure deterministically wherever the pod ends up — but it does **not move the pod**, so co-residency knowledge survives. It never covers `gpuColocation`. |
| `warm-swap` | **nothing** | `rewarmShadow` clears `NodeName` and hands the pod back with identical constraints. Nothing expresses anti-affinity, so the scheduler may re-place it on the same node. "May relocate" cannot back a binary grant — nor can a high empirical relocation rate, nor the existence of a second GPU node. Anti-affinity is deferred by this ticket, so both facts stay audit-only. |

## The rename

`FactSideChannel` → `FactGPUContentionChannel`, rescoped to the **memory, cache and SM contention**
path. Power and thermal channels are explicitly **not** claimed: MIG's isolation of those is a vendor
claim and is contested in published work, so an action that repartitions the device cannot be said to
erase them.

The old name described a *symptom class*; the new one names something an action can actually
invalidate — which is the only kind of thing that belongs in a cover set.

## ⚠ Behaviour change, stated plainly

**`warm-swap` becomes unselectable on this fleet**, exactly as `identity-rotate` did under PHVX-9e.

Its real value — a cutover with no cold load, avoiding a 60–400 s model warm-up on the serving path —
is unaffected and unchanged. Only its co-residency claim was false. An action that cannot be selected
is the honest state for an action whose only cover claim does not hold.

## The trap this ticket warned about

Withdrawing the grants breaks `TestDefensiveActuatorsHaveCover`, whose obvious "fix" is to put the
two actions back into the non-empty list — restoring exactly the false grants this removes. That is
the PHVX-9e trap, and the ticket asks for the test to be amended **in the same commit**. It is.

Both directions are now asserted explicitly, so neither can drift back silently:

- `warm-swap` must have **no** cover — including on MIG-capable hardware;
- `mig-rebind` must have **no** cover on a pod without a MIG device;
- `mig-rebind` on a MIG-capable pod must cover **exactly** `{gpuContentionChannel}` — not a superset.

Regression-verified: restoring the old grants fails the test with
*"warm-swap must have NO cover until anti-affinity lands; got [gpuColocation gpuContentionChannel]"*.

## Acceptance check from the ticket

> *"Confirm with `TestGreedyIsExactOnShippedFleets`."*

```
MEASURED: greedy=exact ratio=1.000000000000 gap=0 disjoint=true
```

Unchanged. Both keys stay pod-scoped and asset-prefixed, so the ownership invariant holds and the
split is structurally free.

## Not implemented here, deliberately

**The asymmetric debounce** (activate after 3 consecutive positive ticks, withdraw immediately on the
first negative) is specified and agreed, but it guards a **fleet-level** capability — "≥2 schedulable
GPU nodes" — which exists only for `warm-swap`, whose grant is withdrawn. A recon profile sees one
workload view, not the node inventory, so wiring it would mean extending `FactContext` and the
generator to carry cross-tick fleet state in order to gate a grant that must not exist yet.

`mig-rebind`'s capability is per-pod (`MIGDevice`) and does not oscillate with node drains, so it
needs no debounce today.

**The debounce is therefore a prerequisite for restoring `warm-swap`'s grant, not for this change.**
It should land with the anti-affinity work.

The remaining two acceptance edges are delivered on this branch too:

- `TestMIGRebindRepartitionFailureEmitsNothing` proves that a physical repartition failure returns
  an error with `Emitted:false`; manager therefore records no actuation and awards no cover credit.
- `PX_Reports_V1/coversets/COVERSETS-DECISION.md` versions the accepted distinction, scope, current
  audit-only state, and all prerequisites for restoring `warm-swap` cover.

## Stack integration and self-expiring exemption

The audited delivery order is PHORVEXSEC-94 (#12) → PHORVEXSEC-133 (#28) →
PHORVEXSEC-120 (#29) → this PR (#31). PR #12 first removes the false `route-rotate` credit; PR #29 initially
needs a `mig-rebind|warm-swap` exemption because the collision still exists at that layer. This PR
splits the cover, so its `TestKnownCoverCollisionsStillExist` guard immediately requires deletion of
that now-stale exemption. The entry is removed here, in the same integrated branch where the cause
ceases to exist.
