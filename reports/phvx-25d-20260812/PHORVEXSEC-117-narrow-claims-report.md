# PHORVEXSEC-117 (PHVX-25a) — GPU co-residency cover made capability-conditional — report

Date: 2026-08-12 · Branch `fix/phvx-26a-gpu-cover-split`
Items 1 and 2 are delivered by the PHORVEXSEC-121 change on this same branch; this report covers the
whole ticket and item 4.

## Status by item

| item | status |
|---|---|
| 1. Make the `gpuCoresidency`/`sideChannel` grant capability-conditional, per-tick from live inventory | ✅ delivered with PHORVEXSEC-121 — and **stronger** than asked: `warm-swap` receives no grant at all |
| 2. Amend `cover_test.go` in the SAME commit | ✅ done in that commit, both directions asserted |
| 3. Annotate `PX_Reports_V1/coversets/COVERSETS-DECISION.md` §4.1 | ✅ added and versioned on this branch; §4.1 records the capability boundary and restoration prerequisites |
| 4. State the narrow true claims wherever these actuators are described | ✅ this change |

## Why item 1 came out stronger than specified

The ticket proposed gating `warm-swap` on **≥2 schedulable GPU nodes**. The math review concluded
that is *necessary but not sufficient*:

> A scheduler-dependent relocation does not satisfy the requirement, because without a hard placement
> constraint the scheduler may place the shadow on the original node.

So the conditional grant the ticket asks for cannot be built today at all: until required
`podAntiAffinity` on `kubernetes.io/hostname` lands — deferred by PHVX-26a — there is no capability
that would make the grant sound. `warm-swap` therefore covers nothing, and both facts are audit-only.

`mig-rebind` keeps a conditional grant, on per-pod MIG capability, and only for
`gpuContentionChannel`.

## Item 4 — the narrow claims

The false claim lives in `internal/console/scenario_meta.go`, which is **customer-facing**: it tells
an operator which actuator answers which attack. Naming an action that cannot deliver is a claim, and
it is read far more often than any report appendix.

```
before   side-channel | co-location  ->  [mig-rebind, warm-swap]
         gpu                         ->  [mig-rebind, warm-swap]

after    side-channel                ->  [mig-rebind]
         co-location                 ->  []          (no autonomous remedy today)
         gpu                         ->  [mig-rebind]
```

The narrow true statements, now written at the site:

- **`mig-rebind`** severs the memory/cache/SM **contention** path by repartitioning the device. The
  pod does not move, so the attacker's knowledge of *who shares it* survives. MIG reconfiguration
  also requires zero CUDA contexts device-wide, so it works on an **idle** GPU — not during a live
  multi-tenant incident.
- **`warm-swap`** performs a cutover with no cold load. That is genuinely valuable, unchanged, and
  unrelated to co-residency.
- **Co-location** has no autonomous remedy. It is a **provisioning** property; the real fix is
  device-plugin capacity, not a moving-target action.

`TestCoLocationHasNoFalseRemedy` and `TestSideChannelRemedyIsMigRebindOnly` bind these to the code.
Restoring the old lists fails the first on all three co-location scenario names.

## Item 3 — decision record is now in-repository

The referenced decision file was absent from every branch, so this branch creates and versions
`PX_Reports_V1/coversets/COVERSETS-DECISION.md` instead of leaving the accepted math out of band.
Section 4.1 records that `gpuCoresidency` is Tier-1 only where a deterministic eraser exists; its
eraser set is empty on T4-class, single-GPU-node, and otherwise incapable fleets. It also records the
anti-affinity, schedulability, asymmetric-debounce, and zero-credit conditions that must all hold
before `warm-swap` can regain cover.

## Not claimed

- No live-cluster verification. `warm-swap` and `mig-rebind` are not exercised on the fleet by this
  change; unit tests bind the narrowed claims and the failed-repartition credit path.
- The asymmetric debounce agreed in the math review is **not** implemented — it guards the
  fleet-level capability that only `warm-swap`'s withdrawn grant needs. It is a prerequisite for
  restoring that grant, not for this change. Reasoning is in the PHORVEXSEC-121 report.
