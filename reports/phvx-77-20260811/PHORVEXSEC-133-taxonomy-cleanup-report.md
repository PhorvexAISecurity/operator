# PHORVEXSEC-133 (PHVX-77) — Taxonomy cleanup — report

Date: 2026-08-11 · Branch `fix/phvx-77-taxonomy-cleanup`

## Scope and delivery stack

| item | status |
|---|---|
| 1. `FactNodePlacement` is dead | ✅ removed |
| 2. `sideChannel` / `gpuColocation` share cover | ✅ delivered by PHORVEXSEC-121 / PR #31 |
| 3. `kv-migrate-invalidate → endpointPath` is a false grant | ✅ repointed to `session` |
| 4. `warm-swap` / `mig-rebind` share cover | ✅ delivered by PHORVEXSEC-121 / PR #31 |

This PR (#28) contains items 1 and 3. Items 2 and 4 are implemented in the dependent PR #31 after the
math owner resolved the open question: scheduler-dependent relocation cannot back deterministic
cover. That PR renames `FactSideChannel` to `FactGPUContentionChannel`, gives `mig-rebind` only that
contention fact on MIG-capable pods, and withdraws both `warm-swap` grants until anti-affinity can
guarantee relocation. The audited delivery order is **#12 → #28 → #29 → #31**: #12 first removes
the false `route-rotate` credit, then these three PRs clean and enforce the remaining taxonomy.
Together they close all four items without reintroducing a false distinction.

## 1. `FactNodePlacement` (item 1)

Confirmed dead: exactly two repo-wide references, its own doc comment and its declaration. No
producer, no consumer, no cover grant. Removed, with a note that the unrelated exposure variable
`model.VarNodePlacement` is still live so the two are not confused if this is ever reintroduced.

## 2. `kv-migrate-invalidate` (item 3)

It granted `endpointPath`. Invalidating or migrating a KV cache destroys the attacker's **in-pod
session state**; it does not change the inference **route** they learned, which is what `endpointPath`
represents and what `endpoint-rotate` erases. The grant asserted a defence the action does not
perform — the same false-credit class as PHVX-9e.

Now repointed to the `session` fact, looked up from the facts `standardRecon` already produced rather
than minting a second one, so there is exactly one session fact per asset and the key cannot drift.
The grant is skipped entirely if no session fact exists, rather than emitting a dangling key.

### A consequence of this change, disclosed

Repointing the grant creates a **new** identical-cover pair: `kv-migrate-invalidate` and `kv-reset`
now both cover `{session}`. This was found by the test written for PHORVEXSEC-120 immediately
afterwards, not overlooked.

It is accepted knowingly, as the lesser of two errors:

- the old grant was **false** — it claimed a defence the action does not perform;
- the new one is **true but indistinguishable** — and it is accurate today, because the capability
  that would separate the two is not built. `gpu_stack_p4set.go` returns
  *"kv MigrateRemote not built [PENDING-GPU-VALIDATION]"* for the cross-worker path, so only
  `InvalidateLocal` runs, and locally it does what `kv-reset` does.

Indistinguishable-but-true beats distinguishable-but-false. The practical cost is that the optimizer
will always take the cheaper of the two, so `kv-migrate-invalidate` cannot be selected on merit —
which is correct while it has no distinct capability. When `MigrateRemote` lands, the cross-worker
erasure is a different fact and the pair separates on its own.

The collision is recorded in PHORVEXSEC-120's `knownIdenticalPairs`, whose guard test fails the
moment it stops being real, so the exemption cannot outlive its cause.

## 3. Tests

**`TestKVMigrateInvalidateCoversSessionNotRoute`** — fails against the old grant with
*"kv-migrate-invalidate still claims endpointPath"*.

**`TestNoDeadFactKinds`** — every declared kind must be emitted by some registered profile on some
archetype.

> **This test was rewritten after it failed to do its job.** The first version hand-listed the
> declared kinds, so re-declaring `FactNodePlacement` did **not** fail it — a test that could only
> catch the dead kind someone had already found. It now parses the `Fact*` constants straight out of
> `facts.go` with `go/ast`, and re-declaring the dead kind fails it by name.

**`TestIdenticalCoverIsStillOutstanding`** records the pre-#31 state on this branch. PR #31 deletes
that transitional test after splitting the cover. The general PHORVEXSEC-120 guard then enforces the
result and removes the pair's self-expiring exemption.

## 4. Not claimed

- This PR alone makes no behavioural change to `warm-swap` or `mig-rebind`; dependent PR #31 does.
- No live-cluster measurement; both fixes are proven against the real `ucwRecon.AssetFacts` path.
- Full suite green apart from `TestScenariosExport`, which fails identically on `origin/main` and is
  fixed separately under PHORVEXSEC-123.
