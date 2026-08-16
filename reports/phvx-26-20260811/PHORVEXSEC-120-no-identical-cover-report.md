# PHORVEXSEC-120 (PHVX-26) — Test: no two actuators may share identical cover — report

Date: 2026-08-11 · corrected 2026-08-12 · Branch `test/phvx-26-no-identical-cover`

## Why this test exists

Two actions with byte-identical cover sets are **indistinguishable to the optimizer**. It takes
whichever is cheaper, and the other can never be selected on merit however different their real
physical effects are. The objective cannot see the difference, so no amount of tuning fixes it — it
is a modelling error that has to be caught structurally.

## What was built

`TestNoTwoActuatorsShareIdenticalCover` — for every registered recon profile × every archetype,
assert no two actions share a cover set.

**Archetypes are derived, not hand-listed**, as the ticket requires. The gates that decide which
facts a profile emits are `HasGPU || ModelID != ""` (the AI block), `SuspectAdapter != ""`
(adapter-integrity) and `HasGPU || Stateful` (in-memory/session weighting), so the archetype space is
the generated boolean product of those four inputs — all 16 combinations.

`TestKnownCoverCollisionsStillExist` is the inverse guard: every exemption must still be observable.
The moment its cause disappears the suite fails and requires deletion of the stale exemption.

## What it found

It caught a collision **created an hour earlier by PHORVEXSEC-133**, which repointed
`kv-migrate-invalidate` from `endpointPath` to `session` and thereby made it identical to `kv-reset`.
That is the test doing exactly its job on its first run, against a change that had already been
reviewed and pushed.

On the corrected stack the test finds **two** non-empty pairs. Both are truthful current limitations
and remain self-expiring exceptions:

| pair | disposition |
|---|---|
| `mig-rebind` / `warm-swap` — `{gpuColocation, sideChannel}` | recorded here; **split by PHORVEXSEC-121 (#31)** in the next stack layer |
| `kv-migrate-invalidate` / `kv-reset` — `{session}` | accepted knowingly — see below |

The KV pair is accurate rather than wrong: `gpu_stack_p4set.go` returns *"kv MigrateRemote not built
[PENDING-GPU-VALIDATION]"*, so the cross-worker path that would distinguish the two does not run, and
locally `kv-migrate-invalidate` does what `kv-reset` does. Indistinguishable-but-true is the better
of the two available states; the previous grant was distinguishable-but-false.

An earlier version of this PR tried to distinguish `quarantine` and `route-rotate` by inventing a
`networkReachability` fact. That was unsound: PHORVEXSEC-94 (#12) proves that `route-rotate` only
writes an unused label and does not invalidate network identity. The corrected stack keeps
`route-rotate` coverless and skips empty-cover pairs here, as the ticket requires. This PR no longer
changes production facts, weights, or decision goldens.

## The exemption cannot rot

The ticket says *"do not loosen the assertion"*. An exemption list is a loosening unless it expires,
so it is paired with `TestKnownCoverCollisionsStillExist`: every exempted pair must still be a real
collision. The moment PHORVEXSEC-121 splits `warm-swap`/`mig-rebind`, or `MigrateRemote` lands, that
test fails and forces the entry to be deleted rather than left weakening the assertion forever.

Verified by substituting a fake pair into the list: the guard fails with *"exempted pair … no longer
shares cover … delete it from knownIdenticalPairs so the assertion is strict again."* The actual
test file is `internal/recon/no_identical_cover_test.go`; the earlier PR accidentally committed only
this report, which is corrected by the follow-up commit on the same branch.

## Merge order

The complete delivery order is **#12 → #28 → #29 → #31**. This branch is based on #28 because the
`kv-migrate-invalidate` exemption describes the state that taxonomy change creates; #28 is based on
#12 so the invariant is evaluated after the false `route-rotate` grant has been removed. Merging #29
without its base would leave exemptions for a different model state and correctly fail the inverse
guard.

## Not claimed

- No production behaviour changed; this adds tests only.
- The two collisions are recorded, not fixed. Fixing them is PHORVEXSEC-121 and the `MigrateRemote`
  implementation respectively.
- Empty cover sets are skipped — that is PHVX-18's subject, not this test's.
