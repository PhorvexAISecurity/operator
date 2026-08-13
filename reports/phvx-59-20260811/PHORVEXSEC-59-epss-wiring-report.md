# PHORVEXSEC-59 — `SeedEPSS` unwired → physics runs without real EPSS signal — report

Date: 2026-08-11 · Branch `fix/phvx-59-epss-ranking-test` · Commit `ee36744`

## Verdict: the premise is stale, but the ticket was **not** already satisfied

The headline claim — *"`SeedEPSS` is unwired"* — is false. Two of the three acceptance criteria were
already met and **neither was recorded anywhere**, which is why the ticket still looked open. The
third was genuinely missing, and it is the one that would have caught a regression.

| Acceptance criterion | Status before | Evidence |
|---|---|---|
| EPSS values flow into `PhysicsWitness` | ✅ already true | `platform.go:137` — `w.EPSS = epssMultiplier(p.ImageID)`; field at `model/types.go:247` |
| `[SP-0-PENDING-P4a]` marker cleared | ✅ already true | zero occurrences in the tree |
| **test proves non-neutral EPSS changes ranking** | ❌ **missing** | no test tied EPSS to ranking |

## 1. Why the missing test mattered

The nearest existing coverage is `internal/decision/ucw_ablation_test.go`, which sets

```go
ph.EPSS = 2.0        // known-exploitable
```

by hand. That exercises the **consumer** of the multiplier but not its **source**, so it would still
pass with `SeedEPSS` completely disconnected — which is precisely the failure this ticket alleges.
The wiring was correct and entirely unguarded.

## 2. What was added

Two tests in `internal/platform/epss_ranking_test.go` driving the real chain
`SeedEPSS → epssMultiplier → PhysicsWitness`, keyed on an image digest:

**`TestSeededEPSSReachesPhysicsWitness`** — a seeded score arrives as the expected multiplier
(`EPSS 0.97, CVSS 9.8 → 1 + clamp01(0.5·0.97 + 0.5·0.98) = 1.975`), and an image with no cache entry
stays at the honest-absent `1.0`.

**`TestNonNeutralEPSSChangesRanking`** — two pods identical in every respect except whether their
image has a cache entry, so any ordering change is attributable to EPSS alone:

```
empty cache   ->  scarcity ratio 1.0000   (exact tie)
seeded        ->  scarcity ratio 1.9750
```

## 3. Regression-proven

Replacing `w.EPSS = epssMultiplier(p.ImageID)` with the unwired state the ticket describes:

```
TestSeededEPSSReachesPhysicsWitness   FAIL — seeded pod reads 1, want 1.975
TestNonNeutralEPSSChangesRanking      FAIL — ratio collapses to 1 (2 vs 2)
```

So the guard actually detects the alleged defect rather than merely passing beside it.

## 4. The limit of this claim, written into the test

These prove the **mechanism**. They do **not** prove EPSS changes ranking on the current cluster, and
the test says so in a comment rather than leaving it to be rediscovered.

Measured under PHORVEXSEC-104 on `phorvex-dev-eks`: the uncapped dispersion product already spans
**1.875–7.500** against `MaxDispersionMult = 4.0`, so **26 of 70 pods (37%) are pinned at the cap**
and an EPSS lift on those is discarded before it reaches a decision. In PHORVEXSEC-104's synthetic
full-coverage scenario, widening EPSS coverage without re-fitting that cap moves **60 of 70 pods
(86%)** onto it and reduces ranking resolution. Those magnitudes are scenario estimates; the
direction of additional saturation at a fixed cap is structural.

The fixtures therefore carry no other dispersion, so the clamp is not what is being measured — and an
assertion fails if a fixture ever drifts above 4.0, which would silently turn the test into a
measurement of the clamp instead of EPSS.

## 5. Relationship to other tickets

- **PHORVEXSEC-104 (PHVX-14b)** covers the live feed: the cache is hand-populated, no CronJob exists,
  and coverage is 7 of 100 containers. This ticket is about the wiring being provable; that one is
  about the data being present. They are not duplicates, and 104 should not be closed by this.
- The cap re-fit is **PHORVEXSEC-115 item 2**, currently with the math owner. The measured percentile
  answer was supplied under PHORVEXSEC-130.

## 6. Not claimed

- Not that EPSS currently influences any live decision. §4 says the opposite for most of the fleet.
- No live-cluster run: this is a unit-level proof against the real `genericK8s.Derive` path.
- The full suite is green on this branch apart from `TestScenariosExport`, which fails identically on
  `origin/main` and is fixed separately in PHORVEXSEC-123.
