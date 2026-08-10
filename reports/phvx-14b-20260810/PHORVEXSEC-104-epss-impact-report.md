# PHORVEXSEC-104 (PHVX-14b) — EPSS impact measurement — report

Date: 2026-08-10 · Cluster `phorvex-dev-eks` (100 running containers, 70 pods, 41 image digests, 5 nodes)
Follows §4.1 of the earlier verification report: **measure the effect before building the feed.**

## Verdict: **do not build the CronJob yet — on its own it makes the ranking worse**

Expanding EPSS coverage at the current `MaxDispersionMult = 4.0` **reduces** the physics engine's
discriminating power. It only pays off if the clamp is re-fitted at the same time, and then it pays
off a lot. The two changes are complementary and must land together.

## 1. What was measured

The EPSS multiplier feeds one per-asset scarcity scalar (`ucw.go:47`):

```
s = ImageRarity · EPSS · CoResidency · [ModelRarity if GPU/model]
s = clamp(s, 1, MaxDispersionMult = 4.0)
```

`ucw.go` states the property that makes this measurable: *"With UNIFORM scarcity across the fleet the
ratio is unchanged … only DIFFERENTIAL dispersion lifts it."* So the question is not whether EPSS
raises the numbers — it always does, the multiplier is `1 + clamp01(...) ≥ 1` — but whether it lets
the engine tell assets **apart**.

Computed per live pod from the real inventory (namespaces per node, digest counts, GPU), using the
shipped formulas. `ModelRarity` is held at 1.0, its measured live value.

## 2. Result at the current cap

| | pinned at the 4.0 cap | distinct scalar values |
|---|---|---|
| today (7 containers covered) | **26 / 70 (37%)** | 8 |
| full coverage | **60 / 70 (86%)** | 8 |

Assets that can be told apart drop from 44 to 10.

At the live move budget (`maxMovesPerTick = 1` on every tenant) the decisive number is the size of the
tie group at the top, because everything in it is indistinguishable on physics:

```
today, cap 4.0 :  26 assets tied at 4.000
full,  cap 4.0 :  60 assets tied at 4.000
```

**This direction does not depend on the synthetic scores in §5.** The EPSS multiplier is bounded below
by 1 and is realistically 1.2–1.9, so multiplying a fleet in which 37% already sit at the cap can only
push more of it over. Broad coverage at a fixed cap is structurally saturating.

## 3. Result once the cap is re-fitted

The raw uncapped products span 1.875–7.500 today and 2.476–7.500 under full coverage, so a cap at 7.5
discards nothing:

| cap | today: pinned / distinct | full: pinned / distinct |
|---|---|---|
| **4.0** (current) | 26 (37%) / 8 | 60 (86%) / 8 |
| 5.0 | 7 (10%) / 9 | 37 (53%) / 16 |
| 6.0 | 3 (4%) / 11 | 11 (16%) / 34 |
| **7.5** | 0 (0%) / **12** | 0 (0%) / **41** |

At 7.5 the top tie group collapses to **1 asset** in both scenarios — physics actually decides.

So the honest summary of the two levers:

- **cap alone** (no EPSS work): 8 → 12 distinct values
- **EPSS alone** (cap unchanged): 8 → 8 distinct, and 26 → 60 assets tied at the top — *harmful*
- **both**: 8 → **41** distinct values

EPSS is worth roughly 3.4× the resolution of the cap change alone, and negative without it.

## 4. Recommendation

1. **Hand the cap sweep in §3 to PHVX-24 item 2** — it is exactly the measured input that item is
   waiting on, and it resolves the apparent circular dependency. That item is currently described as
   *"gated on EPSS"*; the truer statement is that the two must land together, and the sweep can be run
   now because it does not need the feed to exist.
2. **Then** build the CronJob (scan → FIRST.org lookup → `SeedEPSS`), with the digest-churn handling
   and the loaded-entry count from the previous report.
3. **Do not ship the feed alone.** It would move 34 more assets onto the cap and reduce ranking
   information, and the regression would be invisible without the saturation metric PHVX-74 asks for.

## 5. Validity

- The 37 uncovered digests are given **synthetic** EPSS/CVSS values (deterministic per digest,
  heavy-tailed, CVSS 4–10). Real scores could be less dispersed, so the **41 distinct values at cap
  7.5 is an upper estimate**. The harm at cap 4.0 is not an estimate — see §2.
- Read-only: `kubectl get pods -A`. No cluster mutation.
- Container count is 100; scalars are per pod, so the tables are over 70 pods.
- Script: `epss_impact_measurement.py`, raw output `epss-impact-output.txt`.
