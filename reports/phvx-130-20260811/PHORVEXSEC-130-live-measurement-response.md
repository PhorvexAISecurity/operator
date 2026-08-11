# PHORVEXSEC-130 (PHVX-74) — response to the Scale Calibration Audit

**From:** Milad · **Date:** 2026-08-11
**In reply to:** `PHVX-130-scale-calibration-audit-and-run-spec.md`
**Cluster:** `phorvex-dev-eks` (us-east-2) — 100 running containers, 16 namespaces, 5 nodes, 41 image digests

---

## 1. Summary

Your §5 provisional rules were run against the live cluster. Both audited caps fail your own
saturation criterion at their current values, so the answer to "should these move" is yes, and the
percentile rule gives a concrete target for each.

| Scale | Current | P95 rule gives | Saturation at the current value | Your threshold |
|---|---:|---:|---:|---:|
| `CoResidencyCap` | 4.0 | **7.80** | **80%** of nodes | 10% |
| `MaxDispersionMult` | 4.0 | **5.10** | **26%** of assets | 10% |

At `MaxDispersionMult = 5.10` saturation falls to 5%.

Three findings that were not visible from the ticket text are in §4, §5 and §6. The most important is
§5: **the calibration target for `MaxDispersionMult` moves once a change PHVX-24 already asks for
lands.** Setting the cap before that change would put us back in saturation.

---

## 2. Verification of your evidence table

Every row of your §2 table was checked against the actual source on `origin/main`.

**12 of 13 exact. One line-number slip:**

| Claim | Result |
|---|---|
| `CoResidencyCap = 4.0` | ✅ |
| co-residency formula `1 + clamp01((len(t)-1)/CoResidencyCap)` | ✅ |
| `MaxDispersionMult = 4.0` | ✅ |
| uncapped product `ImageRarity * EPSS * CoResidency` (× `ModelRarity` for GPU/model) | ✅ |
| `boundMult` clamps to `[1, MaxDispersionMult]` | ✅ |
| `ReadyDelayReference = 400s` | ✅ |
| `NormalizeReadyDelay` clamps at 2 | ✅ |
| `exactBruteForceAssetCap = 18` | ✅ |
| exact skip returns `(0, true)` | ✅ |
| `SojournScale` / `Shape` are struct fields | ✅ |
| `Shape = 2.0` set in `NewModel()` | ✅ |
| `PerTickTimeout` exists, not exact-check specific | ✅ |
| `trackRotation` at manager.go **280–299** | ⚠️ it is at **277**. The function and its behaviour are exactly as you describe |

Your §3 formulas and your §4 telemetry gaps were also checked and match. Your statement that **no
policy or CRD path overrides `SojournScale` or `Shape`** is confirmed — nothing outside
`killchain/hazard.go` touches either field.

---

## 3. Measured results for your §5 rules

### 3.1 `CoResidencyScale` — P95 of `X_node = namespaceCount(node) − 1`

Per-node values across the 5 nodes: **1, 4, 6, 7, 8**

```
P50 = 6.00    P90 = 7.60    P95 = 7.80    P99 = 7.96    max = 8
```

- **P95 rule → 7.80** (current constant: 4.0)
- At 4.0, **4 of 5 nodes (80%)** are saturated, i.e. their `CoResidency` term is pinned at 2.0 and
  carries no information. That is 8× your 10% warning threshold.
- The median node already has `X = 6`, half again the current denominator.

### 3.2 `MaxDispersionMult` — P95 of the uncapped `U_asset`

Computed over all 100 containers, uncapped, before `boundMult`:

```
min = 1.8750   P50 = 3.3010   P90 = 4.0000   P95 = 5.0992
P97.5 = 5.6307   P99 = 6.1143   max = 7.5000
```

Saturation as a function of the cap:

| Cap | Saturated | Distinct values |
|---:|---:|---:|
| **4.0 (current)** | **26%** | 8 |
| 5.10 (P95) | 5% | — |
| 5.63 (P97.5) | 3% | — |
| 6.11 (P99) | 1% | — |

**P95 rule → 5.10.** This satisfies your ≤10% criterion; the current 4.0 does not.

---

## 4. `ModelRarity` measured on the live cluster — and a correction to PHVX-24

`ModelRarity` was not assumed. It was measured, because the P95 figure in §3.2 depends on it.

```
pods carrying the phorvex.ai/model-id annotation:  1
  Qwen2.5-7B-Instruct-AWQ  ×1   (vllm/vllm-cc4988699-5tqpq)

modelFreq = {Qwen2.5-7B-Instruct-AWQ: 1},  tot = 1
rarity(1, 1) = 1.0   (via the n < 2 honest-neutral guard)
```

So **`ModelRarity = 1.0` is confirmed**, and §3.2's 5.0992 is firm.

**But PHVX-24 describes this population incorrectly.** It states *"ModelRarity's live case is 2 of 2
model-serving pods (100% → maximally common → 1.0)"*. The live cluster has **1 of 1**, not 2 of 2.
The resulting value is the same, but by a different mechanism — the `n < 2` guard, not the
"maximally common" path. Any reasoning that depends on the *shape* of that population rather than
just the value needs re-checking against 1-of-1.

Also measured: of the three GPU pods, **two carry no model-id annotation** —
`mock-rag-chatbot/chatbot-5f555f5449-{kwrhc,lr9bx}`. This matches PHVX-24's own observation that the
annotation is missing there.

---

## 5. ⚠ The `MaxDispersionMult` target is a moving one

PHVX-24 item 4 asks for `phorvex.ai/model-id: sentence-transformers/all-MiniLM-L6-v2` to be added to
the `mock-rag-chatbot` Deployment, calling the expected decision effect "none". Measured, the effect
on **this** calibration is not none:

```
model-serving population:  1  ->  3     (1 × Qwen, 2 × MiniLM)

  vllm      rarity(1, 3) = 2.0000     (was 1.0 — it doubles)
  mock-rag  rarity(2, 3) = 1.3691     (was 1.0)
```

Re-running §3.2 under that population:

| | P95 | max | saturation at 4.0 |
|---|---:|---:|---:|
| today (measured) | **5.0992** | 7.5000 | 26% |
| after the annotation lands | **6.1452** | **10.1972** | 26% |

**Consequence:** if `MaxDispersionMult` is set to 5.10 now and the annotation is added afterwards,
the fleet returns to saturation, and the maximum uncapped product (10.20) then exceeds even a 7.5
cap. PHVX-24's "expected decision effect: none" is true only while the cap stays at 4.0 — precisely
because everything is already clipped. Once the cap moves, the term becomes live, which is the
coupling PHVX-24 §item 2 warns about in the other direction.

**Recommendation:** decide the order deliberately. Either land the annotation first and calibrate
once against the final population, or calibrate now and schedule a re-fit as part of the annotation
change. Calibrating now and treating it as settled is the one option that will silently regress.

---

## 6. Two coordination items

**6.1 §8 item 1 (`ExactSkipped`) is already implemented.** It was done before your report was
written; you had no way to know, and this is my omission, not an error in your audit. `ExactSkipped`
is emitted explicitly, the ratios are left unset rather than zero when a skip occurs, and the
dashboard renders `n/a` instead of a number. The skipped-vs-measured-zero distinction your §8 asks
for is in place.

**6.2 The exact-check runtime budget — your §8 blocker is correct, and it applies to me.**

PHORVEXSEC-114 item 2 instructed: *"Raise the cap where computationally tractable. Measure the
runtime curve and set the cap at the real limit, not a round number. Record what it is."* I did that.
The flat 18-asset cap was replaced with a bound on the work the enumeration performs, because the
measured cost is driven by the move budget far more than by fleet size:

```
n=76  B=1  ->    0.98 ms          n=600 B=1  ->  28.7 ms
n=76  B=2  ->  102    ms          n=300 B=2  ->   4.7 s
n=76  B=3  ->   20.3 s            n=18  B=4  ->   2.8 s
```

Every live tenant policy sets `maxMovesPerTick = 1`, so at the live budget the exact solve reaches a
600-asset fleet in 29 ms while the old cap refused at 19 — which is why the exactness claim had never
been measured at production scale. At 76 assets, B=1, the measured ratio is 1.000000000000, gap 0.

**However**: I also chose the acceptance threshold — a budget equivalent to roughly 0.2–0.6 s worst
case. Measuring the curve was my task; deciding what runtime is *acceptable* is not. Your §8 is right
that this must be an approved number. The mechanism is independent of the value: name a budget and I
will set it to that.

---

## 7. Method and provenance

Stated explicitly so the confidence level of each number is clear.

- **Cluster data is real.** Pod inventory (namespaces, nodes, image digests, GPU limits, model-id
  annotations) was read directly from the live cluster with `kubectl get pods -A`.
- **Formulas were cross-checked, not re-derived.** The percentile computation uses a Python
  re-implementation of `rarity()` and the co-residency formula. Both were verified against the
  shipped Go functions and agree **to 10 decimal places** on every probe value.
- **`ModelRarity = 1.0` is measured**, not assumed (§4), and `rarity(1,1)` was confirmed against the
  Go implementation.
- **These figures were computed offline from live inputs**, not read out of the running engine. The
  engine does not currently export the uncapped product — which is your §4 telemetry gap, and it is
  why this had to be reconstructed.
- **One number is an estimate, not a measurement**: an earlier note gave P95 ≈ 7.04 under full EPSS
  coverage. That scenario assigns synthetic EPSS/CVSS values to the 93 uncovered digests, so treat it
  as directional only. Every figure in §3, §4 and §5 of this report is measured.
- EPSS coverage today is 7 of 100 containers; the other 93 receive the honest-absent 1.0.

## 8. Not addressed here

- `ReadyDelayReference`: no calibration figure yet. Ready-delay observations are not persisted, so
  there is no history to take a percentile of — your §4 identifies this correctly. Producing it needs
  a collection period first.
- Your §7 walk-forward sweep (4 percentiles × 4 refresh intervals) has not been run.
- Your §9 sojourn policy-wiring plan is untouched.
