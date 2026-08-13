# PHORVEXSEC-131 (PHVX-75) — adapterIntegrity weight — fix report

Date: 2026-08-10 · Branch `fix/phvx-75-adapter-integrity-weight` · Commit `240b22d`

## The change

`ucw.go`: `(base + 2.0) * urg * 3` → `base * urg * 3.0`

One line. The reason it matters is that `base = AssetValue * clamp01(PHold)`, so the additive term
detached the fact from the evidence it is supposed to rest on.

## The three defects, measured

The ticket lists three consequences of the `+2.0`. All three were reproduced against the shipped code
before changing it.

**1. It survived `PHold = 0`.**

| | old | new |
|---|---|---|
| weight at `PHold = 0` | **3.0** | **0** |

At `PHold = 0` the attacker is believed gone and every other fact on the asset is 0. The additive form
still produced `2.0 * urg * 3 ≥ 3.0`, so a fact about a departed attacker sat at the *top* of the
objective, and no amount of evidence could retire it. This is the defect with real operational
consequence: the engine would keep paying for `adapter-rotate` on a pod it has already cleaned.

**2. It was not portable.**

| `AssetValue` | old weight | new weight |
|---|---|---|
| 1 | 9 | 3 |
| 100 | 306 | 300 |
| ratio | **34×** | **100×** |

A 100× change in the policy's own asset scale produced only a 34× change in the weight, because the
constant was drowning it. On a fleet emitting O(1) values the `+2.0` dominated outright; on one
emitting O(100) it was rounding noise. The same number meant different things on different clusters —
the class of defect PHVX-74 is about.

**3. It was the only additive weight in the file.** Every other fact is `base * urg * <multiplier>`.

## Dominance is preserved — and now structurally

The additive term existed to make a poisoned adapter dominate. That still holds, for a better reason:

- `ModelRarity` = `1 + clamp01(log2(N/count)/log2(N))` → bounded by **2**
- `CoResidency` = `1 + clamp01((tenants-1)/CoResidencyCap)` → bounded by **2**
- `adapterIntegrity` multiplier = **3**

So the adapter fact outranks any other fact on the same asset by construction, not by a constant that
happens to be large. `TestAdapterFactStillDominates` asserts this against the actually-emitted facts
rather than trusting the reading above, so it will fail if either bound ever changes.

## Behaviour at `PHold = 0`, stated precisely

The fact is **still emitted** — a detector really did flag an adapter — it simply carries zero weight.
So `adapter-rotate` has cover but no gain, and will not be selected. That is deliberate and is
different from the empty-cover case PHVX-9e removed: there the action claimed to invalidate something
it could not touch; here the claim is true but currently worth nothing.

## Tests

| test | pins |
|---|---|
| `TestAdapterFactVanishesWhenAttackerIsGone` | weight 0 at `PHold = 0` — **fails on the old code with weight 3** |
| `TestAdapterFactScalesWithAssetValue` | linear in `AssetValue` — **fails on the old code with ratio 34** |
| `TestAdapterFactStillDominates` | outranks every other fact on the asset |
| `TestAdapterFactAbsentWithoutASuspectAdapter` | the fact and the cover both vanish once the adapter is evicted, which is what stops `adapter-rotate` repeating |

Full suite green apart from `TestScenariosExport`, which fails on `main` as well for an unrelated
reason (`bin/scenarios-instances.jsonl` is a generated fixture that is not present in this checkout).

## Not claimed

- Not validated on the live cluster. No pod on `phorvex-dev-eks` currently carries a
  `SuspectAdapter`, so this path does not execute there today; the change is proven by tests against
  the real `AssetFacts` path.
- The multiplier 3 itself is still an unvalidated constant — it is now *bounded above the others by
  construction*, but why 3 rather than 2.5 has no derivation. That belongs to the constants registry
  in PHVX-24, not here.
