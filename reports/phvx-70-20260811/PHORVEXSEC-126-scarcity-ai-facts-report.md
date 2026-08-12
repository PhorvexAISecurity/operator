# PHORVEXSEC-126 (PHVX-70) — the scarcity scalar never reached any AI fact — fix report

Date: 2026-08-11 · Branch `fix/phvx-70-scarcity-reaches-ai-facts`

## The defect, measured

`ucw.go` computes one per-asset scarcity scalar and its own doc comment says it is applied

> "UNIFORMLY to every fact of the asset"

It was applied immediately where it is computed — which is **before every AI fact is appended**. So it
reached the six `standardRecon` facts and skipped the rest.

Measured on a GPU pod with `ImageRarity 2.0 × CoResidency 2.0` (scalar = 4.0):

```
base fact  podIdentity   lifted 4.0000x
AI fact    endpointPath  lifted 1.0000x
                         => a base fact outranks an AI fact on the SAME asset by 4.00x
```

The engine was therefore steered toward generic moves over the AI-specific ones **on exactly the
workloads the AI facts exist for**. It is a silent failure: nothing errors, the ranking is just wrong.

## Why the uniformity matters, not just the magnitude

The comment is not decoration. Uniformity is what makes the file's own EMR argument sound: a factor
common to *all* of an asset's facts preserves the within-asset ordering and sharpens only the
cross-asset one. Partial application breaks that guarantee — the scalar starts re-ordering an asset's
own facts, which is precisely what it is documented not to do.

So the comment was right and the code was wrong.

## The fix

The scaling loop moved to the end of `AssetFacts`, after both AI append sites. A note at the
computation site explains why it is not applied there, so the next reader does not "tidy" it back.

## Tests

**`TestScarcityScalesEveryFactUniformly`** — a base fact and an AI fact on the same asset must be
lifted by the same factor. Against the pre-fix code it fails with the 4.00x figure above.

**`TestScarcityPreservesWithinAssetOrdering`** — every within-asset ratio is unchanged by dispersion.

### A correction made while writing the second test

Its first version compared *every* pair of facts and failed — correctly. Three facts deliberately
carry a physics term of their own (`modelFingerprint × ModelRarity`, `gpuColocation × CoResidency`),
so their ratio to other facts is *supposed* to move with physics. The assertion was wrong, not the
code. It now compares only the facts weighted as plain `base·urg`, and the reason is written into the
test so it is not "fixed" back later.

## Not claimed

- No live-cluster measurement. The effect is proven against the real `ucwRecon.AssetFacts` path.
- The magnitude is bounded by `MaxDispersionMult` (4.0 today). PHORVEXSEC-130 measures that the cap
  should move to ~5.1; if it does, this defect would have been worth up to 5.1x instead of 4x. The
  fix is independent of that decision.
- Full suite green apart from `TestScenariosExport`, which fails identically on `origin/main` and is
  fixed separately under PHORVEXSEC-123.
