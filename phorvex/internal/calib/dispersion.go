/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import "time"

// DispersionFloor is the safety floor from the spec. A cap below 1.0 would push every asset's
// multiplier below neutral, inverting the term rather than mis-sizing it.
const DispersionFloor = 1.0

// ShippedMaxDispersionMult mirrors recon.MaxDispersionMult, duplicated for the same reason as
// ShippedCoResidencyCap: this package must not import the physics packages. Pinned by
// TestDispersionCapAgreesWithRecon.
const ShippedMaxDispersionMult = 4.0

// AssetObservation is one asset's uncapped multiplier components, as the physics scanner derives
// them. Every field the spec asks to export is here, so a candidate cap can be argued with rather
// than taken on faith.
type AssetObservation struct {
	Key string

	ImageRarity float64
	EPSS        float64
	ModelRarity float64

	// Namespaces is the node's distinct-tenant count, kept RAW rather than pre-multiplied so the
	// co-residency term can be recomputed at a candidate scale. This is what makes the joint fit
	// possible: a stored CoResidency multiplier would already have the shipped cap baked in, and
	// percentiles taken from it would be percentiles of a clipped distribution.
	Namespaces int

	// AIFactEligible mirrors the production gate `ModelID != "" || HasGPU`, which decides whether
	// ModelRarity participates at all. It is not the same as "has a model id": a GPU pod with no
	// model annotation still takes the term.
	AIFactEligible bool
}

// Uncapped reproduces the SHIPPED product at a candidate co-residency scale, with no cap applied:
//
//	s = ImageRarity * EPSS * CoResidency [* ModelRarity if AI-eligible]
//
// The spec is explicit that percentiles must NOT be computed from values already capped at 4.0.
// Reproducing the product from raw components is the only way to obey that — reading back the
// stored multiplier would sample a distribution that has already been truncated at the number
// under review.
func (a AssetObservation) Uncapped(coResidencyScale float64) float64 {
	x := float64(a.Namespaces - 1)
	if x < 0 {
		x = 0
	}
	s := a.ImageRarity * a.EPSS * CoResidencyMultiplier(x, coResidencyScale)
	if a.AIFactEligible {
		s *= a.ModelRarity
	}
	return s
}

// Capped applies a candidate dispersion cap, matching recon.boundMult (floor 1, ceiling cap).
func Capped(uncapped, cap float64) float64 {
	if uncapped < 1 {
		return 1
	}
	if uncapped > cap {
		return cap
	}
	return uncapped
}

// JointReport is the outcome of fitting co-residency and dispersion TOGETHER, which the spec
// requires because U_asset contains the co-residency term: fitting them in sequence measures the
// second against a distribution the first has already moved.
type JointReport struct {
	CoResidency Scale
	Dispersion  Scale

	// Assets is how many observations the dispersion percentile was taken from.
	Assets int
	// UncappedMin/Max bound the reconstructed product at the chosen co-residency scale — the
	// spread the cap is deciding how much of to keep.
	UncappedMin, UncappedMax float64
	// DistinctCapped is how many distinct multipliers the fleet ends up with under the candidate
	// pair. This is the property the ticket actually cares about: a term that assigns nearly every
	// asset the same value has degenerated into a constant, however low its saturation looks.
	DistinctCapped int
	// ShippedAtCeiling is the share pinned under the SHIPPED pair, so the candidate can be
	// compared against today rather than only against itself.
	ShippedAtCeiling float64
	// Grid is the distinct set of dispersion values the candidate percentile grid produces.
	// Length 1 means the grid cannot justify a choice on this sample.
	Grid []float64
}

// CandidateAtCeiling is the share of assets pinned at the candidate cap — the series the
// saturation alarm watches.
func (j JointReport) CandidateAtCeiling() float64 { return j.Dispersion.Clip.AtCeilingRatio() }

// CalibrateJoint runs the four-step procedure the spec lays out: derive the co-residency scale,
// recompute the co-residency multiplier at it, reconstruct the uncapped product, then take the
// dispersion percentile from THAT.
//
// Production is unaffected — both returned scales are proposals.
func CalibrateJoint(
	nodes []NodeObservation,
	assets []AssetObservation,
	coResidencyP, dispersionP float64,
	minObservations int,
	at time.Time,
) JointReport {
	cr := CalibrateCoResidency(nodes, coResidencyP, minObservations, at)
	j := JointReport{CoResidency: cr.Scale, Assets: len(assets)}
	if len(assets) == 0 {
		j.Dispersion = Fallback("dispersion", ShippedMaxDispersionMult, "no assets observed", at)
		return j
	}

	// Step 3: reconstruct the uncapped product at the CANDIDATE co-residency scale.
	raw := make([]float64, 0, len(assets))
	for _, a := range assets {
		raw = append(raw, a.Uncapped(cr.Scale.Value))
	}
	j.UncappedMin, j.UncappedMax = raw[0], raw[0]
	for _, u := range raw {
		if u < j.UncappedMin {
			j.UncappedMin = u
		}
		if u > j.UncappedMax {
			j.UncappedMax = u
		}
	}

	// Step 4: the dispersion percentile, taken from uncapped values.
	j.Dispersion = Measured("dispersion", raw, dispersionP, DispersionFloor, ShippedMaxDispersionMult, minObservations, at)
	j.Grid = Identifiable(raw, []float64{0.90, 0.95, 0.975, 0.99})

	distinct := map[float64]bool{}
	shippedPinned := 0
	for _, a := range assets {
		distinct[Capped(a.Uncapped(cr.Scale.Value), j.Dispersion.Value)] = true
		if Capped(a.Uncapped(ShippedCoResidencyCap), ShippedMaxDispersionMult) >= ShippedMaxDispersionMult-1e-9 {
			shippedPinned++
		}
	}
	j.DistinctCapped = len(distinct)
	j.ShippedAtCeiling = float64(shippedPinned) / float64(len(assets))
	return j
}

// SweepDispersion evaluates candidate caps against a saturation threshold at a fixed co-residency
// scale, which is how the ticket's acceptance rule ("keep saturation acceptable") is actually
// checked. Returns one row per candidate, in the order given.
//
// It exists because the answer is not monotone in any useful sense for a human to eyeball: the
// share pinned falls in steps as the cap crosses clusters of assets, and the interesting question
// is which is the SMALLEST cap that clears the threshold — a larger one discards less signal but
// also stops bounding anything.
type SweepRow struct {
	Cap             float64
	AtCeilingRatio  float64
	DistinctCapped  int
	ClearsThreshold bool
}

// SweepDispersion measures each candidate cap against threshold at coResidencyScale.
func SweepDispersion(assets []AssetObservation, coResidencyScale float64, caps []float64, threshold float64) []SweepRow {
	out := make([]SweepRow, 0, len(caps))
	for _, c := range caps {
		pinned, distinct := 0, map[float64]bool{}
		for _, a := range assets {
			u := a.Uncapped(coResidencyScale)
			if u >= c-1e-9 {
				pinned++
			}
			distinct[Capped(u, c)] = true
		}
		ratio := 0.0
		if len(assets) > 0 {
			ratio = float64(pinned) / float64(len(assets))
		}
		out = append(out, SweepRow{
			Cap: c, AtCeilingRatio: ratio, DistinctCapped: len(distinct),
			ClearsThreshold: ratio <= threshold,
		})
	}
	return out
}
