/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"fmt"
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/recon"
)

// reconstructedAssets is a deterministic fixture rebuilt from the aggregate distribution reported
// on 2026-08-19: 71 pods, the reported node tenancy, and four reported rarity values. Per-pod
// placement is reconstructed, not a raw cluster export, and EPSS stays neutral here.
func reconstructedAssets() []AssetObservation {
	nsByNode := []int{2, 4, 5, 8, 9}
	podsByNode := []int{6, 9, 13, 17, 26}
	rarities := []float64{1.6224, 1.7423, 1.8374, 2.0}

	var out []AssetObservation
	n := 0
	for i, ns := range nsByNode {
		for k := 0; k < podsByNode[i]; k++ {
			out = append(out, AssetObservation{
				Key:         fmt.Sprintf("ns%d/pod%02d", i, k),
				ImageRarity: rarities[n%len(rarities)],
				EPSS:        1.0,
				ModelRarity: 1.0,
				Namespaces:  ns,
			})
			n++
		}
	}
	// The two model-serving pods: 1-of-2 each, so ModelRarity 2.0, and both AI-eligible.
	out[len(out)-1].ModelRarity, out[len(out)-1].AIFactEligible, out[len(out)-1].ImageRarity = 2.0, true, 2.0
	out[len(out)-2].ModelRarity, out[len(out)-2].AIFactEligible, out[len(out)-2].ImageRarity = 2.0, true, 1.7423
	return out
}

// The fit must be joint because the dispersion percentile is taken from a product CONTAINING the
// co-residency term. The coupling is real and shows in the distribution — but on this fleet it does
// NOT show at P95, and that is worth pinning rather than assuming away.
//
// The reason is specific: the assets at the top of the distribution sit on the 9-namespace node, so
// X = 8. At scale 4 that is 8/4 = 2, clamped to 1; at scale 8 it is 8/8 = 1. Both give a multiplier
// of exactly 2.0, so the pods that set the upper percentiles are numerically identical either way.
// Recalibrating co-residency moves the BODY of the distribution and leaves its tail alone.
func TestCoResidencyScaleMovesTheBodyNotTheTail(t *testing.T) {
	assets := reconstructedAssets()
	r4, r8 := uncappedAll(assets, 4.0), uncappedAll(assets, 8.0)

	// The distributions genuinely differ...
	min4, min8 := minOfSlice(r4), minOfSlice(r8)
	if min4 == min8 {
		t.Fatalf("the uncapped distribution is identical at both co-residency scales (min %v); the fits are not coupled at all", min4)
	}
	if min8 >= min4 {
		t.Errorf("raising the scale 4 -> 8 moved the minimum %v -> %v; a larger denominator must shrink the co-residency multiplier", min4, min8)
	}

	// ...but the top does not move, because the tail-setting pods saturate at either scale.
	max4, max8 := maxOfSlice(r4), maxOfSlice(r8)
	if max4 != max8 {
		t.Fatalf("maximum moved %v -> %v; the fixture no longer reproduces the saturating-tail case this test documents", max4, max8)
	}
	p4, _ := Percentile(r4, 0.95)
	p8, _ := Percentile(r8, 0.95)
	if p4 != p8 {
		t.Fatalf("P95 moved %v -> %v; the finding that P95 is insensitive to the co-residency scale on this fleet no longer holds", p4, p8)
	}
	t.Logf("uncapped min %.4f -> %.4f (body moves); max %.4f -> %.4f and P95 %.4f -> %.4f (tail does not)",
		min4, min8, max4, max8, p4, p8)
}

func minOfSlice(v []float64) float64 {
	m := v[0]
	for _, x := range v {
		if x < m {
			m = x
		}
	}
	return m
}

func maxOfSlice(v []float64) float64 {
	m := v[0]
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

func uncappedAll(assets []AssetObservation, scale float64) []float64 {
	out := make([]float64, 0, len(assets))
	for _, a := range assets {
		out = append(out, a.Uncapped(scale))
	}
	return out
}

// The spec forbids computing percentiles from values already capped at 4.0. This checks the
// reconstruction actually escapes the cap: in this fixture the uncapped product exceeds 4.0, so
// a stored (capped) multiplier would have truncated it.
func TestPercentileIsTakenFromUncappedValues(t *testing.T) {
	assets := reconstructedAssets()
	raw := uncappedAll(assets, ShippedCoResidencyCap)

	over := 0
	for _, u := range raw {
		if u > ShippedMaxDispersionMult {
			over++
		}
	}
	if over == 0 {
		t.Fatal("no asset exceeds the shipped cap, so this fixture cannot detect a clipped-input regression")
	}
	max := 0.0
	for _, u := range raw {
		if u > max {
			max = u
		}
	}
	if max <= ShippedMaxDispersionMult {
		t.Fatalf("reconstructed maximum %v does not exceed the shipped cap %v — the input is still clipped", max, ShippedMaxDispersionMult)
	}
}

// ⚠️ FINDING, recorded as a test rather than prose: the two configured parameters are mutually
// inconsistent on this fleet.
//
//	MaxDispersionMult: P95            (OR decision)
//	saturation warning: > 10%          (OR decision)
//
// P95 of the uncapped product is EXACTLY 4.0 — the shipped constant — so calibrating at P95 is a
// no-op for dispersion, and it leaves 11.3% at the ceiling. The recalibration does not clear the
// threshold it is being judged against.
//
// The cause is discreteness, the same family as the co-residency percentile collapse: ImageRarity
// takes only four distinct values on this fleet and most pods sit at co-residency 2.0, so the
// product piles up on a few points. A large mass sits at exactly 2.0 x 2.0 = 4.0, and both P90 and
// P95 land inside it.
//
// This test pins the reconstructed scenario. It is a regression fixture, not evidence that the
// current cluster still has this distribution.
func TestP95DispersionIsANoOpAndMissesTheThreshold(t *testing.T) {
	const threshold = 0.10
	j := CalibrateJoint(reconstructedFleet(), reconstructedAssets(), 0.95, 0.95, 1, at0())

	if j.CoResidency.Value != 8 {
		t.Fatalf("co-residency scale = %v, want 8", j.CoResidency.Value)
	}
	if j.Dispersion.Value != ShippedMaxDispersionMult {
		t.Fatalf("P95 dispersion = %v, want it to land on the shipped %v — the no-op finding no longer reproduces",
			j.Dispersion.Value, ShippedMaxDispersionMult)
	}
	if got := j.CandidateAtCeiling(); got <= threshold {
		t.Fatalf("P95 now pins %.1f%%, within the %.0f%% threshold — the parameters are no longer in conflict and this test should be revisited",
			got*100, threshold*100)
	}
	t.Logf("P95 dispersion = %.4f (= shipped), pinning %.1f%% against a %.0f%% threshold; shipped pair pins %.1f%%",
		j.Dispersion.Value, j.CandidateAtCeiling()*100, threshold*100, j.ShippedAtCeiling*100)
}

// Which percentile DOES clear the threshold, and at what cost. P97.5 clears at 2.8% — but the value
// it picks is set by one of the two GPU pods, so above P95 the cap is determined by ~2 of 71 assets.
// That fragility is the trade-off the choice carries, and it is measured here rather than asserted.
func TestSmallestClearingPercentileIsSetByVeryFewAssets(t *testing.T) {
	const threshold = 0.10
	raw := uncappedAll(reconstructedAssets(), 8.0)

	var clearing float64
	for _, p := range []float64{0.90, 0.95, 0.975, 0.99} {
		q, _ := Percentile(raw, p)
		c := Clipping(raw, q)
		t.Logf("P%-5.1f -> cap %.4f, at-ceiling %.1f%%", p*100, q, c.AtCeilingRatio()*100)
		if c.AtCeilingRatio() <= threshold && clearing == 0 {
			clearing = p
		}
	}
	if clearing != 0.975 {
		t.Fatalf("smallest clearing percentile is P%.1f, expected P97.5", clearing*100)
	}

	q, _ := Percentile(raw, clearing)
	above := 0
	for _, u := range raw {
		if u >= q-1e-9 {
			above++
		}
	}
	if above > 3 {
		t.Fatalf("%d assets sit at or above the P97.5 cap; the fragility finding assumed very few", above)
	}
	t.Logf("P97.5 cap %.4f is set by %d of %d assets", q, above, len(raw))
}

// Low saturation is necessary but not sufficient. A cap could pin almost nothing and still leave
// the fleet with two distinct multipliers, which is a constant with extra steps — the ticket's
// actual complaint. The fit has to widen the term, not just stop clipping it.
func TestJointFitWidensTheTermNotJustTheCeiling(t *testing.T) {
	j := CalibrateJoint(reconstructedFleet(), reconstructedAssets(), 0.95, 0.95, 1, at0())

	shippedDistinct := map[float64]bool{}
	for _, a := range reconstructedAssets() {
		shippedDistinct[Capped(a.Uncapped(ShippedCoResidencyCap), ShippedMaxDispersionMult)] = true
	}
	if j.DistinctCapped <= len(shippedDistinct) {
		t.Fatalf("candidate produces %d distinct multipliers vs shipped %d — the re-fit bought no discrimination",
			j.DistinctCapped, len(shippedDistinct))
	}
	t.Logf("distinct multipliers: shipped %d -> candidate %d", len(shippedDistinct), j.DistinctCapped)
}

// The sweep is what the acceptance rule ("smallest percentile that keeps saturation acceptable")
// is actually checked with. It must be monotone in the cap and identify a smallest clearing value.
func TestSweepFindsTheSmallestClearingCap(t *testing.T) {
	const threshold = 0.10
	rows := SweepDispersion(reconstructedAssets(), 8.0, []float64{3, 4, 5, 6, 7, 8}, threshold)

	prev := math.Inf(1)
	first := -1.0
	for _, r := range rows {
		if r.AtCeilingRatio > prev+1e-12 {
			t.Fatalf("saturation rose from %.4f to %.4f as the cap increased; the sweep is not monotone", prev, r.AtCeilingRatio)
		}
		prev = r.AtCeilingRatio
		if r.ClearsThreshold && first < 0 {
			first = r.Cap
		}
		t.Logf("cap=%.1f pinned=%.1f%% distinct=%d clears=%v", r.Cap, r.AtCeilingRatio*100, r.DistinctCapped, r.ClearsThreshold)
	}
	if first < 0 {
		t.Fatal("no candidate cap cleared the threshold")
	}
}

// A cap of zero assets must fall back rather than invent a number.
func TestNoAssetsFallsBack(t *testing.T) {
	j := CalibrateJoint(reconstructedFleet(), nil, 0.95, 0.95, 1, at0())
	if j.Dispersion.IsMeasured() {
		t.Fatal("an empty fleet produced a measured dispersion scale")
	}
	if j.Dispersion.Value != ShippedMaxDispersionMult || j.Dispersion.Reason == "" {
		t.Fatalf("fallback = %v reason %q, want the shipped cap with a reason", j.Dispersion.Value, j.Dispersion.Reason)
	}
}

// ModelRarity participates only when the production gate says so. A pod that is neither GPU nor
// model-serving must not take the term, or the shadow measures a formula production does not run.
func TestModelRarityOnlyAppliesToAIEligibleAssets(t *testing.T) {
	base := AssetObservation{ImageRarity: 1.5, EPSS: 1.0, ModelRarity: 2.0, Namespaces: 1}
	if got := base.Uncapped(4.0); math.Abs(got-1.5) > 1e-12 {
		t.Fatalf("non-AI asset scored %v, want 1.5 — ModelRarity leaked in", got)
	}
	base.AIFactEligible = true
	if got := base.Uncapped(4.0); math.Abs(got-3.0) > 1e-12 {
		t.Fatalf("AI-eligible asset scored %v, want 3.0", got)
	}
}

// The duplicated constant must not drift from the one production uses.
func TestDispersionCapAgreesWithRecon(t *testing.T) {
	if ShippedMaxDispersionMult != recon.MaxDispersionMult {
		t.Fatalf("calib says the shipped cap is %v, recon says %v — the shadow compares against the wrong baseline",
			ShippedMaxDispersionMult, recon.MaxDispersionMult)
	}
}

// Capped must match recon.boundMult exactly, including the floor: the counterfactual is worthless
// if it applies a different bound than production.
func TestCappedMatchesBoundMult(t *testing.T) {
	for _, v := range []float64{0, 0.5, 1, 1.5, 3.9999, 4, 4.1, 100} {
		want := v
		if want < 1 {
			want = 1
		}
		if want > ShippedMaxDispersionMult {
			want = ShippedMaxDispersionMult
		}
		if got := Capped(v, ShippedMaxDispersionMult); got != want {
			t.Errorf("Capped(%v) = %v, want %v", v, got, want)
		}
	}
}
