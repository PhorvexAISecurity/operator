package recon

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// nonfinite_guard_test.go — PHORVEXSEC-199 / M-111.
//
// Old code: boundMultAt(NaN) returned NaN (both comparisons false) and recon clamp01(NaN)
// returned NaN, so a single non-finite belief or physics input became a NaN weight on every
// fact of the asset, then a NaN marginal and gain. New: a non-finite input is a presence
// state — no fact is minted, AbsentReason names the input — never a value.

var nonFinite = []float64{math.NaN(), math.Inf(1), math.Inf(-1)}
var finiteEdge = []float64{0, 1e-300, -1e-300, 0.5, 1, 2, -1, math.MaxFloat64, -math.MaxFloat64, math.SmallestNonzeroFloat64}

func nonFiniteGPUView() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p", HasGPU: true, ModelID: "m"}, Physics: model.NeutralPhysics()}
}

func assertAllFinite(t *testing.T, label string, af AssetFacts) {
	t.Helper()
	for _, f := range af.Facts {
		if !finite(f.Weight) {
			t.Fatalf("%s: non-finite weight %v reached fact %s (old code let it through)", label, f.Weight, f.Key())
		}
	}
}

// (a) fuzz: a non-finite value in ANY weight input never reaches a fact weight; the asset's
// facts are absent with the input named. Fails on the old code (NaN weights).
func TestNonFiniteInputNeverReachesAFactWeight(t *testing.T) {
	for _, profile := range []ReconProfile{standardRecon{}, ucwRecon{}} {
		for _, bad := range nonFinite {
			cases := map[string]FactContext{
				"assetValue":     {AssetValue: bad, PHold: 0.8, StageUrgency: 0.5},
				"pHold":          {AssetValue: 1, PHold: bad, StageUrgency: 0.5},
				"stageUrgency":   {AssetValue: 1, PHold: 0.8, StageUrgency: bad},
				"lateralUrgency": {AssetValue: 1, PHold: 0.8, StageUrgency: 0.5, LateralUrgency: bad},
				"neighbor:ns/q":  {AssetValue: 1, PHold: 0.8, StageUrgency: 0.5, Neighbors: []NeighborRef{{Key: "ns/q", Value: bad}}},
			}
			for field, fctx := range cases {
				af := profile.AssetFacts(nonFiniteGPUView(), fctx)
				if af.AbsentReason != absentReason(field) || len(af.Facts) != 0 || len(af.CoverByAction) != 0 {
					t.Fatalf("%s %s=%v: facts=%d cover=%d reason=%q, want absent with reason %q",
						profile.Name(), field, bad, len(af.Facts), len(af.CoverByAction), af.AbsentReason, absentReason(field))
				}
			}
		}
	}
	// Physics dispersion inputs (ucw only): every multiplier and the shadow cap.
	for _, bad := range nonFinite {
		for _, set := range []func(*model.PhysicsWitness){
			func(p *model.PhysicsWitness) { p.ImageRarity = bad },
			func(p *model.PhysicsWitness) { p.EPSSMultiplier = bad },
			func(p *model.PhysicsWitness) { p.CoResidency = bad },
			func(p *model.PhysicsWitness) { p.ModelRarity = bad },
			func(p *model.PhysicsWitness) { p.DispersionCap = bad },
		} {
			v := nonFiniteGPUView()
			set(&v.Physics)
			af := ucwRecon{}.AssetFacts(v, FactContext{AssetValue: 1, PHold: 0.8, StageUrgency: 0.5})
			if af.AbsentReason != absentReason("dispersion") || len(af.Facts) != 0 {
				t.Fatalf("physics %v: facts=%d reason=%q, want absent dispersion", bad, len(af.Facts), af.AbsentReason)
			}
			if _, ok := DispersionMultiplier(v); ok {
				t.Fatalf("DispersionMultiplier reported ok on non-finite physics %v", bad)
			}
		}
	}
}

// (b) finite inputs: outputs identical to the unguarded formulas (byte-identical old path).
func TestFiniteInputsAreUnchanged(t *testing.T) {
	oldClamp := func(x float64) float64 {
		if x < 0 {
			return 0
		}
		if x > 1 {
			return 1
		}
		return x
	}
	oldBound := func(m, cap float64) float64 {
		if cap <= 0 {
			cap = MaxDispersionMult
		}
		if m < 1 {
			return 1
		}
		if m > cap {
			return cap
		}
		return m
	}
	for _, x := range finiteEdge {
		got, ok := clamp01(x)
		if !ok || got != oldClamp(x) {
			t.Fatalf("clamp01(%v) = %v,%v; old %v", x, got, ok, oldClamp(x))
		}
		for _, cap := range []float64{0, 1.5, 4, 8} {
			got, ok := boundMultAt(x, cap)
			if !ok || got != oldBound(x, cap) {
				t.Fatalf("boundMultAt(%v,%v) = %v,%v; old %v", x, cap, got, ok, oldBound(x, cap))
			}
		}
	}
	for _, profile := range []ReconProfile{standardRecon{}, ucwRecon{}} {
		af := profile.AssetFacts(nonFiniteGPUView(), FactContext{AssetValue: 3, PHold: 0.7, StageUrgency: 0.4, LateralUrgency: 0.2, Neighbors: []NeighborRef{{Key: "ns/q", Value: 2}}})
		if af.AbsentReason != "" || len(af.Facts) == 0 {
			t.Fatalf("%s: finite inputs produced no facts: %+v", profile.Name(), af)
		}
		assertAllFinite(t, profile.Name(), af)
	}
}

// (c) the two guarded helpers agree on every non-finite input: neither yields a value.
func TestGuardedHelpersAgreeOnNonFinite(t *testing.T) {
	for _, bad := range nonFinite {
		if _, ok := clamp01(bad); ok {
			t.Fatalf("clamp01(%v) reported a value", bad)
		}
		if _, ok := boundMultAt(bad, 0); ok {
			t.Fatalf("boundMultAt(%v) reported a value", bad)
		}
		if _, ok := boundMultAt(1.5, bad); ok {
			t.Fatalf("boundMultAt(1.5, cap=%v) reported a value", bad)
		}
		if _, ok := boundMult(bad); ok {
			t.Fatalf("boundMult(%v) reported a value", bad)
		}
	}
	// The shipped cap and formulas are untouched (M-108).
	if MaxDispersionMult != 4.0 {
		t.Fatalf("MaxDispersionMult changed: %v", MaxDispersionMult)
	}
}
