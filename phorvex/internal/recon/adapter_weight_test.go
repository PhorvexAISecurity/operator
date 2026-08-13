package recon

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// adapter_weight_test.go — PHVX-75 / PHORVEXSEC-131.
//
// The adapterIntegrity weight was `(base + 2.0) * urg * 3`: the only ADDITIVE weight in ucw.go. The
// additive term made the fact independent of the evidence it is supposed to rest on.

func adapterPod() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "llm", HasGPU: true, ModelID: "m", SuspectAdapter: "evil",
	}}
}

func factOfKind(fs []Fact, k string) (Fact, bool) {
	for _, f := range fs {
		if f.Kind == k {
			return f, true
		}
	}
	return Fact{}, false
}

// TestAdapterFactVanishesWhenAttackerIsGone is the regression. At PHold = 0 the attacker is believed
// gone, so `base` is 0 and every other fact on the asset is 0 — but the additive form still produced
// 2.0*urg*3 >= 3.0, leaving a fact about a departed attacker at the TOP of the objective with no way
// for evidence to retire it. Against the pre-fix code this test fails with weight 3.
func TestAdapterFactVanishesWhenAttackerIsGone(t *testing.T) {
	fctx := FactContext{AssetValue: 1, PHold: 0, StageUrgency: 0, HasGPU: true}
	af := ucwRecon{}.AssetFacts(adapterPod(), fctx)
	ai, ok := factOfKind(af.Facts, FactAdapterIntegrity)
	if !ok {
		t.Fatal("the adapter-integrity fact should still be EMITTED (the detector flagged it); only its weight goes to zero")
	}
	if ai.Weight != 0 {
		t.Fatalf("PHold=0 means the attacker is believed gone, so the weight must be 0; got %v. "+
			"A non-zero value here is the additive floor PHVX-75 removed.", ai.Weight)
	}
}

// TestAdapterFactStillDominates pins the intent the additive term was there to serve. Every other
// multiplier in ucw.go has the form 1 + clamp01(...) and is bounded by 2; this one is 3, so a poisoned
// adapter outranks any other fact on the same asset structurally rather than by a large constant.
func TestAdapterFactStillDominates(t *testing.T) {
	fctx := FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true,
		Neighbors: []NeighborRef{{Key: "ns/neighbor", Value: 1}}}
	af := ucwRecon{}.AssetFacts(adapterPod(), fctx)
	ai, ok := factOfKind(af.Facts, FactAdapterIntegrity)
	if !ok {
		t.Fatal("no adapter-integrity fact emitted for a pod with a suspect adapter")
	}
	for _, f := range af.Facts {
		if f.Kind == FactAdapterIntegrity || f.Asset != ai.Asset {
			continue
		}
		if f.Weight >= ai.Weight {
			t.Fatalf("fact %v on the same asset weighs %v, at or above adapter-integrity's %v — "+
				"a poisoned adapter must dominate", f.Kind, f.Weight, ai.Weight)
		}
	}
}

// TestAdapterFactScalesWithAssetValue is the portability property. The additive +2.0 meant the same
// constant dominated a fleet emitting O(1) asset values and was noise on one emitting O(100). A
// multiplicative weight scales with whatever the policy emits, so the ranking is unit-free.
func TestAdapterFactScalesWithAssetValue(t *testing.T) {
	weightAt := func(v float64) float64 {
		af := ucwRecon{}.AssetFacts(adapterPod(),
			FactContext{AssetValue: v, PHold: 1, StageUrgency: 1, HasGPU: true})
		ai, _ := factOfKind(af.Facts, FactAdapterIntegrity)
		return ai.Weight
	}
	small, large := weightAt(1), weightAt(100)
	if large/small < 99 || large/small > 101 {
		t.Fatalf("weight must scale linearly with AssetValue (100x in => ~100x out); got %v -> %v (ratio %.3f). "+
			"A ratio far below 100 means an additive term is back and is drowning the policy's scale.",
			small, large, large/small)
	}
}

// TestAdapterFactAbsentWithoutASuspectAdapter pins the comment at ucw.go: the fact must disappear once
// the adapter is evicted, which is what stops adapter-rotate repeating forever.
func TestAdapterFactAbsentWithoutASuspectAdapter(t *testing.T) {
	clean := adapterPod()
	clean.Pod.SuspectAdapter = ""
	af := ucwRecon{}.AssetFacts(clean, FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, HasGPU: true})
	if _, ok := factOfKind(af.Facts, FactAdapterIntegrity); ok {
		t.Fatal("no adapter is flagged, so the adapter-integrity fact must not exist")
	}
	if len(af.CoverByAction[model.ActionAdapterRotate]) != 0 {
		t.Fatalf("adapter-rotate must have no cover once the adapter is evicted; got %v",
			af.CoverByAction[model.ActionAdapterRotate])
	}
}
