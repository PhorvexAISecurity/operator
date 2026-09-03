package actionset

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// (d) PHORVEXSEC-199 / M-111: an asset whose recon facts are absent (non-finite input) is
// excluded for every enabled action in the NaN category with the reason, and no NaN reaches
// FactWeights. Old code: NaN weights in FactWeights, no exclusion.
func TestNonFiniteReconInputIsExcludedInNaNCategory(t *testing.T) {
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon not registered")
	}
	poisoned := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "poisoned", HasGPU: true}, Physics: model.NeutralPhysics()}
	poisoned.Physics.ImageRarity = math.NaN()
	healthy := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "healthy", HasGPU: true}, Physics: model.NeutralPhysics()}
	d := Deps{
		Recon: profile,
		FactContext: func(*model.WorkloadView) recon.FactContext {
			return recon.FactContext{AssetValue: 1, PHold: 0.8, StageUrgency: 0.5, HasGPU: true}
		},
		ECost: func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.5 },
		CHi:   func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.5 },
	}
	pol := model.Policy{Tenant: "t", EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true}, MaxMovesPerTick: 2}
	set := d.Generate([]*model.WorkloadView{poisoned, healthy}, pol)
	for k, w := range set.FactWeights {
		if math.IsNaN(w) || math.IsInf(w, 0) {
			t.Fatalf("non-finite weight in FactWeights[%s] = %v (old behaviour)", k, w)
		}
	}
	if set.FactsAbsent["ns/poisoned"] == "" || len(set.FactsByAsset["ns/poisoned"]) != 0 {
		t.Fatalf("poisoned asset not recorded absent: %q facts=%d", set.FactsAbsent["ns/poisoned"], len(set.FactsByAsset["ns/poisoned"]))
	}
	excluded := 0
	for _, ex := range set.Excluded {
		if ex.Key != "ns/poisoned" {
			continue
		}
		excluded++
		if ex.Category != cost.UnactionableNaNCategory || ex.Detail != "recon non-finite-input: dispersion" {
			t.Fatalf("exclusion = %+v, want NaN category with the recon reason", ex)
		}
	}
	if excluded != 2 {
		t.Fatalf("poisoned asset excluded for %d actions, want 2 (every enabled action)", excluded)
	}
	for _, c := range set.Candidates {
		if c.Key == "ns/poisoned" {
			t.Fatalf("poisoned asset still produced a candidate: %+v", c)
		}
	}
	if len(set.FactsByAsset["ns/healthy"]) == 0 || set.FactsAbsent["ns/healthy"] != "" {
		t.Fatal("healthy asset must be unaffected")
	}
}
