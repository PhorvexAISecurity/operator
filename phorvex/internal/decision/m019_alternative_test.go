package decision

import (
	"testing"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM019AlternativeUsesOriginalReservationsAndMarginalCover(t *testing.T) {
	e := NewCoverageEngine()
	owner, target, other := "uid\x00policy", "ns/target", "ns/other"
	e.alternative = &alternativeContext{
		owner: owner, lambda: .1, budget: 2,
		selected:   map[string]model.Action{target: model.ActionKVReset, other: model.ActionRotate},
		provenance: map[string]float64{target: 1, other: 1},
		attack:     map[string]bool{target: true, other: true},
		states:     map[string]*model.ExistentialDecision{target: {}, other: {}},
		set: actionset.ActionSet{FactWeights: map[string]float64{"shared": 10, "unique": 4}, Candidates: []actionset.Candidate{
			{Key: other, Action: model.ActionRotate, CoverKeys: []string{"shared"}, ECost: .1},
			{Key: target, Action: model.ActionKVReset, CoverKeys: []string{"shared"}, ECost: .1},
			{Key: target, Action: model.ActionQuarantine, CoverKeys: []string{"shared"}, ECost: .1},
			{Key: target, Action: model.ActionRouteRotate, CoverKeys: []string{"unique"}, ECost: .1},
		}},
	}
	a, ok := e.SelectAlternative(owner, target, model.ActionKVReset)
	if !ok || a.Action != model.ActionRouteRotate || a.Marginal != 4 {
		t.Fatalf("already reserved shared cover counted again: %+v ok=%t", a, ok)
	}
	if _, ok := e.SelectAlternative("uid\x00other", target, model.ActionKVReset); ok {
		t.Fatal("other policy reused selection context")
	}
	if _, ok := e.SelectAlternative(owner, target, model.ActionQuarantine); ok {
		t.Fatal("failed action was not original reservation")
	}
	e.alternative.budget = 1
	if _, ok := e.SelectAlternative(owner, target, model.ActionKVReset); ok {
		t.Fatal("over-budget original reservations licensed fallback")
	}
}
