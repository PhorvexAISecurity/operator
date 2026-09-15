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

func TestM019SuccessiveAlternativesReserveExchangedCover(t *testing.T) {
	e := NewCoverageEngine()
	owner, first, second := "uid\x00policy", "ns/first", "ns/second"
	e.alternative = &alternativeContext{
		owner: owner, lambda: .1, budget: 2,
		selected:   map[string]model.Action{first: model.ActionKVReset, second: model.ActionKVReset},
		provenance: map[string]float64{first: 1, second: 1},
		attack:     map[string]bool{first: true, second: true},
		states:     map[string]*model.ExistentialDecision{first: {}, second: {}},
		set: actionset.ActionSet{FactWeights: map[string]float64{"first-original": 2, "second-original": 2, "shared": 10, "unique": 4}, Candidates: []actionset.Candidate{
			{Key: first, Action: model.ActionKVReset, CoverKeys: []string{"first-original"}, ECost: .1},
			{Key: first, Action: model.ActionQuarantine, CoverKeys: []string{"shared"}, ECost: .1},
			{Key: second, Action: model.ActionKVReset, CoverKeys: []string{"second-original"}, ECost: .1},
			{Key: second, Action: model.ActionQuarantine, CoverKeys: []string{"shared"}, ECost: .1},
			{Key: second, Action: model.ActionRouteRotate, CoverKeys: []string{"unique"}, ECost: .1},
		}},
	}
	a, ok := e.SelectAlternative(owner, first, model.ActionKVReset)
	if !ok || a.Action != model.ActionQuarantine {
		t.Fatalf("first exchange unavailable: %+v %t", a, ok)
	}
	if !e.ReserveAlternative(owner, first, model.ActionKVReset, a.Action) {
		t.Fatal("first exchange reservation failed")
	}
	if _, ok := e.SelectAlternative(owner, first, model.ActionKVReset); ok {
		t.Fatal("first target was licensed for a second alternative")
	}
	b, ok := e.SelectAlternative(owner, second, model.ActionKVReset)
	if !ok || b.Action != model.ActionRouteRotate || b.Marginal != 4 {
		t.Fatalf("second target double-counted earlier fallback shared cover: %+v %t", b, ok)
	}
	if !e.ReserveAlternative(owner, second, model.ActionKVReset, b.Action) {
		t.Fatal("second exchange reservation failed")
	}
	if len(e.alternative.selected) != 2 || len(e.alternative.exchanged) != 2 {
		t.Fatal("exchange changed partition/budget slots")
	}
}
