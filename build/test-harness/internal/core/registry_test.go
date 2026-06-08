package core

import (
	"context"
	"testing"
)

type fakeScenario struct{ name string }

func (f *fakeScenario) Metadata() ScenarioMeta { return ScenarioMeta{Name: f.name, Category: CategoryClassicChain} }
func (f *fakeScenario) Setup(context.Context, *Env) error                  { return nil }
func (f *fakeScenario) Execute(context.Context, *Env) (AttackResult, error) { return AttackResult{}, nil }
func (f *fakeScenario) SuccessOracle(context.Context, *Env) (OracleResult, error) {
	return OracleResult{}, nil
}
func (f *fakeScenario) Teardown(context.Context, *Env) error { return nil }

type fakeDefender struct {
	name     string
	baseline bool
}

func (f *fakeDefender) Metadata() DefenderMeta {
	return DefenderMeta{Name: f.name, IsNegativeControlBaseline: f.baseline}
}
func (f *fakeDefender) Setup(context.Context, *Env) error    { return nil }
func (f *fakeDefender) Start(context.Context, *Env) error    { return nil }
func (f *fakeDefender) Stop(context.Context, *Env) error     { return nil }
func (f *fakeDefender) Teardown(context.Context, *Env) error { return nil }

func TestRegistryRegisterAndEnumerate(t *testing.T) {
	resetRegistriesForTest()
	defer resetRegistriesForTest()

	// Register out of alphabetical order; enumeration must be sorted/deterministic.
	RegisterScenario(&fakeScenario{name: "z-scn"})
	RegisterScenario(&fakeScenario{name: "a-scn"})
	RegisterDefender(&fakeDefender{name: "d-z"})
	RegisterDefender(&fakeDefender{name: "d-a", baseline: true})

	scs := Scenarios()
	if len(scs) != 2 {
		t.Fatalf("want 2 scenarios, got %d", len(scs))
	}
	if scs[0].Metadata().Name != "a-scn" || scs[1].Metadata().Name != "z-scn" {
		t.Fatalf("scenarios not sorted: %s, %s", scs[0].Metadata().Name, scs[1].Metadata().Name)
	}
	ds := Defenders()
	if len(ds) != 2 {
		t.Fatalf("want 2 defenders, got %d", len(ds))
	}
	if ds[0].Metadata().Name != "d-a" {
		t.Fatalf("defenders not sorted: %s", ds[0].Metadata().Name)
	}

	if _, ok := LookupScenario("a-scn"); !ok {
		t.Fatalf("LookupScenario failed")
	}
	if _, ok := LookupDefender("d-a"); !ok {
		t.Fatalf("LookupDefender failed")
	}
	if _, ok := LookupScenario("missing"); ok {
		t.Fatalf("LookupScenario returned a missing plugin")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	resetRegistriesForTest()
	defer resetRegistriesForTest()
	RegisterScenario(&fakeScenario{name: "dup"})
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on duplicate scenario registration")
		}
	}()
	RegisterScenario(&fakeScenario{name: "dup"})
}

func TestRegisterEmptyNamePanics(t *testing.T) {
	resetRegistriesForTest()
	defer resetRegistriesForTest()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on empty-name registration")
		}
	}()
	RegisterDefender(&fakeDefender{name: ""})
}
