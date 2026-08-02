package main

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestValidateNamespaceFailClosed(t *testing.T) {
	for _, ns := range []string{"", "default", "phorvex-system", "phorvex-cost-validate-"} {
		if err := validateNamespace(ns); err == nil {
			t.Fatalf("validateNamespace(%q) allowed a non-disposable target", ns)
		}
	}
	if err := validateNamespace("phorvex-cost-validate-task35"); err != nil {
		t.Fatalf("valid disposable namespace rejected: %v", err)
	}
}

func TestObservedCostUsesOnlyAvailableTerms(t *testing.T) {
	obs := observation{
		AvailabilityLoss: 0.2,
		P99BeforeMS:      nullableFloat{Value: 100, Valid: true},
		P99AfterMS:       nullableFloat{Value: 150, Valid: true},
		TimeToReadySec:   nullableFloat{Value: 40, Valid: true},
		StateOrKVLoss:    nullableFloat{Value: 1, Valid: true},
	}
	got, terms := observedCost(obs)
	// mean(0.2 availability, 0.5 p99 increase, 0.1 ready, 1 state loss)
	want := 0.45
	if !got.Valid || terms != 4 || math.Abs(got.Value-want) > 1e-12 {
		t.Fatalf("observedCost=%+v terms=%d, want %.3f/4", got, terms, want)
	}
}

func TestNullableMetricFieldsRemainExplicitNull(t *testing.T) {
	data, err := json.Marshal(observation{P99BeforeMS: nullableFloat{}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["p99_before_ms"] != nil {
		t.Fatalf("missing measurement serialized as %v, want null", decoded["p99_before_ms"])
	}
}

func TestFeatureComponentsAreActionSpecific(t *testing.T) {
	o := options{Stateful: true, GPU: true}
	m := metricSnapshot{GPUUtil: nullableFloat{Value: 0.7, Valid: true}}
	if got := stateFeature(model.ActionRotate, o); got != 1 {
		t.Fatalf("state feature for stateful rotate=%v", got)
	}
	if got := stateFeature(model.ActionQuarantine, o); got != 0 {
		t.Fatalf("state feature for quarantine=%v", got)
	}
	if got := gpuFeature(model.ActionRotate, o, m); !got.Valid || got.Value != 0.7 {
		t.Fatalf("gpu feature=%+v", got)
	}
	if got := availabilityFeature(model.ActionRotate, 4); got != 0.25 {
		t.Fatalf("availability feature=%v", got)
	}
}
