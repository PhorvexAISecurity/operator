package runner

import (
	"math"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

func TestPost25EconomicsManagerRejectsInvalidConfigBeforeRegistration(t *testing.T) {
	for _, raw := range []string{"-1", "10.01", "NaN", "Inf", "1e0", "+1", "01"} {
		m := &Manager{policies: map[string]*policyEntry{}}
		p := &v1alpha1.PhorvexPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: types.UID("uid")},
			Spec:       v1alpha1.PhorvexPolicySpec{Objective: v1alpha1.ObjectiveSpec{DisruptionAversion: raw}},
		}
		if err := m.Upsert(p); err == nil {
			t.Fatalf("invalid disruptionAversion %q registered", raw)
		}
		if len(m.policies) != 0 {
			t.Fatalf("invalid disruptionAversion %q mutated registry", raw)
		}
	}
}

func TestPost25EconomicsBuildPolicyPatchPresenceAndRemoval(t *testing.T) {
	entry := &policyEntry{key: types.NamespacedName{Namespace: "ns", Name: "policy"}, uid: "uid", tenant: "tenant", namespace: "ns"}
	entry.spec.Objective.DisruptionAversion = "0"
	explicitZero := buildPolicy(entry)
	if !explicitZero.DisruptionAversionConfigured || explicitZero.DisruptionAversion != 0 {
		t.Fatalf("explicit zero lost during API conversion: %+v", explicitZero)
	}
	entry.spec.Objective.DisruptionAversion = "2.5"
	patched := buildPolicy(entry)
	if !patched.DisruptionAversionConfigured || patched.DisruptionAversion != 2.5 || patched.Owner() != explicitZero.Owner() {
		t.Fatalf("same-owner patch did not take the new coefficient: %+v", patched)
	}
	entry.spec.Objective.DisruptionAversion = ""
	removed := buildPolicy(entry)
	if removed.DisruptionAversionConfigured || removed.DisruptionAversion != 0 || removed.Owner() != patched.Owner() {
		t.Fatalf("field removal did not restore legacy mode: %+v", removed)
	}
	entry.spec.Objective.DisruptionAversion = "NaN"
	invalid := buildPolicy(entry)
	if !invalid.DisruptionAversionConfigured || !math.IsNaN(invalid.DisruptionAversion) {
		t.Fatalf("bypassed admission silently fell back: %+v", invalid)
	}
}

func TestPost25EconomicsRunnerFallbackUsesFrozenCoefficient(t *testing.T) {
	original := model.Decision{
		Namespace: "ns", Pod: "pod", Action: model.ActionRotate, Lambda: 9,
		Economics: &model.EconomicsMetadata{
			Version:                  model.EconomicsFixedDisruptionAversionV1,
			DisruptionAversion:       model.OptionalFloat{Present: true, Value: 2},
			LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: 9},
			EffectiveCostCoefficient: 2, CoefficientSource: model.CostCoefficientSourceBeta,
		},
		Measurements: &model.DecisionMeasurementsV1{SchemaVersion: model.DecisionMeasurementsSchemaV1, Source: "test"},
	}
	alt := decision.Alternative{
		Action: model.ActionQuarantine, Coverage: 5, Marginal: 4, Cost: 1,
		Gain: 2, CoverKeys: []string{"a"},
		Attribution: []model.AttributionTerm{{Source: "cost:-disruptionAversion*C", Contribution: -2}},
	}
	got := fallbackDecision(original, alt)
	if got.Net != 3 || got.ProactiveRate != 3 || got.Lambda != 9 || got.Economics == nil ||
		got.Economics.EffectiveCostCoefficient != 2 || got.Attribution[0].Source != "cost:-disruptionAversion*C" {
		t.Fatalf("fallback reconstructed with runtime lambda instead of beta: %+v", got)
	}
	if got.Economics == original.Economics {
		t.Fatal("fallback aliases mutable economics metadata")
	}
}
