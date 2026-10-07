package runner

import (
	"math"
	"testing"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestCostPreferencesManagerRejectsBeforeRegistration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefs  *v1alpha1.CostPreferences
		common string
	}{
		{"empty", &v1alpha1.CostPreferences{}, ""},
		{"missing-norm", &v1alpha1.CostPreferences{Flow: "0"}, ""},
		{"missing-flow", &v1alpha1.CostPreferences{Norm: "0"}, ""},
		{"nonfinite", &v1alpha1.CostPreferences{Norm: "NaN", Flow: "0"}, ""},
		{"negative", &v1alpha1.CostPreferences{Norm: "0", Flow: "-1"}, ""},
		{"conflicting-explicit-zero", &v1alpha1.CostPreferences{Norm: "0", Flow: "0"}, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := &Manager{policies: map[string]*policyEntry{}}
			p := &v1alpha1.PhorvexPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: types.UID("uid")},
				Spec:       v1alpha1.PhorvexPolicySpec{Objective: v1alpha1.ObjectiveSpec{CostPreferences: tc.prefs, DisruptionAversion: tc.common}},
			}
			if err := manager.Upsert(p); err == nil {
				t.Fatal("invalid preferences registered")
			}
			if len(manager.policies) != 0 {
				t.Fatal("invalid preferences changed policy registry")
			}
			// Also verify a direct typed object bypassing Upsert cannot fall back to legacy.
			policy := buildPolicy(&policyEntry{spec: p.Spec})
			if !policy.CostPreferencesConfigured || !math.IsNaN(policy.NormPreference) {
				t.Fatal("invalid direct object silently fell back")
			}
		})
	}
}

func TestCostPreferencesBuildPolicyEditsAndRemoval(t *testing.T) {
	entry := &policyEntry{key: types.NamespacedName{Namespace: "ns", Name: "policy"}, uid: "uid", tenant: "tenant", namespace: "ns"}
	original := buildPolicy(entry)
	if original.CostPreferencesConfigured {
		t.Fatal("absence became configured")
	}
	entry.spec.Objective.CostPreferences = &v1alpha1.CostPreferences{Norm: "0", Flow: "0"}
	zero := buildPolicy(entry)
	if !zero.CostPreferencesConfigured || zero.NormPreference != 0 || zero.FlowPreference != 0 {
		t.Fatal("explicit zero lost")
	}
	entry.spec.Objective.CostPreferences.Norm = "0.2"
	entry.spec.Objective.CostPreferences.Flow = "0.8"
	patched := buildPolicy(entry)
	if !patched.CostPreferencesConfigured || patched.NormPreference != .2 || patched.FlowPreference != .8 || patched.Owner() != original.Owner() {
		t.Fatal("same-owner preference patch did not apply")
	}
	if patched.NormSparsity != original.NormSparsity || patched.FlowDisruption != original.FlowDisruption {
		t.Fatal("preferences changed SLO cost weights")
	}
	entry.spec.Objective.CostPreferences = nil
	removed := buildPolicy(entry)
	if removed.CostPreferencesConfigured || removed.NormPreference != 0 || removed.FlowPreference != 0 || removed.Owner() != original.Owner() {
		t.Fatal("removal did not restore compatibility behavior")
	}
}
