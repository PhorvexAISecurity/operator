package v1alpha1

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sigs.k8s.io/yaml"
	"testing"
)

func TestCostPreferencesPresenceAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name, objective     string
		configured, invalid bool
		norm, flow          float64
	}{
		{name: "absent", objective: `{}`},
		{name: "null retains absence", objective: `{"costPreferences":null}`},
		{name: "explicit zeros", objective: `{"costPreferences":{"norm":"0","flow":"0"}}`, configured: true},
		{name: "independent values", objective: `{"costPreferences":{"norm":"0.2","flow":"0.8"}}`, configured: true, norm: .2, flow: .8},
		{name: "boundaries", objective: `{"costPreferences":{"norm":"10.0","flow":"0"}}`, configured: true, norm: 10},
		{name: "empty legacy coefficient", objective: `{"disruptionAversion":"","costPreferences":{"norm":"1","flow":"2"}}`, configured: true, norm: 1, flow: 2},
		{name: "empty object", objective: `{"costPreferences":{}}`, configured: true, invalid: true},
		{name: "missing norm", objective: `{"costPreferences":{"flow":"0"}}`, configured: true, invalid: true},
		{name: "missing flow", objective: `{"costPreferences":{"norm":"0"}}`, configured: true, invalid: true},
		{name: "conflicting zero coefficient", objective: `{"disruptionAversion":"0","costPreferences":{"norm":"0","flow":"0"}}`, configured: true, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var objective ObjectiveSpec
			if err := json.Unmarshal([]byte(tc.objective), &objective); err != nil {
				t.Fatal(err)
			}
			spec := PhorvexPolicySpec{Objective: objective}
			n, f, present, err := spec.EffectiveCostPreferences()
			if present != tc.configured || (err != nil) != tc.invalid || n != tc.norm || f != tc.flow {
				t.Fatalf("got norm=%g flow=%g present=%t err=%v", n, f, present, err)
			}
			if spec.EffectiveNormSparsity() != .4 || spec.EffectiveFlowDisruption() != .6 {
				t.Fatal("preferences changed the SLO cost weights")
			}
		})
	}
	for _, bad := range []string{"", "NaN", "+Inf", "-Inf", "-0.1", "10.01", "1e0", "+1", "01", " 1", ".2"} {
		for _, norm := range []bool{true, false} {
			p := &CostPreferences{Norm: "0", Flow: "0"}
			if norm {
				p.Norm = bad
			} else {
				p.Flow = bad
			}
			s := PhorvexPolicySpec{Objective: ObjectiveSpec{CostPreferences: p}}
			if _, _, present, err := s.EffectiveCostPreferences(); err == nil || !present {
				t.Errorf("invalid preference %q norm=%t was accepted", bad, norm)
			}
		}
	}
}

func TestCostPreferencesPolicyDeepCopyIsolation(t *testing.T) {
	original := &PhorvexPolicy{Spec: PhorvexPolicySpec{Objective: ObjectiveSpec{CostPreferences: &CostPreferences{Norm: "0.2", Flow: "0.8"}}}}
	copy := original.DeepCopy()
	copy.Spec.Objective.CostPreferences.Norm = "3"
	if original.Spec.Objective.CostPreferences.Norm != "0.2" {
		t.Fatal("policy copy aliases cost preferences")
	}
}

func TestDefensePoliciesUseCompatibilityCostPreferences(t *testing.T) {
	paths, err := filepath.Glob("../../../deploy/policies/*--*-defense.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 9 {
		t.Fatalf("defense policies: got %d want 9", len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var p PhorvexPolicy
			if err := yaml.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			n, f, present, err := p.Spec.EffectiveCostPreferences()
			if err != nil || !present {
				t.Fatalf("missing/invalid migration: present=%t err=%v", present, err)
			}
			if math.Abs(n-p.Spec.EffectiveLambda()*p.Spec.EffectiveNormSparsity()) > 1e-12 || math.Abs(f-p.Spec.EffectiveLambda()*p.Spec.EffectiveFlowDisruption()) > 1e-12 {
				t.Fatalf("migration changes initial configured objective: norm=%g flow=%g", n, f)
			}
		})
	}
}
