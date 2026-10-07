package controller

import (
	"context"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

func validAdmissionPolicy() *v1alpha1.PhorvexPolicy {
	return &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "tenant-a"},
		Spec: v1alpha1.PhorvexPolicySpec{
			Selector:  metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Objective: v1alpha1.ObjectiveSpec{Lambda: "0.6"},
			Mode:      v1alpha1.ModeActive,
		},
	}
}

func TestValidatePhorvexPolicyAcceptsContractBoundaries(t *testing.T) {
	for _, lambda := range []string{"", "0", "0.0", "0.6", "10", "10.0"} {
		p := validAdmissionPolicy()
		p.Spec.Objective.Lambda = lambda
		if errs := ValidatePhorvexPolicy(p); len(errs) != 0 {
			t.Errorf("lambda %q rejected: %v", lambda, errs)
		}
	}
}

func TestValidatePhorvexPolicyRejectsUnsafeLambda(t *testing.T) {
	for _, lambda := range []string{"banana", "-0.1", "10.0001", "99999", "NaN", "+Inf", "+1", "01", "1e0"} {
		p := validAdmissionPolicy()
		p.Spec.Objective.Lambda = lambda
		errs := ValidatePhorvexPolicy(p)
		if len(errs) != 1 || errs[0].Field != "spec.objective.lambda" {
			t.Errorf("lambda %q errors = %v, want one lambda error", lambda, errs)
		}
	}
}

func TestValidatePhorvexPolicyRequiresNonemptySelectorInActiveMode(t *testing.T) {
	p := validAdmissionPolicy()
	p.Spec.Selector = metav1.LabelSelector{}

	if errs := ValidatePhorvexPolicy(p); len(errs) != 1 || errs[0].Field != "spec.selector" {
		t.Fatalf("active empty selector errors = %v", errs)
	}
	p.Spec.Selector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"api"}}}}
	if errs := ValidatePhorvexPolicy(p); len(errs) != 0 {
		t.Fatalf("expression-only active selector rejected: %v", errs)
	}
	p.Spec.Selector = metav1.LabelSelector{}

	p.Spec.Mode = v1alpha1.ModeDryRun
	if errs := ValidatePhorvexPolicy(p); len(errs) != 0 {
		t.Fatalf("dry-run empty selector rejected: %v", errs)
	}
}

func TestValidatePhorvexPolicyRejectsInvalidSelector(t *testing.T) {
	p := validAdmissionPolicy()
	p.Spec.Selector = metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: "app", Operator: metav1.LabelSelectorOperator("Bogus"), Values: []string{"api"},
	}}}
	errList := ValidatePhorvexPolicy(p)
	if len(errList) != 1 || errList[0].Field != "spec.selector" {
		t.Fatalf("invalid active selector errors = %v", errList)
	}
}

func TestPhorvexPolicyWebhookCreateAndUpdateFailClosed(t *testing.T) {
	v := PhorvexPolicyValidator{}
	invalid := validAdmissionPolicy()
	invalid.Spec.Selector = metav1.LabelSelector{}

	if _, err := v.ValidateCreate(context.Background(), invalid); !apierrors.IsInvalid(err) {
		t.Fatalf("create error = %v, want API Invalid", err)
	}
	if _, err := v.ValidateUpdate(context.Background(), validAdmissionPolicy(), invalid); !apierrors.IsInvalid(err) {
		t.Fatalf("update error = %v, want API Invalid", err)
	}
	if _, err := v.ValidateCreate(context.Background(), validAdmissionPolicy()); err != nil {
		t.Fatalf("valid create rejected: %v", err)
	}
}

func TestPhorvexPolicyWebhookRejectsWrongRuntimeType(t *testing.T) {
	v := PhorvexPolicyValidator{}
	if _, err := v.ValidateCreate(context.Background(), &runtime.Unknown{}); !apierrors.IsBadRequest(err) || !strings.Contains(err.Error(), "expected PhorvexPolicy") {
		t.Fatalf("wrong-type error = %v, want API BadRequest", err)
	}
}

func TestPhorvexPolicyWebhookDeleteDoesNotBlockCleanup(t *testing.T) {
	v := PhorvexPolicyValidator{}
	if _, err := v.ValidateDelete(context.Background(), validAdmissionPolicy()); err != nil {
		t.Fatalf("delete rejected: %v", err)
	}
}

// PHORVEXSEC-189 / M-143 test (f): the exposure-pressure cap must stay strictly inside
// (0,1) — 1 would restore the annihilating form, 0 would erase the prior floor.
func TestValidatePhorvexPolicyAcceptsExposurePressureCapInsideUnitInterval(t *testing.T) {
	for _, cap := range []string{"", "0.5", "0.01", "0.999", "0.25"} {
		p := validAdmissionPolicy()
		p.Spec.Belief.ExposurePressureCap = cap
		if errs := ValidatePhorvexPolicy(p); len(errs) != 0 {
			t.Errorf("exposurePressureCap %q rejected: %v", cap, errs)
		}
	}
}

func TestValidatePhorvexPolicyRejectsExposurePressureCapOutsideUnitInterval(t *testing.T) {
	for _, cap := range []string{"0", "0.0", "1", "1.0", "1.5", "-0.5", "banana", "NaN", "+0.5", ".5", "5e-1"} {
		p := validAdmissionPolicy()
		p.Spec.Belief.ExposurePressureCap = cap
		errs := ValidatePhorvexPolicy(p)
		if len(errs) == 0 {
			t.Errorf("exposurePressureCap %q accepted; want rejection", cap)
			continue
		}
		if errs[0].Field != "spec.belief.exposurePressureCap" {
			t.Errorf("exposurePressureCap %q: error field = %q", cap, errs[0].Field)
		}
	}
}

func TestPhorvexPolicyWebhookCostPreferences(t *testing.T) {
	validator := PhorvexPolicyValidator{}
	for _, tc := range []struct {
		name        string
		preferences *v1alpha1.CostPreferences
		common      string
		valid       bool
	}{
		{"absent", nil, "", true},
		{"explicit-zero", &v1alpha1.CostPreferences{Norm: "0", Flow: "0"}, "", true},
		{"independent-boundaries", &v1alpha1.CostPreferences{Norm: "0.2", Flow: "10"}, "", true},
		{"empty-object", &v1alpha1.CostPreferences{}, "", false},
		{"missing-norm", &v1alpha1.CostPreferences{Flow: "0"}, "", false},
		{"missing-flow", &v1alpha1.CostPreferences{Norm: "0"}, "", false},
		{"negative", &v1alpha1.CostPreferences{Norm: "-1", Flow: "0"}, "", false},
		{"nonfinite", &v1alpha1.CostPreferences{Norm: "0", Flow: "NaN"}, "", false},
		{"above-bound", &v1alpha1.CostPreferences{Norm: "10.01", Flow: "0"}, "", false},
		{"conflicting-zero", &v1alpha1.CostPreferences{Norm: "0", Flow: "0"}, "0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := validAdmissionPolicy()
			p.Spec.Objective.CostPreferences = tc.preferences
			p.Spec.Objective.DisruptionAversion = tc.common
			errs := ValidatePhorvexPolicy(p)
			if tc.valid {
				if len(errs) != 0 {
					t.Fatalf("valid preferences rejected: %v", errs)
				}
			} else if len(errs) != 1 || errs[0].Field != "spec.objective.costPreferences" {
				t.Fatalf("invalid preferences require one costPreferences error, got %v", errs)
			}
			_, createErr := validator.ValidateCreate(context.Background(), p)
			_, updateErr := validator.ValidateUpdate(context.Background(), validAdmissionPolicy(), p)
			for _, err := range []error{createErr, updateErr} {
				if tc.valid && err != nil {
					t.Fatalf("valid preferences rejected by admission: %v", err)
				}
				if !tc.valid && !apierrors.IsInvalid(err) {
					t.Fatalf("invalid preferences accepted by admission: %v", err)
				}
			}
		})
	}
}
