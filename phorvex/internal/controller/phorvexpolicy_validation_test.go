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

func TestValidatePhorvexPolicyRequiresMatchLabelsOnlyInActiveMode(t *testing.T) {
	p := validAdmissionPolicy()
	p.Spec.Selector = metav1.LabelSelector{}

	if errs := ValidatePhorvexPolicy(p); len(errs) != 1 || errs[0].Field != "spec.selector.matchLabels" {
		t.Fatalf("active empty selector errors = %v", errs)
	}

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
	if len(errList) != 2 || errList[0].Field != "spec.selector" || errList[1].Field != "spec.selector.matchLabels" {
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
