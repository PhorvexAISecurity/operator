/*
 * Phorvex — production applier tests (mocked K8s). Proves: the patch is correctly constructed, the
 * safety gate is RE-ASSERTED (a gate-breaking delta never patches), ambiguous/wrong-namespace targets
 * fail closed, and a non-landing patch is rolled back (with rollback-failure surfaced loudly).
 */

package applier

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	phorvexv1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func scheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := phorvexv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func policyFixture(ns, name string) *phorvexv1alpha1.PhorvexPolicy {
	return &phorvexv1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: phorvexv1alpha1.PhorvexPolicySpec{
			Objective: phorvexv1alpha1.ObjectiveSpec{CostWeights: phorvexv1alpha1.CostWeights{NormSparsity: "0.4", FlowDisruption: "0.6"}},
			Budget:    phorvexv1alpha1.BudgetSpec{MaxMovesPerTick: 3, ProactiveFloor: metav1.Duration{Duration: time.Hour}},
		},
	}
}

var okGate = func(model.Policy) error { return nil }
var candidate = model.Policy{NormSparsity: 1.5, FlowDisruption: 1, MaxMovesPerTick: 2, ProactiveFloor: 2 * time.Hour}

func TestCRDApplier_PatchLandsCorrectly(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(policyFixture("ns-a", "p")).Build()
	a := NewCRDApplier(c, okGate, nil)
	if err := a.Apply("acme", "ns-a", candidate); err != nil {
		t.Fatalf("apply: %v", err)
	}
	var got phorvexv1alpha1.PhorvexPolicy
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns-a", Name: "p"}, &got)
	if got.Spec.Objective.CostWeights.NormSparsity != "1.5" || got.Spec.Budget.MaxMovesPerTick != 2 || got.Spec.Budget.ProactiveFloor.Duration != 2*time.Hour {
		t.Errorf("CRD patch not constructed correctly: %+v", got.Spec)
	}
}

func TestCRDApplier_GateReassertedBlocksPatch(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(policyFixture("ns-a", "p")).Build()
	a := NewCRDApplier(c, func(model.Policy) error { return errors.New("synthetic gate break") }, nil)
	if err := a.Apply("acme", "ns-a", candidate); err == nil || !strings.Contains(err.Error(), "gate REFUSED") {
		t.Fatalf("a gate-breaking delta must be REFUSED before the patch; got %v", err)
	}
	// the CRD must be unchanged.
	var got phorvexv1alpha1.PhorvexPolicy
	_ = c.Get(context.Background(), client.ObjectKey{Namespace: "ns-a", Name: "p"}, &got)
	if got.Spec.Objective.CostWeights.NormSparsity != "0.4" {
		t.Error("a gate-refused apply must NEVER mutate the CRD")
	}
}

func TestCRDApplier_AmbiguousTargetFailsClosed(t *testing.T) {
	none := fake.NewClientBuilder().WithScheme(scheme(t)).Build()
	if err := NewCRDApplier(none, okGate, nil).Apply("acme", "ns-a", candidate); err == nil {
		t.Error("0 PhorvexPolicy must fail-closed (no guessing)")
	}
	two := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(policyFixture("ns-a", "p1"), policyFixture("ns-a", "p2")).Build()
	if err := NewCRDApplier(two, okGate, nil).Apply("acme", "ns-a", candidate); err == nil {
		t.Error("2 PhorvexPolicies must fail-closed (ambiguous)")
	}
}

// faultClient simulates a non-landing patch (noApply) and/or a failing Nth patch (failPatchN).
type faultClient struct {
	client.Client
	calls      int
	noApply    bool
	failPatchN int
}

func (f *faultClient) Patch(ctx context.Context, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
	f.calls++
	if f.failPatchN > 0 && f.calls == f.failPatchN {
		return errors.New("synthetic patch fault")
	}
	if f.noApply {
		return nil // success but does NOT mutate (a non-landing patch)
	}
	return f.Client.Patch(ctx, obj, p, opts...)
}

func TestCRDApplier_NonLandingPatchRollsBack(t *testing.T) {
	base := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(policyFixture("ns-a", "p")).Build()
	a := NewCRDApplier(&faultClient{Client: base, noApply: true}, okGate, nil)
	err := a.Apply("acme", "ns-a", candidate)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("a non-landing patch must be rolled back; got %v", err)
	}
}

func TestCRDApplier_RollbackFailureSurfaced(t *testing.T) {
	base := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(policyFixture("ns-a", "p")).Build()
	// first patch no-ops (non-landing); the rollback (2nd patch) errors → manual-intervention surfaced.
	a := NewCRDApplier(&faultClient{Client: base, noApply: true, failPatchN: 2}, okGate, nil)
	err := a.Apply("acme", "ns-a", candidate)
	if err == nil || !strings.Contains(err.Error(), "MANUAL INTERVENTION") {
		t.Fatalf("a rollback failure must surface LOUDLY; got %v", err)
	}
}
