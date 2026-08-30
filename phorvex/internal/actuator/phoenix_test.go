/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package actuator

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatalf("add phoenix scheme: %v", err)
	}
	return s
}

func TestPhoenixEnsurePolicy(t *testing.T) {
	s := newScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	pa := NewPhoenixActuator(c)
	ctx := context.Background()

	target := TenantTarget{
		Tenant: "team-a", Namespace: "ns",
		MatchLabels:    map[string]string{"app": "demo"},
		EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true},
	}
	if err := pa.EnsurePolicy(ctx, target); err != nil {
		t.Fatalf("EnsurePolicy: %v", err)
	}
	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	// Name is namespace-qualified (phorvex-<namespace>-<tenant>) so two policies that share a
	// tenant across namespaces can't produce the same cluster-global AMTD RuleID and jam the
	// controller.
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "phorvex-ns-team-a"}, &amtd); err != nil {
		t.Fatalf("AMTD not created: %v", err)
	}
	if amtd.Spec.PodSelector["app"] != "demo" {
		t.Errorf("AMTD podSelector = %v, want app=demo", amtd.Spec.PodSelector)
	}
	if len(amtd.Spec.Strategy) != 2 {
		t.Fatalf("want 2 strategies (rotate+quarantine), got %d", len(amtd.Spec.Strategy))
	}
	if amtd.Spec.MatcherMode != amtdv1beta1.MatcherModeExact {
		t.Errorf("matcher mode should be Exact, got %q", amtd.Spec.MatcherMode)
	}
	// Verify rotate strategy maps to Delete and quarantine to Quarantine.
	var sawRotateDelete, sawQuarantine bool
	for _, st := range amtd.Spec.Strategy {
		if st.Rule.Type == RuleTypeRotate && st.Action.Delete != nil {
			sawRotateDelete = true
		}
		if st.Rule.Type == RuleTypeQuarantine && st.Action.Quarantine != nil {
			sawQuarantine = true
		}
	}
	if !sawRotateDelete || !sawQuarantine {
		t.Errorf("strategy mapping wrong: rotate->Delete=%v quarantine->Quarantine=%v", sawRotateDelete, sawQuarantine)
	}

	// Idempotent: a second EnsurePolicy must not error or duplicate.
	if err := pa.EnsurePolicy(ctx, target); err != nil {
		t.Fatalf("EnsurePolicy (2nd) should be idempotent: %v", err)
	}
}

func TestPhoenixActuateEmitsSecurityEvent(t *testing.T) {
	s := newScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	pa := NewPhoenixActuator(c)
	ctx := context.Background()

	res, err := pa.Actuate(ctx, Request{
		Tenant: "team-a", Namespace: "ns", Pod: "demo-1",
		Action: model.ActionRotate, Reason: "test", Score: 0.9,
	})
	if err != nil {
		t.Fatalf("Actuate: %v", err)
	}
	if !res.Emitted || res.RuleType != RuleTypeRotate || res.RuleSource != RuleSource {
		t.Errorf("unexpected result: %+v", res)
	}

	var seList amtdv1beta1.SecurityEventList
	if err := c.List(ctx, &seList); err != nil {
		t.Fatalf("list SecurityEvents: %v", err)
	}
	if len(seList.Items) != 1 {
		t.Fatalf("want 1 SecurityEvent emitted, got %d", len(seList.Items))
	}
	se := seList.Items[0]
	if len(se.Spec.Targets) != 1 || se.Spec.Targets[0] != "ns/demo-1" {
		t.Errorf("target = %v, want [ns/demo-1]", se.Spec.Targets)
	}
	if se.Spec.Rule.Type != RuleTypeRotate || se.Spec.Rule.Source != RuleSource || se.Spec.Rule.ThreatLevel != RuleThreatLevel {
		t.Errorf("rule = %+v", se.Spec.Rule)
	}
	if se.Spec.AnomalyScore == nil || *se.Spec.AnomalyScore != "0.9000" {
		t.Errorf("anomalyScore = %v, want 0.9000", se.Spec.AnomalyScore)
	}
}

func TestNativeActuatorDispatch(t *testing.T) {
	n := NewNativeActuator(nil)
	if n.Name() != "native" {
		t.Errorf("Name() = %q, want native", n.Name())
	}
	// EnsurePolicy is a no-op (native carries no standing Phoenix CR).
	if err := n.EnsurePolicy(context.Background(), TenantTarget{}); err != nil {
		t.Errorf("native EnsurePolicy should be a no-op nil, got %v", err)
	}
	// Dry-run guard: a handler must never be invoked when DryRun is set.
	n.DryRun = true
	if _, err := n.Actuate(context.Background(), Request{Action: model.ActionRotate}); err != errDryRunGuard {
		t.Errorf("DryRun Actuate should hit the dry-run guard, got %v", err)
	}
	// Unknown action: a LOUD no-handler error (not a silent no-op). Returns before any
	// client use, so a nil client is fine.
	n.DryRun = false
	if _, err := n.Actuate(context.Background(), Request{Action: model.Action("bogus-action")}); err == nil {
		t.Errorf("unknown action should return a no-handler error, got nil")
	}
}
