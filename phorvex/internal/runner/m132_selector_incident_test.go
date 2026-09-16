package runner

import (
	"context"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// This fixture exercises the real runner target handoff and Phoenix AMTD
// producer. At the incident baseline its last selector assertion fails because
// only app=demo was emitted, making tier=other an extra Phoenix guest.
func TestM132RunnerPhoenixSelectorPreservesNarrowingExpression(t *testing.T) {
	ctx := context.Background()
	sel := metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}}}}
	p := &v1alpha1.PhorvexPolicy{Spec: v1alpha1.PhorvexPolicySpec{Selector: sel}}
	compiled, err := metav1LabelSelector(p)
	if err != nil {
		t.Fatal(err)
	}
	selected := labels.Set{"app": "demo", "tier": "prod"}
	extra := labels.Set{"app": "demo", "tier": "other"}
	if !compiled.Matches(selected) || compiled.Matches(extra) {
		t.Fatal("fixture did not reach expression-narrowing arm")
	}
	scheme := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	m := &Manager{Actuator: actuator.NewPhoenixActuator(c), Log: logr.Discard()}
	e := &policyEntry{namespace: "ns", tenant: "team", spec: p.Spec}
	pol := model.Policy{Tenant: "team", EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	d := m018SelectedDecision("ns", "demo-0")
	view := m018TickView("ns", "demo-0")
	view["ns/demo-0"].Pod.UID = "selected-uid"
	if n := actuateWithBoundary(t, m, ctx, e, pol, d, view); n != 1 || !d[0].Actuated {
		t.Fatalf("runner did not deliver positive Phoenix action: n=%d trace=%+v", n, d[0].Trace)
	}
	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "phorvex-ns-team"}, &amtd); err != nil {
		t.Fatal(err)
	}
	var events amtdv1beta1.SecurityEventList
	if err := c.List(ctx, &events); err != nil || len(events.Items) != 1 || !reflect.DeepEqual(events.Items[0].Spec.Targets, []string{"ns/demo-0"}) {
		t.Fatalf("event producer failed: events=%d err=%v", len(events.Items), err)
	}
	guest := labels.SelectorFromSet(amtd.Spec.PodSelector)
	if !guest.Matches(selected) || guest.Matches(extra) || !reflect.DeepEqual(amtd.Spec.PodSelector, map[string]string{"app": "demo", "tier": "prod"}) {
		t.Fatalf("Phoenix guest list expanded: selector=%v selected=%v extra=%v", amtd.Spec.PodSelector, guest.Matches(selected), guest.Matches(extra))
	}
}
