package actuator

import (
	"context"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func TestPhoenixEqualityTranslationMatchesCompleteSelector(t *testing.T) {
	sel := metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "demo"},
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}},
			{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"b", "c"}},
			{Key: "app", Operator: metav1.LabelSelectorOpExists},
			{Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"a"}},
		},
	}
	got, err := phoenixEqualities(sel)
	if err != nil || !reflect.DeepEqual(got, map[string]string{"app": "demo", "tier": "b"}) {
		t.Fatalf("translation = %v, %v", got, err)
	}
	full, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"", "demo", "other"} {
		for _, tier := range []string{"", "a", "b", "c", "other"} {
			set := labels.Set{}
			if app != "" {
				set["app"] = app
			}
			if tier != "" {
				set["tier"] = tier
			}
			if full.Matches(set) != labels.SelectorFromSet(got).Matches(set) {
				t.Fatalf("predicate differs for %v: full=%v map=%v", set, full.Matches(set), labels.SelectorFromSet(got).Matches(set))
			}
		}
	}
}

func TestPhoenixNotInNarrowsFiniteInToEquality(t *testing.T) {
	sel := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}},
		{Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"a"}},
	}}
	got, err := phoenixEqualities(sel)
	if err != nil || !reflect.DeepEqual(got, map[string]string{"tier": "b"}) {
		t.Fatalf("finite NotIn reduction = %v %v", got, err)
	}
	full, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []labels.Set{{}, {"tier": "a"}, {"tier": "b"}, {"tier": "c"}} {
		if full.Matches(set) != labels.SelectorFromSet(got).Matches(set) {
			t.Fatalf("NotIn reduction differs for %v", set)
		}
	}
}

func TestPhoenixPreparationWritesExactSelectorAndRefusesUnsafeUpdate(t *testing.T) {
	ctx := context.Background()
	base := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	counting := &m126CountingClient{Client: base}
	pa := NewPhoenixActuator(counting)
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}}, {Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"b"}}}}
	target := TenantTarget{Tenant: "team", Namespace: "ns", Selector: sel, EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	if err := pa.EnsurePolicy(ctx, target); err != nil {
		t.Fatal(err)
	}
	var amtd amtdv1beta1.AdaptiveMovingTargetDefense
	key := client.ObjectKey{Namespace: "ns", Name: amtdName("ns", "team")}
	if err := base.Get(ctx, key, &amtd); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(amtd.Spec.PodSelector, map[string]string{"app": "demo", "tier": "b"}) || counting.creates != 1 {
		t.Fatalf("AMTD selector/writes = %v creates=%d", amtd.Spec.PodSelector, counting.creates)
	}
	target.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}}}
	if err := pa.EnsurePolicy(ctx, target); err == nil {
		t.Fatal("unsafe update accepted")
	}
	if counting.creates != 1 || counting.updates != 0 {
		t.Fatalf("unsafe selector wrote AMTD: creates=%d updates=%d", counting.creates, counting.updates)
	}
	if err := base.Get(ctx, key, &amtd); err != nil || !reflect.DeepEqual(amtd.Spec.PodSelector, map[string]string{"app": "demo", "tier": "b"}) {
		t.Fatalf("retained AMTD changed: %v %v", amtd.Spec.PodSelector, err)
	}
	var events amtdv1beta1.SecurityEventList
	if err := base.List(ctx, &events); err != nil || len(events.Items) != 0 {
		t.Fatalf("refused preparation emitted events: %d %v", len(events.Items), err)
	}
}

func TestPhoenixEqualityTranslationRefusesBroadening(t *testing.T) {
	for _, tc := range []struct {
		name string
		sel  metav1.LabelSelector
	}{
		{name: "empty", sel: metav1.LabelSelector{}},
		{name: "disjunction", sel: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}}}}},
		{name: "unproven-exists", sel: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}}}},
		{name: "unproven-notin", sel: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"blocked"}}}}},
		{name: "contradiction", sel: metav1.LabelSelector{MatchLabels: map[string]string{"tier": "a"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"b"}}}}},
		{name: "does-not-exist", sel: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpDoesNotExist}}}},
		{name: "invalid-grammar", sel: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOperator("Bogus"), Values: []string{"a"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := phoenixEqualities(tc.sel); err == nil {
				t.Fatalf("unsafe selector accepted as %v", got)
			}
		})
	}
}

func TestCompleteTargetSelectorOwnsItsMapsAndSlices(t *testing.T) {
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"a"}}}}
	got := targetSelector(TenantTarget{Selector: sel, MatchLabels: map[string]string{"app": "wrong"}})
	sel.MatchLabels["app"] = "changed"
	sel.MatchExpressions[0].Values[0] = "changed"
	if got.MatchLabels["app"] != "demo" || got.MatchExpressions[0].Values[0] != "a" {
		t.Fatalf("target selector aliases source: %v", got)
	}
}
