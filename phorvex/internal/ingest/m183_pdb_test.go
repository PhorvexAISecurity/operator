package ingest

import (
	"context"
	"errors"
	"testing"

	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestM183PDBInventoryDistinguishesObservedEmptyFromListFailure(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := policyv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	got, complete := collectPDBs(t.Context(), base)
	if !complete || len(got) != 0 {
		t.Fatalf("observed empty inventory complete=%v PDBs=%+v", complete, got)
	}

	failed := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{List: func(ctx context.Context, inner client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if _, ok := list.(*policyv1.PodDisruptionBudgetList); ok {
			return errors.New("pdb list unavailable")
		}
		return inner.List(ctx, list, opts...)
	}})
	got, complete = collectPDBs(t.Context(), failed)
	if complete || got != nil {
		t.Fatalf("failed inventory complete=%v PDBs=%+v", complete, got)
	}
}

func TestM183PDBProjectionRetainsStatusAuthorityAndPercentageSpecs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := policyv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	minAvailable := intstr.FromString("50%")
	maxUnavailable := intstr.FromString("25%")
	minAvailableInt := intstr.FromInt(2)
	pdbPercentage := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "voice-percentage", UID: "pdb-percentage", Generation: 7},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &minAvailable,
			Selector:     &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 7, CurrentHealthy: 3, DesiredHealthy: 2, ExpectedPods: 4, DisruptionsAllowed: 1},
	}
	pdbMaximum := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "voice-maximum", UID: "pdb-maximum", Generation: 8},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 8, CurrentHealthy: 4, DesiredHealthy: 3, ExpectedPods: 4, DisruptionsAllowed: 1},
	}
	pdbInteger := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "voice-integer", UID: "pdb-integer", Generation: 9},
		Spec:       policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvailableInt, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice"}}},
		Status:     policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 9, CurrentHealthy: 3, DesiredHealthy: 2, ExpectedPods: 3, DisruptionsAllowed: 1},
	}
	pdbStale := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "voice-stale", UID: "pdb-stale", Generation: 10},
		Spec:       policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvailableInt, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice"}}},
		Status:     policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 9, CurrentHealthy: 3, DesiredHealthy: 2, ExpectedPods: 3, DisruptionsAllowed: 1},
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pdbPercentage, pdbMaximum, pdbInteger, pdbStale).Build()
	got, complete := collectPDBs(t.Context(), base)
	if !complete || len(got) != 4 {
		t.Fatalf("complete=%v PDBs=%+v", complete, got)
	}
	byName := make(map[string]PDBInfo, len(got))
	for _, item := range got {
		byName[item.Name] = item
	}
	percentage := byName["voice-percentage"]
	if percentage.UID != "pdb-percentage" || percentage.Generation != 7 || percentage.ObservedGeneration != 7 || !percentage.SelectorValid || percentage.MinAvailable != -1 || percentage.MinAvailableText != "50%" || percentage.MaxUnavailableText != "" || percentage.DisruptionsAllowed != 1 || percentage.DesiredHealthy != 2 || percentage.ExpectedPods != 4 {
		t.Fatalf("percentage projection=%+v", percentage)
	}
	maximum := byName["voice-maximum"]
	if maximum.UID != "pdb-maximum" || maximum.Generation != 8 || maximum.ObservedGeneration != 8 || !maximum.SelectorValid || maximum.MinAvailable != -1 || maximum.MinAvailableText != "" || maximum.MaxUnavailableText != "25%" || maximum.DisruptionsAllowed != 1 || maximum.DesiredHealthy != 3 || maximum.ExpectedPods != 4 {
		t.Fatalf("maxUnavailable projection=%+v", maximum)
	}
	integer := byName["voice-integer"]
	if integer.MinAvailable != 2 || integer.MinAvailableText != "2" || integer.Generation != integer.ObservedGeneration {
		t.Fatalf("integer projection=%+v", integer)
	}
	stale := byName["voice-stale"]
	if stale.Generation != 10 || stale.ObservedGeneration != 9 {
		t.Fatalf("stale generation projection=%+v", stale)
	}
}
