package scopedoutcome

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func TestPost25M106KubernetesResolverDiscoversOnlyNewReadyStableOwnerReplacement(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	yes := true
	grace := int64(30)
	actionAt := time.Date(2026, 9, 21, 11, 0, 0, 500_000_000, time.UTC)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "dep-uid"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app-rs", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &yes}}}}
	foreignDep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "foreign", UID: "foreign-dep-uid"}}
	foreignRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "foreign-rs", UID: "foreign-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: foreignDep.Name, UID: foreignDep.UID, Controller: &yes}}}}
	podFor := func(name, uid string, owner *appsv1.ReplicaSet, ready bool) *corev1.Pod {
		status := corev1.ConditionFalse
		if ready {
			status = corev1.ConditionTrue
		}
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID(uid), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: owner.Name, UID: owner.UID, Controller: &yes}}},
			Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &grace}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}}}
	}
	old := podFor("old", "pod-uid", rs, true)
	preexisting := podFor("peer", "peer-uid", rs, true)
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: types.UID("policy-uid"), Generation: 3}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&corev1.Pod{}).
		WithObjects(dep, rs, foreignDep, foreignRS, old, preexisting, policy).Build()
	resolver := KubernetesBindingResolver{Reader: reader, Timeout: time.Second}
	config := PrepareConfig{Policy: model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 3},
		Workload:   model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "dep-uid"},
		TargetName: "old", TargetUID: "pod-uid", TargetTerminationGraceSeconds: 30}
	workload, gotGrace, err := resolver.Resolve(context.Background(), config)
	if err != nil || workload != config.Workload || gotGrace != grace {
		t.Fatalf("resolved workload=%+v grace=%d err=%v", workload, gotGrace, err)
	}
	boundary, err := resolver.SnapshotReplacementBoundary(context.Background(), config)
	if err != nil || len(boundary) != 2 {
		t.Fatalf("pre-dispatch boundary=%v err=%v", boundary, err)
	}
	if err := resolver.ResolveReplacement(context.Background(), config, boundary, "peer-uid", actionAt); err == nil {
		t.Fatal("pre-existing peer became replacement authority")
	}
	between := podFor("between-prepare-and-dispatch", "between-uid", rs, true)
	between.CreationTimestamp = metav1.NewTime(actionAt.Add(-time.Second))
	if err := reader.Create(context.Background(), between); err != nil {
		t.Fatal(err)
	}
	if err := resolver.ResolveReplacement(context.Background(), config, boundary, "between-uid", actionAt); err == nil {
		t.Fatal("same-owner Pod created before dispatch became replacement authority")
	}

	newPod := podFor("replacement", "replacement-uid", rs, false)
	newPod.CreationTimestamp = metav1.NewTime(actionAt.Add(time.Second))
	if err := reader.Create(context.Background(), newPod); err != nil {
		t.Fatal(err)
	}
	if err := resolver.ResolveReplacement(context.Background(), config, boundary, "replacement-uid", actionAt); err == nil {
		t.Fatal("NotReady replacement became revoked authority")
	}
	newPod.Status.Phase = corev1.PodRunning
	newPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := reader.Status().Update(context.Background(), newPod); err != nil {
		t.Fatal(err)
	}
	if err := resolver.ResolveReplacement(context.Background(), config, boundary, "replacement-uid", actionAt); err != nil {
		t.Fatalf("unique new Ready same-owner replacement was refused: %v", err)
	}

	foreign := podFor("foreign-new", "foreign-uid", foreignRS, true)
	foreign.CreationTimestamp = metav1.NewTime(actionAt.Add(time.Second))
	if err := reader.Create(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	if err := resolver.ResolveReplacement(context.Background(), config, boundary, "foreign-uid", actionAt); err == nil {
		t.Fatal("new foreign-owner Pod became replacement authority")
	}
	ambiguous := podFor("replacement-two", "replacement-two-uid", rs, true)
	ambiguous.CreationTimestamp = metav1.NewTime(actionAt.Add(2 * time.Second))
	if err := reader.Create(context.Background(), ambiguous); err != nil {
		t.Fatal(err)
	}
	if err := resolver.ResolveReplacement(context.Background(), config, boundary, "replacement-uid", actionAt); err == nil {
		t.Fatal("ambiguous new same-owner Pods became replacement authority")
	}

	config.TargetUID = "replacement-uid"
	if _, _, err := resolver.Resolve(context.Background(), config); err == nil {
		t.Fatal("replacement Pod UID inherited old-session authority")
	}
	config.TargetUID = "pod-uid"
	config.Policy.Generation++
	if _, _, err := resolver.Resolve(context.Background(), config); err == nil {
		t.Fatal("stale policy generation retained producer authority")
	}
}
