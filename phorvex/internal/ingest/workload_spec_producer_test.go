package ingest

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// This test intentionally uses reflection only at the new metadata boundary,
// so the same real-producer counterexample compiles and runs on the baseline.
func TestWorkloadSpecRealProducerCounterexample(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	_ = amtd.AddToScheme(s)
	replicas := int32(4)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "dep", Namespace: "ns", UID: "deployment-uid", ResourceVersion: "37", Generation: 5}, Spec: appsv1.DeploymentSpec{Replicas: &replicas}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "ns", UID: "replicaset-uid", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "only-observed-pod", Namespace: "ns", UID: "pod-uid", Labels: map[string]string{"app": "demo"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(dep, rs, pod).Build()
	at := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	snap, err := CollectSnapshotForRotationTargets(context.Background(), c, at, nil, c, func(*corev1.Pod) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	var observed appsv1.Deployment
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(dep), &observed); err != nil {
		t.Fatal(err)
	}
	if len(snap.Pods) != 1 || snap.Pods[0].DesiredReplicas != 1 || observed.Spec.Replicas == nil || *observed.Spec.Replicas != 4 || !snap.Pods[0].RotationOwnership.Eligible {
		t.Fatalf("fixture/control mismatch: pods=%+v deployment=%+v", snap.Pods, observed.Spec.Replicas)
	}
	t.Log("POSITIVE CONTROL: one observed pod, authoritative spec.replicas=4, valid UID-bound Deployment lineage; legacy desired count remains 1")
	field := reflect.ValueOf(snap.Pods[0]).FieldByName("WorkloadSpec")
	if !field.IsValid() {
		t.Fatal("BASELINE COUNTEREXAMPLE: real ingest loses authoritative controller spec.replicas=4 and exposes only observed count=1")
	}
	if !field.FieldByName("Known").Bool() || field.FieldByName("SpecReplicas").Int() != 4 || field.FieldByName("ResourceVersion").String() != "37" || field.FieldByName("Generation").Int() != 5 {
		t.Fatalf("wrong authoritative observation: %+v", field.Interface())
	}
	if field.FieldByName("Workload").FieldByName("UID").String() != "deployment-uid" || field.FieldByName("Controller").FieldByName("UID").String() != "replicaset-uid" {
		t.Fatalf("lineage lost: %+v", field.Interface())
	}
	if !field.FieldByName("ObservedAt").Interface().(time.Time).Equal(at) {
		t.Fatal("observation timestamp changed")
	}
}
