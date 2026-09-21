package ingest

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func controllerRef(apiVersion, kind, name, uid string) metav1.OwnerReference {
	yes := true
	return metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, UID: types.UID(uid), Controller: &yes}
}

func TestM100StableWorkloadOwnerSeparatesReplicaSetAndDeployment(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "dep-uid"}}
	rs1 := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app-a", UID: "rs-a", OwnerReferences: []metav1.OwnerReference{controllerRef("apps/v1", "Deployment", "app", "dep-uid")}}}
	rs2 := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app-b", UID: "rs-b", OwnerReferences: []metav1.OwnerReference{controllerRef("apps/v1", "Deployment", "app", "dep-uid")}}}
	oldPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old-pod", UID: "old-uid", OwnerReferences: []metav1.OwnerReference{controllerRef("apps/v1", "ReplicaSet", "app-a", "rs-a")}}}
	newPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "new-pod", UID: "new-uid", OwnerReferences: []metav1.OwnerReference{controllerRef("apps/v1", "ReplicaSet", "app-b", "rs-b")}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs1, rs2, oldPod, newPod).Build()
	oldImmediate, oldStable, err := ResolveStableWorkloadOwner(context.Background(), c, "ns", "old-pod", "old-uid")
	if err != nil {
		t.Fatal(err)
	}
	newImmediate, newStable, err := ResolveStableWorkloadOwner(context.Background(), c, "ns", "new-pod", "new-uid")
	if err != nil {
		t.Fatal(err)
	}
	if oldImmediate.UID == newImmediate.UID || oldImmediate.Kind != "ReplicaSet" || newImmediate.Kind != "ReplicaSet" {
		t.Fatalf("immediate owner provenance collapsed: old=%+v new=%+v", oldImmediate, newImmediate)
	}
	if oldStable != newStable || oldStable.UID != "dep-uid" || oldStable.Kind != "Deployment" {
		t.Fatalf("stable deployment join failed: old=%+v new=%+v", oldStable, newStable)
	}
	if _, _, err := ResolveStableWorkloadOwner(context.Background(), c, "ns", "old-pod", "replacement-uid"); err == nil {
		t.Fatal("stale target UID accepted")
	}

	recreated := dep.DeepCopy()
	recreated.UID = "new-dep-uid"
	recreated.ResourceVersion = ""
	recreated.CreationTimestamp = metav1.Time{}
	if err := c.Delete(context.Background(), dep); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), recreated); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveStableWorkloadOwner(context.Background(), c, "ns", "new-pod", "new-uid"); err == nil {
		t.Fatal("same-name recreated Deployment inherited old UID chain")
	}
}
