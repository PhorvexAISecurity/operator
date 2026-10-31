package ingest

import (
	"context"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"testing"
	"time"
)

func TestWorkloadSpecUnknownsAndSupportedControllers(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	n := int32(4)
	zero := int32(0)
	at := time.Now().UTC()
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "d", Namespace: "ns", UID: "du", ResourceVersion: "42"}, Spec: appsv1.DeploymentSpec{Replicas: &n}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns", UID: "ru", ResourceVersion: "43", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Spec: appsv1.ReplicaSetSpec{Replicas: &n}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", UID: "pu", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}}
	for _, tc := range []struct {
		name, reason string
		mutate       func(*corev1.Pod, *appsv1.ReplicaSet, *appsv1.Deployment)
		noReader     bool
	}{
		{name: "known"}, {name: "missing reader", reason: "owner-reader-unavailable", noReader: true},
		{name: "stale immediate UID", reason: "workload-identity-stale", mutate: func(p *corev1.Pod, r *appsv1.ReplicaSet, d *appsv1.Deployment) { p.OwnerReferences[0].UID = "old" }},
		{name: "stale parent UID", reason: "workload-identity-stale", mutate: func(p *corev1.Pod, r *appsv1.ReplicaSet, d *appsv1.Deployment) { r.OwnerReferences[0].UID = "old" }},
		{name: "missing owner", reason: "controller-identity-unavailable", mutate: func(p *corev1.Pod, r *appsv1.ReplicaSet, d *appsv1.Deployment) { p.OwnerReferences = nil }},
		{name: "ambiguous owner", reason: "controller-identity-unavailable", mutate: func(p *corev1.Pod, r *appsv1.ReplicaSet, d *appsv1.Deployment) {
			p.OwnerReferences = append(p.OwnerReferences, p.OwnerReferences[0])
		}},
		{name: "missing replicas", reason: "workload-spec-replicas-unavailable", mutate: func(p *corev1.Pod, r *appsv1.ReplicaSet, d *appsv1.Deployment) { d.Spec.Replicas = nil }},
		{name: "unsupported daemonset", reason: "workload-kind-has-no-supported-replica-spec", mutate: func(p *corev1.Pod, r *appsv1.ReplicaSet, d *appsv1.Deployment) {
			p.OwnerReferences[0].Kind = "DaemonSet"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r, d := pod.DeepCopy(), rs.DeepCopy(), dep.DeepCopy()
			if tc.mutate != nil {
				tc.mutate(p, r, d)
			}
			c := fake.NewClientBuilder().WithScheme(s).WithObjects(r, d).Build()
			var reader client.Reader = c
			if tc.noReader {
				reader = nil
			}
			got := workloadSpecObservation(context.Background(), reader, p, at)
			if got.Reason != tc.reason || got.Known != (tc.reason == "") {
				t.Fatalf("observation=%+v", got)
			}
			if got.Known && got.SpecReplicas != 4 {
				t.Fatal(got)
			}
		})
	}
	for _, obj := range []client.Object{
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "standalone", Namespace: "ns", UID: "sr", ResourceVersion: "9"}, Spec: appsv1.ReplicaSetSpec{Replicas: &zero}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "stateful", Namespace: "ns", UID: "ss", ResourceVersion: "9"}, Spec: appsv1.StatefulSetSpec{Replicas: &zero}},
		&corev1.ReplicationController{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "ns", UID: "rc", ResourceVersion: "9"}, Spec: corev1.ReplicationControllerSpec{Replicas: &zero}},
	} {
		t.Run(obj.GetName(), func(t *testing.T) {
			gvks, _, err := s.ObjectKinds(obj)
			if err != nil {
				t.Fatal(err)
			}
			p := pod.DeepCopy()
			p.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(obj, gvks[0])}
			c := fake.NewClientBuilder().WithScheme(s).WithObjects(obj).Build()
			got := workloadSpecObservation(context.Background(), c, p, at)
			if !got.Known || got.SpecReplicas != 0 || got.Workload.UID != string(obj.GetUID()) {
				t.Fatal(got)
			}
		})
	}
}
