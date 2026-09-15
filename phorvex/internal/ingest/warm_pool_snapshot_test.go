package ingest

import (
	"context"
	"fmt"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestWarmPoolSnapshotCachesDistinctControllerAndKeepsPerPodChecks(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	count := int32(2)
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "parent", Namespace: "ns", UID: "parent-uid"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "ns", UID: "pool-uid", Generation: 1, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(d, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Spec: appsv1.ReplicaSetSpec{Replicas: &count, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "model", "phorvex.ai/swap-group": "g"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "model", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "warm-shadow", "phorvex.ai/model-loaded": "false"}, Annotations: map[string]string{"phorvex.ai/route-service": "serving"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "test:unused"}}}}}, Status: appsv1.ReplicaSetStatus{ObservedGeneration: 1, Replicas: 2}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(d, rs).Build()
	reader := countingOwnerReader{Reader: c, calls: map[string]int{}}
	cache := newWarmPoolSnapshotCache(reader, []ServiceInfo{{Namespace: "ns", Name: "serving", Selector: map[string]string{"app": "model", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "leader"}}})
	p := model.Pod{Namespace: "ns", OwnerKind: "ReplicaSet", OwnerName: "pool", WarmPoolOwnerUID: "pool-uid", RouteService: "serving", Labels: map[string]string{"app": "model", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "leader"}}
	for i := 0; i < 100; i++ {
		if !cache.Configured(context.Background(), p) {
			t.Fatal("valid repeated pool member refused")
		}
	}
	if len(reader.calls) != 2 {
		t.Fatalf("controller/parent reads not bounded: %v", reader.calls)
	}
	for _, n := range reader.calls {
		if n != 1 {
			t.Fatalf("duplicate owner Get: %v", reader.calls)
		}
	}
	bad := p
	bad.Labels = map[string]string{"app": "model", "phorvex.ai/swap-group": "other", "phorvex.ai/role": "leader"}
	if cache.Configured(context.Background(), bad) {
		t.Fatal("cached controller fact bypassed per-Pod group check")
	}
	for i := 0; i < 150; i++ {
		other := p
		other.OwnerName = fmt.Sprintf("missing-%d", i)
		other.WarmPoolOwnerUID = fmt.Sprintf("uid-%d", i)
		_ = cache.Configured(context.Background(), other)
	}
	if len(cache.controllers) != warmPoolSnapshotMaxControllers {
		t.Fatalf("distinct-controller bound not enforced: %d", len(cache.controllers))
	}
}
