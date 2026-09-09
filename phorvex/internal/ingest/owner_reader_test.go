package ingest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type countingOwnerReader struct {
	client.Reader
	calls map[string]int
}

func (r countingOwnerReader) Get(ctx context.Context, k client.ObjectKey, o client.Object, opts ...client.GetOption) error {
	r.calls[fmt.Sprintf("%T/%s", o, k)]++
	return r.Reader.Get(ctx, k, o, opts...)
}
func TestSnapshotOwnerReadsDeduplicatedAndScoped(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	_ = amtd.AddToScheme(s)
	count := int32(100)
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "dep", Namespace: "protected", UID: "d"}, Spec: appsv1.DeploymentSpec{Replicas: &count}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "protected", UID: "r", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(d, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Spec: appsv1.ReplicaSetSpec{Replicas: &count, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "yes"}}}}
	objects := []client.Object{d, rs}
	for i := 0; i < 100; i++ {
		for _, ns := range []string{"protected", "unrelated"} {
			objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprint("pod-", i), Namespace: ns, UID: types.UID(fmt.Sprint(ns, i)), Labels: map[string]string{"app": "yes"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}})
		}
	}
	// A same-namespace excluded target must not force another owner lookup.
	objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "excluded", Namespace: "protected", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "other", UID: "other", Controller: func() *bool { v := true; return &v }()}}}})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()
	reader := countingOwnerReader{Reader: c, calls: map[string]int{}}
	collect := func() {
		snap, err := CollectSnapshotForRotationTargets(context.Background(), c, time.Now(), nil, reader, func(p *corev1.Pod) bool { return p.Namespace == "protected" && p.Labels["app"] == "yes" })
		if err != nil {
			t.Fatal(err)
		}
		if len(snap.Pods) != 201 {
			t.Fatalf("inventory lost: %d", len(snap.Pods))
		}
		for _, p := range snap.Pods {
			if (p.Namespace == "protected" && p.Labels["app"] == "yes") != p.RotationOwnership.Eligible {
				t.Fatalf("bad eligibility for %s/%s: %+v", p.Namespace, p.Name, p.RotationOwnership)
			}
		}
	}
	collect()
	if len(reader.calls) != 2 {
		t.Fatalf("expected two unique owner reads: %v", reader.calls)
	}
	for _, n := range reader.calls {
		if n != 1 {
			t.Fatalf("duplicate read: %v", reader.calls)
		}
	}
	collect()
	for _, n := range reader.calls {
		if n != 2 {
			t.Fatalf("cache survived snapshot: %v", reader.calls)
		}
	}
}
