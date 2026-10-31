package ingest

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/ownership"
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

// Defaults cannot expand read authority or introduce latency for owner types
// that the existing rotation producer never fetches.
func TestWorkloadEvidenceUsesOnlyAlreadyObservedOwnerObjects(t *testing.T) {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	_ = amtd.AddToScheme(s)
	n := int32(4)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "dep", Namespace: "ns", UID: "d", ResourceVersion: "9"}, Spec: appsv1.DeploymentSpec{Replicas: &n}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "ns", UID: "r", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Spec: appsv1.ReplicaSetSpec{Replicas: &n, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "yes"}}}}
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "sts", Namespace: "ns", UID: "s"}, Spec: appsv1.StatefulSetSpec{Replicas: &n}}
	mk := func(name string, owner client.Object, kind string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(name), Labels: map[string]string{"app": "yes"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(owner, appsv1.SchemeGroupVersion.WithKind(kind))}}}
	}
	// A separate direct Deployment owner never fetched by the real rotation path.
	direct := dep.DeepCopy()
	direct.Name = "direct"
	direct.UID = "direct"
	pods := []*corev1.Pod{mk("deployment", rs, "ReplicaSet"), mk("stateful", sts, "StatefulSet"), mk("direct", direct, "Deployment")}
	objects := []client.Object{dep, rs, sts, direct}
	for _, p := range pods {
		objects = append(objects, p)
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()
	reference := countingOwnerReader{Reader: c, calls: map[string]int{}}
	cached := newSnapshotOwnerReader(reference)
	for _, p := range pods {
		ownership.Check(context.Background(), cached, p)
	}
	reader := countingOwnerReader{Reader: c, calls: map[string]int{}}
	snap, err := CollectSnapshotForRotationTargets(context.Background(), c, time.Now(), nil, reader, func(*corev1.Pod) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reader.calls, reference.calls) || len(reader.calls) != 2 {
		t.Fatalf("evidence expanded live API reads: reference=%v actual=%v", reference.calls, reader.calls)
	}
	for _, p := range snap.Pods {
		if p.Name == "deployment" {
			if !p.WorkloadSpec.Known || p.WorkloadSpec.SpecReplicas != 4 || p.WorkloadSpec.Workload.UID != "d" {
				t.Fatal(p.WorkloadSpec)
			}
		} else if p.WorkloadSpec.Known || p.WorkloadSpec.Reason != "owner-object-not-observed" {
			t.Fatalf("cache miss was invented: %+v", p.WorkloadSpec)
		}
	}
}
