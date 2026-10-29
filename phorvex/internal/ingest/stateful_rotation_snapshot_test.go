package ingest

import (
	"context"
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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/statefulrotation"
)

// The sensor projects the owner-declared stateful rotation witness for rotation targets only,
// and leaves undeclared StatefulSets without one.
func TestSnapshotProjectsStatefulRotationObservation(t *testing.T) {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	yes, replicas := true, int32(2)
	owner := func(name string, annotations map[string]string) *appsv1.StatefulSet {
		return &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: name, UID: types.UID("uid-" + name), Annotations: annotations},
			Spec:       appsv1.StatefulSetSpec{Replicas: &replicas},
			Status:     appsv1.StatefulSetStatus{ReadyReplicas: 2, CurrentRevision: "r1", UpdateRevision: "r1"},
		}
	}
	member := func(owner string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "db", Name: owner + "-0", UID: types.UID("pod-" + owner),
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: owner, UID: types.UID("uid-" + owner), Controller: &yes}}}}
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		owner("declared", map[string]string{statefulrotation.AnnotationCheckpointPort: "8080",
			statefulrotation.AnnotationCheckpointPath: "/checkpoint", statefulrotation.AnnotationRestorePath: "/restore"}),
		owner("undeclared", nil), member("declared"), member("undeclared"),
	).Build()
	snap, err := CollectSnapshotForRotationTargets(context.Background(), c, time.Now(), nil, c, func(*corev1.Pod) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	declared, undeclared := snap.PodByKey["db/declared-0"], snap.PodByKey["db/undeclared-0"]
	if declared == nil || declared.StatefulRotation == nil || !declared.StatefulRotation.Complete ||
		declared.StatefulRotation.Contract.CheckpointPort != 8080 || declared.StatefulRotation.ReadyReplicas != 2 {
		t.Fatalf("declared member observation = %+v", declared)
	}
	if undeclared == nil || undeclared.StatefulRotation != nil {
		t.Fatalf("undeclared member must carry no observation: %+v", undeclared)
	}

	outside, err := CollectSnapshotForRotationTargets(context.Background(), c, time.Now(), nil, c, func(*corev1.Pod) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if outside.PodByKey["db/declared-0"].StatefulRotation != nil {
		t.Fatal("a Pod outside the rotation targets must not be observed")
	}
}
