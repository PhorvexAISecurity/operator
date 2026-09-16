package actuationbrake

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestM124AnnotationValues(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		present     bool
		engaged     bool
		malformed   bool
	}{
		{name: "absent"},
		{name: "lower", value: "true", present: true, engaged: true},
		{name: "upper-space", value: " TRUE ", present: true, engaged: true},
		{name: "yes", value: "YeS", present: true, engaged: true},
		{name: "one", value: "1", present: true, engaged: true},
		{name: "false", value: " FALSE ", present: true},
		{name: "no", value: "No", present: true},
		{name: "zero", value: "0", present: true},
		{name: "empty", value: "", present: true, engaged: true, malformed: true},
		{name: "unknown", value: "enabled", present: true, engaged: true, malformed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			annotations := map[string]string{}
			if tc.present {
				annotations[NamespaceDryRunAnnotation] = tc.value
			}
			ns := Namespace(annotations)
			if ns.Engaged != tc.engaged || (ns.Cause == NamespaceDryRunMalformed) != tc.malformed {
				t.Fatalf("namespace observation = %+v", ns)
			}
			annotations = map[string]string{}
			if tc.present {
				annotations[PodOptOutAnnotation] = tc.value
			}
			pod := Pod(annotations)
			if pod.Engaged != tc.engaged || (pod.Cause == PodOptOutMalformed) != tc.malformed {
				t.Fatalf("Pod observation = %+v", pod)
			}
		})
	}
}

type m124SlowReader struct{ client.Reader }

func (r m124SlowReader) Get(ctx context.Context, key client.ObjectKey, object client.Object, opts ...client.GetOption) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestM124FreshAuthorityRejectsReplacementReadFailureAndTimeout(t *testing.T) {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", UID: types.UID("new-uid")}},
	).Build()
	if got := ObservePod(context.Background(), c, time.Second, "ns", "pod", "old-uid"); !got.Engaged || got.Cause != PodUIDChanged {
		t.Fatalf("replacement observation = %+v", got)
	}
	if got := ObservePod(context.Background(), c, time.Second, "ns", "missing", "uid"); !got.Engaged || got.Cause != PodReadError {
		t.Fatalf("read failure observation = %+v", got)
	}
	now := metav1.Now()
	terminating := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "terminating", UID: types.UID("terminating-uid"), Finalizers: []string{"fixture"}, DeletionTimestamp: &now}}
	terminatingClient := fake.NewClientBuilder().WithScheme(s).WithObjects(terminating).Build()
	if got := ObservePod(context.Background(), terminatingClient, time.Second, "ns", "terminating", "terminating-uid"); !got.Engaged || got.Cause != PodTerminating {
		t.Fatalf("terminating observation = %+v", got)
	}
	start := time.Now()
	if got := ObservePod(context.Background(), m124SlowReader{Reader: c}, 5*time.Millisecond, "ns", "pod", "new-uid"); !got.Engaged || got.Cause != PodReadError {
		t.Fatalf("timeout observation = %+v", got)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("bounded read took %s", elapsed)
	}
	if got := ObserveNamespace(context.Background(), nil, time.Second, "ns"); !got.Engaged || got.Cause != BoundaryReaderUnavailable {
		t.Fatalf("missing reader observation = %+v", got)
	}
	if got := NamespaceObject(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now}}); !got.Engaged || got.Cause != NamespaceTerminating {
		t.Fatalf("terminating namespace observation = %+v", got)
	}
}
