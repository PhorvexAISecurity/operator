package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestM124SnapshotProjectsNormalizedNamespaceAndPodBrakes(t *testing.T) {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant", Annotations: map[string]string{actuationbrake.NamespaceDryRunAnnotation: " TRUE "}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "blocked", Annotations: map[string]string{actuationbrake.PodOptOutAnnotation: " yes "}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "peer", Annotations: map[string]string{actuationbrake.PodOptOutAnnotation: "false"}}},
	).Build()
	snap, err := CollectSnapshot(context.Background(), c, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.NamespaceDryRun["tenant"]; !got.Engaged || got.Cause != actuationbrake.NamespaceDryRunEngaged {
		t.Fatalf("namespace observation = %+v", got)
	}
	blocked := snap.PodByKey["tenant/blocked"]
	peer := snap.PodByKey["tenant/peer"]
	if blocked == nil || !blocked.OptOut.Engaged || blocked.OptOut.Cause != actuationbrake.PodOptOutEngaged {
		t.Fatalf("blocked projection = %+v", blocked)
	}
	if peer == nil || peer.OptOut.Engaged || peer.OptOut.Cause != actuationbrake.PodOptOutDisengaged {
		t.Fatalf("peer projection = %+v", peer)
	}
}
