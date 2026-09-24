package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// This regression compiles unchanged against the pre-fix source. It drives
// admitted Kubernetes objects through collection and the registered UCW profile;
// no new model field or final coverage flag is set by the test.
func TestM184LeadRealProducerCapability(t *testing.T) {
	for _, projected := range []bool{false, true} {
		name := "ordinary-no-token"
		if projected {
			name = "explicit-api-token-automount-disabled"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 9, 23, 23, 0, 0, 0, time.UTC)
			started, automount := true, false
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "owned", Name: "source", UID: "exact-source", ResourceVersion: "23", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
				Spec: corev1.PodSpec{ServiceAccountName: "reader", AutomountServiceAccountToken: &automount,
					Containers: []corev1.Container{{Name: "app", Image: "owned-fixture"}}},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}},
			}
			if projected {
				pod.Spec.Volumes = []corev1.Volume{{Name: "api-identity", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}},
				}}}}
				pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "api-identity", MountPath: "/var/run/owned-token", ReadOnly: true}}
			}
			sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "owned", Name: "reader", UID: "exact-account", ResourceVersion: "11", CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour))}}
			scheme := runtime.NewScheme()
			for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
				if err := add(scheme); err != nil {
					t.Fatal(err)
				}
			}
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, sa, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned"}}).Build()
			snapshot, err := CollectSnapshot(context.Background(), client, now, nil, client)
			if err != nil {
				t.Fatal(err)
			}
			actual := snapshot.PodByKey["owned/source"]
			if actual == nil {
				t.Fatal("real snapshot omitted fixture")
			}
			profile, ok := recon.Registry.Get("ucw-recon")
			if !ok {
				t.Fatal("production profile absent")
			}
			facts := profile.AssetFacts(&model.WorkloadView{Pod: *actual, Physics: model.NeutralPhysics()}, recon.FactContext{AssetValue: 7, PHold: 1, StageUrgency: 1})
			count, narrow, broad := 0, "", ""
			for _, f := range facts.Facts {
				if f.Kind == "podBoundKubeAPIAuthPotential" {
					count++
					narrow = f.Key()
				}
				if f.Kind == "credential" {
					broad = f.Key()
				}
			}
			want := 0
			if projected {
				want = 1
			}
			if count != want {
				t.Fatalf("real admitted projection=%v produced %d potential API-auth facts, want %d", projected, count, want)
			}
			if broad == "" {
				t.Fatal("broad copied-credential audit fact disappeared")
			}
			rotateCovered := false
			for action, keys := range facts.CoverByAction {
				for _, key := range keys {
					if key == broad || narrow != "" && key == narrow && action != model.ActionRotate {
						t.Fatalf("unsupported erasure claim action=%s fact=%s", action, key)
					}
					rotateCovered = rotateCovered || narrow != "" && key == narrow && action == model.ActionRotate
				}
			}
			if rotateCovered != projected {
				t.Fatalf("planned rotate coverage=%v, qualified projection=%v", rotateCovered, projected)
			}
		})
	}
}
