package ingest

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	amtd "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type unavailableServiceAccounts struct{ client.Reader }

func (c unavailableServiceAccounts) List(ctx context.Context, objects client.ObjectList, opts ...client.ListOption) error {
	if _, ok := objects.(*corev1.ServiceAccountList); ok {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, "", errors.New("denied"))
	}
	return c.Reader.List(ctx, objects, opts...)
}

type blockingServiceAccounts struct{ client.Reader }

func (c blockingServiceAccounts) List(ctx context.Context, objects client.ObjectList, opts ...client.ListOption) error {
	if _, ok := objects.(*corev1.ServiceAccountList); ok {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.Reader.List(ctx, objects, opts...)
}

func tokenProjectionFixture(t *testing.T, change func(*corev1.Pod, *corev1.ServiceAccount), readFailure ...string) *Snapshot {
	t.Helper()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	started := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "source", UID: types.UID("pod-uid"),
			ResourceVersion: "20", CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Spec: corev1.PodSpec{ServiceAccountName: "reader", AutomountServiceAccountToken: boolPtr(false),
			Containers: []corev1.Container{{Name: "hold", VolumeMounts: []corev1.VolumeMount{{Name: "credential", MountPath: "/credential", ReadOnly: true}}}},
			Volumes: []corev1.Volume{{Name: "credential", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", ExpirationSeconds: int64Ptr(600)}}},
			}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "hold", Started: &started,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}},
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "reader", UID: types.UID("sa-uid"),
		ResourceVersion: "5", CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour))}}
	if change != nil {
		change(pod, sa)
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtd.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, sa, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant"}}).Build()
	var reader client.Reader = c
	if len(readFailure) != 0 {
		switch readFailure[0] {
		case "forbidden":
			reader = unavailableServiceAccounts{c}
		case "blocked", "blocked-short-parent":
			reader = blockingServiceAccounts{c}
		default:
			t.Fatalf("unknown reader failure %q", readFailure[0])
		}
	}
	parentBudget := 2 * time.Second
	if len(readFailure) != 0 && readFailure[0] == "blocked-short-parent" {
		parentBudget = 100 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
	defer cancel()
	snap, err := CollectSnapshot(ctx, c, now, nil, reader)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatalf("optional ServiceAccount read exhausted parent snapshot deadline: %v", ctx.Err())
	}
	if snap.ServiceAccountInventoryComplete == (len(readFailure) != 0) {
		t.Fatal("ServiceAccount inventory completeness misreported")
	}
	return snap
}

func boolPtr(v bool) *bool    { return &v }
func int64Ptr(v int64) *int64 { return &v }

func TestPodBoundKubeAPIAuthRealSnapshotAndPlannedCover(t *testing.T) {
	snap := tokenProjectionFixture(t, nil)
	pod := snap.PodByKey["tenant/source"]
	if pod == nil || !pod.HasPodBoundKubeAPIAuth() {
		t.Fatalf("admitted explicit projection with automount=false lacked witness: %+v", pod)
	}
	w := pod.PodBoundKubeAPIAuth
	if w.PodUID != "pod-uid" || w.ServiceAccountUID != "sa-uid" || w.AudienceSource != "kube-apiserver-default" || w.EvidenceSource != "admitted-pod-and-serviceaccount" {
		t.Fatalf("wrong typed witness: %+v", w)
	}
	view := &model.WorkloadView{Pod: *pod, Physics: model.NeutralPhysics()}
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon not registered")
	}
	af := profile.AssetFacts(view, recon.FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1})
	var narrow, broad string
	for _, f := range af.Facts {
		switch f.Kind {
		case recon.FactPodBoundKubeAPIAuthPotential:
			narrow = f.Key()
			if f.Weight != 10 || math.IsNaN(f.Weight) || math.IsInf(f.Weight, 0) {
				t.Fatalf("narrow fact weight=%v, want finite 10", f.Weight)
			}
		case recon.FactCredential:
			broad = f.Key()
		}
	}
	if narrow == "" || broad == "" {
		t.Fatalf("narrow and broad facts not both present: %+v", af.Facts)
	}
	for action, keys := range af.CoverByAction {
		for _, key := range keys {
			if key == broad || key == narrow && action != model.ActionRotate {
				t.Fatalf("wrong token cover %s %s", action, key)
			}
		}
	}
	found := false
	for _, key := range af.CoverByAction[model.ActionRotate] {
		found = found || key == narrow
	}
	if !found {
		t.Fatal("rotate planned cover lacks narrow fact")
	}
	noToken := tokenProjectionFixture(t, func(p *corev1.Pod, _ *corev1.ServiceAccount) { p.Spec.Volumes = nil })
	controlView := &model.WorkloadView{Pod: *noToken.PodByKey["tenant/source"], Physics: model.NeutralPhysics()}
	control := profile.AssetFacts(controlView, recon.FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1})
	rotateValue := func(facts recon.AssetFacts) float64 {
		weights := make(map[string]float64, len(facts.Facts))
		for _, fact := range facts.Facts {
			weights[fact.Key()] = fact.Weight
		}
		var sum float64
		for _, key := range facts.CoverByAction[model.ActionRotate] {
			sum += weights[key]
		}
		return sum
	}
	if got := rotateValue(af) - rotateValue(control); got != 10 {
		t.Fatalf("qualified minus unqualified planned rotate cover = %v, want one 10-weight potential fact", got)
	}
	stale := *pod
	stale.UID = "recreated-pod"
	if stale.HasPodBoundKubeAPIAuth() {
		t.Fatal("recreated Pod inherited old UID witness")
	}
	stale = *pod
	stale.PodResourceVersion = "stale"
	if stale.HasPodBoundKubeAPIAuth() {
		t.Fatal("changed Pod resourceVersion inherited old projection witness")
	}
	sibling := tokenProjectionFixture(t, func(p *corev1.Pod, _ *corev1.ServiceAccount) {
		p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "sibling", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
		p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{Name: "sibling", MountPath: "/credential/other", ReadOnly: true})
	})
	if !sibling.PodByKey["tenant/source"].HasPodBoundKubeAPIAuth() {
		t.Fatal("unrelated sibling mount hid token witness")
	}
}

func TestPodBoundKubeAPIAuthProjectionFailClosed(t *testing.T) {
	cases := []struct {
		name string
		edit func(*corev1.Pod, *corev1.ServiceAccount)
	}{
		{"no projection", func(p *corev1.Pod, _ *corev1.ServiceAccount) { p.Spec.Volumes = nil }},
		{"legacy secret token", func(p *corev1.Pod, _ *corev1.ServiceAccount) {
			p.Spec.Volumes[0].Projected = nil
			p.Spec.Volumes[0].Secret = &corev1.SecretVolumeSource{SecretName: "reader-token"}
		}},
		{"nondefault audience", func(p *corev1.Pod, _ *corev1.ServiceAccount) {
			p.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience = "vault"
		}},
		{"unmounted", func(p *corev1.Pod, _ *corev1.ServiceAccount) { p.Spec.Containers[0].VolumeMounts = nil }},
		{"subpath excludes token", func(p *corev1.Pod, _ *corev1.ServiceAccount) { p.Spec.Containers[0].VolumeMounts[0].SubPath = "ca.crt" }},
		{"dynamic subpath", func(p *corev1.Pod, _ *corev1.ServiceAccount) {
			p.Spec.Containers[0].VolumeMounts[0].SubPathExpr = "$(FILENAME)"
		}},
		{"token file shadowed", func(p *corev1.Pod, _ *corev1.ServiceAccount) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "shadow", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts,
				corev1.VolumeMount{Name: "shadow", MountPath: "/credential/token"})
		}},
		{"token parent shadowed", func(p *corev1.Pod, _ *corev1.ServiceAccount) {
			p.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Path = "nested/token"
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "shadow", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts,
				corev1.VolumeMount{Name: "shadow", MountPath: "/credential/nested"})
		}},
		{"pending", func(p *corev1.Pod, _ *corev1.ServiceAccount) { p.Status.Phase = corev1.PodPending }},
		{"container not started", func(p *corev1.Pod, _ *corev1.ServiceAccount) { p.Status.ContainerStatuses[0].Started = boolPtr(false) }},
		{"service account recreated", func(p *corev1.Pod, sa *corev1.ServiceAccount) {
			sa.CreationTimestamp = metav1.NewTime(p.CreationTimestamp.Time.Add(time.Minute))
		}},
		{"service account deleting", func(_ *corev1.Pod, sa *corev1.ServiceAccount) {
			now := metav1.NewTime(time.Date(2026, 9, 23, 11, 30, 0, 0, time.UTC))
			sa.DeletionTimestamp = &now
			sa.Finalizers = []string{"retain"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := tokenProjectionFixture(t, tc.edit)
			if got := snap.PodByKey["tenant/source"]; got == nil || got.HasPodBoundKubeAPIAuth() {
				t.Fatalf("unsupported projection gained witness: %+v", got)
			}
		})
	}
	t.Run("service account inventory unavailable", func(t *testing.T) {
		snap := tokenProjectionFixture(t, nil, "forbidden")
		if got := snap.PodByKey["tenant/source"]; got == nil || got.HasPodBoundKubeAPIAuth() {
			t.Fatalf("failed inventory gained witness: %+v", got)
		}
	})
	for _, readerFailure := range []string{"blocked", "blocked-short-parent"} {
		t.Run(readerFailure, func(t *testing.T) {
			snap := tokenProjectionFixture(t, nil, readerFailure)
			if got := snap.PodByKey["tenant/source"]; got == nil || got.HasPodBoundKubeAPIAuth() {
				t.Fatalf("blocked inventory gained witness: %+v", got)
			}
			_, hasNamespace := snap.NamespaceLabels["tenant"]
			if !snap.PodInventoryComplete || !snap.EventInventoryComplete || !hasNamespace {
				t.Fatalf("optional ServiceAccount timeout interrupted core snapshot: pod=%v event=%v namespaces=%v",
					snap.PodInventoryComplete, snap.EventInventoryComplete, snap.NamespaceLabels)
			}
		})
	}
}

func TestPodBoundKubeAPIAuthRefreshClearsStaleAndDuplicateIdentity(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	started := true
	object := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "source", UID: "pod-uid", ResourceVersion: "10",
		CreationTimestamp: metav1.NewTime(now.Add(-time.Hour))},
		Spec: corev1.PodSpec{ServiceAccountName: "reader", Containers: []corev1.Container{{Name: "hold", VolumeMounts: []corev1.VolumeMount{{Name: "credential", MountPath: "/credential", ReadOnly: true}}}},
			Volumes: []corev1.Volume{{Name: "credential", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}}}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: "hold", Started: &started,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	sa := corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "reader", UID: "sa-uid", ResourceVersion: "5",
		CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour))}}
	projected := []model.Pod{projectPod(&object, now)}
	bindPodBoundKubeAPIAuth(projected, []corev1.Pod{object}, []corev1.ServiceAccount{sa})
	if !projected[0].HasPodBoundKubeAPIAuth() {
		t.Fatal("initial bound projection absent")
	}
	bindPodBoundKubeAPIAuth(projected, []corev1.Pod{object}, []corev1.ServiceAccount{sa, sa})
	if projected[0].PodBoundKubeAPIAuth != nil {
		t.Fatal("duplicate current ServiceAccount identity retained prior witness")
	}
	bindPodBoundKubeAPIAuth(projected, []corev1.Pod{object}, nil)
	if projected[0].PodBoundKubeAPIAuth != nil {
		t.Fatal("missing current ServiceAccount retained prior witness")
	}
}
