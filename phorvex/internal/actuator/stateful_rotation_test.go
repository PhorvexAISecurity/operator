package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/statefulrotation"
)

const statefulTestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// statefulCluster emulates the API server behaviours the handler depends on: Eviction dry run
// (full admission, no delete), PodDisruptionBudget refusal, UID/resourceVersion preconditions,
// the StatefulSet controller recreating the evicted ordinal (and, for released claims, the
// claims), and the CSI snapshot controller marking snapshots ready.
type statefulCluster struct {
	client.Client
	mu              sync.Mutex
	events          []string
	refusePDB       bool
	replace         bool
	snapshotFailure string
	snapshotPending bool
	realEvictionErr error
	evictions       []*policyv1.Eviction
	claimDeletes    []types.UID
	releasedClaims  []string
}

func (s *statefulCluster) record(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *statefulCluster) subResourceCreate(ctx context.Context, c client.Client, name string, obj, sub client.Object, opts ...client.SubResourceCreateOption) error {
	eviction, ok := sub.(*policyv1.Eviction)
	if name != "eviction" || !ok || eviction.DeleteOptions == nil {
		return errors.New("unexpected subresource create")
	}
	createOpts := &client.SubResourceCreateOptions{}
	createOpts.ApplyOptions(opts)
	dryRun := slices.Contains(eviction.DeleteOptions.DryRun, metav1.DryRunAll)
	if dryRun != slices.Contains(createOpts.DryRun, metav1.DryRunAll) {
		return apierrors.NewBadRequest("conflicting dryRun on eviction")
	}
	s.evictions = append(s.evictions, eviction.DeepCopy())
	if s.refusePDB {
		s.record("eviction-refused")
		return apierrors.NewTooManyRequests("Cannot evict pod as it would violate the pod's disruption budget.", 10)
	}
	if dryRun {
		s.record("eviction-dry-run")
		return nil
	}
	s.record("eviction")
	if s.realEvictionErr != nil {
		return s.realEvictionErr
	}
	if err := c.Delete(ctx, obj, &client.DeleteOptions{Preconditions: eviction.DeleteOptions.Preconditions}); err != nil {
		return err
	}
	if s.replace {
		old := obj.(*corev1.Pod)
		replacement := statefulPod(old.Namespace, old.Name, old.UID+"-next", "10.0.0.6", podClaimNames(old))
		if err := c.Create(ctx, replacement); err != nil {
			return err
		}
		for _, claim := range s.releasedClaims {
			if err := c.Create(ctx, statefulClaim(old.Namespace, claim, types.UID(claim+"-fresh"))); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *statefulCluster) delete(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
	if pvc, ok := obj.(*corev1.PersistentVolumeClaim); ok {
		deleteOpts := &client.DeleteOptions{}
		deleteOpts.ApplyOptions(opts)
		if deleteOpts.Preconditions == nil || deleteOpts.Preconditions.UID == nil {
			return errors.New("claim delete without UID precondition")
		}
		s.claimDeletes = append(s.claimDeletes, *deleteOpts.Preconditions.UID)
		s.releasedClaims = append(s.releasedClaims, pvc.Name)
		s.record("claim-delete:" + pvc.Name)
	}
	return c.Delete(ctx, obj, opts...)
}

func (s *statefulCluster) create(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
	if u, ok := obj.(*unstructured.Unstructured); ok && u.GroupVersionKind() == statefulrotation.VolumeSnapshotGVK {
		s.record("snapshot-create:" + u.GetName())
	}
	return c.Create(ctx, obj, opts...)
}

// get marks snapshots ready (or failed), as the CSI snapshot controller would.
func (s *statefulCluster) get(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := c.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if u, ok := obj.(*unstructured.Unstructured); ok && u.GroupVersionKind() == statefulrotation.VolumeSnapshotGVK {
		if s.snapshotFailure != "" {
			_ = unstructured.SetNestedField(u.Object, s.snapshotFailure, "status", "error", "message")
		} else if !s.snapshotPending {
			_ = unstructured.SetNestedField(u.Object, true, "status", "readyToUse")
		}
	}
	return nil
}

func statefulPod(namespace, name string, uid types.UID, ip string, claims []string) *corev1.Pod {
	yes := true
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: uid, ResourceVersion: "7",
			Labels:          map[string]string{"app": "db", "role": "replica"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "db", UID: "db-uid", Controller: &yes}}},
		Status: corev1.PodStatus{PodIP: ip, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Hour))}}},
	}
	for _, claim := range claims {
		p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: claim,
			VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}})
	}
	if ip != "10.0.0.5" {
		p.ResourceVersion = ""
	}
	return p
}

func podClaimNames(p *corev1.Pod) []string {
	var out []string
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			out = append(out, v.PersistentVolumeClaim.ClaimName)
		}
	}
	return out
}

func statefulClaim(namespace, name string, uid types.UID) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: uid},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
}

type statefulFixtureOptions struct {
	action       model.Action
	volumeless   bool
	leader       bool
	readyMembers int32
	notEnabled   bool
	// settling adds a sibling member that became Ready seconds ago.
	settling bool
}

func statefulFixture(t *testing.T, o statefulFixtureOptions) (*statefulCluster, *corev1.Pod, Request) {
	t.Helper()
	replicas := int32(3)
	ready := replicas
	if o.readyMembers > 0 {
		ready = o.readyMembers
	}
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db", UID: "db-uid", Generation: 2, Annotations: map[string]string{
			statefulrotation.AnnotationQuorum: "2", statefulrotation.AnnotationReplicaRebuild: statefulrotation.ReplicaRebuildPeerResync,
			statefulrotation.AnnotationLeaderLabel: "role=primary", statefulrotation.AnnotationSnapshotClass: "csi",
			statefulrotation.AnnotationCheckpointPort: "8080", statefulrotation.AnnotationCheckpointPath: "/checkpoint",
			statefulrotation.AnnotationRestorePath: "/restore", statefulrotation.AnnotationRecoverySeconds: "60",
		}},
		Spec: appsv1.StatefulSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data"}}}},
		Status: appsv1.StatefulSetStatus{ObservedGeneration: 2, ReadyReplicas: ready, CurrentRevision: "r1", UpdateRevision: "r1"},
	}
	claims := []string{"data-db-1"}
	if o.volumeless {
		claims = nil
		sts.Spec.VolumeClaimTemplates = nil
	}
	pod := statefulPod("ns", "db-1", "db-1-uid", "10.0.0.5", claims)
	if o.leader {
		pod.Labels["role"] = "primary"
	}
	class := &unstructured.Unstructured{}
	class.SetGroupVersionKind(statefulrotation.VolumeSnapshotClassGVK)
	class.SetName("csi")
	enabled := []v1alpha1.ActionType{v1alpha1.ActionType(o.action)}
	if o.notEnabled {
		enabled = []v1alpha1.ActionType{v1alpha1.ActionQuarantine}
	}
	policy := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db-defense", UID: "policy-uid", Generation: 4},
		Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
			Actions:  v1alpha1.ActionsSpec{Enabled: enabled}},
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	objects := []client.Object{sts, pod, class, policy}
	if o.settling {
		sibling := statefulPod("ns", "db-0", "db-0-uid", "10.0.0.4", nil)
		sibling.Status.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(-5 * time.Second))
		objects = append(objects, sibling)
	}
	for _, claim := range claims {
		objects = append(objects, statefulClaim("ns", claim, "claim-uid"))
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	cluster := &statefulCluster{replace: true}
	cluster.Client = interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{
		SubResourceCreate: cluster.subResourceCreate, Delete: cluster.delete, Create: cluster.create, Get: cluster.get,
	})
	req := Request{Namespace: "ns", Pod: "db-1", TargetUID: "db-1-uid", Action: o.action,
		PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, MaxGracePeriodSeconds: 30}
	return cluster, pod, req
}

func statefulEnact(cluster *statefulCluster, transport http.RoundTripper) EnactCtx {
	return EnactCtx{Client: cluster, Reader: cluster, StatefulConfirmTimeout: 300 * time.Millisecond,
		StatefulConfirmInterval: 5 * time.Millisecond, StatefulSnapshotTimeout: 300 * time.Millisecond,
		StatefulCheckpointTransport: transport}
}

func podExists(t *testing.T, c client.Client, uid types.UID) bool {
	t.Helper()
	p := &corev1.Pod{}
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: "ns", Name: "db-1"}, p); err != nil {
		return false
	}
	return p.UID == uid
}

func TestStatefulReplicaRebuildProvesPDBBeforeReleasingClaims(t *testing.T) {
	cluster, pod, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild})
	result, err := dispatch(t.Context(), statefulEnact(cluster, nil), req)
	if err != nil || !result.Emitted || result.MutationKind != "forward-only" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	want := []string{"eviction-dry-run", "claim-delete:data-db-1", "eviction"}
	if !slices.Equal(cluster.events, want) {
		t.Fatalf("operation order = %v, want %v (PDB admission must precede the irreversible claim release)", cluster.events, want)
	}
	if !slices.Equal(cluster.claimDeletes, []types.UID{"claim-uid"}) {
		t.Fatalf("claim deletes not UID-bound: %v", cluster.claimDeletes)
	}
	real := cluster.evictions[len(cluster.evictions)-1]
	if pre := real.DeleteOptions.Preconditions; pre == nil || *pre.UID != pod.UID || *pre.ResourceVersion != pod.ResourceVersion {
		t.Fatalf("eviction preconditions = %+v", real.DeleteOptions.Preconditions)
	}
	if result.GracefulTermination == nil || result.GracefulTermination.PodUID != string(pod.UID) {
		t.Fatalf("receipt = %+v", result.GracefulTermination)
	}
	if !slices.Contains(result.ObjectsTouched, "PersistentVolumeClaim/ns/data-db-1") || !slices.Contains(result.ObjectsTouched, "Pod/ns/db-1") {
		t.Fatalf("objects touched = %v", result.ObjectsTouched)
	}
	if !strings.Contains(result.Note, "Ready and confirmed: member rebuilt on fresh claims") {
		t.Fatalf("replacement continuity not confirmed: %s", result.Note)
	}
}

func TestStatefulRotationRefusalsLeaveTheMemberUntouched(t *testing.T) {
	for name, tc := range map[string]struct {
		opts   statefulFixtureOptions
		pdb    bool
		reason string
	}{
		"pdb refuses":           {opts: statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild}, pdb: true, reason: "pdb-eviction-admission-refused"},
		"leader":                {opts: statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild, leader: true}, reason: "declared leader"},
		"no quorum headroom":    {opts: statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild, readyMembers: 2}, reason: "degraded"},
		"owner settling":        {opts: statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild, settling: true}, reason: "owner settling"},
		"action not enabled":    {opts: statefulFixtureOptions{action: model.ActionStatefulSnapshotRotate, notEnabled: true}, reason: "selecting-policy-not-authorized"},
		"volume-backed handoff": {opts: statefulFixtureOptions{action: model.ActionStatefulCheckpointHandoff}, reason: "volume-backed classes apply"},
	} {
		t.Run(name, func(t *testing.T) {
			cluster, pod, req := statefulFixture(t, tc.opts)
			cluster.refusePDB = tc.pdb
			result, err := dispatch(t.Context(), statefulEnact(cluster, nil), req)
			if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || !strings.Contains(result.Note, tc.reason) {
				t.Fatalf("result=%+v err=%v, want refusal %q", result, err, tc.reason)
			}
			if len(cluster.claimDeletes) != 0 || slices.Contains(cluster.events, "eviction") || !podExists(t, cluster, pod.UID) {
				t.Fatalf("refusal mutated the member: events=%v", cluster.events)
			}
		})
	}
}

// A stop after the claims were released is a confirmed partial mutation: a budget that
// changed after the dry run leaves the member running; an unknown API failure is returned
// with the partial result instead of being reported as a retained member.
func TestStatefulReplicaRebuildStopsAfterReleaseArePartial(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		wantErr  bool
		wantNote string
	}{
		"budget changed after dry run": {err: apierrors.NewTooManyRequests("budget", 1), wantNote: "target Pod retained: eviction: pdb-eviction-admission-refused"},
		"unknown api failure":          {err: apierrors.NewInternalError(errors.New("etcd timeout")), wantErr: true, wantNote: "outcome of eviction unknown: "},
	} {
		t.Run(name, func(t *testing.T) {
			cluster, _, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild})
			cluster.realEvictionErr = tc.err
			result, err := dispatch(t.Context(), statefulEnact(cluster, nil), req)
			if (err != nil) != tc.wantErr || !result.Emitted || result.MutationKind != "partial" || !strings.Contains(result.Note, tc.wantNote) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if !slices.Contains(result.ObjectsTouched, "PersistentVolumeClaim/ns/data-db-1") || result.GracefulTermination != nil {
				t.Fatalf("partial result must keep the released claim and carry no termination receipt: %+v", result)
			}
		})
	}
}

func TestStatefulSnapshotRotateEvictsOnlyBehindReadySnapshot(t *testing.T) {
	cluster, _, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulSnapshotRotate})
	result, err := dispatch(t.Context(), statefulEnact(cluster, nil), req)
	if err != nil || !result.Emitted || result.MutationKind != "forward-only" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	name := statefulSnapshotName("db-1-uid", "claim-uid")
	if want := []string{"eviction-dry-run", "snapshot-create:" + name, "eviction"}; !slices.Equal(cluster.events, want) {
		t.Fatalf("operation order = %v, want %v", cluster.events, want)
	}
	snap := &unstructured.Unstructured{}
	snap.SetGroupVersionKind(statefulrotation.VolumeSnapshotGVK)
	if err := cluster.Get(t.Context(), client.ObjectKey{Namespace: "ns", Name: name}, snap); err != nil {
		t.Fatal(err)
	}
	class, _, _ := unstructured.NestedString(snap.Object, "spec", "volumeSnapshotClassName")
	source, _, _ := unstructured.NestedString(snap.Object, "spec", "source", "persistentVolumeClaimName")
	if class != "csi" || source != "data-db-1" || snap.GetLabels()[labelStatefulTargetUID] != "db-1-uid" {
		t.Fatalf("snapshot spec = class %q source %q labels %v", class, source, snap.GetLabels())
	}
	if result.RollbackRef != "VolumeSnapshot/ns/"+name || len(cluster.claimDeletes) != 0 {
		t.Fatalf("rollback ref %q, claim deletes %v", result.RollbackRef, cluster.claimDeletes)
	}
	if !strings.Contains(result.Note, "confirmed: same claims reattached") {
		t.Fatalf("note: %s", result.Note)
	}

	// A retried dispatch reuses its own snapshot instead of creating another.
	retry, _, retryReq := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulSnapshotRotate})
	existing := snap.DeepCopy()
	existing.SetResourceVersion("")
	if err := retry.Create(t.Context(), existing); err != nil {
		t.Fatal(err)
	}
	retry.events = nil
	if result, err := dispatch(t.Context(), statefulEnact(retry, nil), retryReq); err != nil || !result.Emitted {
		t.Fatalf("retry result=%+v err=%v", result, err)
	}
}

func TestStatefulSnapshotFailureRetainsMemberAsPartial(t *testing.T) {
	cluster, pod, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulSnapshotRotate})
	cluster.snapshotFailure = "csi driver timeout"
	result, err := dispatch(t.Context(), statefulEnact(cluster, nil), req)
	if err != nil || !result.Emitted || result.MutationKind != "partial" || !strings.Contains(result.Note, "csi driver timeout") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if slices.Contains(cluster.events, "eviction") || !podExists(t, cluster, pod.UID) {
		t.Fatalf("member evicted without a ready rollback point: %v", cluster.events)
	}
	if result.RollbackRef == "" || result.GracefulTermination != nil {
		t.Fatalf("partial result must keep the snapshot reference and carry no termination receipt: %+v", result)
	}
}

// checkpointApp is the application side of the checkpoint contract.
type checkpointApp struct {
	failCheckpoint bool
	restoredSHA    string
	calls          []string
}

func (a *checkpointApp) RoundTrip(r *http.Request) (*http.Response, error) {
	a.calls = append(a.calls, r.Method+" "+r.URL.Host+r.URL.Path)
	respond := func(code int, body any) (*http.Response, error) {
		raw, _ := json.Marshal(body)
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(string(raw))), Header: http.Header{}, Request: r}, nil
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/checkpoint":
		if a.failCheckpoint {
			return respond(http.StatusServiceUnavailable, map[string]string{"error": "busy"})
		}
		return respond(http.StatusOK, statefulCheckpoint{ID: "ckpt-42", SHA256: statefulTestDigest})
	case r.Method == http.MethodGet && r.URL.Path == "/restore":
		return respond(http.StatusOK, statefulCheckpoint{ID: "ckpt-42", SHA256: a.restoredSHA})
	}
	return respond(http.StatusNotFound, nil)
}

func TestStatefulCheckpointHandoffConfirmsRestoredDigest(t *testing.T) {
	cluster, _, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulCheckpointHandoff, volumeless: true})
	app := &checkpointApp{restoredSHA: statefulTestDigest}
	result, err := dispatch(t.Context(), statefulEnact(cluster, app), req)
	if err != nil || !result.Emitted || !strings.Contains(result.Note, "confirmed: checkpoint ckpt-42 restored") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if want := []string{"POST 10.0.0.5:8080/checkpoint", "GET 10.0.0.6:8080/restore"}; !slices.Equal(app.calls, want) {
		t.Fatalf("application calls = %v, want checkpoint on the old Pod then restore status on the replacement %v", app.calls, want)
	}
	if want := []string{"eviction-dry-run", "eviction"}; !slices.Equal(cluster.events, want) {
		t.Fatalf("operation order = %v, want %v", cluster.events, want)
	}
}

func TestStatefulCheckpointHandoffFailures(t *testing.T) {
	t.Run("checkpoint refused keeps the member", func(t *testing.T) {
		cluster, pod, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulCheckpointHandoff, volumeless: true})
		result, err := dispatch(t.Context(), statefulEnact(cluster, &checkpointApp{failCheckpoint: true}), req)
		if err != nil || result.Emitted || result.NoEffect != NoEffectRefused || !strings.Contains(result.Note, "checkpoint endpoint returned 503") {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		if slices.Contains(cluster.events, "eviction") || !podExists(t, cluster, pod.UID) {
			t.Fatal("member evicted without a committed checkpoint")
		}
	})
	t.Run("different restored checkpoint is reported unconfirmed", func(t *testing.T) {
		cluster, _, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulCheckpointHandoff, volumeless: true})
		result, err := dispatch(t.Context(), statefulEnact(cluster, &checkpointApp{restoredSHA: strings.Repeat("b", 64)}), req)
		if err != nil || !result.Emitted || !strings.Contains(result.Note, "continuity unconfirmed: replacement restored a different checkpoint") {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
}

func TestStatefulRotationReportsUnobservedReplacement(t *testing.T) {
	cluster, _, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulSnapshotRotate})
	cluster.replace = false
	result, err := dispatch(t.Context(), statefulEnact(cluster, nil), req)
	if err != nil || !result.Emitted || !strings.Contains(result.Note, "replacement not observed Ready within") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestStatefulRotationHonoursDryRunGuard(t *testing.T) {
	cluster, _, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild})
	ec := statefulEnact(cluster, nil)
	ec.DryRun = true
	for _, a := range model.StatefulRotationActions {
		h, ok := HandlerRegistry.Get(string(a))
		if !ok {
			t.Fatalf("%s has no handler", a)
		}
		req.Action = a
		if _, err := h.Enact(t.Context(), ec, req); !errors.Is(err, errDryRunGuard) {
			t.Fatalf("%s ignored the dry-run guard: %v", a, err)
		}
	}
	if len(cluster.events) != 0 {
		t.Fatalf("dry-run reached the API: %v", cluster.events)
	}
}

// statefulRotationCount reads phorvex_stateful_rotations_total from the registry the
// metrics endpoint serves.
func statefulRotationCount(t *testing.T, namespace string, action model.Action, outcome metrics.StatefulRotationOutcome) float64 {
	t.Helper()
	families, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != "phorvex_stateful_rotations_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["namespace"] == namespace && labels["action"] == string(action) && labels["outcome"] == string(outcome) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// Every dispatch records exactly one closed outcome; only a confirmed one has a recovery time.
func TestStatefulRotationRecordsOneOutcomePerDispatch(t *testing.T) {
	for name, tc := range map[string]struct {
		opts    statefulFixtureOptions
		setup   func(*statefulCluster)
		app     http.RoundTripper
		outcome metrics.StatefulRotationOutcome
	}{
		"confirmed rebuild":    {opts: statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild}, outcome: metrics.StatefulRotationConfirmed},
		"pdb refusal":          {opts: statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild}, setup: func(c *statefulCluster) { c.refusePDB = true }, outcome: metrics.StatefulRotationRefused},
		"snapshot failure":     {opts: statefulFixtureOptions{action: model.ActionStatefulSnapshotRotate}, setup: func(c *statefulCluster) { c.snapshotFailure = "csi" }, outcome: metrics.StatefulRotationPartial},
		"unobserved":           {opts: statefulFixtureOptions{action: model.ActionStatefulSnapshotRotate}, setup: func(c *statefulCluster) { c.replace = false }, outcome: metrics.StatefulRotationUnconfirmed},
		"checkpoint refused":   {opts: statefulFixtureOptions{action: model.ActionStatefulCheckpointHandoff, volumeless: true}, app: &checkpointApp{failCheckpoint: true}, outcome: metrics.StatefulRotationRefused},
		"checkpoint confirmed": {opts: statefulFixtureOptions{action: model.ActionStatefulCheckpointHandoff, volumeless: true}, app: &checkpointApp{restoredSHA: statefulTestDigest}, outcome: metrics.StatefulRotationConfirmed},
	} {
		t.Run(name, func(t *testing.T) {
			cluster, _, req := statefulFixture(t, tc.opts)
			if tc.setup != nil {
				tc.setup(cluster)
			}
			before := map[metrics.StatefulRotationOutcome]float64{}
			all := []metrics.StatefulRotationOutcome{metrics.StatefulRotationConfirmed, metrics.StatefulRotationUnconfirmed,
				metrics.StatefulRotationPartial, metrics.StatefulRotationRefused, metrics.StatefulRotationError}
			for _, o := range all {
				before[o] = statefulRotationCount(t, req.Namespace, req.Action, o)
			}
			if _, err := dispatch(t.Context(), statefulEnact(cluster, tc.app), req); err != nil {
				t.Fatal(err)
			}
			for _, o := range all {
				want := before[o]
				if o == tc.outcome {
					want++
				}
				if got := statefulRotationCount(t, req.Namespace, req.Action, o); got != want {
					t.Errorf("%s: outcome %s = %v, want %v", name, o, got, want)
				}
			}
		})
	}
}

// A dispatch runs inside the manager's tick deadline, which is shorter than an EBS snapshot.
// The wait must end before that deadline so the manager receives a definite partial result
// (member retained, snapshot kept for the next attempt) instead of an expired call whose
// unknown outcome holds the owner's capacity.
func TestStatefulSnapshotRotateStopsBeforeTheDispatchDeadline(t *testing.T) {
	cluster, pod, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulSnapshotRotate})
	cluster.snapshotPending = true
	ec := statefulEnact(cluster, nil)
	ec.StatefulSnapshotTimeout = time.Minute
	ec.StatefulDeadlineMargin = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 700*time.Millisecond)
	defer cancel()
	result, err := dispatch(ctx, ec, req)
	if err != nil || ctx.Err() != nil {
		t.Fatalf("dispatch must return before its deadline: err=%v ctx=%v", err, ctx.Err())
	}
	if !result.Emitted || result.MutationKind != "partial" || !strings.Contains(result.Note, "before the dispatch deadline; retained for the next attempt") {
		t.Fatalf("result=%+v", result)
	}
	if slices.Contains(cluster.events, "eviction") || !podExists(t, cluster, pod.UID) || result.RollbackRef == "" {
		t.Fatalf("member must be retained behind its kept snapshot: events=%v result=%+v", cluster.events, result)
	}
}

// After the eviction, the confirmation window is capped the same way: an unobserved
// replacement is reported as a definite unconfirmed emission, not an expired call.
func TestStatefulReplacementConfirmationStopsBeforeTheDispatchDeadline(t *testing.T) {
	cluster, _, req := statefulFixture(t, statefulFixtureOptions{action: model.ActionStatefulReplicaRebuild})
	cluster.replace = false
	ec := statefulEnact(cluster, nil)
	ec.StatefulConfirmTimeout = time.Minute
	ec.StatefulDeadlineMargin = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 700*time.Millisecond)
	defer cancel()
	result, err := dispatch(ctx, ec, req)
	if err != nil || ctx.Err() != nil {
		t.Fatalf("dispatch must return before its deadline: err=%v ctx=%v", err, ctx.Err())
	}
	if !result.Emitted || result.MutationKind != "forward-only" || !strings.Contains(result.Note, "before the dispatch deadline") {
		t.Fatalf("result=%+v", result)
	}
}
