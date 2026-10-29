package statefulrotation

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

func TestParseContractAcceptsEachClass(t *testing.T) {
	c, err := ParseContract(map[string]string{
		AnnotationQuorum: "2", AnnotationReplicaRebuild: ReplicaRebuildPeerResync, AnnotationLeaderLabel: "role=primary",
		AnnotationSnapshotClass: "csi-snap", AnnotationCheckpointPort: "8080", AnnotationCheckpointPath: "/v1/checkpoint",
		AnnotationRestorePath: "/v1/restore", AnnotationRecoverySeconds: "90", AnnotationResyncSeconds: "900",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := model.StatefulRotationContract{Quorum: 2, PeerResync: true, LeaderLabelKey: "role", LeaderLabelValue: "primary",
		SnapshotClass: "csi-snap", CheckpointPort: 8080, CheckpointPath: "/v1/checkpoint", RestorePath: "/v1/restore",
		RecoverySeconds: 90, ResyncSeconds: 900}
	if c != want {
		t.Fatalf("contract = %+v, want %+v", c, want)
	}
	defaults, err := ParseContract(map[string]string{AnnotationSnapshotClass: "csi-snap"})
	if err != nil || defaults.RecoverySeconds != DefaultRecoverySeconds || defaults.ResyncSeconds != MaxDeclaredSeconds {
		t.Fatalf("undeclared durations must default to recovery=%d and the conservative resync=%d: %+v %v",
			DefaultRecoverySeconds, MaxDeclaredSeconds, defaults, err)
	}
}

func TestParseContractFailsClosed(t *testing.T) {
	for name, annotations := range map[string]map[string]string{
		"no class":                   {AnnotationQuorum: "2"},
		"rebuild without quorum":     {AnnotationReplicaRebuild: ReplicaRebuildPeerResync},
		"unknown rebuild mode":       {AnnotationQuorum: "2", AnnotationReplicaRebuild: "wipe"},
		"quorum out of range":        {AnnotationQuorum: "0", AnnotationSnapshotClass: "csi"},
		"quorum not a number":        {AnnotationQuorum: "two", AnnotationSnapshotClass: "csi"},
		"leader label without value": {AnnotationLeaderLabel: "role", AnnotationSnapshotClass: "csi"},
		"invalid snapshot class":     {AnnotationSnapshotClass: "Not_A_Name"},
		"checkpoint without port":    {AnnotationCheckpointPath: "/c", AnnotationRestorePath: "/r"},
		"checkpoint without restore": {AnnotationCheckpointPort: "8080", AnnotationCheckpointPath: "/c"},
		"port out of range":          {AnnotationCheckpointPort: "70000", AnnotationCheckpointPath: "/c", AnnotationRestorePath: "/r"},
		"relative path":              {AnnotationCheckpointPort: "8080", AnnotationCheckpointPath: "c", AnnotationRestorePath: "/r"},
		"path traversal":             {AnnotationCheckpointPort: "8080", AnnotationCheckpointPath: "/a/../admin", AnnotationRestorePath: "/r"},
		"path with query":            {AnnotationCheckpointPort: "8080", AnnotationCheckpointPath: "/c?x=1", AnnotationRestorePath: "/r"},
		"recovery out of range":      {AnnotationSnapshotClass: "csi", AnnotationRecoverySeconds: "7200"},
		"partly malformed":           {AnnotationSnapshotClass: "csi", AnnotationQuorum: "-1"},
	} {
		t.Run(name, func(t *testing.T) {
			if c, err := ParseContract(annotations); err == nil {
				t.Fatalf("malformed contract accepted: %+v", c)
			}
		})
	}
	if Declared(map[string]string{"app": "db"}) {
		t.Fatal("unrelated annotations declared a contract")
	}
}

func healthyReplicated() *model.StatefulRotationObservation {
	return &model.StatefulRotationObservation{
		Contract:  model.StatefulRotationContract{Quorum: 2, PeerResync: true, SnapshotClass: "csi", CheckpointPort: 8080, CheckpointPath: "/c", RestorePath: "/r", RecoverySeconds: 60, ResyncSeconds: 600},
		OwnerName: "db", OwnerUID: "db-uid", Replicas: 3, ReadyReplicas: 3, SnapshotClassReady: true, Complete: true,
		Claims: []model.StatefulClaim{{Name: "data-db-1", UID: "c1", Bound: true, FromTemplate: true}},
	}
}

func TestAdmitPerClass(t *testing.T) {
	type tc struct {
		mutate func(*model.StatefulRotationObservation)
		ready  bool
		want   map[model.Action]string // "" = admitted, else reason substring
	}
	A, B, C := model.ActionStatefulReplicaRebuild, model.ActionStatefulSnapshotRotate, model.ActionStatefulCheckpointHandoff
	cases := map[string]tc{
		"healthy replicated member": {ready: true, want: map[model.Action]string{A: "", B: "", C: "volume claims"}},
		"volume-less member": {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Claims = nil },
			want: map[model.Action]string{A: "no volume claims", B: "no volume claims", C: ""}},
		"target not ready":   {want: map[model.Action]string{A: "not Ready", B: "not Ready", C: "not Ready"}},
		"degraded owner":     {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.ReadyReplicas = 2 }, want: map[model.Action]string{A: "degraded", B: "degraded", C: "degraded"}},
		"rollout":            {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.RolloutInProgress = true }, want: map[model.Action]string{A: "rollout", B: "rollout", C: "rollout"}},
		"no quorum headroom": {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Replicas, o.ReadyReplicas = 2, 2 }, want: map[model.Action]string{A: "quorum headroom", B: "quorum headroom", C: "quorum headroom"}},
		"leader":             {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Leader = true }, want: map[model.Action]string{A: "leader", B: ""}},
		"non-template claim": {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Claims[0].FromTemplate = false }, want: map[model.Action]string{A: "volumeClaimTemplates", B: ""}},
		"unbound claim":      {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Claims[0].Bound = false }, want: map[model.Action]string{A: "not Bound", B: "not Bound"}},
		"terminating claim":  {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Claims[0].Terminating = true }, want: map[model.Action]string{A: "terminating", B: "terminating"}},
		"snapshot class unavailable": {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.SnapshotClassReady = false },
			want: map[model.Action]string{A: "", B: "unavailable"}},
		"class not declared": {ready: true, mutate: func(o *model.StatefulRotationObservation) {
			o.Contract = model.StatefulRotationContract{SnapshotClass: "csi"}
		},
			want: map[model.Action]string{A: "peer-resync", C: "checkpoint endpoint"}},
		"invalid contract": {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Invalid = "bad" }, want: map[model.Action]string{A: "invalid", B: "invalid", C: "invalid"}},
		"incomplete":       {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Complete, o.Reason = false, "claim unreadable" }, want: map[model.Action]string{A: "incomplete", B: "incomplete", C: "incomplete"}},
		"single writer":    {ready: true, mutate: func(o *model.StatefulRotationObservation) { o.Contract.Quorum, o.Replicas, o.ReadyReplicas = 0, 1, 1 }, want: map[model.Action]string{B: ""}},
	}
	for name, c := range cases {
		o := healthyReplicated()
		if c.mutate != nil {
			c.mutate(o)
		}
		for a, want := range c.want {
			ok, why := Admit(o, c.ready, a)
			switch {
			case want == "" && !ok:
				t.Errorf("%s: %s refused: %s", name, a, why)
			case want != "" && (ok || !strings.Contains(why, want)):
				t.Errorf("%s: %s = (%t, %q), want refusal containing %q", name, a, ok, why, want)
			}
		}
	}
	if ok, _ := Admit(nil, true, A); ok {
		t.Fatal("nil observation admitted")
	}
	if ok, _ := Admit(healthyReplicated(), true, model.ActionRotate); ok {
		t.Fatal("plain rotate admitted by the stateful law")
	}
}

func TestObserveReadsOwnerClaimsAndSnapshotClass(t *testing.T) {
	ctx := context.Background()
	replicas, controller := int32(3), true
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db", UID: "db-uid", Generation: 3, ResourceVersion: "7",
			Annotations: map[string]string{AnnotationQuorum: "2", AnnotationReplicaRebuild: ReplicaRebuildPeerResync,
				AnnotationLeaderLabel: "role=primary", AnnotationSnapshotClass: "csi"}},
		Spec: appsv1.StatefulSetSpec{Replicas: &replicas,
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data"}}}},
		Status: appsv1.StatefulSetStatus{ObservedGeneration: 3, ReadyReplicas: 3, CurrentRevision: "r1", UpdateRevision: "r1"},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db-1", UID: "pod-uid", Labels: map[string]string{"role": "replica"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "db", UID: "db-uid", Controller: &controller}}},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{
			{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data-db-1"}}},
			{Name: "extra", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "manual"}}},
		}},
	}
	claim := func(name string) *corev1.PersistentVolumeClaim {
		return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID("uid-" + name)},
			Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	}
	class := &unstructured.Unstructured{}
	class.SetGroupVersionKind(VolumeSnapshotClassGVK)
	class.SetName("csi")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(sts, claim("data-db-1"), claim("manual"), class).Build()

	o := Observe(ctx, c, pod)
	if o == nil || !o.Complete || o.Invalid != "" {
		t.Fatalf("observation = %+v", o)
	}
	if o.Replicas != 3 || o.ReadyReplicas != 3 || o.RolloutInProgress || o.Leader || !o.SnapshotClassReady || o.OwnerUID != "db-uid" {
		t.Fatalf("owner projection wrong: %+v", o)
	}
	if len(o.Claims) != 2 || !o.Claims[0].FromTemplate || o.Claims[1].FromTemplate || !o.Claims[0].Bound {
		t.Fatalf("claims wrong: %+v", o.Claims)
	}
	// The manual claim would not be recreated: replica-rebuild must refuse, snapshot-rotate admits.
	if ok, why := Admit(o, true, model.ActionStatefulReplicaRebuild); ok || !strings.Contains(why, "manual") {
		t.Fatalf("rebuild with a non-template claim: %t %q", ok, why)
	}
	if ok, why := Admit(o, true, model.ActionStatefulSnapshotRotate); !ok {
		t.Fatalf("snapshot rotate refused: %s", why)
	}

	pod.Labels["role"] = "primary"
	if o := Observe(ctx, c, pod); !o.Leader {
		t.Fatal("leader label not observed")
	}

	sts.Status.UpdateRevision = "r2"
	if err := c.Status().Update(ctx, sts); err != nil {
		t.Fatal(err)
	}
	if o := Observe(ctx, c, pod); !o.RolloutInProgress {
		t.Fatal("rollout not observed")
	}

	undeclared := sts.DeepCopy()
	undeclared.Annotations = nil
	c2 := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(undeclared).Build()
	if o := Observe(ctx, c2, pod); o != nil {
		t.Fatalf("undeclared owner produced an observation: %+v", o)
	}
	if o := Observe(ctx, fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), pod); o == nil || o.Complete {
		t.Fatalf("unreadable owner must be incomplete, got %+v", o)
	}
	replicaSetPod := pod.DeepCopy()
	replicaSetPod.OwnerReferences[0].Kind = "ReplicaSet"
	if o := Observe(ctx, c, replicaSetPod); o != nil {
		t.Fatal("non-StatefulSet Pod produced an observation")
	}
	mismatch := pod.DeepCopy()
	mismatch.OwnerReferences[0].UID = "other"
	if o := Observe(ctx, c, mismatch); o == nil || o.Complete || !strings.Contains(o.Reason, "UID") {
		t.Fatalf("owner UID mismatch must be incomplete: %+v", o)
	}
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}
