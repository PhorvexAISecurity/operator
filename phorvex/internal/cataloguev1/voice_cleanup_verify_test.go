package cataloguev1

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeVoiceCleanupReader struct {
	snapshot         VoiceSnapshot
	snapshots        int
	queryCounts      []int
	queries          int
	source           string
	driftAt          int
	failQuery        bool
	datastore        string
	datastoreDriftAt int
	datastoreChecks  int
	absenceChecks    int
	oldAppearsAt     int
}

func (f *fakeVoiceCleanupReader) DatastoreBinding(_ context.Context, _ VoiceConfig, _ VoiceCleanupHistoricalIdentity, _ VoicePod) (string, error) {
	f.datastoreChecks++
	if f.datastoreChecks == f.datastoreDriftAt {
		return strings.Repeat("b", 64), nil
	}
	return f.datastore, nil
}

func (f *fakeVoiceCleanupReader) HistoricalPodUIDsAbsent(_ context.Context, _ VoiceConfig, _, _ string) (bool, error) {
	f.absenceChecks++
	return f.absenceChecks != f.oldAppearsAt, nil
}

func (f *fakeVoiceCleanupReader) Snapshot(_ context.Context, _ VoiceConfig) (VoiceSnapshot, error) {
	f.snapshots++
	s := f.snapshot
	if f.snapshots == f.driftAt {
		s.ServiceUID = "foreign"
	}
	return s, nil
}
func (f *fakeVoiceCleanupReader) SourceSHA256(_ context.Context, _ VoiceConfig, _ VoicePod) (string, error) {
	return f.source, nil
}
func (f *fakeVoiceCleanupReader) ReadTranscriptCount(_ context.Context, _ VoiceConfig, _ VoicePod, _ []string) (int, error) {
	f.queries++
	if f.failQuery {
		return 0, errors.New("read unavailable")
	}
	return f.queryCounts[f.queries-1], nil
}
func voiceCleanupFixture() (VoiceConfig, VoiceCleanupHistoricalIdentity, *fakeVoiceCleanupReader) {
	h := VoiceCleanupHistoricalIdentity{NamespaceUID: "ns-old", DeploymentUID: "dep-old", ServiceUID: "svc-old", PDBUID: "pdb-old", ReplicaSetUID: "rs-old", ReplicaSetSpecSHA256: strings.Repeat("e", 64), TargetPodUID: "target-old", ReplacementPodUID: "replacement-old"}
	pod := VoicePod{Name: "voice-bot-current", UID: "current", ResourceVersion: "7", ReplicaSetName: "rs-current", ReplicaSetUID: "rs-new", Ready: true, Started: true, ContainerID: "containerd://current", ImageID: "registry/voice@sha256:" + strings.Repeat("c", 64)}
	s := VoiceSnapshot{NamespaceUID: h.NamespaceUID, DeploymentUID: h.DeploymentUID, ServiceUID: h.ServiceUID, PDBUID: h.PDBUID, ReplicaSetUID: "rs-new", DeploymentReadyReplicas: 3, DeploymentAvailableReplicas: 3,
		ReadyEndpointUIDs: []string{"current", "other1", "other2"}, Pods: []VoicePod{pod, {Name: "other1", UID: "other1", ResourceVersion: "7", ReplicaSetUID: "rs-new", Ready: true, Started: true, ContainerID: "c1", ImageID: "i1"}, {Name: "other2", UID: "other2", ResourceVersion: "7", ReplicaSetUID: "rs-new", Ready: true, Started: true, ContainerID: "c2", ImageID: "i2"}}}
	cfg := VoiceConfig{Namespace: "voice", DeploymentName: "voice-bot", ServiceName: "voice-bot", PDBName: "voice-bot", ContainerName: "bot", BotSourcePath: "/app/bot.py"}
	return cfg, h, &fakeVoiceCleanupReader{snapshot: s, queryCounts: []int{0, 0, 0}, source: strings.Repeat("a", 64), datastore: strings.Repeat("d", 64)}
}
func TestVoiceCleanupReadOnlyThreeZerosAndAdversaries(t *testing.T) {
	cfg, h, f := voiceCleanupFixture()
	sids := []string{"CA" + strings.Repeat("a", 32), "CA" + strings.Repeat("b", 32)}
	noPause := func(context.Context, time.Duration) error { return nil }
	proof, err := VerifyVoiceCleanupReadOnly(context.Background(), f, cfg, h, sids, noPause)
	if err != nil || len(proof.Samples) != 3 || f.queries != 3 || proof.ReadPodUID != "current" || proof.ReadPodImageID != f.snapshot.Pods[0].ImageID || proof.MongoWrites != 0 || proof.KubernetesWrites != 0 {
		t.Fatalf("three-zero proof failed: %+v %v", proof, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*VoiceCleanupHistoricalIdentity, *fakeVoiceCleanupReader)
	}{
		{"original UID remains", func(h *VoiceCleanupHistoricalIdentity, f *fakeVoiceCleanupReader) {
			f.snapshot.Pods[0].UID = h.TargetPodUID
		}},
		{"wrong original deployment", func(h *VoiceCleanupHistoricalIdentity, f *fakeVoiceCleanupReader) { h.DeploymentUID = "different" }},
		{"late transcript", func(_ *VoiceCleanupHistoricalIdentity, f *fakeVoiceCleanupReader) { f.queryCounts = []int{0, 1, 0} }},
		{"authority drift", func(_ *VoiceCleanupHistoricalIdentity, f *fakeVoiceCleanupReader) { f.driftAt = 4 }},
		{"closing authority drift", func(_ *VoiceCleanupHistoricalIdentity, f *fakeVoiceCleanupReader) { f.driftAt = 8 }},
		{"ambiguous query", func(_ *VoiceCleanupHistoricalIdentity, f *fakeVoiceCleanupReader) { f.failQuery = true }},
		{"relabeled historical Pod outside selector", func(_ *VoiceCleanupHistoricalIdentity, f *fakeVoiceCleanupReader) { f.oldAppearsAt = 3 }},
		{"datastore drift", func(_ *VoiceCleanupHistoricalIdentity, f *fakeVoiceCleanupReader) { f.datastoreDriftAt = 4 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, h, f := voiceCleanupFixture()
			tc.change(&h, f)
			proof, err := VerifyVoiceCleanupReadOnly(context.Background(), f, cfg, h, sids, noPause)
			if err == nil || len(proof.Samples) != 0 {
				t.Fatalf("adverse observation accepted: %+v", proof)
			}
		})
	}
	cfg, h, f = voiceCleanupFixture()
	if _, err := VerifyVoiceCleanupReadOnly(context.Background(), f, cfg, h, []string{sids[0], sids[0]}, noPause); err == nil || f.queries != 0 {
		t.Fatal("duplicate SID accepted")
	}
}

func TestVoiceCleanupDatastoreBindingUsesHistoricalReplicaSet(t *testing.T) {
	values := []corev1.EnvVar{{Name: "MONGO_URI", Value: "mongodb://owned"}, {Name: "MONGO_DB", Value: "owned"}, {Name: "MONGO_COLLECTION", Value: "transcripts"}}
	owner := true
	historical := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-old", Namespace: "voice", UID: types.UID("rs-old"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "voice-bot", UID: types.UID("dep-old"), Controller: &owner}}}, Spec: appsv1.ReplicaSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Env: values}}}}}}
	sha, err := voiceCanonicalSHA(historical.Spec)
	if err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-current", Namespace: "voice", UID: types.UID("pod-current"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "voice-bot-current-rs", UID: types.UID("rs-current"), Controller: &owner}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Env: values}}}}
	kube := fake.NewSimpleClientset(historical, pod)
	runtime := &kubeVoiceRuntime{kube: kube}
	cfg := VoiceConfig{Namespace: "voice", DeploymentName: "voice-bot", ContainerName: "bot"}
	h := VoiceCleanupHistoricalIdentity{ReplicaSetUID: "rs-old", DeploymentUID: "dep-old", ReplicaSetSpecSHA256: sha}
	selected := VoicePod{Name: pod.Name, UID: string(pod.UID), ReplicaSetName: "voice-bot-current-rs", ReplicaSetUID: "rs-current"}
	if got, err := runtime.DatastoreBinding(context.Background(), cfg, h, selected); err != nil || !voiceSHA256.MatchString(got) {
		t.Fatalf("historical datastore binding failed: %q %v", got, err)
	}
	changed := pod.DeepCopy()
	changed.Spec.Containers[0].Env[1].Value = "different"
	if _, err := kube.CoreV1().Pods("voice").Update(context.Background(), changed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.DatastoreBinding(context.Background(), cfg, h, selected); err == nil {
		t.Fatal("current Pod querying a different Mongo database was accepted")
	}
	changed.Spec.Containers[0].Env[1].Value = "owned"
	changed.Spec.Containers[0].Env = append(changed.Spec.Containers[0].Env, corev1.EnvVar{Name: "MONGO_DB", Value: "owned"})
	if _, err := kube.CoreV1().Pods("voice").Update(context.Background(), changed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.DatastoreBinding(context.Background(), cfg, h, selected); err == nil {
		t.Fatal("ambiguous Mongo database env was accepted")
	}
}
