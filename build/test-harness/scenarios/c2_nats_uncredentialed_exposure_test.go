package scenarios

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/natsexposure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stest "k8s.io/client-go/testing"
)

type natsExposureTestGuard struct{}

func (natsExposureTestGuard) AssertMutationAllowed(string) error { return nil }

type natsExposureTestLogger struct{}

func (*natsExposureTestLogger) Logf(string, ...any) {}
func (*natsExposureTestLogger) Command(string)      {}
func (*natsExposureTestLogger) Commands() []string  { return nil }
func (*natsExposureTestLogger) RawLogPath() string  { return "" }

func natsExposureOwnedEnv(t *testing.T) (*core.Env, *c2NATSUncredentialedExposure) {
	t.Helper()
	nonce := "0123456789abcdef01234567"
	ns := "phorvex-nats-exposure-fixture"
	client := k8sfake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: "namespace-owned", Labels: map[string]string{"phorvex.ai/nats-exposure-fixture": "true"}}})
	client.PrependReactor("create", "configmaps", func(action k8stest.Action) (bool, runtime.Object, error) {
		cm := action.(k8stest.CreateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
		cm.UID = "created-cm"
		err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, ns)
		return true, cm, err
	})
	client.PrependReactor("create", "pods", func(action k8stest.Action) (bool, runtime.Object, error) {
		pod := action.(k8stest.CreateAction).GetObject().(*corev1.Pod).DeepCopy()
		pod.UID = "created-pod"
		err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), pod, ns)
		return true, pod, err
	})
	env := &core.Env{Kube: client, Guard: natsExposureTestGuard{}, Log: &natsExposureTestLogger{}, Config: config.TargetConfig{Namespace: ns, OutDir: t.TempDir(), NATSExposureFixture: &config.NATSExposureFixtureConfig{RunID: "run-4", Nonce: nonce, NodeName: "healthy-node", ObserverImage: "docker.io/phorvex/console@sha256:" + strings.Repeat("a", 64)}}, ScenarioName: "c2-nats-uncredentialed-exposure", Trial: 1}
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := &c2NATSUncredentialedExposure{cmName: "nats-observer-" + nonce, podName: "nats-observer-" + nonce, evidence: map[string]string{}, route: natsRouteIdentity{Brokers: []natsBrokerIdentity{{ServerID: "N" + strings.Repeat("A", 55)}}}}
	s.artifact = natsBaselineArtifact{Schema: "nats-baseline-v1", RunID: "run-4", Nonce: nonce, Namespace: ns, NamespaceUID: env.NamespaceUID()}
	return env, s
}

func TestNATSExposureVarzRejectsAmbiguousAuthAndSource(t *testing.T) {
	base := `{"server_id":"N` + strings.Repeat("A", 55) + `","version":"2.10.29","jetstream":{"config":{}},"auth_required":false}`
	if got, err := decodeNATSExposureVarz([]byte(base)); err != nil || !got.AuthPresent || got.AuthRequired == nil || *got.AuthRequired {
		t.Fatalf("valid explicit false rejected: %+v %v", got, err)
	}
	for _, raw := range []string{
		strings.Replace(base, `"auth_required":false`, `"auth_required":null`, 1),
		strings.Replace(base, `"auth_required":false`, `"auth_required":false,"auth_required":false`, 1),
		strings.Replace(base, `"auth_required":false`, `"auth_required":"false"`, 1),
		strings.Replace(base, `"jetstream":{"config":{}}`, `"jetstream":null`, 1),
		strings.Replace(base, `"server_id":"N`+strings.Repeat("A", 55)+`"`, `"server_id":"other"`, 1),
	} {
		if _, err := decodeNATSExposureVarz([]byte(raw)); err == nil {
			t.Errorf("ambiguous or invalid monitor source accepted: %s", raw)
		}
	}
}

func TestNATSExposureRouteRejectsWrongUIDAndRevisions(t *testing.T) {
	yes := true
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "nats-1", Namespace: "nats", UID: types.UID("pod-1"), Labels: map[string]string{"app": "nats", "controller-revision-hash": "rev-1"}, OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: "nats", UID: types.UID("sts-1"), Controller: &yes}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "nats", Args: []string{"--config", "/etc/nats/nats.conf"}, VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/etc/nats"}}}}, Volumes: []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "nats-config"}}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "nats", Ready: true, ImageID: "nats@sha256:abc", ContainerID: "container://one"}}}}
	if _, err := natsReady(p, "sts-1", "rev-1", "nats@sha256:abc"); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*corev1.Pod){
		func(p *corev1.Pod) { p.OwnerReferences[0].UID = "sts-2" },
		func(p *corev1.Pod) { p.Labels["controller-revision-hash"] = "rev-2" },
		func(p *corev1.Pod) { p.Status.ContainerStatuses[0].Ready = false },
		func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].SubPath = "not-config" },
	} {
		copy := p.DeepCopy()
		change(copy)
		if _, err := natsReady(copy, "sts-1", "rev-1", "nats@sha256:abc"); err == nil {
			raw, _ := json.Marshal(copy)
			t.Errorf("changed broker source accepted: %s", raw)
		}
	}
}

func TestNATSExposureImageDigestBinding(t *testing.T) {
	admitted := "docker.io/review/console@sha256:" + strings.Repeat("a", 64)
	if !sameImageDigest("docker-pullable://docker.io/review/console@sha256:"+strings.Repeat("a", 64), admitted) {
		t.Fatal("same digest with kube prefix rejected")
	}
	if sameImageDigest("docker.io/review/console@sha256:"+strings.Repeat("b", 64), admitted) || sameImageDigest("console:latest", admitted) {
		t.Fatal("different or unpinned image accepted")
	}
}

func TestNATSExposureActualOwnedProducerAndReplacementRefusal(t *testing.T) {
	ctx := context.Background()
	env, s := natsExposureOwnedEnv(t)
	payload := natsBaselinePayload(env.Config.NATSExposureFixture.Nonce)
	subject := "cat.exposure." + env.Config.NATSExposureFixture.Nonce
	if err := s.createObserver(ctx, env, subject, payload); err != nil {
		t.Fatal(err)
	}
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, s.cmName, metav1.GetOptions{})
	if err != nil || cm.Immutable == nil || !*cm.Immutable || cm.UID != s.cmUID {
		t.Fatalf("producer ConfigMap not immutable/UID-bound: %+v %v", cm, err)
	}
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.podName, metav1.GetOptions{})
	if err != nil || pod.UID != s.podUID || pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatalf("producer Pod token or UID differed: %+v %v", pod, err)
	}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "observer", ImageID: env.Config.NATSExposureFixture.ObserverImage, ContainerID: "container://one", RestartCount: 0}}
	if _, err = env.Kube.CoreV1().Pods(env.Config.Namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.currentObserver(ctx, env); err != nil {
		t.Fatalf("exact producer Pod rejected: %v", err)
	}
	wrongCommand := pod.DeepCopy()
	wrongCommand.Spec.Containers[0].Command[0] = "/app/console"
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Update(ctx, wrongCommand, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.currentObserver(ctx, env); err == nil {
		t.Fatal("different process in same pinned image accepted")
	}
	wrongMount := pod.DeepCopy()
	wrongMount.Spec.Containers[0].VolumeMounts[0].ReadOnly = false
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Update(ctx, wrongMount, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.currentObserver(ctx, env); err == nil {
		t.Fatal("writable observer config mount accepted")
	}
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	tampered := cm.DeepCopy()
	tampered.Data["observer.json"] = "{}"
	if _, err = env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Update(ctx, tampered, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.currentObserver(ctx, env); err == nil {
		t.Fatal("changed immutable-config source accepted")
	}
	if _, err = env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	replacement := pod.DeepCopy()
	replacement.UID = "replacement-pod"
	if _, err = env.Kube.CoreV1().Pods(env.Config.Namespace).Update(ctx, replacement, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := s.currentObserver(ctx, env); err == nil {
		t.Fatal("same-name replacement Pod accepted")
	}
}

func TestNATSExposureTeardownRetainsArtifactHashAfterOwnedCleanup(t *testing.T) {
	ctx := context.Background()
	env, s := natsExposureOwnedEnv(t)
	payload := natsBaselinePayload(env.Config.NATSExposureFixture.Nonce)
	if err := s.createObserver(ctx, env, "cat.exposure."+env.Config.NATSExposureFixture.Nonce, payload); err != nil {
		t.Fatal(err)
	}
	s.artifact.Protocol.Cleanup = "CONFIRMED_ABSENT"
	if err := s.Teardown(ctx, env); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(env.Config.OutDir, "nats-baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.evidence["nats_baseline_artifact_sha256"] != natsSHA(raw) || s.artifact.Cleanup != "OBSERVER_AND_STREAM_CONFIRMED_ABSENT" {
		t.Fatalf("cleanup artifact digest or status differed: %+v", s.artifact)
	}
	if _, err = env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, s.podName, metav1.GetOptions{}); err == nil {
		t.Fatal("owned Pod remained")
	}
	if _, err = env.Kube.CoreV1().ConfigMaps(env.Config.Namespace).Get(ctx, s.cmName, metav1.GetOptions{}); err == nil {
		t.Fatal("owned config remained")
	}
}

func TestNATSExposurePhaseJournalPersistsCompleteProtocolReceipt(t *testing.T) {
	env, s := natsExposureOwnedEnv(t)
	receipt := natsexposure.Receipt{Phase: "STREAM_CREATED", Nonce: env.Config.NATSExposureFixture.Nonce, Stream: "CAT_" + env.Config.NATSExposureFixture.Nonce, Subject: "cat.exposure." + env.Config.NATSExposureFixture.Nonce, StreamCreatedUTC: "2026-09-24T01:00:00Z", PayloadSHA256: strings.Repeat("a", 64)}
	if err := s.phaseReceipt(env, "PROTOCOL_STREAM_CREATED", &receipt); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(env.Config.OutDir, "nats-baseline-phases.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var row struct {
		Phase           string               `json:"phase"`
		ProtocolReceipt natsexposure.Receipt `json:"protocolReceipt"`
	}
	if json.Unmarshal(raw, &row) != nil || row.Phase != "PROTOCOL_STREAM_CREATED" || row.ProtocolReceipt.Stream != receipt.Stream || row.ProtocolReceipt.StreamCreatedUTC != receipt.StreamCreatedUTC || row.ProtocolReceipt.PayloadSHA256 != receipt.PayloadSHA256 {
		t.Fatalf("phase journal omitted full receipt: %s", raw)
	}
}

func TestNATSExposureCleanupNeverListsOrDeletesOtherFixtureObjects(t *testing.T) {
	ctx := context.Background()
	env, _ := natsExposureOwnedEnv(t)
	if err := env.CleanupOwned(ctx, false); err != nil {
		t.Fatal(err)
	}
	for _, action := range env.Kube.(*k8sfake.Clientset).Actions() {
		if action.GetVerb() != "get" {
			t.Fatalf("NATS cleanup performed broad or mutating action: %#v", action)
		}
	}
	if err := env.CleanupOwned(ctx, true); err == nil {
		t.Fatal("NATS cleanup accepted namespace deletion")
	}
}
