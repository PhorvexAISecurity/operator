package ingest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceoutputpolicy"
)

func TestVoiceOutputPayloadExactAndCurrentOwnerBinding(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	depUID := types.UID("11111111-1111-4111-8111-111111111111")
	polUID := "22222222-2222-4222-8222-222222222222"
	podUID := types.UID("33333333-3333-4333-8333-333333333333")
	cmUID := types.UID("44444444-4444-4444-8444-444444444444")
	marker, creator := strings.Repeat("b", 64), "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
	immutable := true
	sourceCM := &corev1.ConfigMap{Immutable: &immutable, Data: map[string]string{"bot.py": "bot source", "voice_memory_policy.py": "memory source", "voice_output_policy.py": "output source", "voice_mcp_policy.py": "mcp source"}}
	source, bundle, sourceErr := voiceoutputpolicy.SourceHashes(sourceCM)
	if sourceErr != nil {
		t.Fatal(sourceErr)
	}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: depUID}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-rs", Namespace: "voice", UID: types.UID("55555555-5555-4555-8555-555555555555"), OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	sourceCM.ObjectMeta = metav1.ObjectMeta{Name: "voice-memory-source-" + bundle[:12], Namespace: "voice", UID: types.UID("88888888-8888-4888-8888-888888888888"), ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}
	optional := false
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-1", Namespace: "voice", UID: podUID, Annotations: map[string]string{"phorvex.ai/voice-output-policy-configmap": voiceoutputpolicy.ConfigMapName, "phorvex.ai/voice-output-source-sha256": source, "phorvex.ai/voice-output-event-creator": creator}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Env: []corev1.EnvVar{{Name: "VOICE_OUTPUT_POLICY_REQUIRED", Value: "true"}}, VolumeMounts: []corev1.VolumeMount{{Name: "policy", MountPath: "/etc/phorvex/voice-output-policy", ReadOnly: true}, {Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true}, {Name: "test-token", MountPath: "/etc/phorvex/voice-output-test-token", ReadOnly: true}, {Name: "state", MountPath: "/var/lib/phorvex-voice-memory"}}}}, Volumes: []corev1.Volume{{Name: "policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: voiceoutputpolicy.ConfigMapName}, Optional: &optional}}}, {Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "voice-memory-state-token"}}}, {Name: "test-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "voice-output-test-token"}}}, {Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}}}
	pod.Annotations[voiceoutputpolicy.SourceConfigMapAnnotation] = sourceCM.Name
	pod.Spec.Containers[0].Image = "voice@sha256:" + strings.Repeat("c", 64)
	pod.Spec.Containers[0].Command = []string{"python3", "-B", "/app/bot.py"}
	for _, name := range []string{"bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"} {
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "source", MountPath: "/app/" + name, SubPath: name, ReadOnly: true})
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: sourceCM.Name}}}})
	dep.Spec.Template.Annotations = map[string]string{voiceoutputpolicy.SourceConfigMapAnnotation: sourceCM.Name, voiceoutputpolicy.SourceSHAAnnotation: source}
	dep.Spec.Template.Spec = *pod.Spec.DeepCopy()
	rule := voiceoutputpolicy.Rule{Version: 1, DeploymentUID: string(depUID), ConfigMapUID: string(cmUID), PolicyUID: polUID, SourceSHA256: source, Entries: []voiceoutputpolicy.Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceoutputpolicy.ConfigMapName, Namespace: "voice", UID: cmUID, ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Data: map[string]string{voiceoutputpolicy.RuleKey: string(rule.Bytes())}}
	scheme := runtime.NewScheme()
	if e := corev1.AddToScheme(scheme); e != nil {
		t.Fatal(e)
	}
	if e := appsv1.AddToScheme(scheme); e != nil {
		t.Fatal(e)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, pod, cm, sourceCM).Build()
	view := model.Pod{Namespace: "voice", Name: pod.Name, UID: string(podUID), VoiceOutputConfigMap: voiceoutputpolicy.ConfigMapName, VoiceOutputSourceSHA256: source, VoiceOutputEventCreator: creator}
	assertion := map[string]any{"version": 1, "scenarioId": "ai2-system-prompt-leakage", "evidenceSource": "TEST_INJECTED", "rawModelMarkerObserved": true, "assistantOutputMarkerObserved": true, "markerSHA256": marker, "configMapUID": string(cmUID), "deploymentUID": string(depUID), "sourceSHA256": source, "policyName": "voice-defense", "policyUID": polUID, "policyGeneration": int64(1), "podUID": string(podUID), "observedAt": now.Add(-time.Second).Format(time.RFC3339Nano), "requestPath": "/ws"}
	raw, _ := json.Marshal(assertion)
	if _, ok := decodeVoiceOutputPayload(string(raw)); !ok {
		t.Fatal("real assertion shape rejected")
	}
	for _, bad := range []string{strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1), strings.Replace(string(raw), `"markerSHA256":`, `"MarkerSHA256":`, 1), string(raw) + "{}"} {
		if _, ok := decodeVoiceOutputPayload(bad); ok {
			t.Fatal("malformed alias/duplicate/trailing accepted")
		}
	}
	event := model.SecurityEventInfo{Name: "voice-output-event", UID: "66666666-6666-4666-8666-666666666666", Type: model.AttackVectorVoiceOutput, Trust: eventtrust.TrustTrusted, TargetsPod: true, CreatorIdentity: creator, ConsoleTargetPodUID: string(podUID), CreatedAt: now, Age: time.Second, VoiceOutputRaw: string(raw)}
	bindVoiceOutputObservation(ctx, c, &view, []model.SecurityEventInfo{event})
	if !view.HasBoundVoiceOutputObservation() {
		t.Fatalf("exact observed rule did not bind: %+v", view.VoiceOutputObservation)
	}
	if !voiceOutputRequiredMode(pod) {
		t.Fatal("exact synthetic-session token mount refused")
	}
	withoutTestToken := pod.DeepCopy()
	withoutTestToken.Spec.Containers[0].VolumeMounts = append(withoutTestToken.Spec.Containers[0].VolumeMounts[:2], withoutTestToken.Spec.Containers[0].VolumeMounts[3])
	if voiceOutputRequiredMode(withoutTestToken) {
		t.Fatal("observation accepted without authenticated synthetic-session token mount")
	}
	if _, err := voiceoutputpolicy.VerifySource(ctx, c, pod, dep); err != nil {
		t.Fatal(err)
	}
	mutatedSource := sourceCM.DeepCopy()
	mutatedSource.Data["voice_output_policy.py"] = "changed output source"
	if err := c.Update(ctx, mutatedSource); err != nil {
		t.Fatal(err)
	}
	mutatedView := view
	mutatedView.VoiceOutputObservation = nil
	bindVoiceOutputObservation(ctx, c, &mutatedView, []model.SecurityEventInfo{event})
	if mutatedView.VoiceOutputObservation != nil {
		t.Fatal("changed mounted output source bound")
	}
	mutatedSource.Data["voice_output_policy.py"] = sourceCM.Data["voice_output_policy.py"]
	if err := c.Update(ctx, mutatedSource); err != nil {
		t.Fatal(err)
	}
	bad := view
	bad.VoiceOutputObservation = nil
	event.Age = 61 * time.Second
	bindVoiceOutputObservation(ctx, c, &bad, []model.SecurityEventInfo{event})
	if bad.VoiceOutputObservation != nil {
		t.Fatal("stale observation bound")
	}
	event.Age = time.Second
	current := &corev1.ConfigMap{}
	if e := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voiceoutputpolicy.ConfigMapName}, current); e != nil {
		t.Fatal(e)
	}
	current.OwnerReferences[0].UID = types.UID("77777777-7777-4777-8777-777777777777")
	if e := c.Update(ctx, current); e != nil {
		t.Fatal(e)
	}
	bindVoiceOutputObservation(ctx, c, &bad, []model.SecurityEventInfo{event})
	if bad.VoiceOutputObservation != nil {
		t.Fatal("wrong CM owner bound")
	}
}
