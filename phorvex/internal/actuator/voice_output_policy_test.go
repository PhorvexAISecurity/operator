package actuator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceoutputpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type voiceOutputRoundTrip func(*http.Request) (*http.Response, error)

func (f voiceOutputRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVoiceOutputNativeAppendAllPodReadbackAndProtectedHistory(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	depUID := types.UID("11111111-1111-4111-8111-111111111111")
	rsUID := types.UID("22222222-2222-4222-8222-222222222222")
	polUID := types.UID("33333333-3333-4333-8333-333333333333")
	cmUID := types.UID("44444444-4444-4444-8444-444444444444")
	podUID := types.UID("55555555-5555-4555-8555-555555555555")
	source := strings.Repeat("a", 64)
	creator := "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
	optional := false
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "bot", Namespace: "voice", UID: depUID}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "bot"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "bot-rs", Namespace: "voice", UID: rsUID, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	volumes := []corev1.Volume{{Name: "policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: voiceoutputpolicy.ConfigMapName}, Optional: &optional}}}, {Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: voiceOutputSecretName}}}, {Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	bot := corev1.Container{Name: "bot", Env: []corev1.EnvVar{{Name: "VOICE_OUTPUT_POLICY_REQUIRED", Value: "true"}}, VolumeMounts: []corev1.VolumeMount{{Name: "policy", MountPath: "/etc/phorvex/voice-output-policy", ReadOnly: true}, {Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true}, {Name: "state", MountPath: "/var/lib/phorvex-voice-memory"}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "bot-1", Namespace: "voice", UID: podUID, Labels: map[string]string{"app": "bot"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}, Annotations: map[string]string{"phorvex.ai/voice-output-policy-configmap": voiceoutputpolicy.ConfigMapName, "phorvex.ai/voice-output-source-sha256": source, "phorvex.ai/voice-output-event-creator": creator}}, Spec: corev1.PodSpec{Containers: []corev1.Container{bot}, Volumes: volumes}, Status: corev1.PodStatus{PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	peer := pod.DeepCopy()
	peer.Name = "bot-2"
	peer.UID = types.UID("77777777-7777-4777-8777-777777777777")
	peer.Status.PodIP = "127.0.0.2"
	rule := voiceoutputpolicy.Rule{Version: 1, ConfigMapUID: string(cmUID), DeploymentUID: string(depUID), PolicyUID: string(polUID), SourceSHA256: source, Entries: []voiceoutputpolicy.Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceoutputpolicy.ConfigMapName, Namespace: "voice", UID: cmUID, ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Data: map[string]string{voiceoutputpolicy.RuleKey: string(rule.Bytes())}}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "voice-policy", Namespace: "voice", UID: polUID, Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "bot"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionVoiceOutputPolicyActivate}}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: voiceOutputSecretName, Namespace: "voice"}, Data: map[string][]byte{"token": []byte(strings.Repeat("s", 32))}}
	journal := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceOutputJournalName, Namespace: "operator", Labels: map[string]string{voiceOutputJournalLabel: "v1"}}, Data: map[string]string{"receipts.json": `{"receipts":[],"version":1}`}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(dep, rs, pod, peer, cm, pol, secret, journal, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "voice"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).Build()
	stateUID := string(podUID)
	transport := voiceOutputRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != voiceoutputpolicy.StatePath || req.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			t.Fatal("wrong private state route/auth")
		}
		marker := req.URL.Query().Get("markerSHA256")
		current := &corev1.ConfigMap{}
		if e := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voiceoutputpolicy.ConfigMapName}, current); e != nil {
			return nil, e
		}
		r, e := voiceoutputpolicy.Parse(current.Data[voiceoutputpolicy.RuleKey])
		if e != nil {
			return nil, e
		}
		op := ""
		for _, entry := range r.Entries {
			if entry.MarkerSHA256 == marker {
				op = entry.OperationID
			}
		}
		uid := stateUID
		if req.URL.Hostname() == peer.Status.PodIP && stateUID != "wrong" {
			uid = string(peer.UID)
		}
		body, _ := json.Marshal(voiceOutputState{Version: 1, PodUID: uid, ConfigMapUID: r.ConfigMapUID, DeploymentUID: r.DeploymentUID, PolicyUID: r.PolicyUID, SourceSHA256: r.SourceSHA256, RuleSHA256: r.SHA256(), Revision: r.Revision, OperationID: r.OperationID, EntryCount: len(r.Entries), MarkerSHA256: marker, Active: op != "", MatchedOperationID: op, Ready: true})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	ec := EnactCtx{Reader: c, Client: c, JournalNamespace: "operator", VoiceOutputTransport: transport}
	makeReq := func(i int, current voiceoutputpolicy.Rule, rv string) Request {
		marker := strings.Repeat(string(rune('0'+i)), 64)
		eventUID := "66666666-6666-4666-8666-66666666666" + string(rune('0'+i))
		eventName := "output-event-" + string(rune('0'+i))
		observed := now.Add(-time.Second)
		assertion := map[string]any{"version": 1, "scenarioId": "ai2-system-prompt-leakage", "evidenceSource": "TEST_INJECTED", "rawModelMarkerObserved": true, "assistantOutputMarkerObserved": true, "markerSHA256": marker, "configMapUID": string(cmUID), "deploymentUID": string(depUID), "sourceSHA256": source, "policyName": "voice-policy", "policyUID": string(polUID), "policyGeneration": int64(1), "podUID": string(podUID), "observedAt": observed.Format(time.RFC3339Nano), "requestPath": "/ws"}
		raw, _ := json.Marshal(assertion)
		event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: eventName, UID: types.UID(eventUID), CreationTimestamp: metav1.NewTime(now), Annotations: map[string]string{"phorvex.ai/creator-identity": creator, model.ConsoleTargetPodUIDAnnotation: string(podUID), voiceOutputObservationAnnotation: string(raw)}}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"voice/bot-1"}, Rule: amtdv1beta1.Rule{Type: model.AttackVectorVoiceOutput, Source: "redteam"}}}
		if e := c.Create(ctx, event); e != nil {
			t.Fatal(e)
		}
		return Request{Namespace: "voice", Pod: "bot-1", TargetUID: string(podUID), PolicyName: "voice-policy", PolicyUID: string(polUID), PolicyGeneration: 1, TickID: "tick-" + string(rune('0'+i)), OperationID: "decision-" + string(rune('0'+i)), Action: model.ActionVoiceOutputPolicyActivate, VoiceOutputObservation: &model.VoiceOutputObservation{EventName: eventName, EventUID: eventUID, CreatorIdentity: creator, ScenarioID: "ai2-system-prompt-leakage", EvidenceSource: "TEST_INJECTED", TargetPodUID: string(podUID), DeploymentUID: string(depUID), ConfigMapUID: string(cmUID), ConfigMapResourceVersion: rv, RuleSHA256: current.SHA256(), SourceSHA256: source, MarkerSHA256: marker, PolicyName: "voice-policy", PolicyUID: string(polUID), PolicyGeneration: 1, SelectedRevision: current.Revision, RawModelMarkerObserved: true, AssistantOutputMarkerObserved: true, ObservedAt: observed}}
	}
	req := makeReq(1, rule, cm.ResourceVersion)
	result, e := (voiceOutputHandler{}).Enact(ctx, ec, req)
	if e != nil || !result.Emitted {
		t.Fatalf("first append: %+v %v", result, e)
	}
	if again, retryErr := (voiceOutputHandler{}).Enact(ctx, ec, req); retryErr != nil || !again.Emitted {
		t.Fatalf("same selected operation failed idempotent readback: %+v %v", again, retryErr)
	}
	protected := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "operator", Name: voiceOutputJournalName}, protected); err != nil {
		t.Fatal(err)
	}
	var pending voiceOutputJournal
	if err := json.Unmarshal([]byte(protected.Data["receipts.json"]), &pending); err != nil {
		t.Fatal(err)
	}
	pending.Receipts[0].Phase = "prepared"
	pendingRaw, _ := json.Marshal(pending)
	protected.Data["receipts.json"] = string(pendingRaw)
	if err := c.Update(ctx, protected); err != nil {
		t.Fatal(err)
	}
	if blocked, err := PendingVoiceOutputOperation(ctx, c, "operator", "voice", "bot-1", string(podUID)); err != nil || !blocked {
		t.Fatalf("prepared operation failed to fence target: %v %v", blocked, err)
	}
	if blocked, err := PendingVoiceOutputOperation(ctx, c, "operator", "voice", peer.Name, string(peer.UID)); err != nil || !blocked {
		t.Fatalf("prepared operation failed to fence serving peer: %v %v", blocked, err)
	}
	if recovered, err := recoverVoiceOutputOperations(ctx, ec, func(a model.Action) bool { return a == model.ActionVoiceOutputPolicyActivate }); err != nil || len(recovered) != 1 || recovered[0].Outcome != "confirmed" {
		t.Fatalf("prepared effect failed protected recovery: %+v %v", recovered, err)
	}
	current := &corev1.ConfigMap{}
	if e = c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voiceoutputpolicy.ConfigMapName}, current); e != nil {
		t.Fatal(e)
	}
	first, e := voiceoutputpolicy.Parse(current.Data[voiceoutputpolicy.RuleKey])
	if e != nil || first.Revision != 1 {
		t.Fatalf("first policy: %+v %v", first, e)
	}
	_, doc, e := voiceOutputJournalGet(ctx, c, "operator")
	if e != nil || len(doc.Receipts) != 1 || doc.Receipts[0].Phase != "terminal-full" {
		t.Fatalf("first protected receipt: %+v %v", doc, e)
	}
	stateUID = "wrong"
	if e = voiceOutputReadback(ctx, voiceOutputScope{pods: []corev1.Pod{*pod}, token: []byte(strings.Repeat("s", 32))}, first, strings.Repeat("1", 64), true, transport); e == nil {
		t.Fatal("wrong Pod UID earned readback")
	}
	stateUID = string(podUID)
	req2 := makeReq(2, first, current.ResourceVersion)
	result, e = (voiceOutputHandler{}).Enact(ctx, ec, req2)
	if e != nil || !result.Emitted {
		t.Fatalf("second append: %+v %v", result, e)
	}
	if e = c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voiceoutputpolicy.ConfigMapName}, current); e != nil {
		t.Fatal(e)
	}
	second, e := voiceoutputpolicy.Parse(current.Data[voiceoutputpolicy.RuleKey])
	if e != nil || second.Revision != 2 || len(second.Entries) != 2 {
		t.Fatalf("prior marker lost: %+v %v", second, e)
	}
	_, doc, e = voiceOutputJournalGet(ctx, c, "operator")
	if e != nil || len(doc.Receipts) != 2 || doc.Receipts[1].Phase != "terminal-full" {
		t.Fatalf("second protected receipt: %+v %v", doc, e)
	}
	if ok, why := voiceOutputCapability(ctx, c, "operator", Target{Namespace: "voice", Pod: "bot-1", UID: string(podUID), PolicyName: "voice-policy", PolicyUID: string(polUID)}, transport); !ok {
		t.Fatalf("capability lost after append: %s", why)
	}
}
