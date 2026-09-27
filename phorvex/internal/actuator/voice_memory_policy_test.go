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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voicememorypolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type voiceMemoryRoundTrip func(*http.Request) (*http.Response, error)

func (f voiceMemoryRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVoiceMemoryPrivateAllPodReadback(t *testing.T) {
	rule := voicememorypolicy.Rule{Version: 1, DeploymentUID: "11111111-1111-4111-8111-111111111111", PolicyUID: "22222222-2222-4222-8222-222222222222", SourceSHA256: strings.Repeat("a", 64), Entries: []voicememorypolicy.Entry{}}
	s := voiceMemoryScope{rule: rule, secret: []byte(strings.Repeat("s", 32)), pods: []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-1")}, Status: corev1.PodStatus{PodIP: "127.0.0.1"}},
		{ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-2")}, Status: corev1.PodStatus{PodIP: "127.0.0.2"}},
	}}
	seen := map[string]bool{}
	transport := voiceMemoryRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != voicememorypolicy.StatePath || req.Header.Get("Authorization") != "Bearer "+string(s.secret) {
			t.Fatalf("private readback request invalid: %s", req.URL)
		}
		uid := "pod-1"
		if req.URL.Hostname() == "127.0.0.2" {
			uid = "pod-2"
		}
		seen[uid] = true
		state := voiceMemoryState{Version: 1, PodUID: uid, DeploymentUID: rule.DeploymentUID, PolicyUID: rule.PolicyUID, SourceSHA256: rule.SourceSHA256,
			RuleSHA256: rule.SHA256(), Revision: rule.Revision, OperationID: rule.OperationID, EntryCount: len(rule.Entries), Ready: true}
		data, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{}}, nil
	})
	if err := voiceMemoryReadback(context.Background(), s, rule, transport); err != nil || len(seen) != 2 {
		t.Fatalf("two-pod readback failed: %v seen=%v", err, seen)
	}
	bad := voiceMemoryRoundTrip(func(req *http.Request) (*http.Response, error) {
		state := voiceMemoryState{Version: 1, PodUID: "wrong-pod", DeploymentUID: rule.DeploymentUID, PolicyUID: rule.PolicyUID, SourceSHA256: rule.SourceSHA256, RuleSHA256: rule.SHA256(), Ready: true}
		data, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{}}, nil
	})
	if err := voiceMemoryReadback(context.Background(), s, rule, bad); err == nil {
		t.Fatal("wrong Pod identity accepted")
	}
	duplicate := voiceMemoryRoundTrip(func(req *http.Request) (*http.Response, error) {
		data := `{"version":1,"version":1,"podUID":"pod-1","deploymentUID":"` + rule.DeploymentUID + `","policyUID":"` + rule.PolicyUID + `","sourceSHA256":"` + rule.SourceSHA256 + `","ruleSHA256":"` + rule.SHA256() + `","revision":0,"operationId":"","entryCount":0,"ready":true}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(data)), Header: http.Header{}}, nil
	})
	if err := voiceMemoryReadback(context.Background(), s, rule, duplicate); err == nil {
		t.Fatal("ambiguous duplicate state key accepted")
	}
}

func TestVoiceMemoryNativeAppendKeepsPreviousCaller(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	depUID := types.UID("11111111-1111-4111-8111-111111111111")
	rsUID := types.UID("22222222-2222-4222-8222-222222222222")
	policyUID := types.UID("33333333-3333-4333-8333-333333333333")
	cmUID := types.UID("44444444-4444-4444-8444-444444444444")
	podUID := types.UID("55555555-5555-4555-8555-555555555555")
	creator := "system:serviceaccount:phorvex-system:console"
	source := strings.Repeat("a", 64)
	optional := true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "bot", Namespace: "voice", UID: depUID}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "bot"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "bot-rs", Namespace: "voice", UID: rsUID, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	volumes := []corev1.Volume{
		{Name: "policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: voicememorypolicy.ConfigMapName}, Optional: &optional}}},
		{Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: voiceMemorySecretName}}},
		{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	bot := corev1.Container{Name: "bot", VolumeMounts: []corev1.VolumeMount{{Name: "policy", MountPath: "/etc/phorvex/voice-memory-policy", ReadOnly: true},
		{Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true}, {Name: "state", MountPath: "/var/lib/phorvex-voice-memory"}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "bot-1", Namespace: "voice", UID: podUID, Labels: map[string]string{"app": "bot"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}, Annotations: map[string]string{
		"phorvex.ai/voice-memory-policy-configmap": voicememorypolicy.ConfigMapName, "phorvex.ai/voice-memory-source-sha256": source, "phorvex.ai/voice-memory-event-creator": creator}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{bot}, Volumes: volumes}, Status: corev1.PodStatus{PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	rule := voicememorypolicy.Rule{Version: 1, DeploymentUID: string(depUID), PolicyUID: string(policyUID), SourceSHA256: source, Entries: []voicememorypolicy.Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voicememorypolicy.ConfigMapName, Namespace: "voice", UID: cmUID, ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Data: map[string]string{voicememorypolicy.RuleKey: string(rule.Bytes())}}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "voice-policy", Namespace: "voice", UID: policyUID, Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "bot"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionVoiceMemoryNoteRevoke}}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: voiceMemorySecretName, Namespace: "voice"}, Data: map[string][]byte{"token": []byte(strings.Repeat("s", 32))}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(dep, rs, pod, cm, pol, secret, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "voice"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).Build()
	transport := voiceMemoryRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			t.Fatal("private token absent")
		}
		current := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicememorypolicy.ConfigMapName}, current); err != nil {
			return nil, err
		}
		got, err := voicememorypolicy.Parse(current.Data[voicememorypolicy.RuleKey])
		if err != nil {
			return nil, err
		}
		state := voiceMemoryState{Version: 1, PodUID: string(podUID), DeploymentUID: got.DeploymentUID, PolicyUID: got.PolicyUID, SourceSHA256: got.SourceSHA256,
			RuleSHA256: got.SHA256(), Revision: got.Revision, OperationID: got.OperationID, EntryCount: len(got.Entries), Ready: true}
		data, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{}}, nil
	})
	ec := EnactCtx{Reader: c, Client: c, JournalNamespace: "operator", VoiceMemoryTransport: transport}
	makeReq := func(eventName, eventUID, caller, noteSHA, tick, decision string, current voicememorypolicy.Rule, rv string) Request {
		observed := now.Add(-time.Second)
		payload := map[string]any{"version": 1, "scenarioId": "voice-live", "caseId": "owned-memory", "callerId": caller, "noteSHA256": noteSHA, "deploymentUID": string(depUID),
			"podUID": string(podUID), "sourceSHA256": source, "policyName": "voice-policy", "policyUID": string(policyUID), "policyGeneration": int64(1),
			"observedAt": observed.Format(time.RFC3339Nano), "evidenceSource": "TEST_INJECTED", "observed": true}
		raw, _ := json.Marshal(payload)
		event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: eventName, UID: types.UID(eventUID), CreationTimestamp: metav1.NewTime(now), Annotations: map[string]string{
			"phorvex.ai/creator-identity": creator, model.ConsoleTargetPodUIDAnnotation: string(podUID), voiceMemoryEventAnnotation: string(raw)}},
			Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"voice/bot-1"}, Rule: amtdv1beta1.Rule{Type: model.AttackVectorVoiceMemory}}}
		if err := c.Create(ctx, event); err != nil {
			t.Fatal(err)
		}
		return Request{Namespace: "voice", Pod: "bot-1", TargetUID: string(podUID), PolicyName: "voice-policy", PolicyUID: string(policyUID), PolicyGeneration: 1,
			TickID: tick, OperationID: decision, Action: model.ActionVoiceMemoryNoteRevoke, VoiceMemoryObservation: &model.VoiceMemoryObservation{EventName: eventName, EventUID: eventUID,
				CreatorIdentity: creator, ScenarioID: "voice-live", CaseID: "owned-memory", TargetPodUID: string(podUID), DeploymentUID: string(depUID), ConfigMapUID: string(cmUID), ConfigMapResourceVersion: rv,
				RuleSHA256: current.SHA256(), SourceSHA256: source, CallerID: caller, NoteSHA256: noteSHA, PolicyName: "voice-policy", PolicyUID: string(policyUID), PolicyGeneration: 1,
				SelectedRevision: current.Revision, ObservedAt: observed}}
	}
	firstReq := makeReq("voice-event-1", "66666666-6666-4666-8666-666666666666", "+15551234567", strings.Repeat("b", 64), "tick-1", "decision-1", rule, cm.ResourceVersion)
	result, err := (voiceMemoryHandler{}).Enact(ctx, ec, firstReq)
	if err != nil || !result.Emitted || result.MutationKind != "forward-only" {
		t.Fatalf("first append not confirmed: %+v %v", result, err)
	}
	updated := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicememorypolicy.ConfigMapName}, updated); err != nil {
		t.Fatal(err)
	}
	first, err := voicememorypolicy.Parse(updated.Data[voicememorypolicy.RuleKey])
	if err != nil || len(first.Entries) != 1 {
		t.Fatalf("first rule invalid: %+v %v", first, err)
	}
	secondReq := makeReq("voice-event-2", "77777777-7777-4777-8777-777777777777", "+15551234568", strings.Repeat("c", 64), "tick-2", "decision-2", first, updated.ResourceVersion)
	result, err = (voiceMemoryHandler{}).Enact(ctx, ec, secondReq)
	if err != nil || !result.Emitted {
		t.Fatalf("second append not confirmed: %+v %v", result, err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicememorypolicy.ConfigMapName}, updated); err != nil {
		t.Fatal(err)
	}
	second, err := voicememorypolicy.Parse(updated.Data[voicememorypolicy.RuleKey])
	if err != nil || second.Revision != 2 || len(second.Entries) != 2 || second.Entries[0] != first.Entries[0] {
		t.Fatalf("prior caller was erased: %+v %v", second, err)
	}
	if _, _, err := voiceMemoryJournalGet(ctx, ec, voiceMemoryJournalName(string(depUID), 2)); err != nil {
		t.Fatalf("second terminal receipt invalid: %v", err)
	}
	thirdReq := makeReq("voice-event-3", "88888888-8888-4888-8888-888888888888", "+15551234569", strings.Repeat("d", 64), "tick-3", "decision-3", second, updated.ResourceVersion)
	thirdEvent := &amtdv1beta1.SecurityEvent{}
	if err := c.Get(ctx, client.ObjectKey{Name: "voice-event-3"}, thirdEvent); err != nil {
		t.Fatal(err)
	}
	thirdEvent.Annotations["phorvex.ai/creator-identity"] = "system:serviceaccount:voice:untrusted"
	if err := c.Update(ctx, thirdEvent); err != nil {
		t.Fatal(err)
	}
	if result, err := (voiceMemoryHandler{}).Enact(ctx, ec, thirdReq); err == nil || result.Emitted {
		t.Fatalf("wrong event creator admitted: %+v %v", result, err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicememorypolicy.ConfigMapName}, updated); err != nil {
		t.Fatal(err)
	}
	unchanged, err := voicememorypolicy.Parse(updated.Data[voicememorypolicy.RuleKey])
	if err != nil || unchanged.SHA256() != second.SHA256() {
		t.Fatalf("wrong-creator event mutated rule: %+v %v", unchanged, err)
	}
	if _, _, err := voiceMemoryJournalGet(ctx, ec, voiceMemoryJournalName(string(depUID), 3)); !apierrors.IsNotFound(err) {
		t.Fatalf("wrong-creator event reserved a journal: %v", err)
	}
	podLive := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: "bot-1"}, podLive); err != nil {
		t.Fatal(err)
	}
	podLive.Spec.Containers[0].VolumeMounts[0].SubPath = "rule.json"
	if err := c.Update(ctx, podLive); err != nil {
		t.Fatal(err)
	}
	if ok, why := voiceMemoryCapability(ctx, c, "operator", Target{Namespace: "voice", Pod: "bot-1", UID: string(podUID), PolicyName: "voice-policy", PolicyUID: string(policyUID)}, transport); ok || why == "" {
		t.Fatalf("stale subPath mount accepted: %t %s", ok, why)
	}
}
