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
	"github.com/phorvex/phorvex/internal/voicerefundpolicy"
)

func TestVoiceRefundObservationPayloadExactShape(t *testing.T) {
	valid := `{"version":1,"scenarioId":"voice-live","caseId":"owned-note","assertedCallerSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","orderSHA256":"` + strings.Repeat("a", 64) + `","deploymentUID":"11111111-1111-4111-8111-111111111111","podUID":"pod-uid","sourceSHA256":"` + strings.Repeat("b", 64) + `","policyName":"policy","policyUID":"22222222-2222-4222-8222-222222222222","policyGeneration":1,"observedAt":"2026-09-27T00:00:00Z","evidenceSource":"TEST_INJECTED","modelCallbackObserved":true,"crmSideEffectObserved":true}`
	if _, ok := decodeVoiceRefundPayload(valid); !ok {
		t.Fatal("exact producer payload rejected")
	}
	for name, raw := range map[string]string{
		"duplicate": strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"unknown":   strings.Replace(valid, `"modelCallbackObserved":true,"crmSideEffectObserved":true`, `"modelCallbackObserved":true,"crmSideEffectObserved":true,"unexpected":1`, 1),
		"trailing":  valid + `{}`,
		"oversize":  valid + strings.Repeat("x", 2049),
		"alias":     strings.Replace(valid, `"orderSHA256":`, `"OrderSHA256":`, 1),
	} {
		if _, ok := decodeVoiceRefundPayload(raw); ok {
			t.Fatalf("%s payload accepted", name)
		}
	}
	if parsed, ok := decodeVoiceRefundPayload(strings.Replace(valid, `"crmSideEffectObserved":true`, `"crmSideEffectObserved":false`, 1)); !ok || parsed.CRMSideEffectObserved {
		t.Fatal("negative CRM effect countercontrol did not remain false")
	}
}

func TestVoiceRefundBinderRechecksCurrentOwnedRule(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	depUID := types.UID("11111111-1111-4111-8111-111111111111")
	polUID := "22222222-2222-4222-8222-222222222222"
	podUID := types.UID("33333333-3333-4333-8333-333333333333")
	cmUID := types.UID("44444444-4444-4444-8444-444444444444")
	source, caller, order := "204eb4c003e4fe1324ac64bd48f4a97ce1b60e992866fbf1d5187a0b24c06d6a", strings.Repeat("b", 64), strings.Repeat("c", 64)
	creator := "system:serviceaccount:phorvex-system:console"
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: depUID}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-rs", Namespace: "voice", UID: types.UID("55555555-5555-4555-8555-555555555555"), OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-1", Namespace: "voice", UID: podUID, Annotations: map[string]string{
		"phorvex.ai/voice-refund-policy-configmap": voicerefundpolicy.ConfigMapName,
		"phorvex.ai/voice-refund-source-sha256":    source, "phorvex.ai/voice-refund-event-creator": creator},
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Env: []corev1.EnvVar{{Name: "VOICE_REFUND_POLICY_REQUIRED", Value: "true"}}}}}}
	rule := voicerefundpolicy.Rule{Version: 1, DeploymentUID: string(depUID), PolicyUID: polUID, SourceSHA256: source, Entries: []voicerefundpolicy.Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voicerefundpolicy.ConfigMapName, Namespace: "voice", UID: cmUID, ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Data: map[string]string{voicerefundpolicy.RuleKey: string(rule.Bytes())}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, pod, cm).Build()
	view := model.Pod{Namespace: "voice", Name: "voice-bot-1", UID: string(podUID), VoiceRefundConfigMap: voicerefundpolicy.ConfigMapName, VoiceRefundSourceSHA256: source, VoiceRefundEventCreator: creator}
	payload := map[string]any{"version": 1, "scenarioId": "ai2-agent-excessive-agency", "caseId": "owned-refund", "assertedCallerSHA256": caller, "orderSHA256": order,
		"deploymentUID": string(depUID), "podUID": string(podUID), "sourceSHA256": source, "policyName": "voice-defense", "policyUID": polUID, "policyGeneration": int64(1),
		"observedAt": now.Add(-time.Second).Format(time.RFC3339Nano), "evidenceSource": "TEST_INJECTED", "modelCallbackObserved": true, "crmSideEffectObserved": true}
	raw, _ := json.Marshal(payload)
	event := model.SecurityEventInfo{Name: "voice-refund-event", UID: "66666666-6666-4666-8666-666666666666", Type: model.AttackVectorVoiceRefund, Trust: eventtrust.TrustTrusted,
		TargetsPod: true, CreatorIdentity: creator, ConsoleTargetPodUID: string(podUID), CreatedAt: now, Age: time.Second, VoiceRefundRaw: string(raw)}
	bindVoiceRefundObservation(ctx, c, &view, []model.SecurityEventInfo{event})
	if !view.HasBoundVoiceRefundObservation() || view.VoiceRefundObservation.ConfigMapUID != string(cmUID) {
		t.Fatalf("valid current object did not bind: %+v", view.VoiceRefundObservation)
	}
	bad := view
	bad.VoiceRefundObservation = nil
	event.Age = 61 * time.Second
	bindVoiceRefundObservation(ctx, c, &bad, []model.SecurityEventInfo{event})
	if bad.VoiceRefundObservation != nil {
		t.Fatal("stale event bound")
	}
	event.Age = time.Second
	current := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName}, current); err != nil {
		t.Fatal(err)
	}
	current.OwnerReferences[0].UID = types.UID("77777777-7777-4777-8777-777777777777")
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	bindVoiceRefundObservation(ctx, c, &bad, []model.SecurityEventInfo{event})
	if bad.VoiceRefundObservation != nil {
		t.Fatal("wrong ConfigMap owner bound")
	}
}
