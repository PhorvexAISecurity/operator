package actuator

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	"github.com/phorvex/phorvex/internal/voicerefundpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type voiceRefundRoundTrip func(*http.Request) (*http.Response, error)

func (f voiceRefundRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type voiceRefundSupersedingClient struct {
	client.Client
	superseding voicerefundpolicy.Rule
	updated     bool
}

type voiceRefundCreateRaceClient struct {
	client.Client
	competing *corev1.ConfigMap
	inserted  bool
}

func (c *voiceRefundCreateRaceClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Namespace == c.competing.Namespace && cm.Name == c.competing.Name && !c.inserted {
		c.inserted = true
		if err := c.Client.Create(ctx, c.competing); err != nil {
			return err
		}
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *voiceRefundSupersedingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm.Namespace != voicerefundpolicy.Namespace || cm.Name != voicerefundpolicy.ConfigMapName || c.updated {
		return nil
	}
	c.updated = true
	fresh := &corev1.ConfigMap{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: cm.Namespace, Name: cm.Name}, fresh); err != nil {
		return err
	}
	fresh.Data[voicerefundpolicy.RuleKey] = string(c.superseding.Bytes())
	return c.Client.Update(ctx, fresh)
}

func TestVoiceRefundPrivateAllPodReadback(t *testing.T) {
	rule := voicerefundpolicy.Rule{Version: 1, DeploymentUID: "11111111-1111-4111-8111-111111111111", PolicyUID: "22222222-2222-4222-8222-222222222222", SourceSHA256: strings.Repeat("a", 64), Entries: []voicerefundpolicy.Entry{}}
	if err := voiceRefundReadback(context.Background(), voiceRefundScope{}, rule, nil); err == nil {
		t.Fatal("empty Pod readback scope credited")
	}
	s := voiceRefundScope{rule: rule, secret: []byte(strings.Repeat("s", 32)), pods: []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-1")}, Status: corev1.PodStatus{PodIP: "127.0.0.1"}},
		{ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-2")}, Status: corev1.PodStatus{PodIP: "127.0.0.2"}},
	}}
	seen := map[string]bool{}
	transport := voiceRefundRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != voicerefundpolicy.StatePath || req.Header.Get("Authorization") != "Bearer "+string(s.secret) {
			t.Fatalf("private readback request invalid: %s", req.URL)
		}
		uid := "pod-1"
		if req.URL.Hostname() == "127.0.0.2" {
			uid = "pod-2"
		}
		seen[uid] = true
		state := voiceRefundState{Version: 1, PodUID: uid, DeploymentUID: rule.DeploymentUID, PolicyUID: rule.PolicyUID, SourceSHA256: rule.SourceSHA256,
			RuleSHA256: rule.SHA256(), Revision: rule.Revision, OperationID: rule.OperationID, EntryCount: len(rule.Entries), Ready: true}
		data, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	})
	if err := voiceRefundReadback(context.Background(), s, rule, transport); err != nil || len(seen) != 2 {
		t.Fatalf("two-pod readback failed: %v seen=%v", err, seen)
	}
	bad := voiceRefundRoundTrip(func(req *http.Request) (*http.Response, error) {
		state := voiceRefundState{Version: 1, PodUID: "wrong-pod", DeploymentUID: rule.DeploymentUID, PolicyUID: rule.PolicyUID, SourceSHA256: rule.SourceSHA256, RuleSHA256: rule.SHA256(), Ready: true}
		data, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	})
	if err := voiceRefundReadback(context.Background(), s, rule, bad); err == nil {
		t.Fatal("wrong Pod identity accepted")
	}
	duplicate := voiceRefundRoundTrip(func(req *http.Request) (*http.Response, error) {
		data := `{"version":1,"version":1,"podUID":"pod-1","deploymentUID":"` + rule.DeploymentUID + `","policyUID":"` + rule.PolicyUID + `","sourceSHA256":"` + rule.SourceSHA256 + `","ruleSHA256":"` + rule.SHA256() + `","revision":0,"operationId":"","entryCount":0,"ready":true}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(data)), Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	})
	if err := voiceRefundReadback(context.Background(), s, rule, duplicate); err == nil {
		t.Fatal("ambiguous duplicate state key accepted")
	}
	stalePod := voiceRefundRoundTrip(func(req *http.Request) (*http.Response, error) {
		uid := "pod-1"
		revision := rule.Revision
		if req.URL.Hostname() == "127.0.0.2" {
			uid = "pod-2"
			revision++
		}
		state := voiceRefundState{Version: 1, PodUID: uid, DeploymentUID: rule.DeploymentUID, PolicyUID: rule.PolicyUID,
			SourceSHA256: rule.SourceSHA256, RuleSHA256: rule.SHA256(), Revision: revision, OperationID: rule.OperationID,
			EntryCount: len(rule.Entries), Ready: true}
		data, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	})
	if err := voiceRefundReadback(context.Background(), s, rule, stalePod); err == nil {
		t.Fatal("one stale serving Pod credited as all-Pod effect")
	}
	redirect := voiceRefundRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"http://127.0.0.9/"}}}, nil
	})
	if err := voiceRefundReadback(context.Background(), s, rule, redirect); err == nil {
		t.Fatal("redirect accepted as private state")
	}
}

func TestVoiceRefundHTTPReadbackUsesFixedPrivateRouteAndDeadline(t *testing.T) {
	rule := voicerefundpolicy.Rule{Version: 1, DeploymentUID: "11111111-1111-4111-8111-111111111111", PolicyUID: "22222222-2222-4222-8222-222222222222",
		SourceSHA256: strings.Repeat("a", 64), Entries: []voicerefundpolicy.Entry{}}
	s := voiceRefundScope{secret: []byte(strings.Repeat("s", 32)), pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{UID: types.UID("pod-1")}, Status: corev1.PodStatus{PodIP: "127.0.0.1"}}}}
	var mode atomic.Value
	mode.Store("good")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != voicerefundpolicy.StatePath || r.Header.Get("Authorization") != "Bearer "+string(s.secret) {
			http.Error(w, "wrong private request", 400)
			return
		}
		if mode.Load().(string) == "timeout" {
			<-r.Context().Done()
			return
		}
		if mode.Load().(string) == "wrong-type" {
			w.Header().Set("Content-Type", "text/html")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		state := voiceRefundState{Version: 1, PodUID: "pod-1", DeploymentUID: rule.DeploymentUID, PolicyUID: rule.PolicyUID, SourceSHA256: rule.SourceSHA256,
			RuleSHA256: rule.SHA256(), Revision: rule.Revision, OperationID: rule.OperationID, EntryCount: 0, Ready: true}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer server.Close()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "127.0.0.1:8080" {
			t.Fatalf("readback used unexpected destination %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	if err := voiceRefundReadback(context.Background(), s, rule, transport); err != nil {
		t.Fatalf("real private HTTP readback failed: %v", err)
	}
	mode.Store("wrong-type")
	if err := voiceRefundReadback(context.Background(), s, rule, transport); err == nil {
		t.Fatal("HTML content type accepted")
	}
	mode.Store("timeout")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := voiceRefundReadback(ctx, s, rule, transport); err == nil {
		t.Fatal("timed-out private state accepted")
	}
}

func TestVoiceRefundNativeAppendKeepsPreviousCaller(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	depUID := types.UID("11111111-1111-4111-8111-111111111111")
	rsUID := types.UID("22222222-2222-4222-8222-222222222222")
	policyUID := types.UID("33333333-3333-4333-8333-333333333333")
	cmUID := types.UID("44444444-4444-4444-8444-444444444444")
	podUID := types.UID("55555555-5555-4555-8555-555555555555")
	creator := "system:serviceaccount:phorvex-system:console"
	source := "204eb4c003e4fe1324ac64bd48f4a97ce1b60e992866fbf1d5187a0b24c06d6a"
	optional := false
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "bot", Namespace: "voice", UID: depUID}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "bot"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "bot-rs", Namespace: "voice", UID: rsUID, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	volumes := []corev1.Volume{
		{Name: "policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: voicerefundpolicy.ConfigMapName}, Optional: &optional}}},
		{Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: voiceRefundSecretName}}},
		{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	bot := corev1.Container{Name: "bot", Env: []corev1.EnvVar{{Name: "VOICE_REFUND_POLICY_REQUIRED", Value: "true"}}, VolumeMounts: []corev1.VolumeMount{{Name: "policy", MountPath: "/etc/phorvex/voice-refund-policy", ReadOnly: true},
		{Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true}, {Name: "state", MountPath: "/var/lib/phorvex-voice-memory"}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "bot-1", Namespace: "voice", UID: podUID, Labels: map[string]string{"app": "bot"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}, Annotations: map[string]string{
		"phorvex.ai/voice-refund-policy-configmap": voicerefundpolicy.ConfigMapName, "phorvex.ai/voice-refund-source-sha256": source, "phorvex.ai/voice-refund-event-creator": creator}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{bot}, Volumes: volumes}, Status: corev1.PodStatus{PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	rule := voicerefundpolicy.Rule{Version: 1, DeploymentUID: string(depUID), PolicyUID: string(policyUID), SourceSHA256: source, Entries: []voicerefundpolicy.Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voicerefundpolicy.ConfigMapName, Namespace: "voice", UID: cmUID, ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Data: map[string]string{voicerefundpolicy.RuleKey: string(rule.Bytes())}}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "voice-policy", Namespace: "voice", UID: policyUID, Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "bot"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionVoiceRefundPairDeny}}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: voiceRefundSecretName, Namespace: "voice"}, Data: map[string][]byte{"token": []byte(strings.Repeat("s", 32))}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(dep, rs, pod, cm, pol, secret, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "voice"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).Build()
	transport := voiceRefundRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			t.Fatal("private token absent")
		}
		current := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName}, current); err != nil {
			return nil, err
		}
		got, err := voicerefundpolicy.Parse(current.Data[voicerefundpolicy.RuleKey])
		if err != nil {
			return nil, err
		}
		state := voiceRefundState{Version: 1, PodUID: string(podUID), DeploymentUID: got.DeploymentUID, PolicyUID: got.PolicyUID, SourceSHA256: got.SourceSHA256,
			RuleSHA256: got.SHA256(), Revision: got.Revision, OperationID: got.OperationID, EntryCount: len(got.Entries), Ready: true}
		data, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	})
	ec := EnactCtx{Reader: c, Client: c, JournalNamespace: "operator", VoiceRefundTransport: transport}
	makeReq := func(eventName, eventUID, caller, noteSHA, tick, decision string, current voicerefundpolicy.Rule, rv string) Request {
		observed := now.Add(-time.Second)
		payload := map[string]any{"version": 1, "scenarioId": "voice-live", "caseId": "owned-memory", "assertedCallerSHA256": caller, "orderSHA256": noteSHA, "deploymentUID": string(depUID),
			"podUID": string(podUID), "sourceSHA256": source, "policyName": "voice-policy", "policyUID": string(policyUID), "policyGeneration": int64(1),
			"observedAt": observed.Format(time.RFC3339Nano), "evidenceSource": "TEST_INJECTED", "modelCallbackObserved": true, "crmSideEffectObserved": true}
		raw, _ := json.Marshal(payload)
		event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: eventName, UID: types.UID(eventUID), CreationTimestamp: metav1.NewTime(now), Annotations: map[string]string{
			"phorvex.ai/creator-identity": creator, model.ConsoleTargetPodUIDAnnotation: string(podUID), voiceRefundEventAnnotation: string(raw)}},
			Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"voice/bot-1"}, Rule: amtdv1beta1.Rule{Type: model.AttackVectorVoiceRefund}}}
		if err := c.Create(ctx, event); err != nil {
			t.Fatal(err)
		}
		return Request{Namespace: "voice", Pod: "bot-1", TargetUID: string(podUID), PolicyName: "voice-policy", PolicyUID: string(policyUID), PolicyGeneration: 1,
			TickID: tick, OperationID: decision, Action: model.ActionVoiceRefundPairDeny, VoiceRefundObservation: &model.VoiceRefundObservation{EventName: eventName, EventUID: eventUID,
				CreatorIdentity: creator, ScenarioID: "voice-live", CaseID: "owned-memory", TargetPodUID: string(podUID), DeploymentUID: string(depUID), ConfigMapUID: string(cmUID), ConfigMapResourceVersion: rv,
				RuleSHA256: current.SHA256(), SourceSHA256: source, AssertedCallerSHA256: caller, OrderSHA256: noteSHA, PolicyName: "voice-policy", PolicyUID: string(policyUID), PolicyGeneration: 1,
				SelectedRevision: current.Revision, ObservedAt: observed}}
	}
	firstReq := makeReq("voice-event-1", "66666666-6666-4666-8666-666666666666", strings.Repeat("1", 64), strings.Repeat("b", 64), "tick-1", "decision-1", rule, cm.ResourceVersion)
	result, err := (voiceRefundHandler{}).Enact(ctx, ec, firstReq)
	if err != nil || !result.Emitted || result.MutationKind != "forward-only" {
		t.Fatalf("first append not confirmed: %+v %v", result, err)
	}
	if again, err := (voiceRefundHandler{}).Enact(ctx, ec, firstReq); err != nil || !again.Emitted {
		t.Fatalf("same selection did not resume idempotently: %+v %v", again, err)
	}
	competing := firstReq
	competing.TickID = "competing-tick"
	if got, err := (voiceRefundHandler{}).Enact(ctx, ec, competing); err == nil || got.Emitted {
		t.Fatalf("competing selection claimed prior journal: %+v %v", got, err)
	}
	peer := pod.DeepCopy()
	peer.Name = "bot-2"
	peer.UID = types.UID("99999999-9999-4999-8999-999999999999")
	peer.ResourceVersion = ""
	peer.Labels = map[string]string{"app": "drifted"}
	peer.Status.PodIP = "127.0.0.2"
	if err := c.Create(ctx, peer); err != nil {
		t.Fatal(err)
	}
	if ok, why := voiceRefundCapability(ctx, c, "operator", Target{Namespace: "voice", Pod: "bot-1", UID: string(podUID), PolicyName: "voice-policy", PolicyUID: string(policyUID)}, transport); ok || why == "" {
		t.Fatalf("owned peer with drifted labels escaped all-Pod scope: %t %s", ok, why)
	}
	if err := c.Delete(ctx, peer); err != nil {
		t.Fatal(err)
	}
	updated := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName}, updated); err != nil {
		t.Fatal(err)
	}
	first, err := voicerefundpolicy.Parse(updated.Data[voicerefundpolicy.RuleKey])
	if err != nil || len(first.Entries) != 1 {
		t.Fatalf("first rule invalid: %+v %v", first, err)
	}
	secondReq := makeReq("voice-event-2", "77777777-7777-4777-8777-777777777777", strings.Repeat("2", 64), strings.Repeat("c", 64), "tick-2", "decision-2", first, updated.ResourceVersion)
	competingReq := secondReq
	competingReq.TickID = "different-tick"
	competingID := voiceRefundOperationID(competingReq, competingReq.VoiceRefundObservation)
	competingRule, err := voicerefundpolicy.Append(first, voicerefundpolicy.Entry{AssertedCallerSHA256: competingReq.VoiceRefundObservation.AssertedCallerSHA256,
		OrderSHA256: competingReq.VoiceRefundObservation.OrderSHA256}, competingID)
	if err != nil {
		t.Fatal(err)
	}
	competingReceipt := voiceRefundReceipt{Version: 1, Phase: "prepared", PolicyName: secondReq.PolicyName, PolicyUID: secondReq.PolicyUID,
		PolicyGeneration: secondReq.PolicyGeneration, DeploymentUID: string(depUID), TargetName: secondReq.Pod, TargetPodUID: secondReq.TargetUID,
		EventName: secondReq.VoiceRefundObservation.EventName, EventUID: secondReq.VoiceRefundObservation.EventUID,
		CreatorIdentity: creator, TickID: competingReq.TickID, SelectionDecisionID: competingReq.OperationID, ConfigMapUID: string(cmUID),
		Prior: first, Desired: competingRule, OperationID: competingID}
	competingJSON, _ := json.Marshal(competingReceipt)
	competingJournal := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceRefundJournalName(string(depUID), 2), Namespace: "operator", Labels: map[string]string{voiceRefundJournalLabel: "v1"}},
		Data: map[string]string{"receipt.json": string(competingJSON)}}
	race := &voiceRefundCreateRaceClient{Client: c, competing: competingJournal}
	raceCtx := ec
	raceCtx.Client = race
	if raced, err := (voiceRefundHandler{}).Enact(ctx, raceCtx, secondReq); err == nil || raced.Emitted || !race.inserted {
		t.Fatalf("create race claimed competing tick: %+v %v inserted=%t", raced, err, race.inserted)
	}
	if err := c.Delete(ctx, competingJournal); err != nil {
		t.Fatal(err)
	}
	result, err = (voiceRefundHandler{}).Enact(ctx, ec, secondReq)
	if err != nil || !result.Emitted {
		t.Fatalf("second append not confirmed: %+v %v", result, err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName}, updated); err != nil {
		t.Fatal(err)
	}
	second, err := voicerefundpolicy.Parse(updated.Data[voicerefundpolicy.RuleKey])
	if err != nil || second.Revision != 2 || len(second.Entries) != 2 || second.Entries[0] != first.Entries[0] {
		t.Fatalf("prior caller was erased: %+v %v", second, err)
	}
	if _, _, err := voiceRefundJournalGet(ctx, ec, voiceRefundJournalName(string(depUID), 2)); err != nil {
		t.Fatalf("second terminal receipt invalid: %v", err)
	}
	// A manager restart after the CAS but before the terminal journal write
	// completes the same operation from live readback without appending again.
	completedJournal, pendingReceipt, err := voiceRefundJournalGet(ctx, ec, voiceRefundJournalName(string(depUID), 2))
	if err != nil {
		t.Fatal(err)
	}
	pendingReceipt.Phase = "prepared"
	pendingBytes, _ := json.Marshal(pendingReceipt)
	completedJournal.Data["receipt.json"] = string(pendingBytes)
	if err := c.Update(ctx, completedJournal); err != nil {
		t.Fatal(err)
	}
	recovered, err := recoverVoiceRefundOperations(ctx, ec, func(a model.Action) bool { return a == model.ActionVoiceRefundPairDeny })
	if err != nil || len(recovered) != 2 || recovered[1].Outcome != "confirmed" {
		t.Fatalf("restart recovery failed: %+v %v", recovered, err)
	}
	_, recoveredReceipt, err := voiceRefundJournalGet(ctx, ec, voiceRefundJournalName(string(depUID), 2))
	if err != nil || recoveredReceipt.Phase != "terminal-full" {
		t.Fatalf("recovered journal not terminal: %+v %v", recoveredReceipt, err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName}, updated); err != nil {
		t.Fatal(err)
	}
	afterRecovery, err := voicerefundpolicy.Parse(updated.Data[voicerefundpolicy.RuleKey])
	if err != nil || afterRecovery.SHA256() != second.SHA256() {
		t.Fatalf("recovery replayed mutation: %+v %v", afterRecovery, err)
	}
	thirdReq := makeReq("voice-event-3", "88888888-8888-4888-8888-888888888888", strings.Repeat("3", 64), strings.Repeat("d", 64), "tick-3", "decision-3", second, updated.ResourceVersion)
	thirdEvent := &amtdv1beta1.SecurityEvent{}
	if err := c.Get(ctx, client.ObjectKey{Name: "voice-event-3"}, thirdEvent); err != nil {
		t.Fatal(err)
	}
	thirdEvent.Annotations["phorvex.ai/creator-identity"] = "system:serviceaccount:voice:untrusted"
	if err := c.Update(ctx, thirdEvent); err != nil {
		t.Fatal(err)
	}
	if result, err := (voiceRefundHandler{}).Enact(ctx, ec, thirdReq); err == nil || result.Emitted {
		t.Fatalf("wrong event creator admitted: %+v %v", result, err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName}, updated); err != nil {
		t.Fatal(err)
	}
	unchanged, err := voicerefundpolicy.Parse(updated.Data[voicerefundpolicy.RuleKey])
	if err != nil || unchanged.SHA256() != second.SHA256() {
		t.Fatalf("wrong-creator event mutated rule: %+v %v", unchanged, err)
	}
	if _, _, err := voiceRefundJournalGet(ctx, ec, voiceRefundJournalName(string(depUID), 3)); !apierrors.IsNotFound(err) {
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
	if ok, why := voiceRefundCapability(ctx, c, "operator", Target{Namespace: "voice", Pod: "bot-1", UID: string(podUID), PolicyName: "voice-policy", PolicyUID: string(policyUID)}, transport); ok || why == "" {
		t.Fatalf("stale subPath mount accepted: %t %s", ok, why)
	}
	podLive.Spec.Containers[0].VolumeMounts[0].SubPath = ""
	podLive.Spec.Containers[0].Env = nil
	if err := c.Update(ctx, podLive); err != nil {
		t.Fatal(err)
	}
	if ok, why := voiceRefundCapability(ctx, c, "operator", Target{Namespace: "voice", Pod: "bot-1", UID: string(podUID), PolicyName: "voice-policy", PolicyUID: string(policyUID)}, transport); ok || why == "" {
		t.Fatalf("legacy optional-policy Pod accepted without required mode: %t %s", ok, why)
	}
	// A conflicting API write immediately after our desired CAS must never be
	// mistaken for complete readback or turn the prepared receipt terminal.
	podLive.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "VOICE_REFUND_POLICY_REQUIRED", Value: "true"}}
	if err := c.Update(ctx, podLive); err != nil {
		t.Fatal(err)
	}
	currentCM := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName}, currentCM); err != nil {
		t.Fatal(err)
	}
	currentCM.Data[voicerefundpolicy.RuleKey] = string(first.Bytes())
	if err := c.Update(ctx, currentCM); err != nil {
		t.Fatal(err)
	}
	journal, secondReceipt, err := voiceRefundJournalGet(ctx, ec, voiceRefundJournalName(string(depUID), 2))
	if err != nil || secondReceipt.Phase != "terminal-full" {
		t.Fatalf("second terminal journal unavailable: %v %+v", err, secondReceipt)
	}
	secondReceipt.Phase = "prepared"
	preparedJSON, err := json.Marshal(secondReceipt)
	if err != nil {
		t.Fatal(err)
	}
	journal.Data["receipt.json"] = string(preparedJSON)
	if err := c.Update(ctx, journal); err != nil {
		t.Fatal(err)
	}
	superseding, err := voicerefundpolicy.Append(first, voicerefundpolicy.Entry{AssertedCallerSHA256: strings.Repeat("4", 64), OrderSHA256: strings.Repeat("e", 64)}, strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	tracer := &voiceRefundSupersedingClient{Client: c, superseding: superseding}
	resumeCtx := EnactCtx{Reader: c, Client: tracer, JournalNamespace: "operator", VoiceRefundTransport: transport}
	result, err = voiceRefundResume(ctx, resumeCtx, journal, secondReceipt)
	if err == nil || result.Emitted || result.MutationKind != "partial" || !tracer.updated {
		t.Fatalf("post-CAS superseding rule falsely confirmed: %+v %v updated=%t", result, err, tracer.updated)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName}, currentCM); err != nil {
		t.Fatal(err)
	}
	actual, err := voicerefundpolicy.Parse(currentCM.Data[voicerefundpolicy.RuleKey])
	if err != nil || actual.SHA256() != superseding.SHA256() {
		t.Fatalf("superseding rule was replayed or overwritten: %+v %v", actual, err)
	}
	_, retained, err := voiceRefundJournalGet(ctx, ec, voiceRefundJournalName(string(depUID), 2))
	if err != nil || retained.Phase != "prepared" {
		t.Fatalf("superseded operation was marked terminal: %+v %v", retained, err)
	}
}
