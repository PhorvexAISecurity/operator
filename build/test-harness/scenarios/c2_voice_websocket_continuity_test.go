package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func completeVoiceWSReceipt(uid string, frames int) voiceWSReceipt {
	sequences := make([]int, frames)
	for i := range sequences {
		sequences[i] = i + 1
	}
	return voiceWSReceipt{Version: 1, ServiceURL: "http://c2-voice-ws-target:8080", SessionID: "voice-1", StartedAtUTC: "2026-09-21T00:00:00Z", EndedAtUTC: "2026-09-21T00:00:01Z", TwiMLStatus: 200, TwiMLSHA256: strings.Repeat("a", 64), WebSocketURL: "ws://c2-voice-ws-target:8080/ws", TargetPodUID: uid, Outcome: "completed", ExpectedFrames: frames, ReceivedSequences: sequences, EndMarker: true, CloseCode: 1000}
}

func TestVoiceWSReceiptRequiresExactCompletion(t *testing.T) {
	valid := completeVoiceWSReceipt("old-uid", 3)
	if !voiceWSReceiptCompleted(valid) {
		t.Fatal("exact completed receipt rejected")
	}
	for name, mutate := range map[string]func(*voiceWSReceipt){
		"missing-end":   func(r *voiceWSReceipt) { r.EndMarker = false },
		"wrong-close":   func(r *voiceWSReceipt) { r.CloseCode = 1006 },
		"gap":           func(r *voiceWSReceipt) { r.ReceivedSequences = []int{1, 3}; r.Gaps = 1 },
		"duplicate":     func(r *voiceWSReceipt) { r.ReceivedSequences = []int{1, 2, 2}; r.DuplicateSequences = 1 },
		"wrong-order":   func(r *voiceWSReceipt) { r.ReceivedSequences = []int{2, 1, 3} },
		"failure":       func(r *voiceWSReceipt) { r.Failure = "late-error" },
		"false-summary": func(r *voiceWSReceipt) { r.ReceivedSequences = []int{1, 1, 3}; r.DuplicateSequences = 0; r.Gaps = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.ReceivedSequences = append([]int(nil), valid.ReceivedSequences...)
			mutate(&candidate)
			if voiceWSReceiptCompleted(candidate) {
				t.Fatal("malformed completion accepted")
			}
		})
	}
}

func TestValidateVoiceWSReceiptSeparatesEarlyClose(t *testing.T) {
	base, id := "http://c2-voice-ws-target:8080", "voice-1"
	valid := completeVoiceWSReceipt("old-uid", 3)
	if err := validateVoiceWSReceipt(valid, base, id, 3); err != nil {
		t.Fatalf("valid completion: %v", err)
	}
	early := valid
	early.Outcome = "early-close"
	early.EndMarker = false
	early.CloseCode = 1006
	early.ReceivedSequences = []int{1}
	early.Gaps = 2
	early.Failure = "connection-closed-before-end"
	if err := validateVoiceWSReceipt(early, base, id, 3); err != nil {
		t.Fatalf("valid early close: %v", err)
	}
	for name, mutate := range map[string]func(*voiceWSReceipt){
		"false-end":  func(r *voiceWSReceipt) { r.EndMarker = true },
		"all-frames": func(r *voiceWSReceipt) { r.ReceivedSequences = []int{1, 2, 3} },
		"no-failure": func(r *voiceWSReceipt) { r.Failure = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := early
			candidate.ReceivedSequences = append([]int(nil), early.ReceivedSequences...)
			mutate(&candidate)
			if err := validateVoiceWSReceipt(candidate, base, id, 3); err == nil {
				t.Fatal("contradictory early close accepted")
			}
		})
	}
}

func TestVoiceWSOracleNoActionAndTimerReplacementAreDiscriminating(t *testing.T) {
	noAction := &c2VoiceWebSocketContinuity{originalUID: types.UID("old-uid"), receipt: completeVoiceWSReceipt("old-uid", 3), sharedProbe: completeVoiceWSReceipt("peer-1", 2), availability: voiceWSAvailability{Samples: 10, MinimumReady: 3, OriginalSeen: true, ObservedReadyUIDs: []string{"old-uid", "peer-1", "peer-2"}}}
	got, err := noAction.SuccessOracle(context.Background(), nil)
	if err != nil || !got.Achieved {
		t.Fatalf("no action got=%+v err=%v", got, err)
	}
	early := completeVoiceWSReceipt("old-uid", 3)
	early.Outcome = "early-close"
	early.EndMarker = false
	early.CloseCode = 1006
	early.ReceivedSequences = []int{1}
	early.Gaps = 2
	early.Failure = "connection-closed-before-end"
	rotate := &c2VoiceWebSocketContinuity{originalUID: types.UID("old-uid"), replacementUID: types.UID("new-uid"), originalAPIAbsent: true, originalAbsenceObservedAt: "2026-09-21T00:00:01Z", replacementObservedAt: "2026-09-21T00:00:02Z", receipt: early, sharedProbe: completeVoiceWSReceipt("peer-1", 2), recovery: completeVoiceWSReceipt("new-uid", 2), availability: voiceWSAvailability{Samples: 40, MinimumReady: 2, OriginalSeen: true, OriginalAbsentSeen: true, ObservedReadyUIDs: []string{"old-uid", "new-uid", "peer-1", "peer-2"}}}
	got, err = rotate.SuccessOracle(context.Background(), nil)
	if err != nil || got.Achieved {
		t.Fatalf("rotation got=%+v err=%v", got, err)
	}
	rotate.availability.MinimumReady = 1
	if _, err = rotate.SuccessOracle(context.Background(), nil); err == nil {
		t.Fatal("availability-floor breach accepted")
	}
}

func TestVoiceWSWorkloadRotatesOnlyTargetAndPinsSources(t *testing.T) {
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned", BenignSessionNodeSelector: map[string]string{"kubernetes.io/hostname": "reviewed-node"}}, ScenarioName: voiceWSScenario, DefenderName: "d-r6blindtimer", Trial: 2}
	target := voiceWSDeployment(env, voiceWSTargetDeployment, "target", 1, true)
	peers := voiceWSDeployment(env, voiceWSPeerDeployment, "peer", 2, false)
	if target.Spec.Template.Labels[defenders.RotationTargetLabel] != "true" {
		t.Fatal("target is not rotation selected")
	}
	if _, present := peers.Spec.Template.Labels[defenders.RotationTargetLabel]; present {
		t.Fatal("peer availability replicas are rotation selected")
	}
	if *target.Spec.Replicas != 1 || *peers.Spec.Replicas != 2 {
		t.Fatal("fixture replica split changed")
	}
	if got := target.Spec.Template.Annotations["fixture.phorvex.ai/source-sha256"]; got != voiceWSServerSourceSHA256() || len(got) != 64 {
		t.Fatalf("server source pin=%q", got)
	}
	if got := target.Spec.Template.Annotations["fixture.phorvex.ai/runtime-bot-sha256"]; got != voiceWSRuntimeBotSHA256 {
		t.Fatalf("runtime source profile=%q", got)
	}
	if target.Spec.Template.Spec.Containers[0].Image != voiceWSRuntimeImage || peers.Spec.Template.Spec.Containers[0].Image != voiceWSRuntimeImage {
		t.Fatal("fixture image is not exact digest")
	}
	producer := voiceWSProducerPod(env)
	wantEnv := map[string]string{"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "http_proxy": "", "https_proxy": "", "all_proxy": "", "NO_PROXY": "*", "no_proxy": "*"}
	for _, item := range producer.Spec.Containers[0].Env {
		want, ok := wantEnv[item.Name]
		if !ok {
			continue
		}
		if item.Value != want {
			t.Fatalf("producer environment %s=%q, want %q", item.Name, item.Value, want)
		}
		delete(wantEnv, item.Name)
	}
	if len(wantEnv) != 0 {
		t.Fatalf("producer proxy environment not explicitly neutralized: %v", wantEnv)
	}
}

func TestVoiceWSFixtureHasNoProviderOrSemanticOracle(t *testing.T) {
	for _, forbidden := range []string{"OPENAI_API_KEY", "DEEPGRAM_API_KEY", "ELEVENLABS_API_KEY", "MONGODB_URI", "CHROMA", "run_bot", "transcript"} {
		if strings.Contains(voiceWSServerSource, forbidden) || strings.Contains(voiceWSClientSource, forbidden) {
			t.Fatalf("fixture source contains external/semantic path %q", forbidden)
		}
	}
	for _, required := range []string{"from fastapi import", "@app.websocket", "connected", "sequenceNumber", "end-"} {
		if !strings.Contains(voiceWSServerSource, required) {
			t.Fatalf("server source missing %q", required)
		}
	}
	for _, required := range []string{"import websockets", "websockets.connect", "urllib.request.ProxyHandler({})", "parsed.hostname != base_parsed.hostname", "object_pairs_hook=strict_object", "receivedSequences"} {
		if !strings.Contains(voiceWSClientSource, required) {
			t.Fatalf("client source missing %q", required)
		}
	}
}

func readyVoiceWSPod(name string, uid types.UID, role, replicaSetName string, replicaSetUID types.UID) *corev1.Pod {
	controller := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "owned", UID: uid, Labels: map[string]string{"app": voiceWSApp, "role": role}, Annotations: map[string]string{"fixture.phorvex.ai/source-sha256": voiceWSServerSourceSHA256(), "fixture.phorvex.ai/runtime-bot-sha256": voiceWSRuntimeBotSHA256}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: replicaSetName, UID: replicaSetUID, Controller: &controller}}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: voiceWSRuntimeImage, Command: []string{"python3", "-B", "-c", voiceWSServerSource}}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "fixture", Ready: true, Image: voiceWSRuntimeImage, ImageID: "docker-pullable://voice@" + voiceWSRuntimeDigest}}},
	}
}

func voiceWSTestControllerObjects() (*appsv1.Deployment, *appsv1.Deployment, *appsv1.ReplicaSet, *appsv1.ReplicaSet) {
	controller := true
	targetDeployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: voiceWSTargetDeployment, Namespace: "owned", UID: types.UID("target-deployment-uid")}}
	peerDeployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: voiceWSPeerDeployment, Namespace: "owned", UID: types.UID("peer-deployment-uid")}}
	targetRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "target-rs", Namespace: "owned", UID: types.UID("target-rs-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: targetDeployment.Name, UID: targetDeployment.UID, Controller: &controller}}}}
	peerRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "peer-rs", Namespace: "owned", UID: types.UID("peer-rs-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: peerDeployment.Name, UID: peerDeployment.UID, Controller: &controller}}}}
	return targetDeployment, peerDeployment, targetRS, peerRS
}

func TestVoiceWSReadyEndpointUIDsRequireControllerOwnedExactObjects(t *testing.T) {
	controller, ready := true, true
	serviceUID := types.UID("service-uid")
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: voiceWSSharedService, Namespace: "owned", UID: serviceUID}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": voiceWSApp}}}
	targetDeployment, peerDeployment, targetRS, peerRS := voiceWSTestControllerObjects()
	peer1 := readyVoiceWSPod("peer-1", types.UID("peer-uid-1"), "peer", peerRS.Name, peerRS.UID)
	peer2 := readyVoiceWSPod("peer-2", types.UID("peer-uid-2"), "peer", peerRS.Name, peerRS.UID)
	foreign := readyVoiceWSPod("foreign", types.UID("foreign-uid"), "peer", peerRS.Name, peerRS.UID)
	foreign.Spec.Containers[0].Image = "example.invalid/foreign@sha256:deadbeef"
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "owned-slice", Namespace: "owned", Labels: map[string]string{discoveryv1.LabelServiceName: voiceWSSharedService}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: voiceWSSharedService, UID: serviceUID, Controller: &controller}}}, Endpoints: []discoveryv1.Endpoint{
		{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "owned", Name: peer1.Name, UID: peer1.UID}},
		{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "owned", Name: peer2.Name, UID: peer2.UID}},
		{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "owned", Name: foreign.Name, UID: foreign.UID}},
	}}
	foreignSlice := slice.DeepCopy()
	foreignSlice.Name = "foreign-slice"
	foreignSlice.OwnerReferences[0].UID = types.UID("foreign-service")
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: k8sfake.NewSimpleClientset(service, targetDeployment, peerDeployment, targetRS, peerRS, peer1, peer2, foreign, slice, foreignSlice)}
	uids, err := voiceWSReadyEndpointUIDs(context.Background(), env, voiceWSSharedService, serviceUID, targetDeployment.UID, peerDeployment.UID)
	if err != nil {
		t.Fatal(err)
	}
	if len(uids) != 2 || uids[0] != peer1.UID || uids[1] != peer2.UID {
		t.Fatalf("ready UIDs=%v", uids)
	}
	if _, err = voiceWSReadyEndpointUIDs(context.Background(), env, voiceWSSharedService, types.UID("replacement-service"), targetDeployment.UID, peerDeployment.UID); err == nil {
		t.Fatal("replacement Service UID accepted")
	}
	changed := service.DeepCopy()
	changed.Spec.Selector = map[string]string{"app": voiceWSApp, "role": "foreign"}
	if _, err = env.Kube.CoreV1().Services("owned").Update(context.Background(), changed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = voiceWSReadyEndpointUIDs(context.Background(), env, voiceWSSharedService, serviceUID, targetDeployment.UID, peerDeployment.UID); err == nil {
		t.Fatal("changed Service selector accepted")
	}
}

func TestValidateVoiceWSControllerReadsDeploymentAndReplicaSet(t *testing.T) {
	targetDeployment, peerDeployment, targetRS, peerRS := voiceWSTestControllerObjects()
	pod := readyVoiceWSPod("target-0", types.UID("pod-uid"), "target", targetRS.Name, targetRS.UID)
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: k8sfake.NewSimpleClientset(targetDeployment, peerDeployment, targetRS, peerRS, pod)}
	if err := validateVoiceWSController(context.Background(), env, pod, voiceWSTargetDeployment, targetDeployment.UID); err != nil {
		t.Fatalf("valid controller chain: %v", err)
	}
	if err := validateVoiceWSController(context.Background(), env, pod, voiceWSTargetDeployment, types.UID("recreated-deployment")); err == nil {
		t.Fatal("recreated Deployment UID accepted")
	}
	forged := pod.DeepCopy()
	forged.OwnerReferences[0].UID = types.UID("forged-rs")
	if err := validateVoiceWSController(context.Background(), env, forged, voiceWSTargetDeployment, targetDeployment.UID); err == nil {
		t.Fatal("forged ReplicaSet UID accepted")
	}
}

func TestVoiceWSProducerUsesExplicitThirtySecondForegroundExec(t *testing.T) {
	serviceUID, producerUID := types.UID("service-uid"), types.UID("producer-uid")
	selector := map[string]string{"app": voiceWSApp, "role": "target"}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: voiceWSTargetService, Namespace: "owned", UID: serviceUID}, Spec: corev1.ServiceSpec{Selector: selector}}
	producer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: voiceWSProducer, Namespace: "owned", UID: producerUID}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: k8sfake.NewSimpleClientset(service, producer), Rest: &rest.Config{Host: "https://example.invalid"}, Log: &ctLogger{}}
	receipt := completeVoiceWSReceipt("target-uid", voiceWSExpectedFrames)
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	defaultCalls, timedCalls := 0, 0
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		defaultCalls++
		return core.ExecResult{ExitCode: -1, Err: errors.New("default exec used")}
	})
	core.SetTimedExecer(func(ctx context.Context, _ *rest.Config, _ kubernetes.Interface, _, pod, container string, timeout time.Duration, command []string) core.ExecResult {
		timedCalls++
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || timeout != voiceWSExecTimeout || remaining <= 29*time.Second || remaining > voiceWSExecTimeout || pod != voiceWSProducer || container != "producer" {
			return core.ExecResult{ExitCode: -1, Err: fmt.Errorf("exec contract timeout=%s remaining=%s pod=%s container=%s", timeout, remaining, pod, container)}
		}
		if len(command) != 8 || command[0] != "python3" || command[5] != "voice-1" || command[6] != "20" || command[7] != "0.900" {
			return core.ExecResult{ExitCode: -1, Err: fmt.Errorf("producer argv=%v", command)}
		}
		timer := time.NewTimer(20*time.Second + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return core.ExecResult{ExitCode: -1, Err: ctx.Err()}
		case <-timer.C:
		}
		return core.ExecResult{Stdout: string(raw)}
	})
	t.Cleanup(func() { core.SetExecer(nil); core.SetTimedExecer(nil) })
	got, err := performVoiceWS(t.Context(), env, voiceWSTargetService, serviceUID, selector, "voice-1", voiceWSExpectedFrames, voiceWSFrameInterval, producerUID)
	if err != nil || !voiceWSReceiptCompleted(got) || defaultCalls != 0 || timedCalls != 1 {
		t.Fatalf("receipt=%+v default/timed=%d/%d err=%v", got, defaultCalls, timedCalls, err)
	}
	core.SetTimedExecer(func(ctx context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, timeout time.Duration, _ []string) core.ExecResult {
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || timeout <= time.Second || timeout > 2*time.Second || remaining <= time.Second || remaining > 2*time.Second {
			return core.ExecResult{ExitCode: -1, Err: fmt.Errorf("short parent bound not propagated: timeout=%s remaining=%s", timeout, remaining)}
		}
		return core.ExecResult{Stdout: `{"partial":true}`, ExitCode: -1, Err: context.DeadlineExceeded}
	})
	shortCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := performVoiceWS(shortCtx, env, voiceWSTargetService, serviceUID, selector, "voice-1", voiceWSExpectedFrames, voiceWSFrameInterval, producerUID); err == nil || !strings.Contains(err.Error(), "producer failed") || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("earlier parent deadline was not a producer failure: %v", err)
	}
}

func TestWaitVoiceWSTargetOutcomeRequiresOriginalAPIAbsence(t *testing.T) {
	targetDeployment, peerDeployment, targetRS, peerRS := voiceWSTestControllerObjects()
	replacement := readyVoiceWSPod("target-new", types.UID("new-uid"), "target", targetRS.Name, targetRS.UID)
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: k8sfake.NewSimpleClientset(targetDeployment, peerDeployment, targetRS, peerRS, replacement)}
	pod, replaced, timeline, err := waitVoiceWSTargetOutcome(context.Background(), env, "target-old", types.UID("old-uid"), targetDeployment.UID, time.Second)
	if err != nil || !replaced || pod.UID != replacement.UID || timeline.AbsenceObservedAt == "" || timeline.ReplacementObservedAt == "" {
		t.Fatalf("pod=%v replaced=%v timeline=%+v err=%v", pod, replaced, timeline, err)
	}
}
