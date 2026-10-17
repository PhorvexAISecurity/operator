package console

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/voicerefundpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The real console event builder is admitted by a fake Kubernetes API; the
// production snapshot, recon and decision paths then run unchanged. This is
// source wiring evidence, not a simulated Voice outcome or live defense claim.
func TestVoiceAgencyConsoleProducerToNormalDecision(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	const depUID = "11111111-1111-4111-8111-111111111111"
	const rsUID = "22222222-2222-4222-8222-222222222222"
	const policyUID = "33333333-3333-4333-8333-333333333333"
	const cmUID = "44444444-4444-4444-8444-444444444444"
	const podUID = "55555555-5555-4555-8555-555555555555"
	const eventUID = "66666666-6666-4666-8666-666666666666"
	const creator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
	const run = "a1b2c3d4e5f60708"
	const source = "585fd2dce545cfdd163635c2e2929b193e2395329a5073b9ae14a8f033c08a9c"
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "voice-bot", UID: types.UID(depUID)},
		Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice-bot"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "voice-rs", UID: types.UID(rsUID),
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "voice-bot-1", UID: types.UID(podUID),
		CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)), Labels: map[string]string{"app": "voice-bot"},
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))},
		Annotations: map[string]string{"phorvex.ai/voice-refund-policy-configmap": voicerefundpolicy.ConfigMapName,
			"phorvex.ai/voice-refund-source-sha256": source, "phorvex.ai/voice-refund-event-creator": creator}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Env: []corev1.EnvVar{{Name: "VOICE_REFUND_POLICY_REQUIRED", Value: "true"}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	rule := voicerefundpolicy.Rule{Version: 1, DeploymentUID: depUID, PolicyUID: policyUID, SourceSHA256: source, Entries: []voicerefundpolicy.Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: voicerefundpolicy.ConfigMapName,
		UID: types.UID(cmUID), ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}},
		Data: map[string]string{voicerefundpolicy.RuleKey: string(rule.Bytes())}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: voiceAgencyPolicyName, UID: types.UID(policyUID), Generation: 1},
		Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice-bot"}},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionVoiceRefundPairDeny, v1alpha1.ActionRotate, v1alpha1.ActionQuarantine}}}}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if e := add(scheme); e != nil {
			t.Fatal(e)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, pod, cm, policy, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "voice"}}).Build()
	priorTrust := ingest.EventTrust()
	ingest.ConfigureEventTrust(ingest.NewTrustedDetectors([]string{"phorvex-system/phorvex-phorvex-console"}))
	t.Cleanup(func() { ingest.ConfigureEventTrust(priorTrust) })
	server := NewServer(Config{StateDir: t.TempDir(), Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || len(args) != 5 || args[0] != "create" || args[1] != "-f" || args[3] != "-o" || args[4] != "json" {
			t.Fatalf("unexpected event transport %s %q", bin, args)
		}
		raw, e := os.ReadFile(args[2])
		if e != nil {
			return "", e
		}
		if strings.Contains(string(raw), voiceAgencyPhone(run, "A")) {
			t.Fatal("raw asserted caller entered event")
		}
		var event amtdv1beta1.SecurityEvent
		if e = json.Unmarshal(raw, &event); e != nil {
			return "", e
		}
		event.UID = types.UID(eventUID)
		event.CreationTimestamp = metav1.NewTime(now)
		event.Annotations["phorvex.ai/creator-identity"] = creator
		if e = c.Create(ctx, &event); e != nil {
			return "", e
		}
		reply, e := json.Marshal(event)
		return string(reply), e
	}})
	before := voiceAgencySnapshot{DeploymentUID: depUID, PolicyUID: policyUID, PolicyGeneration: 1, EventCreator: creator, SourceSHA256: source}
	stimulus, e := server.createVoiceAgencyEvent(ctx, t.TempDir(), "voice-agency-"+run, *pod, before, run, now.Add(-time.Second))
	if e != nil || stimulus.EventUID != eventUID {
		t.Fatalf("real console event producer failed: %+v %v", stimulus, e)
	}
	snap, e := ingest.CollectSnapshot(ctx, c, now.Add(time.Second), nil, c)
	if e != nil {
		t.Fatal(e)
	}
	observed := snap.PodByKey["voice/"+pod.Name]
	if observed == nil || observed.VoiceRefundObservation == nil || observed.VoiceRefundObservation.EventUID != eventUID ||
		observed.VoiceRefundObservation.AssertedCallerSHA256 != voiceAgencyCallerSHA(run) ||
		observed.VoiceRefundObservation.OrderSHA256 != voiceAgencyStringDigest("9142") {
		t.Fatalf("real producer did not bind exact observed pair: %+v", observed)
	}
	view := &model.WorkloadView{Pod: *observed, Physics: model.NeutralPhysics(), Phase: model.PhaseWarm,
		Events: snap.EventByPod["voice/"+pod.Name]}
	pol := model.Policy{Tenant: "voice", Namespace: "voice", PolicyName: voiceAgencyPolicyName, PolicyUID: policyUID, PolicyGeneration: 1,
		Mode: "active", TraceEnabled: true, TickID: "voice-agency-tick", MaxMovesPerTick: 1, NormSparsity: .4, FlowDisruption: .6,
		WeightSecrets: .8, Lambda: .4, CostCeiling: model.DefaultCostCeiling, MinAvailableReplicas: 1, ProactiveFloor: 15 * time.Minute,
		ExposurePressureScale: 15 * time.Minute, AntiOverRotationWindow: 90 * time.Second, TickInterval: 10 * time.Second,
		EventAgeHorizon: time.Hour, EventDriven: true, ReactiveOnly: true, AssetWeights: model.AssetLabelWeights{Default: .4},
		EnabledActions: map[model.Action]bool{model.ActionVoiceRefundPairDeny: true, model.ActionRotate: true, model.ActionQuarantine: true}}
	clock := exposure.NewClock()
	clock.Observe(exposure.Observation{Owner: pol.Owner(), Namespace: pod.Namespace, Pod: pod.Name,
		StartedAt: observed.StartedAt, Fingerprints: model.ExposureFingerprints(*observed)}, now.Add(time.Second))
	view.ExposureByVariable = clock.Since(pol.Owner(), pod.Namespace, pod.Name, now.Add(time.Second))
	engine := decision.NewCoverageEngine()
	engine.Now = func() time.Time { return now.Add(time.Second) }
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("normal recon absent")
	}
	engine.Recon = profile
	set, _ := engine.AssembleSet([]*model.WorkloadView{view}, pol)
	seen := map[model.Action]bool{}
	for _, item := range set.Candidates {
		seen[item.Action] = true
	}
	for _, item := range set.Excluded {
		seen[item.Action] = true
	}
	for _, action := range []model.Action{model.ActionVoiceRefundPairDeny, model.ActionRotate, model.ActionQuarantine} {
		if !seen[action] {
			t.Fatalf("normal alternative %s absent", action)
		}
	}
	selected := engine.Decide([]*model.WorkloadView{view}, pol)
	if len(selected) != 1 || !selected[0].Selected || selected[0].Action != model.ActionVoiceRefundPairDeny || selected[0].Trace == nil || selected[0].Trace.Validate() != nil {
		t.Fatalf("normal decision for actual producer absent: %+v", selected)
	}
	row := audit.ToRecord(selected[0])
	joined, ok := voiceMemorySelectedDecision(row, &attackRecord{Pod: pod.Name, TargetUID: podUID, started: now.Add(-time.Minute)},
		voiceMemorySnapshot{PolicyUID: policyUID}, eventUID)
	if !ok || joined.DecisionID != selected[0].Trace.DecisionID || joined.TickID != selected[0].Trace.TickID {
		t.Fatalf("selected audit row lost event/policy/Pod join: %+v", row)
	}
	// A stale event and a foreign Pod UID must never produce the same observed candidate.
	event := &amtdv1beta1.SecurityEvent{}
	if e = c.Get(ctx, client.ObjectKey{Name: stimulus.EventName}, event); e != nil {
		t.Fatal(e)
	}
	event.CreationTimestamp = metav1.NewTime(now.Add(-61 * time.Second))
	if e = c.Update(ctx, event); e != nil {
		t.Fatal(e)
	}
	stale, e := ingest.CollectSnapshot(ctx, c, now.Add(time.Second), nil, c)
	if e != nil {
		t.Fatal(e)
	}
	if got := stale.PodByKey["voice/"+pod.Name]; got != nil && got.VoiceRefundObservation != nil {
		t.Fatal("stale event bound to Voice refund action")
	}
	event.CreationTimestamp = metav1.NewTime(now)
	event.Annotations[model.ConsoleTargetPodUIDAnnotation] = "foreign"
	if e = c.Update(ctx, event); e != nil {
		t.Fatal(e)
	}
	foreign, e := ingest.CollectSnapshot(ctx, c, now.Add(time.Second), nil, c)
	if e != nil {
		t.Fatal(e)
	}
	if got := foreign.PodByKey["voice/"+pod.Name]; got != nil && got.VoiceRefundObservation != nil {
		t.Fatal("foreign target UID bound to Voice refund action")
	}
}
