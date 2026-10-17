package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/voicememorypolicy"
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

type voiceChainRoundTrip func(*http.Request) (*http.Response, error)

func (f voiceChainRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// The fake API supplies Kubernetes admission metadata and resource versions; every
// producer, snapshot, decision, native dispatch, and readback step is production code.
// This proves wiring, not a live Voice outcome.
func TestVoiceMemoryConsoleEventToNativeRuleReadback(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	const depUID = "11111111-1111-4111-8111-111111111111"
	const rsUID = "22222222-2222-4222-8222-222222222222"
	const policyUID = "33333333-3333-4333-8333-333333333333"
	const cmUID = "44444444-4444-4444-8444-444444444444"
	const podUID = "55555555-5555-4555-8555-555555555555"
	const eventUID = "66666666-6666-4666-8666-666666666666"
	const creator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
	const caller = "+15551234567"
	optional := true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "voice-bot", UID: types.UID(depUID)},
		Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice-bot"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "voice-bot-rs", UID: types.UID(rsUID),
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "voice-bot-1", UID: types.UID(podUID),
		CreationTimestamp: metav1.NewTime(now.Add(-2 * time.Hour)), Labels: map[string]string{"app": "voice-bot"},
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))},
		Annotations: map[string]string{"phorvex.ai/voice-memory-policy-configmap": voicememorypolicy.ConfigMapName,
			"phorvex.ai/voice-memory-source-sha256": voiceMemorySourceSHA256, "phorvex.ai/voice-memory-event-creator": creator}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Env: []corev1.EnvVar{{Name: "VOICE_MEMORY_POLICY_REQUIRED", Value: "true"}}, VolumeMounts: []corev1.VolumeMount{
			{Name: "policy", MountPath: "/etc/phorvex/voice-memory-policy", ReadOnly: true},
			{Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true},
			{Name: "state", MountPath: "/var/lib/phorvex-voice-memory"}}}}, Volumes: []corev1.Volume{
			{Name: "policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: voicememorypolicy.ConfigMapName}, Optional: &optional}}},
			{Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "voice-memory-state-token"}}},
			{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	rule := voicememorypolicy.Rule{Version: 1, DeploymentUID: depUID, PolicyUID: policyUID, SourceSHA256: voiceMemorySourceSHA256, Entries: []voicememorypolicy.Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: voicememorypolicy.ConfigMapName, UID: types.UID(cmUID),
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}},
		Data: map[string]string{voicememorypolicy.RuleKey: string(rule.Bytes())}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: voiceMemoryPolicyName, UID: types.UID(policyUID), Generation: 1},
		Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "voice-bot"}},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionVoiceMemoryNoteRevoke, v1alpha1.ActionRotate, v1alpha1.ActionQuarantine}}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "voice-memory-state-token"}, Data: map[string][]byte{"token": []byte(strings.Repeat("s", 32))}}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, pod, cm, policy, secret,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "voice"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).Build()
	priorTrust := ingest.EventTrust()
	ingest.ConfigureEventTrust(ingest.NewTrustedDetectors([]string{"phorvex-system/phorvex-phorvex-console"}))
	t.Cleanup(func() { ingest.ConfigureEventTrust(priorTrust) })
	server := NewServer(Config{StateDir: t.TempDir(), Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || len(args) != 5 || args[0] != "create" || args[1] != "-f" || args[3] != "-o" || args[4] != "json" {
			t.Fatalf("unexpected event transport %s %q", bin, args)
		}
		data, err := os.ReadFile(args[2])
		if err != nil {
			return "", err
		}
		if strings.Contains(string(data), voiceMemoryAttackNote) {
			t.Fatal("raw note entered event")
		}
		var event amtdv1beta1.SecurityEvent
		if err = json.Unmarshal(data, &event); err != nil {
			return "", err
		}
		if event.Namespace != "" || len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != "voice/voice-bot-1" {
			t.Fatalf("event scope/target invalid: %+v", event)
		}
		event.UID = types.UID(eventUID)
		event.CreationTimestamp = metav1.NewTime(now)
		event.Annotations["phorvex.ai/creator-identity"] = creator
		if err = c.Create(ctx, &event); err != nil {
			return "", err
		}
		reply, err := json.Marshal(event)
		return string(reply), err
	}})
	stimulus, err := server.createVoiceMemoryEvent(t.TempDir(), "observed-context", *pod, voiceMemorySnapshot{
		DeploymentUID: depUID, PolicyUID: policyUID, PolicyGeneration: 1, EventCreator: creator}, caller,
		voiceMemoryDigest(voiceMemoryAttackNote), now.Add(-time.Second))
	if err != nil || stimulus.EventUID != eventUID {
		t.Fatalf("console event rejected: %+v %v", stimulus, err)
	}
	snapshot, err := ingest.CollectSnapshot(ctx, c, now.Add(time.Second), nil, c)
	if err != nil {
		t.Fatal(err)
	}
	observed := snapshot.PodByKey["voice/voice-bot-1"]
	if observed == nil || observed.VoiceMemoryObservation == nil || observed.VoiceMemoryObservation.EventUID != eventUID {
		t.Fatalf("console event did not bind through snapshot: %+v", observed)
	}
	legacyPod := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: pod.Name}, legacyPod); err != nil {
		t.Fatal(err)
	}
	legacyPod.Spec.Containers[0].Env = nil
	if err := c.Update(ctx, legacyPod); err != nil {
		t.Fatal(err)
	}
	legacySnapshot, err := ingest.CollectSnapshot(ctx, c, now.Add(time.Second), nil, c)
	if err != nil {
		t.Fatal(err)
	}
	if legacy := legacySnapshot.PodByKey["voice/voice-bot-1"]; legacy == nil || legacy.VoiceMemoryObservation != nil {
		t.Fatalf("legacy-mode Pod retained Voice memory authority: %+v", legacy)
	}
	legacyPod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "VOICE_MEMORY_POLICY_REQUIRED", Value: "true"}}
	if err := c.Update(ctx, legacyPod); err != nil {
		t.Fatal(err)
	}
	view := &model.WorkloadView{Pod: *observed, Physics: model.NeutralPhysics(), Phase: model.PhaseWarm,
		Events: snapshot.EventByPod["voice/voice-bot-1"], ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour}}
	pol := model.Policy{Tenant: "voice", Namespace: "voice", PolicyName: voiceMemoryPolicyName, PolicyUID: policyUID, PolicyGeneration: 1,
		Mode: "active", TraceEnabled: true, TickID: "voice-chain-tick", MaxMovesPerTick: 1, NormSparsity: .4, FlowDisruption: .6,
		WeightSecrets: .8, Lambda: .4, CostCeiling: model.DefaultCostCeiling, MinAvailableReplicas: 1,
		ProactiveFloor: 15 * time.Minute, ExposurePressureScale: 15 * time.Minute, AntiOverRotationWindow: 90 * time.Second,
		TickInterval: 10 * time.Second, EventAgeHorizon: time.Hour, EventDriven: true, ReactiveOnly: true,
		AssetWeights: model.AssetLabelWeights{Default: .4}, EnabledActions: map[model.Action]bool{
			model.ActionVoiceMemoryNoteRevoke: true, model.ActionRotate: true, model.ActionQuarantine: true}}
	engine := decision.NewCoverageEngine()
	engine.Now = func() time.Time { return now.Add(time.Second) }
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("UCW recon absent")
	}
	engine.Recon = profile
	set, _ := engine.AssembleSet([]*model.WorkloadView{view}, pol)
	seen := map[model.Action]bool{}
	for _, c := range set.Candidates {
		seen[c.Action] = true
	}
	for _, c := range set.Excluded {
		seen[c.Action] = true
	}
	for _, a := range []model.Action{model.ActionVoiceMemoryNoteRevoke, model.ActionRotate, model.ActionQuarantine} {
		if !seen[a] {
			t.Fatalf("normal alternative %s missing", a)
		}
	}
	selected := engine.Decide([]*model.WorkloadView{view}, pol)
	if len(selected) != 1 || !selected[0].Selected || selected[0].Action != model.ActionVoiceMemoryNoteRevoke || selected[0].Trace == nil || selected[0].Trace.DecisionID == "" {
		t.Fatalf("normal selection failed: %+v", selected)
	}
	if trace := selected[0].Trace; trace.Validate() != nil || trace.PolicyNamespace != "voice" || trace.PolicyName != voiceMemoryPolicyName ||
		trace.PolicyUID != policyUID || trace.AssetNamespace != "voice" || trace.AssetName != pod.Name || trace.AssetUID != podUID {
		t.Fatalf("selected decision trace lost exact policy or asset identity: %+v", trace)
	}
	auditRow := audit.ToRecord(selected[0])
	correlated, ok := voiceMemorySelectedDecision(auditRow, &attackRecord{
		Pod: pod.Name, TargetUID: podUID, started: now.Add(-time.Minute),
	}, voiceMemorySnapshot{PolicyUID: policyUID}, eventUID)
	if !ok || !correlated.Selected || correlated.Actuated || correlated.DecisionID != selected[0].Trace.DecisionID {
		t.Fatalf("real decision audit did not join the console event before dispatch: %+v row=%+v", correlated, auditRow)
	}
	readbacks := 0
	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	native.JournalNamespace = "operator"
	native.VoiceMemoryTransport = voiceChainRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != voicememorypolicy.StatePath || req.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			t.Fatalf("unauthenticated or wrong readback: %s", req.URL)
		}
		readbacks++
		current := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicememorypolicy.ConfigMapName}, current); err != nil {
			return nil, err
		}
		r, err := voicememorypolicy.Parse(current.Data[voicememorypolicy.RuleKey])
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(map[string]any{"version": 1, "podUID": podUID, "deploymentUID": depUID, "policyUID": policyUID,
			"sourceSHA256": voiceMemorySourceSHA256, "ruleSHA256": r.SHA256(), "revision": r.Revision,
			"operationId": r.OperationID, "entryCount": len(r.Entries), "ready": true})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{}}, nil
	})
	if err := native.EnsurePolicy(ctx, actuator.TenantTarget{Tenant: "voice", Namespace: "voice", PolicyUID: policyUID}); err != nil {
		t.Fatal(err)
	}
	if ok, reason := native.SupportsAction(ctx, model.ActionVoiceMemoryNoteRevoke, actuator.Target{
		Namespace: "voice", Pod: pod.Name, UID: podUID, PolicyName: voiceMemoryPolicyName, PolicyUID: policyUID,
	}); !ok {
		t.Fatalf("native Voice capability absent before selected dispatch: %s", reason)
	}
	result, err := native.Actuate(ctx, actuator.Request{Tenant: pol.Tenant, Namespace: "voice", Pod: pod.Name, TargetUID: podUID,
		PolicyName: pol.PolicyName, PolicyUID: policyUID, PolicyGeneration: 1, TickID: pol.TickID,
		Action: selected[0].Action, OperationID: selected[0].Trace.DecisionID, VoiceMemoryObservation: observed.VoiceMemoryObservation})
	if err != nil || !result.Emitted || readbacks == 0 {
		t.Fatalf("native dispatch/readback failed: %+v %v reads=%d", result, err, readbacks)
	}
	updated := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicememorypolicy.ConfigMapName}, updated); err != nil {
		t.Fatal(err)
	}
	active, err := voicememorypolicy.Parse(updated.Data[voicememorypolicy.RuleKey])
	operationDigest := sha256.Sum256([]byte("phorvex-voice-memory-v1\x00" + policyUID + "\x00" + depUID + "\x00" + eventUID + "\x00" + pol.TickID + "\x00" + selected[0].Trace.DecisionID))
	if err != nil || active.Revision != 1 || active.OperationID != hex.EncodeToString(operationDigest[:]) || len(active.Entries) != 1 ||
		active.Entries[0].CallerID != caller || active.Entries[0].NoteSHA256 != voiceMemoryDigest(voiceMemoryAttackNote) {
		t.Fatalf("exact Voice rule not active: %+v %v", active, err)
	}
	if active.Entries[0].NoteSHA256 == voiceMemoryDigest(voiceMemoryBenignNote) {
		t.Fatal("benign control was revoked")
	}
	journals := &corev1.ConfigMapList{}
	if err := c.List(ctx, journals, client.InNamespace("operator")); err != nil {
		t.Fatal(err)
	}
	terminal := false
	for _, journal := range journals.Items {
		var receipt struct {
			Phase               string `json:"phase"`
			SelectionDecisionID string `json:"selectionDecisionId"`
			OperationID         string `json:"operationId"`
			EventUID            string `json:"eventUID"`
		}
		if json.Unmarshal([]byte(journal.Data["receipt.json"]), &receipt) == nil &&
			receipt.Phase == "terminal-full" && receipt.SelectionDecisionID == selected[0].Trace.DecisionID &&
			receipt.OperationID == active.OperationID && receipt.EventUID == eventUID {
			terminal = true
		}
	}
	if !terminal {
		t.Fatal("native dispatch lacked a terminal receipt bound to the selected decision")
	}
}
