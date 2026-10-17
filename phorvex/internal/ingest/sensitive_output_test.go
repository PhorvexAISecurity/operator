package ingest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/outputpolicy"
	"github.com/phorvex/phorvex/internal/recon"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const outputPodUID = "11111111-1111-4111-8111-111111111111"
const outputCMUID = "22222222-2222-4222-8222-222222222222"
const outputPolicyUID = "33333333-3333-4333-8333-333333333333"
const outputCreator = "system:serviceaccount:phorvex-system:phorvex-console"

func outputFixtureObjects(now time.Time) (*corev1.Pod, *corev1.ConfigMap, *amtdv1beta1.SecurityEvent) {
	name := "phorvex-output-policy-fixture"
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "vllm", Name: "fixture", UID: types.UID(outputPodUID), ResourceVersion: "4",
		Annotations: map[string]string{outputpolicy.PodConfigMapAnnotation: name,
			outputpolicy.PodRuleSHAAnnotation:    outputpolicy.RuleSHA256(outputPodUID),
			outputpolicy.PodProxySHAAnnotation:   strings.Repeat("a", 64),
			outputpolicy.PodSupportSHAAnnotation: strings.Repeat("b", 64),
			"phorvex.ai/output-event-creator":    outputCreator,
			"phorvex.ai/serving-port":            "8000"}},
		Status: corev1.PodStatus{PodIP: "10.0.0.2", ContainerStatuses: []corev1.ContainerStatus{{Name: "guardrail-proxy", ImageID: "proxy@sha256:aaa"}, {Name: "support-app", ImageID: "support@sha256:bbb"}}}}
	active := outputpolicy.Activation{Version: 1, RuleID: outputpolicy.RuleID, ConfigMapUID: outputCMUID}
	controller := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "vllm", Name: name, UID: types.UID(outputCMUID), ResourceVersion: "2",
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID, Controller: &controller}}},
		Data: map[string]string{outputpolicy.RuleKey: string(outputpolicy.RuleBytes(outputPodUID)), outputpolicy.ActivationKey: string(active.Bytes())}}
	payload, _ := json.Marshal(map[string]any{"version": 1, "ruleId": outputpolicy.RuleID, "ruleSHA256": outputpolicy.RuleSHA256(outputPodUID),
		"configMapUID": outputCMUID, "podUID": outputPodUID, "policyName": "guardrail-output-fixture", "policyUID": outputPolicyUID, "policyGeneration": int64(1),
		"requestPath": outputpolicy.Route, "observedAt": now.Add(-10 * time.Second).Format(time.RFC3339Nano)})
	e := m95Event("observed", "44444444-4444-4444-8444-444444444444", outputCreator, model.AttackVectorSensitiveOutput, outputPodUID, "", now.Add(-5*time.Second), "vllm/fixture")
	e.Annotations[ConsoleTargetPodUIDAnnotation] = outputPodUID
	e.Annotations[outputpolicy.EventAnnotation] = string(payload)
	return pod, cm, e
}

func TestSensitiveOutputProducerBoundary(t *testing.T) {
	trustEvents(t, "phorvex-system/phorvex-console")
	now := time.Date(2026, 9, 26, 19, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		change func(*corev1.Pod, *corev1.ConfigMap, *amtdv1beta1.SecurityEvent)
		want   bool
	}{
		{name: "exact admitted event and inactive owner rule", want: true},
		{name: "untrusted creator", change: func(_ *corev1.Pod, _ *corev1.ConfigMap, e *amtdv1beta1.SecurityEvent) {
			e.Annotations[CreatorIdentityAnnotation] = "system:serviceaccount:vllm:other"
		}},
		{name: "wrong target UID", change: func(_ *corev1.Pod, _ *corev1.ConfigMap, e *amtdv1beta1.SecurityEvent) {
			e.Annotations[ConsoleTargetPodUIDAnnotation] = "other"
		}},
		{name: "rule drift", change: func(_ *corev1.Pod, c *corev1.ConfigMap, _ *amtdv1beta1.SecurityEvent) {
			c.Data[outputpolicy.RuleKey] += " "
		}},
		{name: "owner drift", change: func(_ *corev1.Pod, c *corev1.ConfigMap, _ *amtdv1beta1.SecurityEvent) {
			c.OwnerReferences[0].UID = "other"
		}},
		{name: "already active", change: func(_ *corev1.Pod, c *corev1.ConfigMap, _ *amtdv1beta1.SecurityEvent) {
			c.Data[outputpolicy.ActivationKey] = string((outputpolicy.Activation{Version: 1, RuleID: outputpolicy.RuleID, ConfigMapUID: outputCMUID, Active: true, Revision: 1, OperationID: "op1"}).Bytes())
		}},
		{name: "stale observation", change: func(_ *corev1.Pod, _ *corev1.ConfigMap, e *amtdv1beta1.SecurityEvent) {
			e.CreationTimestamp = metav1.NewTime(now.Add(-70 * time.Second))
		}},
		{name: "same-second timestamp truncation", want: true, change: func(_ *corev1.Pod, _ *corev1.ConfigMap, e *amtdv1beta1.SecurityEvent) {
			e.CreationTimestamp = metav1.NewTime(now.Add(-time.Second))
			e.Annotations[outputpolicy.EventAnnotation] = strings.Replace(e.Annotations[outputpolicy.EventAnnotation],
				now.Add(-10*time.Second).Format(time.RFC3339Nano), now.Add(-200*time.Millisecond).Format(time.RFC3339Nano), 1)
		}},
		{name: "more than one second in future", change: func(_ *corev1.Pod, _ *corev1.ConfigMap, e *amtdv1beta1.SecurityEvent) {
			e.CreationTimestamp = metav1.NewTime(now.Add(-time.Second))
			e.Annotations[outputpolicy.EventAnnotation] = strings.Replace(e.Annotations[outputpolicy.EventAnnotation],
				now.Add(-10*time.Second).Format(time.RFC3339Nano), now.Add(500*time.Millisecond).Format(time.RFC3339Nano), 1)
		}},
		{name: "case alias overwrite", change: func(_ *corev1.Pod, _ *corev1.ConfigMap, e *amtdv1beta1.SecurityEvent) {
			e.Annotations[outputpolicy.EventAnnotation] = strings.Replace(e.Annotations[outputpolicy.EventAnnotation], `"observedAt":`, `"ObservedAt":"2026-09-26T19:00:00Z","observedAt":`, 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, cm, event := outputFixtureObjects(now)
			if tc.change != nil {
				tc.change(pod, cm, event)
			}
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := amtdv1beta1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, cm, event).Build()
			_, byPod, _, err := collectEventsAndReceipts(context.Background(), c, now, map[string]string{"vllm/fixture": outputPodUID})
			if err != nil {
				t.Fatal(err)
			}
			p := projectPod(pod, now)
			bindSensitiveOutputObservation(context.Background(), c, &p, byPod["vllm/fixture"])
			if got := p.HasBoundSensitiveOutputObservation(); got != tc.want {
				t.Fatalf("bound=%v want=%v observation=%+v", got, tc.want, p.OutputPolicyObservation)
			}
		})
	}
}

// Exercise the actual K8s/event producer through the normal recon, action-set
// and optimizer while other policy-enabled moves remain in the choice set.
func TestSensitiveOutputProducerFeedsNormalDecision(t *testing.T) {
	for _, tc := range []struct {
		name string
		age  time.Duration
	}{{"recent-pod-2m", 2 * time.Minute}, {"settled-pod-20m", 20 * time.Minute}} {
		t.Run(tc.name, func(t *testing.T) { testSensitiveOutputDecisionAtAge(t, tc.age) })
	}
}

func testSensitiveOutputDecisionAtAge(t *testing.T, age time.Duration) {
	trustEvents(t, "phorvex-system/phorvex-console")
	now := time.Date(2026, 9, 26, 19, 0, 0, 0, time.UTC)
	pod, cm, event := outputFixtureObjects(now)
	pod.CreationTimestamp = metav1.NewTime(now.Add(-age))
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(now.Add(-time.Hour))}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "vllm"}}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, cm, event, ns).Build()
	snap, err := CollectSnapshot(context.Background(), c, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := snap.PodByKey["vllm/fixture"]
	if p == nil || !p.HasBoundSensitiveOutputObservation() {
		t.Fatalf("real producer did not bind: %+v", p)
	}
	p.ReadyReplicas = 1
	v := &model.WorkloadView{Pod: *p, Events: snap.EventByPod["vllm/fixture"], Physics: model.NeutralPhysics(), Phase: model.PhaseWarm}
	// Match the owned fixture policy rendered by build/test-harness/fixtures/guardrail-output/render.py.
	// This is an active policy with the ordinary cost seed and alternatives, not a
	// test-only objective tuned to make the output action win.
	pol := model.Policy{Tenant: "vllm", Namespace: "vllm", PolicyName: "guardrail-output-fixture", PolicyUID: outputPolicyUID, PolicyGeneration: 1,
		Mode: "active", TraceEnabled: true, MaxMovesPerTick: 1, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, Lambda: .4,
		CostCeiling: model.DefaultCostCeiling, MinAvailableReplicas: 1, ProactiveFloor: 15 * time.Minute,
		ExposurePressureScale: 15 * time.Minute, AntiOverRotationWindow: 90 * time.Second, TickInterval: 10 * time.Second,
		EventAgeHorizon: time.Hour, EventDriven: true, ReactiveOnly: true, BlastRadiusFromGraph: true,
		AssetWeights:   model.AssetLabelWeights{Default: .4},
		EnabledActions: map[model.Action]bool{model.ActionSensitiveOutputPolicyActivate: true, model.ActionRotate: true, model.ActionQuarantine: true}}
	clock := exposure.NewClock()
	clock.Observe(exposure.Observation{Owner: pol.Owner(), Namespace: p.Namespace, Pod: p.Name,
		StartedAt: p.StartedAt, Fingerprints: model.ExposureFingerprints(*p)}, now)
	v.ExposureByVariable = clock.Since(pol.Owner(), p.Namespace, p.Name, now)
	engine := decision.NewCoverageEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw profile absent")
	}
	engine.Recon = profile
	set, _ := engine.AssembleSet([]*model.WorkloadView{v}, pol)
	found := false
	for _, candidate := range set.Candidates {
		if candidate.Action == model.ActionSensitiveOutputPolicyActivate && len(candidate.CoverKeys) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("output candidate absent: exclusions=%+v facts=%+v", set.Excluded, set.FactsByAsset)
	}
	considered := map[model.Action]bool{}
	for _, candidate := range set.Candidates {
		considered[candidate.Action] = true
	}
	for _, exclusion := range set.Excluded {
		considered[exclusion.Action] = true
	}
	if !considered[model.ActionRotate] || !considered[model.ActionQuarantine] {
		t.Fatalf("other enabled moves were not evaluated: candidates=%+v exclusions=%+v", set.Candidates, set.Excluded)
	}
	ds := engine.Decide([]*model.WorkloadView{v}, pol)
	if len(ds) != 1 || !ds[0].Selected || ds[0].Action != model.ActionSensitiveOutputPolicyActivate || ds[0].OutputPolicyObservation == nil || ds[0].OutputPolicyObservation.EventUID != string(event.UID) {
		t.Fatalf("normal brain did not select exact output action: %+v", ds)
	}
	pol.PolicyUID = "wrong-policy"
	wrong, _ := engine.AssembleSet([]*model.WorkloadView{v}, pol)
	for _, candidate := range wrong.Candidates {
		if candidate.Action == model.ActionSensitiveOutputPolicyActivate {
			t.Fatal("wrong selecting policy kept candidate")
		}
	}
}
