//go:build live

package decision

// Live end-to-end proof of the stateful rotation family against a real cluster. It runs the
// production chain on one live StatefulSet member — the statefulrotation observation the
// sensor projects, the unmodified coverage engine, and the native actuator's real handler —
// and fails unless the selected class is the expected one and the handler confirms the
// replacement member and its class continuity property.
//
// The held foothold is modelled exactly as the engine's detection-independent proactive
// trigger sees it: every exposure clock past the policy's proactive floor. The run never
// touches any object outside PHORVEX_LIVE_NAMESPACE; it is skipped unless the variables are
// set:
//
//	PHORVEX_LIVE_NAMESPACE  namespace of the member and its PhorvexPolicy
//	PHORVEX_LIVE_POLICY     PhorvexPolicy name
//	PHORVEX_LIVE_POD        target member Pod name
//	PHORVEX_LIVE_EXPECT     expected selected action ("noop" for a decide-only refusal check)
//	PHORVEX_LIVE_DECIDE     "1" to decide without dispatching
//
// go test -tags live ./internal/decision -run TestLiveStatefulRotation -v

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/statefulrotation"
)

func TestLiveStatefulRotation(t *testing.T) {
	ns, policyName, podName, expect := os.Getenv("PHORVEX_LIVE_NAMESPACE"), os.Getenv("PHORVEX_LIVE_POLICY"),
		os.Getenv("PHORVEX_LIVE_POD"), model.Action(os.Getenv("PHORVEX_LIVE_EXPECT"))
	if ns == "" || policyName == "" || podName == "" || expect == "" {
		t.Skip("live stateful rotation run not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	scheme := runtime.NewScheme()
	// The full client-go scheme, as the manager registers it: the Eviction body must encode.
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}

	policy := &v1alpha1.PhorvexPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: policyName}, policy); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: podName}, pod); err != nil {
		t.Fatal(err)
	}
	observation := statefulrotation.Observe(ctx, c, pod)
	if observation == nil {
		t.Fatalf("%s/%s carries no stateful rotation contract", ns, podName)
	}
	t.Logf("observation: complete=%t replicas=%d ready=%d rollout=%t leader=%t claims=%+v snapshotClassReady=%t contract=%+v reason=%q",
		observation.Complete, observation.Replicas, observation.ReadyReplicas, observation.RolloutInProgress,
		observation.Leader, observation.Claims, observation.SnapshotClassReady, observation.Contract, observation.Reason)

	pol := livePolicy(t, policy)
	view := &model.WorkloadView{
		Pod: model.Pod{
			Namespace: ns, Name: pod.Name, UID: string(pod.UID), PodResourceVersion: pod.ResourceVersion,
			Labels: pod.Labels, Node: pod.Spec.NodeName, Ready: statefulrotation.PodReady(pod), Stateful: true,
			OwnerKind: "StatefulSet", OwnerName: observation.OwnerName,
			DesiredReplicas: observation.Replicas, ReadyReplicas: observation.ReadyReplicas,
			StatefulRotation: observation,
		},
		Physics:            model.NeutralPhysics(),
		Phase:              model.PhaseWarm,
		ExposureByVariable: allVarsAt(pol.ProactiveFloor + time.Hour),
		Telemetry:          model.Telemetry{ReqRate: model.PresentSignal(0, "live-fixture")},
	}
	var selected *model.Decision
	for _, d := range NewCoverageEngine().Decide([]*model.WorkloadView{view}, pol) {
		t.Logf("decision: action=%s selected=%t feasible=%t net=%.3f reason=%q", d.Action, d.Selected, d.Feasible, d.Net, d.Reason)
		if d.Selected {
			d := d
			selected = &d
		}
	}
	got := model.ActionNoop
	if selected != nil {
		got = selected.Action
	}
	if got != expect {
		t.Fatalf("brain selected %q, want %q", got, expect)
	}
	if os.Getenv("PHORVEX_LIVE_DECIDE") == "1" || got == model.ActionNoop {
		return
	}

	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	result, err := native.Actuate(ctx, actuator.Request{
		Namespace: ns, Pod: pod.Name, TargetUID: string(pod.UID), Action: got, Tenant: pol.Tenant,
		PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation,
		MaxGracePeriodSeconds: pol.MaxGracePeriodSeconds,
	})
	t.Logf("result: emitted=%t kind=%s noEffect=%q touched=%v rollback=%q", result.Emitted, result.MutationKind, result.NoEffect, result.ObjectsTouched, result.RollbackRef)
	t.Logf("note: %s", result.Note)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Emitted || result.MutationKind != "forward-only" || !strings.Contains(result.Note, "Ready and confirmed") {
		t.Fatalf("%s did not confirm its replacement: %+v", got, result)
	}
}

// livePolicy mirrors the core of runner.buildPolicy for the fields the coverage engine and
// the native rotation boundary read.
func livePolicy(t *testing.T, p *v1alpha1.PhorvexPolicy) model.Policy {
	t.Helper()
	s := &p.Spec
	grace, err := s.EffectiveMaxGracePeriodSeconds()
	if err != nil {
		t.Fatal(err)
	}
	enabled := map[model.Action]bool{}
	for _, a := range s.Actions.Enabled {
		enabled[model.Action(a)] = true
	}
	return model.Policy{
		Tenant: s.Tenant, Namespace: p.Namespace, PolicyName: p.Name, PolicyUID: string(p.UID), PolicyGeneration: p.Generation,
		Mode: s.EffectiveMode(), DryRun: s.IsDryRun(), Lambda: s.EffectiveLambda(),
		NormSparsity: s.EffectiveNormSparsity(), FlowDisruption: s.EffectiveFlowDisruption(),
		CostCeiling: s.EffectiveCostCeiling(), WeightSecrets: s.EffectiveWeightSecrets(),
		BlastRadiusFromGraph: s.AssetValue.BlastRadiusFromGraph, MaxMovesPerTick: s.EffectiveMaxMovesPerTick(),
		MaxGracePeriodSeconds: grace, TickInterval: s.EffectiveTickInterval(),
		AntiOverRotationWindow: s.EffectiveAntiOverRotationWindow(), ProactiveFloor: s.EffectiveProactiveFloor(),
		EventAgeHorizon: s.EffectiveEventAgeHorizon(), ExposurePressureScale: s.EffectiveProactiveFloor(),
		MinAvailableReplicas: s.EffectiveMinAvailableReplicas(), EnabledActions: enabled,
		AssetWeights: s.AssetLabelWeights(),
	}
}
