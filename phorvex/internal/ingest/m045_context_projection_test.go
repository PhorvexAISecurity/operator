package ingest

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func TestM045ProjectedContextScopesFactsAndActionSet(t *testing.T) {
	const (
		servingPort = "phorvex.ai/serving-port"
		modelID     = "phorvex.ai/model-id"
	)
	allActions := map[model.Action]bool{
		model.ActionMIGRebind: true, model.ActionRequestDrain: true,
		model.ActionGuardrailRotate: true, model.ActionKVReset: true,
		model.ActionKVMigrateInvalidate: true,
	}
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon is not registered")
	}
	deps := actionset.Deps{
		Recon: profile,
		FactContext: func(v *model.WorkloadView) recon.FactContext {
			return recon.FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1, HasGPU: v.Pod.HasGPU}
		},
		ECost: func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.1 },
		CHi:   func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.1 },
	}

	tests := []struct {
		name        string
		annotations map[string]string
		gpu         bool
		ready       bool
		ip          bool
		wantModel   bool
		wantServing bool
		wantGPU     bool
		wantActions map[model.Action]bool
	}{
		{name: "gpu batch", gpu: true, ready: true, ip: true, wantGPU: true,
			wantActions: map[model.Action]bool{model.ActionMIGRebind: true}},
		{name: "cpu model server", annotations: map[string]string{modelID: "model-v1"}, ready: true, ip: true,
			wantModel: true, wantServing: true, wantActions: servingActions()},
		{name: "combined", annotations: map[string]string{modelID: "model-v1"}, gpu: true, ready: true, ip: true,
			wantModel: true, wantServing: true, wantGPU: true,
			wantActions: mergeActions(servingActions(), map[model.Action]bool{model.ActionMIGRebind: true})},
		{name: "ordinary", ready: true, ip: true},
		{name: "explicit port", annotations: map[string]string{servingPort: " 8000 "}, ready: true, ip: true,
			wantServing: true, wantActions: servingActions()},
		{name: "malformed port", annotations: map[string]string{servingPort: "http"}, ready: true, ip: true},
		{name: "whitespace declarations", annotations: map[string]string{modelID: " \t", servingPort: " \n"}, ready: true, ip: true},
		{name: "declared but unready", annotations: map[string]string{modelID: "model-v1"}, ip: true,
			wantModel: true, wantServing: true,
			wantActions: map[model.Action]bool{model.ActionRequestDrain: true, model.ActionGuardrailRotate: true}},
		{name: "declared without pod ip", annotations: map[string]string{modelID: "model-v1"}, ready: true,
			wantModel: true, wantServing: true,
			wantActions: map[model.Action]bool{model.ActionRequestDrain: true, model.ActionGuardrailRotate: true}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "target", UID: "pod-uid", Annotations: tc.annotations}}
			if tc.gpu {
				pod.Spec.Containers = []corev1.Container{{Name: "worker", Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceName("nvidia.com/mig-1g.10gb"): resource.MustParse("1")},
				}}}
			}
			if tc.ready {
				pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
			}
			if tc.ip {
				pod.Status.PodIP = "10.0.0.8"
			}

			projected := projectPod(pod, time.Unix(10, 0))
			if projected.HasModelDeclaration() != tc.wantModel || projected.HasServingDeclaration() != tc.wantServing || projected.HasGPU != tc.wantGPU {
				t.Fatalf("projected contexts: model=%v serving=%v gpu=%v; want %v/%v/%v", projected.HasModelDeclaration(), projected.HasServingDeclaration(), projected.HasGPU, tc.wantModel, tc.wantServing, tc.wantGPU)
			}
			if projected.ServingEndpointReady != (tc.wantServing && tc.ready && tc.ip) {
				t.Fatalf("ServingEndpointReady=%v", projected.ServingEndpointReady)
			}

			view := &model.WorkloadView{Pod: projected, Phase: model.PhaseWarm, Physics: model.NeutralPhysics(),
				Events: []model.SecurityEventInfo{{Name: "guard", UID: "event-1", Type: model.AttackVectorGuardrail, TargetsPod: true}}}
			facts := profile.AssetFacts(view, recon.FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1, HasGPU: projected.HasGPU})
			byKind := map[string]bool{}
			for _, fact := range facts.Facts {
				byKind[fact.Kind] = true
			}
			for _, kind := range []string{recon.FactPodIdentity, recon.FactSession, recon.FactNetworkIdentity} {
				if !byKind[kind] {
					t.Errorf("universal non-AI fact %s was lost", kind)
				}
			}
			if byKind[recon.FactModelFingerprint] != tc.wantModel {
				t.Errorf("modelFingerprint=%v, want %v", byKind[recon.FactModelFingerprint], tc.wantModel)
			}
			for _, kind := range []string{recon.FactEndpointPath, recon.FactInflightRequests, recon.FactGuardrailBypass} {
				if byKind[kind] != tc.wantServing {
					t.Errorf("%s=%v, want serving=%v", kind, byKind[kind], tc.wantServing)
				}
			}
			for _, kind := range []string{recon.FactGPUColocation, recon.FactGPUContentionChannel} {
				if byKind[kind] != tc.wantGPU {
					t.Errorf("%s=%v, want gpu=%v", kind, byKind[kind], tc.wantGPU)
				}
			}

			set := deps.Generate([]*model.WorkloadView{view}, model.Policy{EnabledActions: allActions})
			gotActions := map[model.Action]bool{}
			for _, candidate := range set.Candidates {
				gotActions[candidate.Action] = true
			}
			for action := range allActions {
				if gotActions[action] != tc.wantActions[action] {
					t.Errorf("candidate %s=%v, want %v; exclusions=%+v", action, gotActions[action], tc.wantActions[action], set.Excluded)
				}
			}
		})
	}
}

func servingActions() map[model.Action]bool {
	return map[model.Action]bool{
		model.ActionRequestDrain: true, model.ActionGuardrailRotate: true,
		model.ActionKVReset: true, model.ActionKVMigrateInvalidate: true,
	}
}

func mergeActions(left, right map[model.Action]bool) map[model.Action]bool {
	out := map[model.Action]bool{}
	for action, enabled := range left {
		out[action] = enabled
	}
	for action, enabled := range right {
		out[action] = enabled
	}
	return out
}
