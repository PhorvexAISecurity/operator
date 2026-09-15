package ingest

import (
	"context"
	"math"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// The event stream is projected by the real ingestion gate, then the same views
// pass through production AssembleSet and Decide. A busy shared GPU node may
// supply AI context, but it cannot authenticate an attack observation.
func TestM026ObservationProvenanceFromIngestionToSelection(t *testing.T) {
	trustEvents(t, "ns/detector")
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		event   *amtdv1beta1.SecurityEvent
		adapter string
		wantObs bool
	}{
		{name: "event-free topology"},
		{name: "annotation alone", adapter: "suspicious"},
		{name: "unstamped event", event: seEvent("unstamped", "", "detector", "ns/physics")},
		{name: "missing timestamp", event: seEvent("missing", "system:serviceaccount:ns:detector", "detector", "ns/physics")},
		{name: "stale trusted event", event: seEvent("stale", "system:serviceaccount:ns:detector", "detector", "ns/physics")},
		{name: "weak trusted event", event: seEvent("weak", "system:serviceaccount:ns:detector", "detector", "ns/physics"), wantObs: true},
		{name: "trusted lateral event", event: seEvent("lateral", "system:serviceaccount:ns:detector", "detector", "ns/physics-neighbor"), wantObs: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := amtdv1beta1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tc.event != nil {
				event := tc.event.DeepCopy()
				if tc.name == "missing timestamp" {
					event.CreationTimestamp = metav1.Time{}
				} else if tc.name == "stale trusted event" {
					event.CreationTimestamp = metav1.NewTime(now.Add(-2 * time.Hour))
				} else {
					event.CreationTimestamp = metav1.NewTime(now.Add(-time.Minute))
				}
				event.Spec.Rule.ThreatLevel = "low"
				builder = builder.WithObjects(event)
			}
			_, byPod, err := collectEvents(context.Background(), builder.Build(), now)
			if err != nil {
				t.Fatal(err)
			}
			physicsEvents := append([]model.SecurityEventInfo{}, byPod["ns/physics"]...)
			// Match runner's neighbor projection: preserve collector trust and age,
			// then mark a neighbor's event as lateral rather than direct.
			for _, neighborEvent := range byPod["ns/physics-neighbor"] {
				neighborEvent.TargetsPod = false
				physicsEvents = append(physicsEvents, neighborEvent)
			}
			floor := 15 * time.Minute
			physics := &model.WorkloadView{
				Pod: model.Pod{Namespace: "ns", Name: "physics", UID: "physics", Node: "gpu-1", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3,
					HasGPU: true, ModelID: "qwen", SuspectAdapter: tc.adapter, Labels: map[string]string{"role": "physics"}},
				Phase: model.PhaseWarm, Physics: model.PhysicsWitness{CoResidency: 1.5, ModelRarity: 1.4, SMOccupancy: .9},
				Events: physicsEvents, ExposureByVariable: map[string]time.Duration{
					model.VarPodIdentity: 90 * time.Second, model.VarNodePlacement: 90 * time.Second, model.VarSession: 90 * time.Second},
				Neighbors: []model.NeighborRef{{Key: "ns/physics-neighbor", Value: 5}},
			}
			physics.Pod.MountedSecrets = []string{"creds"}
			due := &model.WorkloadView{
				Pod: model.Pod{Namespace: "ns", Name: "due", UID: "due", Node: "gpu-1", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3,
					Labels: map[string]string{"role": "due"}, MountedSecrets: []string{"creds"}},
				Phase: model.PhaseWarm, ExposureByVariable: map[string]time.Duration{
					model.VarPodIdentity: 16 * time.Minute, model.VarNodePlacement: 16 * time.Minute, model.VarSession: 16 * time.Minute},
				Neighbors: []model.NeighborRef{{Key: "ns/due-neighbor", Value: 5}},
			}
			pol := model.Policy{Tenant: "m026-" + tc.name, DryRun: true, Lambda: 0, NormSparsity: .4, FlowDisruption: .6,
				WeightSecrets: .8, BlastRadiusFromGraph: true, MaxMovesPerTick: 1, ProactiveFloor: floor,
				AntiOverRotationWindow: 90 * time.Second, EnabledActions: map[model.Action]bool{model.ActionQuarantine: true},
				AssetWeightFromLabels: func(labels map[string]string) float64 {
					if labels["role"] == "physics" {
						return 160
					}
					return 40
				}, TraceEnabled: true}
			engine := decision.NewCoverageEngine()
			_, _ = engine.AssembleSet([]*model.WorkloadView{physics, due}, pol)
			assessment := killchain.NewModel().Assess(physics, pol, 90, floor.Seconds())
			if !assessment.HasEvidence || assessment.HasEventEvidence != tc.wantObs {
				t.Fatalf("real assessment broad/strict=%v/%v, want true/%v", assessment.HasEvidence, assessment.HasEventEvidence, tc.wantObs)
			}
			if physics.HasEventEvidence != tc.wantObs {
				t.Fatalf("stamped observation=%v, want %v", physics.HasEventEvidence, tc.wantObs)
			}
			decisions := engine.Decide([]*model.WorkloadView{physics, due}, pol)
			wantProv := 1.0
			if !tc.wantObs {
				wantProv = .34 + .66*(90.0/float64(floor.Seconds()))
			}
			selected := ""
			for _, d := range decisions {
				if d.Pod == "physics" {
					if math.Abs(d.Provenance-wantProv) > 1e-9 {
						t.Fatalf("physics provenance=%v, want %v; decision=%+v", d.Provenance, wantProv, d)
					}
					if d.StageAI == "" {
						t.Fatal("fixture lost physics/AI stage")
					}
					if d.Selected {
						selected = d.Pod
					}
				} else if d.Selected {
					selected = d.Pod
				}
			}
			if !tc.wantObs && selected != "due" {
				t.Fatalf("discount did not free the slot for overdue workload: selected=%q, decisions=%+v", selected, decisions)
			}
			if tc.wantObs && selected != "physics" {
				t.Fatalf("trusted weak observation did not preserve ordinary selection: selected=%q, decisions=%+v", selected, decisions)
			}
		})
	}
}
