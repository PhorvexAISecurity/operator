package ingest

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func TestM100CurrentInventoryCannotBecomeThreatEvidence(t *testing.T) {
	observer := "system:serviceaccount:ns:current-observer"
	trustEvents(t, observer)
	now := time.Date(2026, 9, 21, 4, 0, 0, 0, time.UTC)
	payload := model.CurrentInventoryV1{
		SchemaVersion: model.CurrentInventorySchemaV1, EvidenceID: "current-v2", Synthetic: true,
		PolicyEpoch:         model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1},
		DecisionAsset:       model.DecisionAssetIdentity{Namespace: "ns", Name: "pod", TargetUID: "pod-uid"},
		ImmediateController: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "ns", Name: "rs", UID: "rs-uid"},
		StableWorkloadOwner: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ns", Name: "app", UID: "dep-uid"},
		ProtectedScope:      model.ProtectedScope{Tenant: "tenant", Asset: "synthetic/data", Version: "v2", Property: "confidentiality"},
		SourceBinding:       model.CurrentInventorySourceBinding{ConfigMap: model.ObjectIdentity{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "data", UID: "cm-uid"}, ResourceVersion: "7", Key: "payload", VolumeName: "data", ContainerName: "server", MountPath: "/data", ProjectedPath: "payload", Bytes: 2, SHA256: strings.Repeat("a", 64)},
		Classification:      model.CurrentInventoryClassification{RuleVersion: model.CurrentInventoryRuleVersionV1, RuleDigest: strings.Repeat("b", 64), InventoryClass: model.CurrentInventoryClass, PossibleOutcome: "unauthorized-disclosure", ObserverIdentity: observer},
		Observation:         model.CurrentInventoryObservation{StartedAt: now.Add(-2 * time.Second), CompletedAt: now.Add(-time.Second), ValidUntil: now.Add(time.Minute), StatusCode: 200, ManifestEOF: true},
	}
	raw, _, err := currentinventory.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	current := seEvent("current", observer, model.CurrentInventorySource, "ns/pod")
	current.CreationTimestamp = metav1.NewTime(now.Add(-time.Second))
	current.Annotations[currentinventory.Annotation] = raw
	current.Spec.Rule.Type = model.CurrentInventoryRuleType
	current.Spec.Rule.ThreatLevel = "high"
	current.Spec.Description = model.CurrentInventoryDescription
	attack := seEvent("attack", observer, "qualified-detector", "ns/pod")
	attack.CreationTimestamp = metav1.NewTime(now.Add(-time.Second))
	attack.Spec.Rule.Type = "Panic"
	attack.Spec.Rule.ThreatLevel = "high"

	evaluate := func(events ...*amtdv1beta1.SecurityEvent) (killchain.Assessment, []model.Decision, []model.SecurityEventInfo) {
		scheme := runtime.NewScheme()
		if err := amtdv1beta1.AddToScheme(scheme); err != nil {
			t.Fatal(err)
		}
		builder := fake.NewClientBuilder().WithScheme(scheme)
		for _, event := range events {
			builder = builder.WithObjects(event.DeepCopy())
		}
		all, byPod, err := collectEvents(context.Background(), builder.Build(), now)
		if err != nil {
			t.Fatal(err)
		}
		view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "pod", UID: "pod-uid", Ready: true, DesiredReplicas: 2, ReadyReplicas: 2, MountedSecrets: []string{"secret"}}, Phase: model.PhaseWarm, Events: byPod["ns/pod"], ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: time.Minute, model.VarNodePlacement: time.Minute, model.VarSession: time.Minute}}
		policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 1, DryRun: true, Lambda: 0.05, MaxMovesPerTick: 1, ProactiveFloor: 15 * time.Minute, AntiOverRotationWindow: time.Minute, EnabledActions: map[model.Action]bool{model.ActionRotate: true}, AssetWeights: model.AssetLabelWeights{Default: 1}}
		assessment := killchain.NewModel().Assess(view, policy, 60, policy.ProactiveFloor.Seconds())
		decisions := decision.NewCoverageEngine().Decide([]*model.WorkloadView{view}, policy)
		return assessment, decisions, all
	}
	cleanAssessment, cleanDecisions, _ := evaluate()
	currentAssessment, currentDecisions, all := evaluate(current)
	if len(all) != 1 || len(currentAssessment.Events) != 0 || currentAssessment.PHold != cleanAssessment.PHold || currentAssessment.StageName != cleanAssessment.StageName || len(currentDecisions) != len(cleanDecisions) {
		t.Fatalf("current inventory changed threat assessment: clean=%+v current=%+v all=%+v", cleanAssessment, currentAssessment, all)
	}
	for i := range cleanDecisions {
		if currentDecisions[i].PHold != cleanDecisions[i].PHold || currentDecisions[i].Stage != cleanDecisions[i].Stage || currentDecisions[i].Selected != cleanDecisions[i].Selected || currentDecisions[i].Action != cleanDecisions[i].Action || currentDecisions[i].Net != cleanDecisions[i].Net {
			t.Fatalf("current inventory changed ranking/selection: clean=%+v current=%+v", cleanDecisions[i], currentDecisions[i])
		}
	}
	attackAssessment, _, _ := evaluate(attack)
	if attackAssessment.EventEvidence <= 0 || attackAssessment.PHold == cleanAssessment.PHold || attackAssessment.StageName == cleanAssessment.StageName {
		t.Fatalf("normal trusted attack positive did not affect assessment: clean=%+v attack=%+v", cleanAssessment, attackAssessment)
	}
}

// The event stream is projected by the real ingestion gate, then the same views
// pass through production AssembleSet and Decide. Namespace/GPU topology supplies
// no attack evidence; supported detector and trusted-event signals retain their contracts.
func TestM026ObservationProvenanceFromIngestionToSelection(t *testing.T) {
	trustEvents(t, "ns/detector")
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		event     *amtdv1beta1.SecurityEvent
		adapter   string
		wantBroad bool
		wantObs   bool
	}{
		{name: "event-free topology"},
		{name: "annotation alone", adapter: "suspicious", wantBroad: true},
		{name: "unstamped event", event: seEvent("unstamped", "", "detector", "ns/physics")},
		{name: "missing timestamp", event: seEvent("missing", "system:serviceaccount:ns:detector", "detector", "ns/physics")},
		{name: "stale trusted event", event: seEvent("stale", "system:serviceaccount:ns:detector", "detector", "ns/physics")},
		{name: "weak trusted event", event: seEvent("weak", "system:serviceaccount:ns:detector", "detector", "ns/physics"), wantBroad: true, wantObs: true},
		{name: "trusted lateral event", event: seEvent("lateral", "system:serviceaccount:ns:detector", "detector", "ns/physics-neighbor"), wantBroad: true, wantObs: true},
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
				AssetWeights: model.AssetLabelWeights{ByLabel: map[string]map[string]float64{"role": {"physics": 160}}, Default: 40},
				TraceEnabled: true}
			engine := decision.NewCoverageEngine()
			_, _ = engine.AssembleSet([]*model.WorkloadView{physics, due}, pol)
			assessment := killchain.NewModel().Assess(physics, pol, 90, floor.Seconds())
			if assessment.HasEvidence != tc.wantBroad || assessment.HasEventEvidence != tc.wantObs {
				t.Fatalf("real assessment broad/strict=%v/%v, want %v/%v", assessment.HasEvidence, assessment.HasEventEvidence, tc.wantBroad, tc.wantObs)
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
					if d.StageAI == "model-theft" || d.StageAI == "gpu-side-channel" {
						t.Fatalf("namespace topology manufactured GPU stage %q", d.StageAI)
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
