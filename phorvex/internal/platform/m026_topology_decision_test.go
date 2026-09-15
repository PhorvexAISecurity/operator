package platform

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM026DerivedSharedGPUTopologyCannotSupplySelectionObservation(t *testing.T) {
	physicsPod := model.Pod{Namespace: "physics", Name: "serve", UID: "physics", Node: "gpu-1", HasGPU: true,
		ModelID: "qwen", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, Labels: map[string]string{"role": "physics"},
		MountedSecrets: []string{"creds"}}
	duePod := model.Pod{Namespace: "due", Name: "serve", UID: "due", Node: "gpu-1", HasGPU: true,
		ModelID: "llama", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, Labels: map[string]string{"role": "due"},
		MountedSecrets: []string{"creds"}}
	snap := &ingest.Snapshot{Pods: []model.Pod{physicsPod, duePod}, Nodes: []ingest.NodeInfo{{Name: "gpu-1", AllocatableGPU: 1}}}
	_, witnesses := Derive(snap)
	physicsWitness := witnesses["physics/serve"]
	if !physicsWitness.Scanned || !physicsWitness.CoResidencyPresent || !physicsWitness.ModelRarityPresent ||
		physicsWitness.CoResidency <= 1 || physicsWitness.ModelRarity <= 1 {
		t.Fatalf("derived shared namespace/model topology did not generate the AI context: %+v", physicsWitness)
	}
	floor := 15 * time.Minute
	clocks := func(d time.Duration) map[string]time.Duration {
		return map[string]time.Duration{model.VarPodIdentity: d, model.VarNodePlacement: d, model.VarSession: d}
	}
	physics := &model.WorkloadView{Pod: physicsPod, Phase: model.PhaseWarm, Physics: physicsWitness,
		ExposureByVariable: clocks(90 * time.Second), Neighbors: []model.NeighborRef{{Key: "physics/neighbor", Value: 5}}}
	due := &model.WorkloadView{Pod: duePod, Phase: model.PhaseWarm, Physics: witnesses["due/serve"],
		ExposureByVariable: clocks(16 * time.Minute), Neighbors: []model.NeighborRef{{Key: "due/neighbor", Value: 5}}}
	pol := model.Policy{Tenant: "m026-derived-topology", DryRun: true, Lambda: 0, NormSparsity: .4, FlowDisruption: .6,
		WeightSecrets: .8, BlastRadiusFromGraph: true, MaxMovesPerTick: 1, ProactiveFloor: floor,
		AntiOverRotationWindow: 90 * time.Second, EnabledActions: map[model.Action]bool{model.ActionQuarantine: true},
		AssetWeightFromLabels: func(l map[string]string) float64 {
			if l["role"] == "physics" {
				return 120
			}
			return 40
		}, TraceEnabled: true}
	a := killchain.NewModel().Assess(physics, pol, 90, floor.Seconds())
	if !a.HasEvidence || a.HasEventEvidence || a.AIStageName == "" {
		t.Fatalf("derived topology must produce broad inference without strict observation: %+v", a)
	}
	engine := decision.NewCoverageEngine()
	decisions := engine.Decide([]*model.WorkloadView{physics, due}, pol)
	selected := ""
	for _, d := range decisions {
		if d.Selected {
			selected = d.Namespace + "/" + d.Pod
		}
		if d.Namespace == "physics" && math.Abs(d.Provenance-.406) > 1e-9 {
			t.Fatalf("derived physics-only topology received provenance=%v, want 0.406; decision=%+v", d.Provenance, d)
		}
		if d.Namespace == "due" && d.Provenance != 1 {
			t.Fatalf("overdue control lost full provenance: %+v", d)
		}
	}
	if selected != "due/serve" {
		t.Fatalf("derived physics-only context took the single slot from overdue control: selected=%q decisions=%+v", selected, decisions)
	}
}
