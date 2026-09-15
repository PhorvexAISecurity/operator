package decision

import (
	"fmt"
	"testing"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type adversarialSharedRecon struct{}

func (adversarialSharedRecon) Name() string { return "test-adversarial-shared" }
func (adversarialSharedRecon) AssetFacts(_ *model.WorkloadView, _ recon.FactContext) recon.AssetFacts {
	return recon.AssetFacts{CoverByAction: map[model.Action][]string{
		model.ActionRotate: {"shared-block|gpuColocation"},
	}}
}

func adversarialTopology() []*model.WorkloadView {
	views := make([]*model.WorkloadView, 0, 8)
	for i := 0; i < 8; i++ {
		physics := model.NeutralPhysics()
		physics.CoResidency = 2
		physics.ModelRarity = 2
		views = append(views, &model.WorkloadView{
			Pod: model.Pod{
				Namespace: "adversarial", Name: fmt.Sprintf("gpu-pod-%d", i), UID: fmt.Sprintf("uid-%d", i),
				Node: fmt.Sprintf("shared-node-%d", i%2), HasGPU: true, MIGDevice: "1g.10gb",
				ModelID: "shared-model", SuspectAdapter: "suspect", DesiredReplicas: 8, ReadyReplicas: 8, Ready: true,
			},
			Neighbors: []model.NeighborRef{{Key: "adversarial/shared-target", Value: 1}},
			Physics:   physics,
		})
		views[len(views)-1].Pod.AdapterObservation = &model.AdapterObservation{EventName: "detected", EventUID: fmt.Sprintf("event-%d", i),
			CreatorIdentity: "system:serviceaccount:adversarial:detector", TargetPodUID: views[len(views)-1].Pod.UID, AdapterName: "suspect"}
	}
	return views
}

func allActionSet(profile recon.ReconProfile, views []*model.WorkloadView, policy model.Policy) actionset.ActionSet {
	set := actionset.ActionSet{FactWeights: map[string]float64{}}
	for _, view := range views {
		owner := view.Pod.Namespace + "/" + view.Pod.Name
		ctx := recon.FactContext{
			AssetValue: 1, PHold: 1, StageUrgency: 1, LateralUrgency: 1,
			Neighbors: []recon.NeighborRef{{Key: "adversarial/shared-target", Value: 1}},
			HasGPU:    true,
		}
		af := profile.AssetFacts(view, ctx)
		for _, fact := range af.Facts {
			set.FactWeights[fact.Key()] = fact.Weight
		}
		for _, action := range model.MutatingActions {
			if !model.ActionEnabled(policy, action) {
				continue
			}
			set.Candidates = append(set.Candidates, actionset.Candidate{
				Key: owner, View: view, Action: action, CoverKeys: af.CoverByAction[action],
			})
		}
	}
	return set
}

func TestAdversarialTopologyStaysDisjoint(t *testing.T) {
	enabled := make(map[model.Action]bool, len(model.MutatingActions))
	for _, action := range model.MutatingActions {
		enabled[action] = true
	}
	policy := model.Policy{EnabledActions: enabled}
	views := adversarialTopology()

	profiles := recon.Registry.All()
	if len(profiles) == 0 {
		t.Fatal("recon registry is empty")
	}
	for _, profile := range profiles {
		profile := profile
		t.Run(profile.Name(), func(t *testing.T) {
			if disjoint, note := coversDisjoint(allActionSet(profile, views, policy)); !disjoint {
				t.Fatalf("adversarial topology broke disjointness: %s", note)
			}
		})
	}

	// Mutation proof: a profile that emits one shared key must trip the production checker.
	if disjoint, note := coversDisjoint(allActionSet(adversarialSharedRecon{}, views, policy)); disjoint {
		t.Fatalf("deliberately shared cover key passed adversarial check: %s", note)
	}
}
