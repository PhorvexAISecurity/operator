package runner

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"k8s.io/apimachinery/pkg/types"
)

func TestM022BuildPolicyPreservesZeroThroughDecisionSelection(t *testing.T) {
	view := &model.WorkloadView{
		Pod: model.Pod{
			Namespace:       "m022",
			Name:            "target",
			UID:             "target-uid",
			DesiredReplicas: 3,
			ReadyReplicas:   3,
			Ready:           true,
			MountedSecrets:  []string{"credentials"},
		},
		Phase:       model.PhaseWarm,
		BlastRadius: 0.6,
		Neighbors:   []model.NeighborRef{{Key: "m022/crown", Value: 5}},
		ExposureByVariable: map[string]time.Duration{
			model.VarPodIdentity:   3 * time.Hour,
			model.VarNodePlacement: 3 * time.Hour,
			model.VarSession:       3 * time.Hour,
		},
	}
	for _, tc := range []struct {
		name         string
		budget       int
		wantSelected int
	}{
		{name: "explicit-zero", budget: 0, wantSelected: 0},
		{name: "positive-control", budget: 1, wantSelected: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := tc.budget
			entry := &policyEntry{
				key:       types.NamespacedName{Namespace: "m022", Name: "policy"},
				uid:       "policy-uid",
				tenant:    "m022",
				namespace: "m022",
				spec: v1alpha1.PhorvexPolicySpec{
					Budget: v1alpha1.BudgetSpec{MaxMovesPerTick: &budget},
				},
			}
			policy := buildPolicy(entry)
			if policy.MaxMovesPerTick != tc.budget {
				t.Fatalf("buildPolicy maxMovesPerTick = %d, want %d", policy.MaxMovesPerTick, tc.budget)
			}
			decisions := decision.NewCoverageEngine().Decide([]*model.WorkloadView{view}, policy)
			if len(decisions) == 0 || decisions[0].Measurements == nil {
				t.Fatalf("decision producer omitted decision/trace: %+v", decisions)
			}
			selected := 0
			for _, d := range decisions {
				if d.Selected {
					selected++
				}
			}
			if selected != tc.wantSelected {
				t.Fatalf("selected decisions = %d, want %d: %+v", selected, tc.wantSelected, decisions)
			}
		})
	}
}
