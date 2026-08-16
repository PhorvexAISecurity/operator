package actionset

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type collisionRecon struct {
	crossBlock bool
}

func (collisionRecon) Name() string { return "test-collision-recon" }
func (r collisionRecon) AssetFacts(view *model.WorkloadView, _ recon.FactContext) recon.AssetFacts {
	owner := view.Pod.Namespace + "/" + view.Pod.Name
	if r.crossBlock {
		owner = "shared-block"
	}
	fact := recon.Fact{Asset: owner, Kind: recon.FactPodIdentity, Weight: 1}
	return recon.AssetFacts{
		Facts: []recon.Fact{fact},
		CoverByAction: map[model.Action][]string{
			model.ActionRotate:         {fact.Key()},
			model.ActionIdentityRotate: {fact.Key()},
		},
	}
}

func collisionDeps(profile recon.ReconProfile) Deps {
	return Deps{
		Recon:       profile,
		FactContext: func(*model.WorkloadView) recon.FactContext { return recon.FactContext{} },
		ECost:       func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0 },
		CHi:         func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0 },
	}
}

func TestWithinPodOverlapDoesNotRejectActionSet(t *testing.T) {
	set := collisionDeps(collisionRecon{}).Generate(
		[]*model.WorkloadView{baseView("one"), baseView("two")}, testPolicy())
	if set.Rejected || set.CollisionError() != nil {
		t.Fatalf("legal within-pod overlap rejected: %+v", set.CrossBlockCollisions)
	}
}

func TestCrossBlockCollisionRejectsActionSet(t *testing.T) {
	set := collisionDeps(collisionRecon{crossBlock: true}).Generate(
		[]*model.WorkloadView{baseView("one"), baseView("two")}, testPolicy())
	if !set.Rejected {
		t.Fatal("cross-block collision did not reject the ActionSet")
	}
	if len(set.Candidates) != 0 {
		t.Fatalf("rejected ActionSet retained %d selectable candidates", len(set.Candidates))
	}
	if len(set.CrossBlockCollisions) != 1 {
		t.Fatalf("collisions = %d, want 1: %+v", len(set.CrossBlockCollisions), set.CrossBlockCollisions)
	}
	err := set.CollisionError()
	if err == nil || !strings.Contains(err.Error(), "ns/one") || !strings.Contains(err.Error(), "ns/two") {
		t.Fatalf("collision error does not identify both blocks: %v", err)
	}
}
