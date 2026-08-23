/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 *
 * MODULARITY PROOF: this ONE test file adds a new FeasibilityConstraint, a new
 * ReconProfile, and a new CostModel — each by a single init() Register call, with
 * ZERO change to any core file — and asserts each registry picks them up. That is the
 * "add a constraint/profile/context/cost model = one file, zero core change" guarantee.
 */

package decision

import (
	"testing"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// --- a new hard constraint (one file) ---
type noWeekendMoves struct{}

func (noWeekendMoves) Name() string { return "test-no-weekend" }
func (noWeekendMoves) Check(_ *model.WorkloadView, _ model.Move, _ model.Policy) feasibility.Verdict {
	return feasibility.Verdict{Feasible: true}
}

// --- a new recon profile (one file) ---
type minimalRecon struct{}

func (minimalRecon) Name() string { return "test-minimal-recon" }
func (minimalRecon) AssetFacts(v *model.WorkloadView, _ recon.FactContext) recon.AssetFacts {
	asset := v.Pod.Namespace + "/" + v.Pod.Name
	f := recon.Fact{Scope: recon.ScopePod, Asset: asset, Kind: recon.FactPodIdentity, Weight: 1}
	return recon.AssetFacts{
		Facts:         []recon.Fact{f},
		CoverByAction: map[model.Action][]string{model.ActionRotate: {f.Key()}},
	}
}

// --- a new cost model (one file) ---
type flatCost struct{}

func (flatCost) Name() string                                                          { return "test-flat-cost" }
func (flatCost) Switching(_ *model.WorkloadView, _ model.Move, _ model.Policy) float64 { return 0.5 }

func init() {
	feasibility.Registry.Register(noWeekendMoves{})
	recon.Registry.Register(minimalRecon{})
	cost.Registry.Register(flatCost{})
}

func TestModularityOneFileAddsAnImpl(t *testing.T) {
	if _, ok := feasibility.Registry.Get("test-no-weekend"); !ok {
		t.Errorf("a feasibility constraint added in one file should be registered")
	}
	if _, ok := recon.Registry.Get("test-minimal-recon"); !ok {
		t.Errorf("a recon profile added in one file should be registered")
	}
	if _, ok := cost.Registry.Get("test-flat-cost"); !ok {
		t.Errorf("a cost model added in one file should be registered")
	}
	// The default impls still exist (no core change displaced them).
	if _, ok := recon.Registry.Get("standard-recon"); !ok {
		t.Errorf("the default recon profile must still be registered")
	}
}
