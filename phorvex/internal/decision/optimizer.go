/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package decision

import "github.com/phorvex/phorvex/internal/model"

// Optimizer is the swappable BRAIN: it turns the per-tick WorkloadViews + resolved
// Policy into one Decision per pod (with at most MaxMovesPerTick selected). The P0
// greedy (Engine) and the P1 submodular coverage engine (CoverageEngine) both
// implement it, so the runner can be pointed at either via one flag — and a future
// brain drops in the same way.
type Optimizer interface {
	Name() string
	Decide(views []*model.WorkloadView, pol model.Policy) []model.Decision
}

// Name implements Optimizer for the P0 greedy engine.
func (*Engine) Name() string { return "p0-greedy" }

var _ Optimizer = (*Engine)(nil)
var _ Optimizer = (*CoverageEngine)(nil)
