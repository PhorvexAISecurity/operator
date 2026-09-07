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

// CheckedOptimizer is implemented by brains whose dynamic substrate can be structurally
// invalid. The runner uses this seam to reject the whole tick instead of treating an
// invalid empty set as an ordinary no-op decision.
type CheckedOptimizer interface {
	Optimizer
	DecideChecked(views []*model.WorkloadView, pol model.Policy) ([]model.Decision, error)
}

// ShadowCheckedOptimizer evaluates the same state and substrate without persisting dual-price
// or kill-chain-memory updates. It lets calibration compare candidate scales without teaching the
// production optimizer from a decision that was never actuated.
type ShadowCheckedOptimizer interface {
	CheckedOptimizer
	DecideShadowChecked(views []*model.WorkloadView, pol model.Policy) ([]model.Decision, error)
}

// RotationObserver is the optional feedback seam implemented by an optimizer with
// an online rotation-cost learner. The runner invokes it only for completed,
// measured live rotations; a stateless optimizer need not implement it.
type RotationObserver interface {
	ObserveRotation(tenant string, view *model.WorkloadView, measuredFlow float64)
}

var _ Optimizer = (*CoverageEngine)(nil)
var _ CheckedOptimizer = (*CoverageEngine)(nil)
var _ ShadowCheckedOptimizer = (*CoverageEngine)(nil)
var _ RotationObserver = (*CoverageEngine)(nil)
