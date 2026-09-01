/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package cost is the swappable COST surface (PRD §5.1B: the switching-cost matrix
// K(i->j) that R6 lacks entirely). A CostModel returns a bounded, dimensionless
// disruption-loss score for mutating a pod now. Restart/recovery, connection,
// serving-state and GPU/LLM signals are normalized before entering this score. It lets
// Phorvex rotate the right pod at the right MOMENT (high risk AND low cost) instead
// of blindly.
//
// Add a model = add ONE file with an init() that calls Registry.Register.
package cost

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/registry"
)

// CostModel computes the per-move switching cost.
type CostModel interface {
	registry.Named
	// Switching returns K in [0, ~1+]: the normalized disruption cost of applying
	// move to this pod now. Quarantine and rotate carry different costs.
	Switching(view *model.WorkloadView, move model.Move, pol model.Policy) float64
}

// Registry holds the registered CostModels.
var Registry = registry.New[CostModel]()
