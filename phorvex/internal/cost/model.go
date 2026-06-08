/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package cost is the swappable COST surface (PRD §5.1B: the switching-cost matrix
// K(i->j) that R6 lacks entirely). A CostModel returns the disruption cost of
// mutating a pod NOW — restart seconds + dropped connections for general K8s; KV-
// cache rebuild + model warm-load dominate for GPU/LLM. This is the term that lets
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
