/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package feasibility is the swappable FEASIBILITY surface (PRD §5.1A: the hard laws
// — never propose an infeasible move). Each FeasibilityConstraint vetoes a proposed
// move that would violate availability, SLO, the anti-over-rotation/forensic window,
// or stateful integrity. This is the layer that directly fixes R6 pain point #4
// (R6's static action list can prescribe a physically impossible action).
//
// Add a constraint = add ONE file with an init() that calls Registry.Register. The
// decision engine runs Registry.All() (deterministic order) and the FIRST veto wins.
package feasibility

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/registry"
)

// Verdict is a constraint's ruling on a move.
type Verdict struct {
	Feasible bool
	// Reason is a short machine-stable explanation when Feasible is false.
	Reason string
}

// feasible is the universal "ok" verdict.
var feasible = Verdict{Feasible: true}

// FeasibilityConstraint vetoes infeasible moves.
type FeasibilityConstraint interface {
	registry.Named
	// Check returns a non-feasible Verdict (with a reason) iff this constraint
	// forbids the move on this pod under this policy. A noop move is always feasible.
	Check(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict
}

// Registry holds the registered FeasibilityConstraints.
var Registry = registry.New[FeasibilityConstraint]()

// Evaluate runs ALL registered constraints in deterministic order and returns the
// first veto, or a feasible verdict. A noop short-circuits to feasible.
func Evaluate(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict {
	if move.Action == model.ActionNoop {
		return feasible
	}
	for _, c := range Registry.All() {
		if v := c.Check(view, move, pol); !v.Feasible {
			return v
		}
	}
	return feasible
}
