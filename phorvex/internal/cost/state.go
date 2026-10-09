/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import (
	"fmt"
	"math"
)

// state.go exports and restores the complete learned state of one cost bucket so an
// offline replay can price a recorded tick exactly as production priced it (Math Lab
// snapshot replay). Export is a pure copy: it never folds, freezes or reseeds anything.
// Restore builds NEW objects; it never mutates a live bucket.

// RLSState is the complete recursive-least-squares state, including the forgetting
// factor and the freeze switch, so a restored learner predicts bit-identically.
type RLSState struct {
	Theta   [featureDim]float64
	P       [featureDim][featureDim]float64
	FF      float64
	Primed  bool
	Updates int
	Frozen  bool
}

// ConformalState is the residual window plus its configuration.
type ConformalState struct {
	Residuals []float64
	Cap       int
	Alpha     float64
}

// DualState is the legacy runtime lambda controller state.
type DualState struct {
	RuntimeLegacy float64
	Step          float64
	Min           float64
	Max           float64
}

// P1CostState is the complete state of one per-owner cost bucket.
type P1CostState struct {
	HasRLS       bool
	RLS          RLSState
	HasConformal bool
	Conformal    ConformalState
	HasDual      bool
	Dual         DualState
}

// State returns a copy of the learner state.
func (r *RLS) State() RLSState {
	return RLSState{Theta: r.theta, P: r.p, FF: r.ff, Primed: r.primed, Updates: r.updates, Frozen: r.frozen}
}

// RestoreRLS builds a learner from an exported state. The state is validated rather than
// trusted: a non-finite parameter would make Predict serve a value production never saw.
func RestoreRLS(s RLSState) (*RLS, error) {
	for i := 0; i < featureDim; i++ {
		if !finite(s.Theta[i]) {
			return nil, fmt.Errorf("rls theta[%d] is not finite", i)
		}
		for j := 0; j < featureDim; j++ {
			if !finite(s.P[i][j]) {
				return nil, fmt.Errorf("rls covariance[%d][%d] is not finite", i, j)
			}
		}
	}
	if !finite(s.FF) || s.FF <= 0 || s.FF > 1 {
		return nil, fmt.Errorf("rls forgetting factor %v outside (0,1]", s.FF)
	}
	if s.Updates < 0 {
		return nil, fmt.Errorf("rls update count %d is negative", s.Updates)
	}
	return &RLS{theta: s.Theta, p: s.P, ff: s.FF, primed: s.Primed, updates: s.Updates, frozen: s.Frozen}, nil
}

// State returns a copy of the residual window and its configuration.
func (c *ConformalBound) State() ConformalState {
	return ConformalState{Residuals: append([]float64(nil), c.residuals...), Cap: c.cap, Alpha: c.alpha}
}

// RestoreConformal builds a bound from an exported state.
func RestoreConformal(s ConformalState) (*ConformalBound, error) {
	if s.Cap <= 0 {
		return nil, fmt.Errorf("conformal window capacity %d is not positive", s.Cap)
	}
	if len(s.Residuals) > s.Cap {
		return nil, fmt.Errorf("conformal window holds %d residuals above capacity %d", len(s.Residuals), s.Cap)
	}
	if !finite(s.Alpha) || s.Alpha <= 0 || s.Alpha >= 1 {
		return nil, fmt.Errorf("conformal alpha %v outside (0,1)", s.Alpha)
	}
	for i, r := range s.Residuals {
		if !finite(r) || r < 0 {
			return nil, fmt.Errorf("conformal residual[%d]=%v is not a finite non-negative value", i, r)
		}
	}
	return &ConformalBound{residuals: append([]float64(nil), s.Residuals...), cap: s.Cap, alpha: s.Alpha}, nil
}

// State returns a copy of the controller state.
func (d *DualSolver) State() DualState {
	return DualState{RuntimeLegacy: d.runtimeLegacy, Step: d.step, Min: d.min, Max: d.max}
}

// RestoreDual builds a controller from an exported state without the seed clamping
// NewDualSolverWithSeed applies: the exported value already passed that clamp once.
func RestoreDual(s DualState) (*DualSolver, error) {
	for name, v := range map[string]float64{"lambda": s.RuntimeLegacy, "step": s.Step, "min": s.Min, "max": s.Max} {
		if !finite(v) {
			return nil, fmt.Errorf("dual %s is not finite", name)
		}
	}
	if s.Min > s.Max || s.RuntimeLegacy < s.Min || s.RuntimeLegacy > s.Max {
		return nil, fmt.Errorf("dual lambda %v outside [%v,%v]", s.RuntimeLegacy, s.Min, s.Max)
	}
	return &DualSolver{runtimeLegacy: s.RuntimeLegacy, step: s.Step, min: s.Min, max: s.Max}, nil
}

// State returns a copy of every learner in the bucket.
func (c *P1Cost) State() P1CostState {
	var out P1CostState
	if c.RLS != nil {
		out.HasRLS, out.RLS = true, c.RLS.State()
	}
	if c.Conformal != nil {
		out.HasConformal, out.Conformal = true, c.Conformal.State()
	}
	if c.Dual != nil {
		out.HasDual, out.Dual = true, c.Dual.State()
	}
	return out
}

// RestoreP1Cost builds a new bucket from an exported state.
func RestoreP1Cost(s P1CostState) (*P1Cost, error) {
	out := &P1Cost{}
	var err error
	if s.HasRLS {
		if out.RLS, err = RestoreRLS(s.RLS); err != nil {
			return nil, err
		}
	}
	if s.HasConformal {
		if out.Conformal, err = RestoreConformal(s.Conformal); err != nil {
			return nil, err
		}
	}
	if s.HasDual {
		if out.Dual, err = RestoreDual(s.Dual); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
