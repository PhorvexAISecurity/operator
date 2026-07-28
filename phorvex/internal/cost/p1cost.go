/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import "github.com/phorvex/phorvex/internal/model"

// P1Cost is the assembled P1 cost model: C = normSparsity*C_norm + flowDisruption*
// C_flow, where C_flow is an RLS-shaped FIXED PRIOR today (the update path exists but has no
// callers — see ObserveRotation), lambda is the dual-descent shadow-price, and CHi is the
// conformal robust upper bound used by the HARD SLO gate. It is a
// stateful object (the RLS, conformal window and dual persist across ticks) owned by
// the decision engine.
type P1Cost struct {
	RLS       *RLS
	Conformal *ConformalBound
	Dual      *DualSolver
}

// NewP1Cost constructs the P1 cost model seeded at the P0-equivalent prior.
func NewP1Cost() *P1Cost {
	return &P1Cost{RLS: NewRLS(), Conformal: NewConformalBound(), Dual: NewDualSolver()}
}

// normCost is the structural C_norm = fraction of live exposure variables a move
// resets (rotate moves all; quarantine flips only the network share). Shared with the
// P0 switching model's intuition.
func normCostP1(move model.Move) float64 {
	live := len(model.LiveExposureVariables)
	if live == 0 {
		live = 1
	}
	switch move.Action {
	case model.ActionRotate:
		return 1.0
	case model.ActionQuarantine:
		return 1.0 / float64(live+1)
	default:
		return 0
	}
}

// ECost is the expected (objective) cost of a move: the calibrated point estimate.
func (c *P1Cost) ECost(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	if move.Action == model.ActionNoop {
		return 0
	}
	cNorm := normCostP1(move)
	cFlow := 0.0
	if move.Action == model.ActionQuarantine {
		// Quarantine does not pay a warm-load; small, phase-independent flow hit.
		cFlow = 0.25
		if view.Telemetry.Present {
			cFlow += 0.15 * sat(view.Telemetry.ConnCount/100.0)
		}
	} else {
		cFlow = c.RLS.Predict(Features(view))
	}
	return pol.NormSparsity*cNorm + pol.FlowDisruption*cFlow
}

// CHi is the conformal robust UPPER bound used by the hard SLO/feasibility gate. For a
// rotate it adds the conformal slack (which, cold-start, is the [SP-0-PENDING] GPU
// envelope) on top of E[C]; for a GPU pod the envelope dominates until SP-0 measures
// the real warm-load. NEVER a fabricated number — a declared fail-safe ceiling.
func (c *P1Cost) CHi(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	e := c.ECost(view, move, pol)
	if move.Action != model.ActionRotate {
		return e
	}
	slack := c.Conformal.Quantile()
	// CHi >= ECost is the SLO contract: the robust UPPER bound must never sit below the point
	// estimate. That holds today because ConformalBound.Observe stores |residual|, so Quantile()
	// is an order statistic over non-negative values (verified by test, not assumed). This clamp
	// is belt-and-braces: it keeps the contract true by construction if that ever changes.
	if slack < 0 {
		slack = 0
	}
	if view.Pod.HasGPU && !c.RLS.Primed() {
		// Unmeasured GPU warm-load: the worst-case envelope applies.
		slack = maxf(slack, pol.FlowDisruption*GPUEnvelopeMax)
	}
	return e + slack
}

// ObserveRotation folds a measured rotation disruption into the calibrators (offline
// cadence). measuredFlow is the real C_flow proxy (e.g. normalized time-to-Ready of
// the replacement). A no-op if the measurement is unavailable (dry-run): the model
// stays honestly at its prior.
//
// [SP-0-PENDING-P4a] UNWIRED: as of P4a this method has ZERO callers in the operator
// loop, so the RLS C_flow calibrator never self-updates — C_flow stays a permanent PRIOR,
// not a live-calibrated value. Wiring a post-actuation measured-flow callback is a P4a/P4b
// follow-up; until then C_flow must NOT be presented as "self-calibrating today."
func (c *P1Cost) ObserveRotation(view *model.WorkloadView, measuredFlow float64) {
	f := Features(view)
	pred := c.RLS.Predict(f)
	c.Conformal.Observe(measuredFlow - pred)
	c.RLS.Update(f, measuredFlow)
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// --- modularity: register a CostModel wrapper so "add a cost model = one file" holds.
// The wrapper is stateless (a fresh P1Cost per call returns the PRIOR estimate); the
// stateful calibrating instance is owned by the engine. This entry just proves the P1
// cost is a registered, swappable CostModel.
type p1CostModel struct{}

func (p1CostModel) Name() string { return "rls-dual-conformal" }
func (p1CostModel) Switching(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	return NewP1Cost().ECost(view, move, pol)
}

func init() { Registry.Register(p1CostModel{}) }
