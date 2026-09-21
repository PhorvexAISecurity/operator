/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import "math"

// dual.go carries the legacy runtime lambda controller. Its update signal is
// move-count pressure, while its current selection role is an ECost coefficient.
// Those resources are not formally matched, so this state is deliberately not
// described as an exact Lagrange dual. The hard move budget remains an independent
// top-B constraint in the decision engine.

// DualSolver maintains the legacy mixed runtime lambda across ticks.
type DualSolver struct {
	runtimeLegacy float64
	step          float64
	min           float64
	max           float64
}

// DualUpdate is the complete deterministic transition record for one tick.
// Demand, spent and budget are move/asset-slot counts; they are not disruption
// costs. Applied distinguishes production state mutation from a shadow preview.
type DualUpdate struct {
	Applied         bool    `json:"applied"`
	Demand          int     `json:"demand"`
	Spent           int     `json:"spent"`
	Budget          int     `json:"budget"`
	RawExcess       int     `json:"rawExcess"`
	EffectiveExcess int     `json:"effectiveExcess"`
	LambdaBefore    float64 `json:"lambdaBefore"`
	LambdaAfter     float64 `json:"lambdaAfter"`
	UpdateReason    string  `json:"updateReason"`
}

const (
	DualReasonBudgetNonpositive  = "budget_nonpositive_no_update"
	DualReasonPressureSuppressed = "positive_pressure_suppressed_spent_below_budget"
	DualReasonPositiveCapped     = "positive_pressure_capped"
	DualReasonNegativeCapped     = "negative_pressure_capped"
	DualReasonBindingPositive    = "binding_positive_update"
	DualReasonExactBinding       = "exact_binding_no_update"
	DualReasonNonbindingDecay    = "nonbinding_decay"
	DualReasonMinClamp           = "min_clamp"
	DualReasonMaxClamp           = "max_clamp"
)

// DefaultLambdaSeed preserves the shipped runtime-controller seed when
// policy.lambda is omitted.
const (
	DefaultLambdaSeed = 0.6
	LambdaStep        = 0.05
	LambdaMinimum     = 0.0
	LambdaMaximum     = 10.0
	LambdaMaxExcess   = 1
)

// NewDualSolver returns a solver seeded at the P0 default lambda (0.6) — so untuned
// behavior matches P0 — that then adapts to the realized budget pressure.
func NewDualSolver() *DualSolver {
	return NewDualSolverWithSeed(DefaultLambdaSeed)
}

// NewDualSolverWithSeed starts the legacy runtime state from the tenant policy's lambda.
// The seed is read once when the tenant bucket is created; subsequent policy reconciles
// do not erase the runtime state learned from realized budget pressure.
func NewDualSolverWithSeed(seed float64) *DualSolver {
	if math.IsNaN(seed) || math.IsInf(seed, 0) || seed < 0 {
		seed = DefaultLambdaSeed
	}
	if seed > LambdaMaximum {
		seed = LambdaMaximum
	}
	return &DualSolver{runtimeLegacy: seed, step: LambdaStep, min: LambdaMinimum, max: LambdaMaximum}
}

// Lambda returns the legacy mixed runtime value. The method name is retained for
// source compatibility; audit and documentation use lambdaRuntimeLegacy.
func (d *DualSolver) Lambda() float64 { return d.runtimeLegacy }

// transition computes one legacy controller update. demand is the number of
// assets with a positive standalone full-value score; spent is the number of
// selected assets; budget is the unit-count MaxMovesPerTick limit.
// [P-REDTEAM λ-starvation FIX — explicitly-gated brain change] The dual subgradient is now BOUNDED
// and gated on the budget being genuinely BINDING (the SELECTED set's economics), so an attacker
// cannot manufacture demand to rocket λ and starve a due rotation into NOOP.
//
// THE BUG: previously g=(demand-budget) was UNBOUNDED in demand and `spent` was ignored. `demand`
// counts EVERY asset with a positive standalone covValue-λ·ECost (coverage.go:181-194), including
// never-selected ones. So K net-positive DECOY pods pumped λ by ~K·step/tick toward the clamp; once
// λ becomes large enough, the strict selection score gain=marginal*prov-λ*ECost
// becomes non-positive. Verified: 6 decoys drove λ 0.6→3.6 in 12 ticks.
//
// THE FIX: (1) the price only RISES when the budget is actually binding — spent>=budget (the selected
// set consumed the whole budget) AND positive-net candidates were excluded; (2) the per-tick
// subgradient is CLAMPED to maxExcess, so a decoy flood raises λ by at most maxExcess·step/tick
// (matched by the slack-decay) regardless of decoy count. For legitimately small over-demand
// (excess<=maxExcess — the P3/lead-demo regime) the trajectory is byte-UNCHANGED; only a manufactured
// flood is capped. No learning enters the decision path; lambda remains a deterministic integrator.
func (d *DualSolver) transition(demand, spent, budget int) DualUpdate {
	update := DualUpdate{
		Demand:       demand,
		Spent:        spent,
		Budget:       budget,
		RawExcess:    demand - budget,
		LambdaBefore: d.runtimeLegacy,
		LambdaAfter:  d.runtimeLegacy,
	}
	if budget <= 0 {
		update.UpdateReason = DualReasonBudgetNonpositive
		return update
	}
	const maxExcess = LambdaMaxExcess // cap the manufacturable rise to one step/tick (== the slack-decay rate)
	excess := update.RawExcess
	switch {
	case excess > 0 && spent < budget:
		excess = 0 // budget not fully consumed => not actually binding => do not raise the price
		update.UpdateReason = DualReasonPressureSuppressed
	case excess > maxExcess:
		excess = maxExcess // clamp the decoy-pumpable rocket
		update.UpdateReason = DualReasonPositiveCapped
	case excess < -1:
		excess = -1 // symmetric: bound the decay too
		update.UpdateReason = DualReasonNegativeCapped
	case excess > 0:
		update.UpdateReason = DualReasonBindingPositive
	case excess == 0:
		update.UpdateReason = DualReasonExactBinding
	default:
		update.UpdateReason = DualReasonNonbindingDecay
	}
	update.EffectiveExcess = excess
	update.LambdaAfter += d.step * float64(excess) / float64(budget)
	if update.LambdaAfter < d.min {
		update.LambdaAfter = d.min
		update.UpdateReason = DualReasonMinClamp
	}
	if update.LambdaAfter > d.max {
		update.LambdaAfter = d.max
		update.UpdateReason = DualReasonMaxClamp
	}
	return update
}

// PreviewStep returns the exact transition without mutating runtime state.
func (d *DualSolver) PreviewStep(demand, spent, budget int) DualUpdate {
	return d.transition(demand, spent, budget)
}

// StepDetailed applies one transition and returns its complete audit record.
func (d *DualSolver) StepDetailed(demand, spent, budget int) DualUpdate {
	update := d.transition(demand, spent, budget)
	d.runtimeLegacy = update.LambdaAfter
	update.Applied = true
	return update
}

// Step retains the existing caller contract.
func (d *DualSolver) Step(demand, spent, budget int) {
	d.StepDetailed(demand, spent, budget)
}
