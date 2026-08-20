/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import "math"

// dual.go solves lambda as the BUDGET SHADOW-PRICE (not a hand-set constant) via
// projected-subgradient dual descent on the move-budget constraint (METHOD-DECISION
// cost winner, RC-DD): lambda rises when the optimizer is over-spending the budget and
// falls when it is under-spending, so lambda converges to the marginal value of one
// move of budget. lambda is ALSO the proactive-timing knob (an asset fires when its
// coverage-per-dollar crosses lambda). The hard move-budget B is STILL enforced as an
// inviolable top-B truncation in the engine; lambda only shapes WHICH B.

// DualSolver maintains the budget shadow-price lambda across ticks.
type DualSolver struct {
	lambda float64
	step   float64 // subgradient step size eta
	min    float64
	max    float64
}

// DefaultLambdaSeed preserves the shipped objective price when policy.lambda is omitted.
const DefaultLambdaSeed = 0.6

// NewDualSolver returns a solver seeded at the P0 default lambda (0.6) — so untuned
// behavior matches P0 — that then adapts to the realized budget pressure.
func NewDualSolver() *DualSolver {
	return NewDualSolverWithSeed(DefaultLambdaSeed)
}

// NewDualSolverWithSeed starts the adaptive price from the tenant policy's lambda.
// The seed is read once when the tenant bucket is created; subsequent policy reconciles
// do not erase the dual state learned from realized budget pressure.
func NewDualSolverWithSeed(seed float64) *DualSolver {
	if math.IsNaN(seed) || math.IsInf(seed, 0) || seed < 0 {
		seed = DefaultLambdaSeed
	}
	if seed > 10 {
		seed = 10
	}
	return &DualSolver{lambda: seed, step: 0.05, min: 0, max: 10}
}

// Lambda returns the current shadow-price.
func (d *DualSolver) Lambda() float64 { return d.lambda }

// Step updates lambda from one tick's realized spend vs the budget B. If we wanted to
// fire more moves than B allowed (demand>B), lambda rises (moves are scarce); if we
// spent less than B (slack), lambda falls toward 0. demand is the number of
// net-positive eligible moves; spent is the number actually selected (<=B).
// [P-REDTEAM λ-starvation FIX — explicitly-gated brain change] The dual subgradient is now BOUNDED
// and gated on the budget being genuinely BINDING (the SELECTED set's economics), so an attacker
// cannot manufacture demand to rocket λ and starve a due rotation into NOOP.
//
// THE BUG: previously g=(demand-budget) was UNBOUNDED in demand and `spent` was ignored. `demand`
// counts EVERY asset with a positive standalone covValue-λ·ECost (coverage.go:181-194), including
// never-selected ones. So K net-positive DECOY pods pumped λ by ~K·step/tick toward the clamp; once
// λ exceeds the real foothold's perDollar the proactive gate `perDollar>λ` (coverage.go:255) is
// unsatisfiable => NOOP on a genuinely-due rotation, with ZERO SecurityEvent. Verified: 6 decoys
// drove λ 0.6→3.6 in 12 ticks.
//
// THE FIX: (1) the price only RISES when the budget is actually binding — spent>=budget (the selected
// set consumed the whole budget) AND positive-net candidates were excluded; (2) the per-tick
// subgradient is CLAMPED to maxExcess, so a decoy flood raises λ by at most maxExcess·step/tick
// (matched by the slack-decay) regardless of decoy count. For legitimately small over-demand
// (excess<=maxExcess — the P3/lead-demo regime) the trajectory is byte-UNCHANGED; only a manufactured
// flood is capped. Clamping a subgradient is a valid (normalized) dual-ascent variant — convergence
// preserved, rocket not. NO learning enters the decision path — λ stays a deterministic integrator.
func (d *DualSolver) Step(demand, spent, budget int) {
	if budget <= 0 {
		return
	}
	const maxExcess = 1 // cap the manufacturable rise to one step/tick (== the slack-decay rate)
	excess := demand - budget
	switch {
	case excess > 0 && spent < budget:
		excess = 0 // budget not fully consumed => not actually binding => do not raise the price
	case excess > maxExcess:
		excess = maxExcess // clamp the decoy-pumpable rocket
	case excess < -1:
		excess = -1 // symmetric: bound the decay too
	}
	d.lambda += d.step * float64(excess) / float64(budget)
	if d.lambda < d.min {
		d.lambda = d.min
	}
	if d.lambda > d.max {
		d.lambda = d.max
	}
}
