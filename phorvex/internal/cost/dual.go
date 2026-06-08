/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

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

// NewDualSolver returns a solver seeded at the P0 default lambda (0.6) — so untuned
// behavior matches P0 — that then adapts to the realized budget pressure.
func NewDualSolver() *DualSolver {
	return &DualSolver{lambda: 0.6, step: 0.05, min: 0, max: 10}
}

// Lambda returns the current shadow-price.
func (d *DualSolver) Lambda() float64 { return d.lambda }

// Step updates lambda from one tick's realized spend vs the budget B. If we wanted to
// fire more moves than B allowed (demand>B), lambda rises (moves are scarce); if we
// spent less than B (slack), lambda falls toward 0. demand is the number of
// net-positive eligible moves; spent is the number actually selected (<=B).
func (d *DualSolver) Step(demand, spent, budget int) {
	if budget <= 0 {
		return
	}
	// subgradient of the dual is (demand - budget): positive => constraint tight/violated
	g := float64(demand - budget)
	d.lambda += d.step * g / float64(budget)
	if d.lambda < d.min {
		d.lambda = d.min
	}
	if d.lambda > d.max {
		d.lambda = d.max
	}
	_ = spent
}
