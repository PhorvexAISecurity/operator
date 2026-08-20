package cost

import (
	"math"
	"testing"
)

func TestDualPolicySeedIsAppliedDefensively(t *testing.T) {
	tests := []struct {
		name string
		seed float64
		want float64
	}{
		{name: "zero is valid", seed: 0, want: 0},
		{name: "configured", seed: 0.9, want: 0.9},
		{name: "negative falls back", seed: -1, want: DefaultLambdaSeed},
		{name: "nan falls back", seed: math.NaN(), want: DefaultLambdaSeed},
		{name: "above solver range clamps", seed: 12, want: 10},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewDualSolverWithSeed(tc.seed).Lambda(); got != tc.want {
				t.Fatalf("lambda seed = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDualResistsDecoyStarvation — P-REDTEAM λ-fix: a manufactured-demand (decoy) flood can no longer
// rocket λ to the clamp. With the OLD subgradient g=(demand-budget), 6 decoys drove λ 0.6→3.6 in 12
// ticks (and on to the clamp), starving the proactive gate. With the fix the rise is capped to
// step/tick, so after 12 ticks λ is bounded far below the old trajectory.
func TestDualResistsDecoyStarvation(t *testing.T) {
	d := NewDualSolver()
	for i := 0; i < 12; i++ {
		d.Step(7, 1, 1) // 7 net-positive candidates (6 decoys + 1 real), B=1, one move spent
	}
	// fix: <= 0.6 + 12*0.05 = 1.2 ; old buggy: 0.6 + 12*6*0.05 = 4.2 (clamped path to 10).
	if got := d.Lambda(); got > 1.21 {
		t.Errorf("decoy flood pumped λ to %.3f — the starvation rocket is NOT bounded (want <=1.20)", got)
	}
	// and it must never approach the clamp under a sustained flood within a proactive-floor window.
	d2 := NewDualSolver()
	for i := 0; i < 60; i++ {
		d2.Step(50, 1, 1) // 50-decoy flood
	}
	if got := d2.Lambda(); got >= 10.0 {
		t.Errorf("a 50-decoy flood drove λ to the clamp %.1f — rocket not neutralized", got)
	}
}

// TestDualLegitimateRationingUnchanged — the fix is byte-identical to the old formula in the
// legitimate low-demand regime (|demand-budget| <= 1, which is the P3/lead-demo regime), so the
// gates that depend on the λ trajectory are preserved.
func TestDualLegitimateRationingUnchanged(t *testing.T) {
	oldStep := func(lambda float64, demand, budget int) float64 {
		l := lambda + 0.05*float64(demand-budget)/float64(budget)
		return math.Max(0, math.Min(10, l))
	}
	for _, tc := range []struct{ demand, spent int }{{2, 1}, {1, 1}, {0, 0}} { // excess in {+1,0,-1}
		d := NewDualSolver()
		want := oldStep(0.6, tc.demand, 1)
		d.Step(tc.demand, tc.spent, 1)
		if math.Abs(d.Lambda()-want) > 1e-9 {
			t.Errorf("demand=%d: λ=%.4f, old formula=%.4f — low-demand trajectory must be UNCHANGED", tc.demand, d.Lambda(), want)
		}
	}
}
