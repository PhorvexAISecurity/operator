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

func TestDualRulingVectorsAndReasons(t *testing.T) {
	tests := []struct {
		name          string
		seed          float64
		demand, spent int
		budget        int
		wantRaw       int
		wantEffective int
		wantAfter     float64
		wantReason    string
	}{
		{name: "TV4 binding recovery", seed: 0, demand: 2, spent: 1, budget: 1,
			wantRaw: 1, wantEffective: 1, wantAfter: 0.05, wantReason: DualReasonBindingPositive},
		{name: "TV5 suppressed pressure", seed: 0, demand: 3, spent: 1, budget: 2,
			wantRaw: 1, wantEffective: 0, wantAfter: 0, wantReason: DualReasonPressureSuppressed},
		{name: "TV6 nonbinding decay", seed: 0.6, demand: 0, spent: 0, budget: 1,
			wantRaw: -1, wantEffective: -1, wantAfter: 0.55, wantReason: DualReasonNonbindingDecay},
		{name: "TV7 exact binding", seed: 0.6, demand: 1, spent: 1, budget: 1,
			wantRaw: 0, wantEffective: 0, wantAfter: 0.6, wantReason: DualReasonExactBinding},
		{name: "positive pressure capped", seed: 0.6, demand: 20, spent: 1, budget: 1,
			wantRaw: 19, wantEffective: 1, wantAfter: 0.65, wantReason: DualReasonPositiveCapped},
		{name: "negative pressure capped", seed: 0.6, demand: 0, spent: 0, budget: 3,
			wantRaw: -3, wantEffective: -1, wantAfter: 0.6 - 0.05/3, wantReason: DualReasonNegativeCapped},
		{name: "TV8 maximum clamp", seed: 9.99, demand: 2, spent: 1, budget: 1,
			wantRaw: 1, wantEffective: 1, wantAfter: 10, wantReason: DualReasonMaxClamp},
		{name: "budget nonpositive", seed: 0.6, demand: 2, spent: 0, budget: 0,
			wantRaw: 2, wantEffective: 0, wantAfter: 0.6, wantReason: DualReasonBudgetNonpositive},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDualSolverWithSeed(tc.seed)
			got := d.StepDetailed(tc.demand, tc.spent, tc.budget)
			if !got.Applied || got.RawExcess != tc.wantRaw || got.EffectiveExcess != tc.wantEffective ||
				got.UpdateReason != tc.wantReason || math.Abs(got.LambdaAfter-tc.wantAfter) > 1e-12 {
				t.Fatalf("update = %+v, want raw=%d effective=%d after=%g reason=%s",
					got, tc.wantRaw, tc.wantEffective, tc.wantAfter, tc.wantReason)
			}
			if got.LambdaBefore != tc.seed || math.Abs(d.Lambda()-tc.wantAfter) > 1e-12 {
				t.Fatalf("transition/runtime mismatch: update=%+v runtime=%g", got, d.Lambda())
			}
		})
	}
}

func TestDualPreviewIsDeterministicAndDoesNotMutate(t *testing.T) {
	d := NewDualSolverWithSeed(0)
	first := d.PreviewStep(2, 1, 1)
	second := d.PreviewStep(2, 1, 1)
	if first != second || first.Applied {
		t.Fatalf("preview is not deterministic/non-mutating: first=%+v second=%+v", first, second)
	}
	if d.Lambda() != 0 {
		t.Fatalf("preview mutated runtime lambda to %g", d.Lambda())
	}
	actual := d.StepDetailed(2, 1, 1)
	first.Applied = true
	if actual != first {
		t.Fatalf("preview/actual drift: preview=%+v actual=%+v", first, actual)
	}
}

func TestDualZeroFloorIsValid(t *testing.T) {
	d := NewDualSolver()
	for i := 0; i < 20; i++ {
		d.Step(0, 0, 1)
	}
	if got := d.Lambda(); got != 0 {
		t.Fatalf("TV9 runtime lambda = %g, want valid zero floor", got)
	}
	update := d.StepDetailed(0, 0, 1)
	if update.LambdaAfter != 0 || update.UpdateReason != DualReasonMinClamp {
		t.Fatalf("zero floor transition = %+v", update)
	}
}
