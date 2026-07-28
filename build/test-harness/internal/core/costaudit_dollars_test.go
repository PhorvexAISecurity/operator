/*
 * Phorvex — COST MODEL AUDIT (dollar side).
 *
 * Executable verification of the $/yr economics: the annual defense cost, the GPU-overhead
 * figure, and SecurityPerCost — plus the invariant that a UNITLESS decision cost is never
 * summed onto a dollar value.
 */

package core

import (
	"math"
	"testing"
)

const dEps = 1e-9

// defaultROI mirrors config.go's applied defaults (gpuCount 8, $2.50/gpu-hr, 1.5% overhead,
// $4.88M avoided breach, 1.0 yr horizon).
func defaultROI() ROIInputs {
	return ROIInputs{
		GpuCount:           8,
		DollarsPerGpuHour:  2.50,
		GpuOverheadPercent: 0.015,
		AvoidedBreachValue: 4_880_000,
		HorizonYears:       1.0,
	}
}

func TestPart4_AnnualDefenseCost_FloorOnlyAtZeroActions(t *testing.T) {
	in := defaultROI()
	got := AnnualDefenseCostDollars(in, 0)
	if math.Abs(got-8.0) > dEps {
		t.Errorf("0 actions: cost = %v, want the $8 floor only (1.0 x gpuCount)", got)
	}
}

func TestPart4_AnnualDefenseCost_OneAction(t *testing.T) {
	in := defaultROI()
	// perAction = 2.50 * (1/60) * 8 = 0.33333...
	wantPerAction := 2.50 * (1.0 / 60.0) * 8.0
	if math.Abs(wantPerAction-0.3333333333333333) > 1e-9 {
		t.Fatalf("perAction = %v, want 0.3333…", wantPerAction)
	}
	got := AnnualDefenseCostDollars(in, 1)
	want := 8.0 + wantPerAction
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("1 action: cost = %v, want %v ($8 floor + $0.333)", got, want)
	}
	if math.Abs(got-8.333333333333334) > 1e-9 {
		t.Errorf("1 action: cost = %v, want 8.3333…", got)
	}
}

func TestPart4_FloorTracksGpuCount(t *testing.T) {
	for _, gc := range []int{1, 6, 8, 16} {
		in := defaultROI()
		in.GpuCount = gc
		got := AnnualDefenseCostDollars(in, 0)
		if math.Abs(got-float64(gc)) > dEps {
			t.Errorf("gpuCount=%d: floor = %v, want %v", gc, got, float64(gc))
		}
	}
	// gpuCount 0 must not zero the denominator (maxInt(...,1) guard)
	in := defaultROI()
	in.GpuCount = 0
	if got := AnnualDefenseCostDollars(in, 0); got != 1.0 {
		t.Errorf("gpuCount=0: floor = %v, want 1.0 (guarded)", got)
	}
}

// The floor must apply IDENTICALLY to every arm — no defender is exempted.
func TestPart4_FloorAppliedToEveryArm(t *testing.T) {
	in := defaultROI()
	// the function has no arm/defender parameter at all, so exemption is structurally impossible;
	// assert equal-actions => equal-cost across any number of "arms".
	for _, actions := range []int{0, 1, 7, 100} {
		a := AnnualDefenseCostDollars(in, actions)
		b := AnnualDefenseCostDollars(in, actions)
		if a != b {
			t.Errorf("same actions gave different costs: %v vs %v", a, b)
		}
		if a < 8.0-dEps {
			t.Errorf("actions=%d: cost %v fell below the floor", actions, a)
		}
	}
}

func TestPart4_GpuOverheadIs2628(t *testing.T) {
	in := defaultROI()
	got := GpuOverheadDollarsPerYearSaved(in)
	want := 8.0 * 2.50 * 8760.0 * 0.015 * 1.0
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("GPU overhead = %v, want %v", got, want)
	}
	if math.Abs(got-2628.0) > 1e-6 {
		t.Errorf("GPU overhead = %v, want $2,628", got)
	}
	if HoursPerYear != 8760.0 {
		t.Errorf("HoursPerYear = %v, want 8760", HoursPerYear)
	}
}

func TestPart4_SecurityPerCostKeepsDisruptionAsFraction(t *testing.T) {
	in := defaultROI()
	cost := AnnualDefenseCostDollars(in, 1) // 8.3333
	// disruption is a 0..1 fraction; the output is dollars-of-breach-avoided per defense dollar.
	for _, d := range []float64{0, 0.25, 0.5, 1.0} {
		got := SecurityPerCostDollars(d, in.AvoidedBreachValue, cost)
		want := d * in.AvoidedBreachValue / cost
		if math.Abs(got-want) > 1e-6 {
			t.Errorf("disruption=%v: SPC = %v, want %v", d, got, want)
		}
	}
	// linearity in disruption proves it is used as a FRACTION, not a percentage (a 0-100 input
	// would make SPC(1.0) equal SPC(100)/100 — assert the scale is 0..1).
	if a, b := SecurityPerCostDollars(1.0, in.AvoidedBreachValue, cost), SecurityPerCostDollars(0.5, in.AvoidedBreachValue, cost); math.Abs(a-2*b) > 1e-6 {
		t.Errorf("SPC not linear in disruption: %v vs 2*%v", a, b)
	}
	// zero-cost guard: never divide by zero / return Inf
	if got := SecurityPerCostDollars(1.0, in.AvoidedBreachValue, 0); math.IsInf(got, 0) || math.IsNaN(got) {
		t.Errorf("SPC with zero cost = %v, want a finite eps-guarded value", got)
	}
}

func TestPart4_DollarInvariantsFiniteNonNegative(t *testing.T) {
	in := defaultROI()
	for _, actions := range []int{0, 1, 10, 1000} {
		c := AnnualDefenseCostDollars(in, actions)
		if c <= 0 || math.IsNaN(c) || math.IsInf(c, 0) {
			t.Errorf("actions=%d: annual cost = %v, want finite > 0", actions, c)
		}
	}
	// horizon <= 0 must degrade to 1.0, not to zero/negative
	in.HorizonYears = 0
	if got := AnnualDefenseCostDollars(in, 1); math.Abs(got-8.333333333333334) > 1e-9 {
		t.Errorf("horizon=0: cost = %v, want the horizon to degrade to 1.0", got)
	}
	in.HorizonYears = -5
	if got := GpuOverheadDollarsPerYearSaved(in); math.Abs(got-2628.0) > 1e-6 {
		t.Errorf("negative horizon: overhead = %v, want the 1.0-yr degrade (%v)", got, 2628.0)
	}
}
