package core

import (
	"math"
	"testing"
)

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestMeanAndStdDev(t *testing.T) {
	xs := []float64{1, 2, 3, 4, 5}
	if !almost(Mean(xs), 3) {
		t.Fatalf("mean want 3 got %v", Mean(xs))
	}
	// sample stddev of 1..5 = sqrt(10/4) = 1.5811388...
	if !almost(SampleStdDev(xs), math.Sqrt(2.5)) {
		t.Fatalf("stddev want %v got %v", math.Sqrt(2.5), SampleStdDev(xs))
	}
	if SampleStdDev([]float64{7}) != 0 {
		t.Fatalf("stddev of single sample must be 0")
	}
}

func TestConfidenceInterval_SmokeN2IsWide(t *testing.T) {
	// n=2 with the t-interval must produce a WIDE interval (t crit 12.706 at 95%).
	xs := []float64{0.0, 1.0}
	agg := ConfidenceInterval(xs, 0.95)
	if agg.N != 2 {
		t.Fatalf("N want 2 got %d", agg.N)
	}
	if !almost(agg.Mean, 0.5) {
		t.Fatalf("mean want 0.5 got %v", agg.Mean)
	}
	// stddev = sqrt(((0.5)^2+(0.5)^2)/1) = sqrt(0.5) ~ 0.7071; stderr = 0.5.
	if !almost(agg.StdErr, 0.5) {
		t.Fatalf("stderr want 0.5 got %v", agg.StdErr)
	}
	// half-width = 12.706 * 0.5 = 6.353 — honestly very wide for n=2.
	if agg.HalfWidth < 6.0 {
		t.Fatalf("n=2 t-interval should be wide, got half-width %v", agg.HalfWidth)
	}
}

func TestConfidenceInterval_DegenerateSample(t *testing.T) {
	agg := ConfidenceInterval([]float64{0.7, 0.7, 0.7}, 0.95)
	// Half-width is ~0 up to floating-point rounding of the variance sum.
	if !almost(agg.Mean, 0.7) || math.Abs(agg.HalfWidth) > 1e-9 {
		t.Fatalf("zero-variance sample must have ~zero half-width, got mean=%v hw=%v", agg.Mean, agg.HalfWidth)
	}
}

func TestConfidenceInterval_Empty(t *testing.T) {
	agg := ConfidenceInterval(nil, 0.95)
	if agg.N != 0 || agg.Mean != 0 {
		t.Fatalf("empty aggregate must be zero")
	}
}

func TestTrialSeedDeterministic(t *testing.T) {
	a := TrialSeed(1337, "scn", "def", 3)
	b := TrialSeed(1337, "scn", "def", 3)
	if a != b {
		t.Fatalf("TrialSeed not deterministic: %d != %d", a, b)
	}
	// Different inputs => (almost surely) different seeds.
	if TrialSeed(1337, "scn", "def", 4) == a {
		t.Fatalf("TrialSeed collided across trial index")
	}
	if TrialSeed(1338, "scn", "def", 3) == a {
		t.Fatalf("TrialSeed collided across master seed")
	}
}

func TestDisruptionAndCostHelpers(t *testing.T) {
	if disruption(true, false) != 1.0 {
		t.Fatalf("baseline-hit + arm-miss must be full disruption")
	}
	if disruption(true, true) != 0.0 {
		t.Fatalf("both hit => no disruption")
	}
	if disruption(false, false) != 0.0 {
		t.Fatalf("baseline-miss => no anchored disruption")
	}
	if securityPerCost(1.0, 0) != 1.0 {
		t.Fatalf("free disruption (0 actions) should score as the disruption")
	}
	if !almost(securityPerCost(1.0, 4), 0.25) {
		t.Fatalf("sec/cost want 0.25 got %v", securityPerCost(1.0, 4))
	}
}
