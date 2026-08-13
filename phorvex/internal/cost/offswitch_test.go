package cost

import (
	"math"
	"testing"
)

// offswitch_test.go — PHVX-2 / PHORVEXSEC-84 step 3.
//
// The ticket's "Done when" asks for theta that demonstrably adapts *with a documented off-switch*.
// Adaptation was already proven on the live cluster; this file covers the other half. Before it there
// was no revert, no disable and no freeze anywhere in this package — only Predict's OUTPUT clamp,
// which bounds the symptom rather than the parameter.

func obs() ([featureDim]float64, float64) {
	var f [featureDim]float64
	f[0], f[2], f[4] = 1, 1, 1 // bias + warm + gpu
	return f, 0.05
}

// TestFreezeRevertsToPrior is the core of the off-switch: freezing must reproduce the shipped
// nil-data behaviour EXACTLY, not hold whatever was learned before the operator lost trust in it.
func TestFreezeRevertsToPrior(t *testing.T) {
	r := NewRLS()
	f, y := obs()
	before := r.Predict(f)
	for i := 0; i < 50; i++ {
		r.Update(f, y)
	}
	learned := r.Predict(f)
	if math.Abs(learned-before) < 1e-6 {
		t.Fatalf("the fixture did not move theta (%.6f -> %.6f); the test would prove nothing", before, learned)
	}
	r.SetFrozen(true)
	if got := r.Predict(f); math.Abs(got-before) > 1e-12 {
		t.Fatalf("after freezing, Predict must return the PRIOR %.12f exactly; got %.12f", before, got)
	}
	if r.Primed() {
		t.Error("a frozen learner must report itself as uncalibrated, not primed")
	}
}

// TestFrozenLearnerIgnoresObservations pins that freezing actually stops learning rather than only
// resetting once.
func TestFrozenLearnerIgnoresObservations(t *testing.T) {
	r := NewRLS()
	r.SetFrozen(true)
	f, y := obs()
	prior := r.Predict(f)
	for i := 0; i < 100; i++ {
		r.Update(f, y)
	}
	if got := r.Predict(f); math.Abs(got-prior) > 1e-12 {
		t.Fatalf("a frozen learner moved from %.12f to %.12f — Update is not suppressed", prior, got)
	}
	if !r.Frozen() {
		t.Error("Frozen() must report the state so it can be surfaced in audit")
	}
}

// TestUnfreezingResumesFromThePrior documents the deliberate choice that this is a safety control,
// not a pause button: it does not restore the discarded calibration.
func TestUnfreezingResumesFromThePrior(t *testing.T) {
	r := NewRLS()
	f, y := obs()
	prior := r.Predict(f)
	for i := 0; i < 50; i++ {
		r.Update(f, y)
	}
	r.SetFrozen(true)
	r.SetFrozen(false)
	if got := r.Predict(f); math.Abs(got-prior) > 1e-12 {
		t.Fatalf("unfreezing must resume from the prior (%.12f), not the discarded estimate; got %.12f", prior, got)
	}
	r.Update(f, y)
	if !r.Primed() {
		t.Error("after unfreezing, a real observation must prime the learner again")
	}
}

// TestSingleObservationCannotSwingTheta is the rate limit. Predict's clamp bounds the OUTPUT; nothing
// bounded the PARAMETER, so one pathological measurement — a pod that took 300s to become Ready
// because its node was draining — could reprice a whole tenant in a single step.
func TestSingleObservationCannotSwingTheta(t *testing.T) {
	r := NewRLS()
	var f [featureDim]float64
	f[0], f[1] = 1, 1
	beforeTheta := r.theta
	r.Update(f, 1000) // absurd observation
	for i := range beforeTheta {
		if moved := math.Abs(r.theta[i] - beforeTheta[i]); moved > maxThetaStep+1e-12 {
			t.Fatalf("theta[%d] moved %.6f in ONE update, above the %.2f cap — an outlier can still reprice a tenant",
				i, moved, maxThetaStep)
		}
	}
}

// TestRateLimitStillConverges guards the other side: the cap must slow a single outlier without
// preventing a real trend from being learned. If this fails the cap is too tight to be useful.
func TestRateLimitStillConverges(t *testing.T) {
	r := NewRLS()
	f, y := obs()
	for i := 0; i < 200; i++ {
		r.Update(f, y)
	}
	if got := r.Predict(f); math.Abs(got-y) > 0.02 {
		t.Fatalf("with the rate limit in place the estimate still has to converge toward the observed %.3f; got %.6f", y, got)
	}
}
