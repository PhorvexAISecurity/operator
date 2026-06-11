package soak

import "testing"

// TestFitOLSDetectsLeakAndFlat — a clean upward ramp is detected (CI excludes 0, not Flat);
// a flat-with-noise series is Flat.
func TestFitOLSDetectsLeakAndFlat(t *testing.T) {
	// leak: y grows 10 units/sec exactly.
	xs := make([]float64, 60)
	leak := make([]float64, 60)
	flat := make([]float64, 60)
	for i := 0; i < 60; i++ {
		xs[i] = float64(i)
		leak[i] = 1000 + 10*float64(i)
		flat[i] = 1000 + float64((i*7)%5) - 2 // tiny bounded sawtooth, no trend
	}
	lf := FitOLS(xs, leak)
	if lf.CILow <= 0 && lf.CIHigh >= 0 {
		t.Errorf("leak slope CI should EXCLUDE 0, got [%g,%g]", lf.CILow, lf.CIHigh)
	}
	if lf.Flat(0.10) {
		t.Errorf("a 10/sec leak (36000/hr on mean ~1300) must NOT be Flat")
	}
	ff := FitOLS(xs, flat)
	if !ff.Flat(0.10) {
		t.Errorf("a trendless bounded series must be Flat (slope/hr CI=[%g,%g], mean=%g)", PerHour(ff.CILow), PerHour(ff.CIHigh), ff.Mean)
	}
}
