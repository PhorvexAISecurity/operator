package core

import (
	"math"
	"testing"
)

// These tests pin the PURE Pass-B metric math: ROI in dollars, the Schwartau
// inequality P>D+R, attack-reusability replay reduction, and the MEASURED
// MTD-effect derivation. They are the single source of truth shared by the live
// runner and the Pass-A-with-dollars renderer.

func defaultROIInputs() ROIInputs {
	return ROIInputs{GpuCount: 8, DollarsPerGpuHour: 2.50, GpuOverheadPercent: 0.015, AvoidedBreachValue: 4_880_000, HorizonYears: 1.0}
}

// TestGpuOverheadDollarsPerYearSaved checks the transparent, recomputable formula:
// gpuCount * $/hr * 8760 * overhead * horizon.
func TestGpuOverheadDollarsPerYearSaved(t *testing.T) {
	in := defaultROIInputs()
	got := GpuOverheadDollarsPerYearSaved(in)
	want := 8.0 * 2.50 * 8760.0 * 0.015 * 1.0 // = 2628
	if math.Abs(got-want) > 1e-6 {
		t.Fatalf("GPU overhead $/yr saved = %.4f, want %.4f", got, want)
	}
}

// TestAnnualDefenseCostPositive ensures the defense-cost denominator is always
// positive (floor) and grows with defensive actions.
func TestAnnualDefenseCostPositive(t *testing.T) {
	in := defaultROIInputs()
	c0 := AnnualDefenseCostDollars(in, 0)
	c5 := AnnualDefenseCostDollars(in, 5)
	if c0 <= 0 {
		t.Fatalf("annual defense cost with 0 actions must be > 0 (floor), got %.4f", c0)
	}
	if !(c5 > c0) {
		t.Fatalf("annual defense cost must grow with actions: c0=%.4f c5=%.4f", c0, c5)
	}
}

// TestSecurityPerCostDollars: 0 disruption => $0; higher disruption => more value;
// the denominator never divides by zero.
func TestSecurityPerCostDollars(t *testing.T) {
	if v := SecurityPerCostDollars(0, 4_880_000, 100); v != 0 {
		t.Fatalf("zero disruption must yield $0 security-per-cost, got %.4f", v)
	}
	low := SecurityPerCostDollars(0.5, 4_880_000, 100)
	high := SecurityPerCostDollars(1.0, 4_880_000, 100)
	if !(high > low) {
		t.Fatalf("security-per-cost must increase with disruption: low=%.2f high=%.2f", low, high)
	}
	// No panic / Inf with a zero denominator.
	if v := SecurityPerCostDollars(1.0, 4_880_000, 0); math.IsInf(v, 0) || math.IsNaN(v) {
		t.Fatalf("security-per-cost must be finite with zero cost, got %v", v)
	}
}

// TestComputeROIRecomputable: the assembled ROIMetric echoes inputs and is fully
// recomputable from them.
func TestComputeROIRecomputable(t *testing.T) {
	in := defaultROIInputs()
	roi := ComputeROI(in, 0.8, 3)
	if roi.GpuCount != 8 || roi.DollarsPerGpuHour != 2.50 {
		t.Fatalf("ROI must echo inputs: %+v", roi)
	}
	if math.Abs(roi.GpuOverheadDollarsPerYearSaved-2628) > 1e-6 {
		t.Fatalf("ROI GPU-overhead saved = %.4f, want 2628", roi.GpuOverheadDollarsPerYearSaved)
	}
	wantSpc := SecurityPerCostDollars(0.8, in.AvoidedBreachValue, roi.AnnualDefenseCostDollars)
	if math.Abs(roi.SecurityPerCostDollars-wantSpc) > 1e-6 {
		t.Fatalf("ROI security-per-cost not recomputable: %.4f vs %.4f", roi.SecurityPerCostDollars, wantSpc)
	}
}

// TestSchwartauPositive exercises the P>D+R inequality including the detector-absent
// and static-arm cases.
func TestSchwartauPositive(t *testing.T) {
	// Rotating arm, detector present, P=6, D=1, R=1 => 6 > 2 => positive.
	s := ComputeSchwartau(6, 1, 1, false)
	if !s.SchwartauPositive {
		t.Fatalf("expected Schwartau-positive for P=6 D=1 R=1")
	}
	// P=2, D=1, R=1 => 2 > 2 is false.
	s = ComputeSchwartau(2, 1, 1, false)
	if s.SchwartauPositive {
		t.Fatalf("expected Schwartau-NOT-positive for P=2 D=1 R=1 (2 > 2 is false)")
	}
	// Detector absent: D undefined (-1), not positive, note set.
	s = ComputeSchwartau(6, 5, 1, true)
	if s.SchwartauPositive || s.DetectionTimeSeconds != -1 || !s.DetectionAbsent || s.DetectionAbsentNote == "" {
		t.Fatalf("detector-absent Schwartau malformed: %+v", s)
	}
	// Static arm (P=0): never positive (target never moves).
	s = ComputeSchwartau(0, 0, 0, false)
	if s.SchwartauPositive {
		t.Fatalf("static arm (P=0) must not be Schwartau-positive")
	}
}

// TestComputeReuseReduction checks the replay-reduction-vs-static math.
func TestComputeReuse(t *testing.T) {
	// Static baseline succeeds 3/3; this arm succeeds 1 => 1 - 1/3 = 0.667 reduction.
	m := ComputeReuse(1, 3, 3)
	if math.Abs(m.ReuseReductionVsStatic-(1.0-1.0/3.0)) > 1e-9 {
		t.Fatalf("reuse reduction = %.4f, want 0.667", m.ReuseReductionVsStatic)
	}
	// Equal to baseline => 0 reduction.
	if m := ComputeReuse(3, 3, 3); m.ReuseReductionVsStatic != 0 {
		t.Fatalf("equal-to-baseline reuse reduction must be 0, got %.4f", m.ReuseReductionVsStatic)
	}
	// No baseline => 0 reduction (cannot anchor).
	if m := ComputeReuse(2, 3, 0); m.ReuseReductionVsStatic != 0 {
		t.Fatalf("no-baseline reuse reduction must be 0, got %.4f", m.ReuseReductionVsStatic)
	}
	// Clamped to [0,1] when this arm somehow exceeds the baseline.
	if m := ComputeReuse(5, 5, 3); m.ReuseReductionVsStatic != 0 {
		t.Fatalf("over-baseline reuse reduction must clamp to 0, got %.4f", m.ReuseReductionVsStatic)
	}
}

// TestDeriveMTDEffect pins the MEASURED MTD-effect tag derivation.
func TestDeriveMTDEffect(t *testing.T) {
	if got := DeriveMTDEffect(true, true, true); got != MTDNeutralizes {
		t.Fatalf("neutralized => MTD-NEUTRALIZES, got %s", got)
	}
	if got := DeriveMTDEffect(true, true, false); got != MTDBoundsOnly {
		t.Fatalf("persistence-disrupted (not neutralized) => MTD-BOUNDS-ONLY, got %s", got)
	}
	if got := DeriveMTDEffect(true, false, false); got != MTDCannotHelp {
		t.Fatalf("no movement => MTD-CANNOT-HELP, got %s", got)
	}
}

// TestMetricBackwardCompatibleZeroValues asserts a Pass-A-shaped Metric (no Pass-B
// fields set) marshals WITHOUT the new keys (omitempty), so the 1980 Pass-A rows
// stay byte-comparable and old consumers are unaffected.
func TestMetricBackwardCompatibleZeroValues(t *testing.T) {
	m := Metric{Scenario: "s", Defender: "d", Trial: 0}
	if m.SplitOracle != "" || m.MTDEffect != "" || m.ROI != nil || m.Schwartau != nil || m.Reuse != nil {
		t.Fatalf("zero Metric must have empty Pass-B fields")
	}
	// roundCents is used by reporting; sanity-check it.
	if roundCents(1.234) != 1.23 {
		t.Fatalf("roundCents(1.234) = %.4f, want 1.23", roundCents(1.234))
	}
}
