/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"testing"
	"time"
)

// history builds n samples at the given spacing. drift scales the asset multipliers over time so
// the fleet genuinely changes, which is the only condition under which cadence matters at all.
func history(n int, spacing time.Duration, drift float64) []CadenceSample {
	base := at0()
	var out []CadenceSample
	for i := 0; i < n; i++ {
		assets := liveAssets()
		f := 1 + drift*float64(i)
		for k := range assets {
			assets[k].EPSS = f
		}
		out = append(out, CadenceSample{At: base.Add(time.Duration(i) * spacing), Nodes: liveFleet(), Assets: assets})
	}
	return out
}

// THE property the whole section rests on. If the scale were fitted on the same observations it is
// scored against, the evaluation would be circular: it could not tell a scale that generalises from
// one that memorised its own sample. The two sets must never intersect.
func TestFitAndEvaluationWindowsNeverOverlap(t *testing.T) {
	samples := history(24, 5*time.Minute, 0.01)
	fits, evals := cadenceWindows(samples, 15*time.Minute)

	if len(fits) == 0 {
		t.Fatal("no windows produced")
	}
	for i := range fits {
		seen := map[time.Time]bool{}
		for _, f := range fits[i] {
			seen[f.At] = true
		}
		for _, e := range evals[i] {
			if seen[e.At] {
				t.Fatalf("window %d: sample at %v appears in BOTH the fit and evaluation sets — the validation is circular", i, e.At)
			}
		}
		// And ordering: every evaluation sample must be strictly after every fit sample.
		for _, f := range fits[i] {
			for _, e := range evals[i] {
				if !f.At.Before(e.At) {
					t.Fatalf("window %d: fit sample %v is not before evaluation sample %v — the scale saw the future", i, f.At, e.At)
				}
			}
		}
	}
	t.Logf("%d windows, all disjoint and forward-ordered", len(fits))
}

// A longer interval yields fewer testable windows from the same history. That is information, not
// an inconvenience: an interval the history can only exercise once has not really been evaluated.
func TestLongerIntervalsYieldFewerWindows(t *testing.T) {
	samples := history(48, 5*time.Minute, 0.005)
	rows := EvaluateCadence(samples, []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, 60 * time.Minute},
		0.95, 0.95, 1, 0.10)

	prev := 1 << 30
	for _, r := range rows {
		if r.Windows > prev {
			t.Errorf("interval %v produced %d windows, more than the shorter interval's %d", r.Interval, r.Windows, prev)
		}
		prev = r.Windows
		t.Logf("interval=%-6v windows=%d skipped=%d maxAtCeiling=%.1f%% drift=%.3f clears=%v",
			r.Interval, r.Windows, r.Skipped, r.MaxAtCeiling*100, r.MaxScaleDrift, r.ClearsThreshold)
	}
}

// An interval the history cannot test must NOT be reported as clearing. This is the same mistake
// as reporting an unmeasured optimality ratio as 1.0 (PHVX-23): an absent measurement is not a
// passing one.
func TestUnevaluableIntervalDoesNotCountAsClearing(t *testing.T) {
	// Three samples five minutes apart cannot exercise a one-hour cadence.
	samples := history(3, 5*time.Minute, 0)
	rows := EvaluateCadence(samples, []time.Duration{time.Hour}, 0.95, 0.95, 1, 0.10)

	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Windows != 0 {
		t.Fatalf("windows = %d, want 0 — the fixture was supposed to be untestable at this interval", rows[0].Windows)
	}
	if rows[0].ClearsThreshold {
		t.Fatal("an interval with zero evaluated windows reported as clearing the threshold; an absent measurement is not a passing one")
	}
	if _, ok := SelectCadence(rows); ok {
		t.Fatal("SelectCadence chose an interval that was never evaluated")
	}
}

// The selection rule is LARGEST-that-holds, not safest. A shorter interval is not free: it re-fits
// more often, and every re-fit moves the ground the optimizer ranks on.
func TestSelectionPrefersTheLargestValidInterval(t *testing.T) {
	rows := []CadenceRow{
		{Interval: 5 * time.Minute, Windows: 10, ClearsThreshold: true},
		{Interval: 30 * time.Minute, Windows: 4, ClearsThreshold: true},
		{Interval: time.Hour, Windows: 2, ClearsThreshold: false}, // fails: must not be chosen
	}
	got, ok := SelectCadence(rows)
	if !ok {
		t.Fatal("no interval selected despite two clearing")
	}
	if got.Interval != 30*time.Minute {
		t.Fatalf("selected %v, want 30m — the largest interval that actually held", got.Interval)
	}
}

func TestSelectionReportsNoneWhenNothingHolds(t *testing.T) {
	rows := []CadenceRow{
		{Interval: 5 * time.Minute, Windows: 10, ClearsThreshold: false},
		{Interval: 30 * time.Minute, Windows: 4, ClearsThreshold: false},
	}
	if _, ok := SelectCadence(rows); ok {
		t.Fatal("an interval was selected although none cleared the threshold")
	}
}

// Drift must be visible. A fleet that changes fast should show a larger scale movement between
// consecutive refreshes than a static one — otherwise the churn side of the trade-off is invisible
// and every cadence looks equally good.
func TestDriftIsReportedAndTracksFleetChange(t *testing.T) {
	static := EvaluateCadence(history(48, 5*time.Minute, 0), []time.Duration{15 * time.Minute}, 0.95, 0.95, 1, 0.10)
	moving := EvaluateCadence(history(48, 5*time.Minute, 0.02), []time.Duration{15 * time.Minute}, 0.95, 0.95, 1, 0.10)

	if static[0].MaxScaleDrift != 0 {
		t.Errorf("a static fleet reported drift %.4f, want 0", static[0].MaxScaleDrift)
	}
	if moving[0].MaxScaleDrift <= 0 {
		t.Fatalf("a drifting fleet reported drift %.4f; the churn side of the trade-off is invisible", moving[0].MaxScaleDrift)
	}
	t.Logf("static drift %.4f vs moving drift %.4f", static[0].MaxScaleDrift, moving[0].MaxScaleDrift)
}

// Saturation is judged on the WORST window, not the average. An average hides the interval in
// which the alarm actually fired, which is the only one anybody would care about.
func TestSaturationIsJudgedOnTheWorstWindowNotTheMean(t *testing.T) {
	samples := history(36, 5*time.Minute, 0.03)
	rows := EvaluateCadence(samples, []time.Duration{15 * time.Minute}, 0.95, 0.95, 1, 0.10)
	r := rows[0]

	if r.Windows < 2 {
		t.Skip("fixture did not produce enough windows to distinguish max from mean")
	}
	if r.MaxAtCeiling < r.MeanAtCeiling {
		t.Fatalf("max %.4f below mean %.4f, which is impossible", r.MaxAtCeiling, r.MeanAtCeiling)
	}
	if r.ClearsThreshold != (r.MaxAtCeiling <= 0.10) {
		t.Fatalf("clears=%v but max is %.4f against a 0.10 threshold — the verdict is not using the worst window",
			r.ClearsThreshold, r.MaxAtCeiling)
	}
	t.Logf("max %.1f%% vs mean %.1f%% over %d windows -> clears=%v",
		r.MaxAtCeiling*100, r.MeanAtCeiling*100, r.Windows, r.ClearsThreshold)
}

func TestEmptyHistoryProducesNoWindows(t *testing.T) {
	rows := EvaluateCadence(nil, []time.Duration{15 * time.Minute}, 0.95, 0.95, 1, 0.10)
	if len(rows) != 1 || rows[0].Windows != 0 || rows[0].ClearsThreshold {
		t.Fatalf("empty history produced %+v, want zero windows and no pass", rows)
	}
}

// ⚠️ FINDING: cadence cannot rescue a wrong percentile.
//
// At the configured P95 the dispersion cap is a no-op (see TestP95DispersionIsANoOpAndMissesThe
// Threshold), so the fleet sits at 11.3% pinned regardless of how often the scales are refreshed.
// Every candidate interval fails the 10% threshold by the same margin.
//
// This matters for the order of decisions in §5: the spec's rule is "smallest percentile that
// keeps saturation acceptable, then largest interval that stays valid". The two are not
// independent knobs to sweep in parallel — until the percentile is right, the cadence sweep has
// nothing to discriminate between, and four identical failures can be mistaken for a robust
// result. Fix the percentile first, then choose the interval.
func TestCadenceCannotRescueAWrongPercentile(t *testing.T) {
	samples := history(48, 5*time.Minute, 0)
	intervals := []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}
	rows := EvaluateCadence(samples, intervals, 0.95, 0.95, 1, 0.10)

	first := rows[0].MaxAtCeiling
	for _, r := range rows {
		if r.Windows == 0 {
			t.Fatalf("interval %v produced no windows; the fixture cannot show this", r.Interval)
		}
		if r.ClearsThreshold {
			t.Fatalf("interval %v cleared the threshold at P95; the finding that no cadence rescues it no longer holds", r.Interval)
		}
		if r.MaxAtCeiling != first {
			t.Errorf("interval %v pinned %.4f vs %.4f at the shortest interval; on a static fleet the cadence should not change saturation at all",
				r.Interval, r.MaxAtCeiling, first)
		}
	}
	if _, ok := SelectCadence(rows); ok {
		t.Fatal("an interval was selected although none cleared")
	}
	t.Logf("all %d intervals pin %.1f%% against a 10%% threshold — the cadence is not the binding choice here", len(rows), first*100)
}
