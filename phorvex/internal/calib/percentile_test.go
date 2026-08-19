/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"math"
	"testing"
)

// The spec fixes the estimator to nearest rank, Q(p) = sorted[ceil(p*n)] over 1-based ranks.
// These cases pin the 0-based translation, which is the only place it can go wrong.
func TestPercentileIsNearestRank(t *testing.T) {
	vals := []float64{10, 20, 30, 40, 50} // n=5
	for _, tc := range []struct {
		p    float64
		want float64
		why  string
	}{
		{0.0, 10, "rank ceil(0)=0 is not a valid 1-based rank; clamps to the first element"},
		{0.2, 10, "ceil(1.0)=1 -> sorted[0]"},
		{0.21, 20, "ceil(1.05)=2 -> sorted[1]; the boundary is exact, not rounded"},
		{0.5, 30, "ceil(2.5)=3 -> sorted[2]"},
		{0.8, 40, "ceil(4.0)=4 -> sorted[3]"},
		{0.95, 50, "ceil(4.75)=5 -> sorted[4]"},
		{1.0, 50, "ceil(5)=5 -> the maximum"},
	} {
		got, ok := Percentile(vals, tc.p)
		if !ok {
			t.Fatalf("P%.4g reported no value on a non-empty sample", tc.p)
		}
		if got != tc.want {
			t.Errorf("P%.4g = %v, want %v — %s", tc.p, got, tc.want, tc.why)
		}
	}
}

// A percentile of nothing is not zero. Returning 0 with ok=true would hand a caller a scale of
// zero, which divides the co-residency term into infinity — so the absence has to be visible.
func TestPercentileOfEmptyIsNotZero(t *testing.T) {
	if _, ok := Percentile(nil, 0.95); ok {
		t.Fatal("empty sample reported a usable percentile")
	}
}

func TestPercentileDoesNotMutateInput(t *testing.T) {
	vals := []float64{5, 1, 4}
	_, _ = Percentile(vals, 0.5)
	if vals[0] != 5 || vals[1] != 1 || vals[2] != 4 {
		t.Fatalf("input was reordered: %v — a caller's raw observations must survive being measured", vals)
	}
}

// This is the live fleet on 2026-08-19: 5 nodes carrying 2, 4, 5, 8 and 9 namespaces, so
// X_node = [1,3,4,7,8]. It is the case the spec warns about directly ("do not assume P95
// automatically produces exactly 5% at the ceiling"), and it fails in two separate ways.
func TestLiveFleetPercentileGridHasNoResolution(t *testing.T) {
	X := []float64{1, 3, 4, 7, 8}

	grid := Identifiable(X, []float64{0.90, 0.95, 0.975, 0.99})
	if len(grid) != 1 {
		t.Fatalf("expected the P90..P99 grid to collapse to one value on 5 nodes, got %v", grid)
	}
	if grid[0] != 8 {
		t.Fatalf("collapsed value = %v, want 8 (the maximum)", grid[0])
	}

	// Nearest rank over n samples can only ever return one of n values, so a four-point grid
	// on five nodes is not a sweep. Anything above P80 is the maximum.
	if q, _ := Percentile(X, 0.80); q != 7 {
		t.Errorf("P80 = %v, want 7 — P80 is the last percentile that still discriminates here", q)
	}

	// And the tail is nothing like 5%.
	c := Clipping(X, 8)
	if got := c.AtCeilingRatio(); math.Abs(got-0.20) > 1e-9 {
		t.Errorf("at-ceiling ratio = %.4f, want 0.20 — P95 leaves 20%% at the ceiling on this sample, not 5%%", got)
	}
	if got := c.StrictlyClippedRatio(); got != 0 {
		t.Errorf("strictly-clipped ratio = %.4f, want 0 — nothing exceeds the maximum", got)
	}
}

// The two ratios must not be conflated. At-ceiling answers "how much of the fleet gets the
// maximum multiplier"; strictly-clipped answers "how much real magnitude was discarded". On
// ties they differ, and only reporting one hides either the saturation or the loss.
func TestTheTwoClipRatiosDifferOnTies(t *testing.T) {
	vals := []float64{1, 5, 5, 5, 9}
	c := Clipping(vals, 5)
	if c.AtCeiling != 4 {
		t.Errorf("at-ceiling = %d, want 4 (three ties plus the 9)", c.AtCeiling)
	}
	if c.StrictlyClipped != 1 {
		t.Errorf("strictly-clipped = %d, want 1 (only the 9 loses magnitude)", c.StrictlyClipped)
	}
}
