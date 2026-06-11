/*
 * Phorvex P4b — leak/drift detector: ordinary-least-squares slope with a 95% CI and a
 * minimum-detectable-effect, so "no leak" is a STATISTICAL claim (the slope CI is flat to
 * within the window's resolving power), not an eyeballed curve. ADDITIVE soak tooling — it
 * reads sampled metrics; it never touches the engine/actuator/runner.
 */

package soak

import "math"

// Fit is an OLS regression of ys on xs (xs typically seconds since start).
type Fit struct {
	N          int     `json:"n"`
	Slope      float64 `json:"slopePerSec"` // units per second
	SE         float64 `json:"se"`
	CILow      float64 `json:"ciLowPerSec"`  // 95% CI on the slope
	CIHigh     float64 `json:"ciHighPerSec"`
	MDEPerSec  float64 `json:"mdePerSec"` // minimum-detectable-effect = t*se (smallest slope distinguishable from 0)
	Mean       float64 `json:"mean"`
	R2         float64 `json:"r2"`
}

// FitOLS computes the slope, its standard error, the 95% CI, and the MDE.
func FitOLS(xs, ys []float64) Fit {
	n := len(xs)
	if n != len(ys) || n < 3 {
		return Fit{N: n}
	}
	var sx, sy float64
	for i := 0; i < n; i++ {
		sx += xs[i]
		sy += ys[i]
	}
	mx, my := sx/float64(n), sy/float64(n)
	var sxx, sxy, syy float64
	for i := 0; i < n; i++ {
		dx, dy := xs[i]-mx, ys[i]-my
		sxx += dx * dx
		sxy += dx * dy
		syy += dy * dy
	}
	if sxx == 0 {
		return Fit{N: n, Mean: my}
	}
	b := sxy / sxx
	a := my - b*mx
	var rss float64
	for i := 0; i < n; i++ {
		r := ys[i] - (a + b*xs[i])
		rss += r * r
	}
	df := n - 2
	se := math.Sqrt((rss / float64(df)) / sxx)
	t := tCrit975(df)
	r2 := 0.0
	if syy > 0 {
		r2 = 1 - rss/syy
	}
	return Fit{N: n, Slope: b, SE: se, CILow: b - t*se, CIHigh: b + t*se, MDEPerSec: t * se, Mean: my, R2: r2}
}

// PerHour scales a per-second rate to per-hour (for human-readable leak reporting).
func PerHour(perSec float64) float64 { return perSec * 3600 }

// NoConfirmedTrend is the rigorous no-leak criterion: the 95% slope CI includes zero, so the
// null hypothesis "no trend" cannot be rejected at this window's resolving power. (The MDE
// reports the smallest slope the window COULD have resolved — honest about what a short kind
// window can and cannot rule out.)
func (f Fit) NoConfirmedTrend() bool { return f.CILow <= 0 && f.CIHigh >= 0 }

// Flat reports no meaningful leak: EITHER the slope CI includes zero (no detectable trend),
// OR the per-hour CI upper bound is below tolFracOfMean of the mean (any resolvable growth is
// below tolerance). A wide CI straddling zero is FLAT (not a confirmed leak); the MDE carries
// the honesty about window resolution.
func (f Fit) Flat(tolFracOfMean float64) bool {
	if f.N < 3 {
		return false
	}
	if f.NoConfirmedTrend() {
		return true
	}
	if f.Mean == 0 {
		return true
	}
	tol := tolFracOfMean * math.Abs(f.Mean) // per-hour tolerance in absolute units
	return PerHour(f.CIHigh) <= tol
}

// tCrit975 is the two-sided 95% Student-t critical value for df degrees of freedom.
func tCrit975(df int) float64 {
	table := map[int]float64{1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
		8: 2.306, 9: 2.262, 10: 2.228, 12: 2.179, 15: 2.131, 20: 2.086, 25: 2.060, 30: 2.042, 40: 2.021, 60: 2.000, 120: 1.980}
	if v, ok := table[df]; ok {
		return v
	}
	if df <= 0 {
		return 12.706
	}
	if df > 120 {
		return 1.96
	}
	// nearest lower key
	best, bv := 1, 12.706
	for k, v := range table {
		if k <= df && k > best {
			best, bv = k, v
		}
	}
	return bv
}
