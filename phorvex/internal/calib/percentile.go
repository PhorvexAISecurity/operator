/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package calib derives cluster-calibrated SCALES from measured distributions, replacing
// constants that were fitted to one cluster and shipped to every other one (PHVX-74).
//
// The rule the package exists to enforce: a constant is portable iff it is dimensionless.
// Anything carrying units, or acting as a cap or a denominator, is a scale — and a scale is
// only correct on the cluster it was measured on.
//
// SHADOW ONLY. Nothing here is read by the decision path. The calibrators compute what the
// scales WOULD be and what would have changed; the shipped constants keep driving production
// until the results are reviewed. Nothing in this package imports the optimizer, and the
// optimizer must never import this package.
package calib

import (
	"math"
	"sort"
)

// Percentile returns the nearest-rank quantile of vals at p in [0,1].
//
// The estimator is FIXED to nearest rank on purpose: Q(p) = sorted[ceil(p*n)] over 1-based
// ranks. Interpolating estimators (R-7 and friends) would invent values that no node or pod
// ever had, and every scale here is later compared against raw observations to compute a
// clipping ratio — a scale that sits between two observed values makes that ratio incoherent.
// Nearest rank always returns a value the cluster actually exhibited.
//
// vals is not modified. Returns 0, false for an empty input; the caller decides what an
// unmeasurable scale means, because "no data" must never silently become a number.
func Percentile(vals []float64, p float64) (float64, bool) {
	n := len(vals)
	if n == 0 {
		return 0, false
	}
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)

	// 1-based rank ceil(p*n), converted to a 0-based index. At p=0 the rank is 0, which is
	// not a valid 1-based rank, so it clamps to the first element.
	rank := int(math.Ceil(p * float64(n)))
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return s[rank-1], true
}

// ClipReport describes how a candidate scale sits against the raw observations it was derived
// from. Both ratios are reported because they answer different questions and, on discrete data,
// they differ a lot.
//
// The spec is explicit that P95 must NOT be assumed to leave 5% at the ceiling, and this is
// where that shows up. Namespace counts are small integers with heavy ties: on the live fleet
// (5 nodes, X_node = [1,3,4,7,8]) every percentile from P81 to P99 returns 8, at which point
// AtCeiling is 20% and StrictlyClipped is 0%. Neither is 5%, and neither is wrong — the sample
// simply cannot express a 5% tail.
type ClipReport struct {
	// N is the number of raw observations the scale was derived from.
	N int
	// AtCeiling counts observations >= the scale. These are the ones that produce the maximum
	// multiplier, whether or not the scale actually truncated them.
	AtCeiling int
	// StrictlyClipped counts observations > the scale — the ones whose real magnitude the scale
	// genuinely discards. This is the number that means "signal was thrown away".
	StrictlyClipped int
}

// AtCeilingRatio is the fraction of observations sitting at or above the scale. This is the
// series the saturation alarm watches: when too much of the fleet pins at the ceiling, the
// scale is wrong and the term has degenerated into a constant.
func (c ClipReport) AtCeilingRatio() float64 {
	if c.N == 0 {
		return 0
	}
	return float64(c.AtCeiling) / float64(c.N)
}

// StrictlyClippedRatio is the fraction whose magnitude the scale actually discards.
func (c ClipReport) StrictlyClippedRatio() float64 {
	if c.N == 0 {
		return 0
	}
	return float64(c.StrictlyClipped) / float64(c.N)
}

// Clipping measures vals against a candidate scale.
func Clipping(vals []float64, scale float64) ClipReport {
	r := ClipReport{N: len(vals)}
	for _, v := range vals {
		if v >= scale {
			r.AtCeiling++
		}
		if v > scale {
			r.StrictlyClipped++
		}
	}
	return r
}

// Identifiable reports whether the candidate percentiles actually distinguish between each
// other on this sample. It exists because a percentile SWEEP over a tiny sample is not a
// sweep: with n nodes, nearest rank can only ever return one of n values, so a grid of
// P90/P95/P97.5/P99 can collapse to a single point and look like agreement when it is really
// an absence of resolution.
//
// Returns the distinct values the grid produces. len(result) == 1 means the grid told you
// nothing about which percentile to choose.
func Identifiable(vals []float64, ps []float64) []float64 {
	seen := map[float64]bool{}
	var out []float64
	for _, p := range ps {
		if q, ok := Percentile(vals, p); ok && !seen[q] {
			seen[q] = true
			out = append(out, q)
		}
	}
	sort.Float64s(out)
	return out
}
