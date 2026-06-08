package core

import (
	"hash/fnv"
	"math"
)

// Aggregate is the per-arm summary: mean + a (two-sided) confidence interval. The
// CI math is kept even though a smoke n=2 yields a very wide interval — the SAME
// function serves the full n>=20 benchmark.
type Aggregate struct {
	N        int     `json:"n"`
	Mean     float64 `json:"mean"`
	StdDev   float64 `json:"stdDev"`
	StdErr   float64 `json:"stdErr"`
	CILow    float64 `json:"ciLow"`
	CIHigh   float64 `json:"ciHigh"`
	CILevel  float64 `json:"ciLevel"`  // e.g. 0.95
	HalfWidth float64 `json:"halfWidth"`
}

// Mean returns the arithmetic mean (0 for empty input).
func Mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

// SampleStdDev returns the sample (n-1) standard deviation; 0 for n<2.
func SampleStdDev(xs []float64) float64 {
	n := len(xs)
	if n < 2 {
		return 0
	}
	m := Mean(xs)
	var ss float64
	for _, x := range xs {
		d := x - m
		ss += d * d
	}
	return math.Sqrt(ss / float64(n-1))
}

// ConfidenceInterval computes a t-distribution confidence interval at the given
// level (e.g. 0.95). It uses a small lookup of two-sided t critical values and
// degrades gracefully for n<2 (interval == mean, half-width 0). For n>=2 with a
// degenerate (zero-variance) sample the half-width is 0, which is correct.
//
// The t-interval (not z) is deliberate: at smoke n=2 the t critical value is
// large (12.706 at 95%), so the interval is HONESTLY wide — the function does not
// pretend a 2-sample mean is precise.
func ConfidenceInterval(xs []float64, level float64) Aggregate {
	n := len(xs)
	agg := Aggregate{N: n, CILevel: level}
	if n == 0 {
		return agg
	}
	agg.Mean = Mean(xs)
	if n == 1 {
		agg.CILow, agg.CIHigh = agg.Mean, agg.Mean
		return agg
	}
	agg.StdDev = SampleStdDev(xs)
	agg.StdErr = agg.StdDev / math.Sqrt(float64(n))
	t := tCritical(n-1, level)
	agg.HalfWidth = t * agg.StdErr
	agg.CILow = agg.Mean - agg.HalfWidth
	agg.CIHigh = agg.Mean + agg.HalfWidth
	return agg
}

// tCritical returns the two-sided t critical value for the given degrees of
// freedom and confidence level. A compact table covers the common cases (90/95/99)
// for the df the harness actually produces (smoke n=2 => df=1; full n>=20 =>
// df>=19); df beyond the table falls back to the normal approximation.
func tCritical(df int, level float64) float64 {
	table := tTableFor(level)
	if df <= 0 {
		df = 1
	}
	if v, ok := table[df]; ok {
		return v
	}
	// Nearest tabulated df at or below; else normal approximation.
	best, bestDF := 0.0, -1
	for k, v := range table {
		if k <= df && k > bestDF {
			best, bestDF = v, k
		}
	}
	if bestDF > 0 {
		return best
	}
	return zCritical(level)
}

func tTableFor(level float64) map[int]float64 {
	switch {
	case level >= 0.99:
		return map[int]float64{1: 63.657, 2: 9.925, 3: 5.841, 4: 4.604, 5: 4.032, 10: 3.169, 15: 2.947, 19: 2.861, 20: 2.845, 30: 2.750, 60: 2.660, 120: 2.617}
	case level >= 0.95:
		return map[int]float64{1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 10: 2.228, 15: 2.131, 19: 2.093, 20: 2.086, 30: 2.042, 60: 2.000, 120: 1.980}
	default: // 0.90
		return map[int]float64{1: 6.314, 2: 2.920, 3: 2.353, 4: 2.132, 5: 2.015, 10: 1.812, 15: 1.753, 19: 1.729, 20: 1.725, 30: 1.697, 60: 1.671, 120: 1.658}
	}
}

func zCritical(level float64) float64 {
	switch {
	case level >= 0.99:
		return 2.576
	case level >= 0.95:
		return 1.960
	default:
		return 1.645
	}
}

// TrialSeed derives a deterministic per-trial seed from the master seed plus the
// scenario, defender and trial index. The SAME (master, scenario, defender,
// trial) tuple always yields the SAME seed, so the whole run reproduces.
func TrialSeed(master int64, scenario, defender string, trial int) int64 {
	h := fnv.New64a()
	var buf [8]byte
	u := uint64(master)
	for i := 0; i < 8; i++ {
		buf[i] = byte(u >> (8 * i))
	}
	_, _ = h.Write(buf[:])
	_, _ = h.Write([]byte(scenario))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(defender))
	_, _ = h.Write([]byte{0})
	ti := uint64(trial)
	for i := 0; i < 8; i++ {
		buf[i] = byte(ti >> (8 * i))
	}
	_, _ = h.Write(buf[:])
	return int64(h.Sum64())
}
