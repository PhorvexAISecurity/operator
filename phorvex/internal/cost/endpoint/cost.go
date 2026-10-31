package endpoint

import (
	"math"
	"sort"
)

// BinomialCDF uses log probabilities to remain stable for the bounded n<=200
// history. The one-sided Clopper-Pearson upper solves P_p[X<=x]=0.05.
func BinomialCDF(n, x int, p float64) float64 {
	if x >= n || p <= 0 {
		return 1
	}
	if x < 0 || p >= 1 {
		return 0
	}
	a, _ := math.Lgamma(float64(n + 1))
	total := 0.0
	for k := 0; k <= x; k++ {
		b, _ := math.Lgamma(float64(k + 1))
		c, _ := math.Lgamma(float64(n - k + 1))
		total += math.Exp(a - b - c + float64(k)*math.Log(p) + float64(n-k)*math.Log1p(-p))
	}
	return math.Min(1, total)
}

func FailureUpper(n, x int) float64 {
	if n == 0 || x == n {
		return 1
	}
	if n < 0 || x < 0 || x > n {
		return math.NaN()
	}
	lo, hi := 0.0, 1.0
	for i := 0; i < 70; i++ {
		mid := (lo + hi) / 2
		if BinomialCDF(n, x, mid) > .05 {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi
}

func ConfidenceRank(n int) int {
	for r := 1; r <= n; r++ {
		if BinomialCDF(n, r-1, .9) >= .95 {
			return r
		}
	}
	return 0
}

func median(values []float64) float64 {
	n := len(values)
	if n == 0 {
		return math.NaN()
	}
	return (values[(n-1)/2] + values[n/2]) / 2
}

func Duration(samples []Sample, prior float64) (mid, upper, pf float64) {
	values, observed := []float64{}, []float64{}
	overdue := 0
	for _, s := range samples {
		if s.Overdue {
			overdue++
		}
		if s.Censored {
			values = append(values, math.Inf(1))
			continue
		}
		if !nonnegative(s.Duration) {
			return math.NaN(), math.NaN(), math.NaN()
		}
		values = append(values, *s.Duration)
		observed = append(observed, *s.Duration)
	}
	sort.Float64s(values)
	sort.Float64s(observed)
	n := len(values)
	pf = FailureUpper(n, overdue)
	if n < 29 {
		upper = prior
		if n > 0 {
			upper = math.Max(prior, values[n-1])
		}
		return prior, upper, pf
	}
	rank := ConfidenceRank(n)
	upper = math.Inf(1)
	if rank > 0 {
		upper = values[rank-1]
	}
	// Censoring is retained in the upper statistic, never in the median of
	// usable observed durations. No observed values means no usable estimate.
	return median(observed), upper, pf
}

func Price(t Tick, c Candidate, b Budget, cfg Config) Cost {
	out := Cost{Rollback: "STUDY_PROXY_T_UPPER"}
	refuse := func(reason string) Cost { out.Refusal = reason; return out }
	if c.K == nil || *c.K < 0 {
		return refuse("BOUND_MISSING: served endpoint impact k")
	}
	k := float64(*c.K)
	if c.Action == "quarantine" && k > 1 {
		return refuse("BOUND_MISSING: quarantine k must be 0 or 1")
	}
	// A documented no-endpoint impact is a genuine zero, independent of a
	// duration estimate. k itself must come from authoritative endpoint data.
	if k == 0 {
		out.E = ptr(0)
		out.Rho = ptr(0)
		out.Flow = ptr(0)
		out.Norm = ptr(0)
		return out
	}
	var mid, upper, pf float64
	sampleAction := c.Action
	if c.Action == "quarantine" {
		sampleAction = "rotate"
	}
	switch c.Action {
	case "rotate", "request-drain", "quarantine":
		if !c.HistoryKnown {
			return refuse("BOUND_MISSING: workload/action duration history not recorded")
		}
		if t.SLO == nil || t.SLO.Window <= 0 {
			return refuse("BOUND_MISSING: accepted/study window")
		}
		prior, ok := map[string]float64{"gpu": 130, "stateful": 141, "stateless": 43, "unknown": 400}[c.Class]
		if !ok {
			return refuse("BOUND_MISSING: workload duration class")
		}
		samples := []Sample{}
		seen := map[string]bool{}
		for _, s := range c.Samples {
			if s.ID == "" || seen[s.ID] {
				return refuse("BOUND_MISSING: duplicate/missing duration sample identity")
			}
			seen[s.ID] = true
			if !finite(s.At) || s.At > t.At {
				return refuse("BOUND_MISSING: future/invalid duration observation")
			}
			if s.WorkloadUID != t.WorkloadUID || s.Action != sampleAction || s.At < t.At-t.SLO.Window || s.Suspect {
				continue
			}
			if (!s.Censored && !nonnegative(s.Duration)) || (s.Duration != nil && !nonnegative(s.Duration)) {
				return refuse("BOUND_MISSING: invalid duration")
			}
			samples = append(samples, s)
		}
		sort.Slice(samples, func(i, j int) bool {
			if samples[i].At == samples[j].At {
				return samples[i].ID < samples[j].ID
			}
			return samples[i].At > samples[j].At
		})
		if len(samples) > 200 {
			samples = samples[:200]
		}
		out.SampleCount = len(samples)
		mid, upper, pf = Duration(samples, prior)
	default:
		bound := c.DocumentedBound
		if bound == nil || !bound.Approved || bound.Source == "" {
			return refuse("BOUND_MISSING: no approved action-specific duration bound (including kv-reset)")
		}
		mid, upper, pf = bound.Mid, bound.Upper, bound.FailureUpper
	}
	if finite(mid) {
		out.Mid = ptr(mid)
	}
	if finite(upper) {
		out.Upper = ptr(upper)
	}
	if finite(pf) {
		out.FailureUpper = ptr(pf)
	}
	if !finite(mid) || !finite(upper) || !finite(pf) || mid < 0 || upper < mid || pf < 0 || pf > 1 {
		return refuse("BOUND_MISSING: censored or invalid upper estimate")
	}
	d := upper
	if c.Action == "quarantine" {
		if !nonnegative(c.HoldCap) || b.Left == nil {
			return refuse("BOUND_MISSING: quarantine hold cap or remaining budget")
		}
		hold := math.Min(*c.HoldCap, *b.Left-cfg.Delta-3*upper)
		if hold <= 0 {
			return refuse("BUDGET: no feasible quarantine hold")
		}
		out.Hold = ptr(hold)
		d = hold + upper
		mid = hold + mid
		out.Mid = ptr(mid)
	}
	rho := k*(d+cfg.Delta+upper) + k*upper
	flow := k * mid
	norm := pf * (k*(d-mid+cfg.Delta+upper) + k*upper)
	if !finite(rho) || !finite(flow+norm) || flow+norm < 0 {
		return refuse("BOUND_MISSING: non-finite endpoint cost")
	}
	out.Rho = ptr(rho)
	out.E = ptr(flow + norm)
	out.Flow = ptr(flow)
	out.Norm = ptr(norm)
	return out
}
