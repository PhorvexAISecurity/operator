/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import "sort"

// conformal.go provides the DISTRIBUTIONALLY-ROBUST upper bound C_hi used by the HARD
// feasibility/SLO gate (METHOD-DECISION cost graft, CDR-Cost): while a cost coefficient
// is literally unmeasured (GPU/KV-cache/warm-load = [SP-0-PENDING]), the gate must
// still PROVABLY not breach SLO. C_hi = E[C] + conformal-residual-quantile + a DECLARED
// GPU envelope (NOT a measured number). Feasibility uses C_hi; the objective uses E[C].

// GPUEnvelopeMax is the DECLARED engineering upper bound on the unmeasured GPU/KV-cache
// warm-load flow-cost contribution. It is [SP-0-PENDING]: a fail-safe ceiling, never a
// measurement. Once SP-0 measures the real curve this is replaced by the calibrated RLS
// coefficient and the envelope collapses.
const GPUEnvelopeMax = 1.0

// ConformalBound maintains a sliding window of |observed - predicted| cost residuals
// and returns their (1-alpha) empirical quantile — the conformal slack added to E[C]
// to get a long-run-coverage upper bound.
type ConformalBound struct {
	residuals []float64
	cap       int
	alpha     float64 // miscoverage level (e.g. 0.1 => 90% coverage)
}

// NewConformalBound returns a bound with a default 90% long-run coverage target.
func NewConformalBound() *ConformalBound {
	return &ConformalBound{cap: 200, alpha: 0.1}
}

// Observe records one absolute residual.
func (c *ConformalBound) Observe(residual float64) {
	if residual < 0 {
		residual = -residual
	}
	c.residuals = append(c.residuals, residual)
	if len(c.residuals) > c.cap {
		c.residuals = c.residuals[len(c.residuals)-c.cap:]
	}
}

// ColdStartSlack is the modest general residual slack used before any cost residual
// has been observed (the GPU/[SP-0-PENDING] envelope is applied SEPARATELY, in CHi,
// only for GPU pods — so non-GPU rotates are not over-pruned at cold-start).
const ColdStartSlack = 0.1

// Quantile returns the conformal slack q (the (1-alpha) empirical quantile of
// residuals). With no data it returns a modest cold-start slack.
func (c *ConformalBound) Quantile() float64 {
	if len(c.residuals) == 0 {
		return ColdStartSlack
	}
	s := append([]float64(nil), c.residuals...)
	sort.Float64s(s)
	idx := int(float64(len(s)-1) * (1 - c.alpha))
	if idx < 0 {
		idx = 0
	}
	return s[idx]
}

// Calibrated reports whether enough residuals exist for a meaningful (non-cold-start)
// quantile.
func (c *ConformalBound) Calibrated() bool { return len(c.residuals) >= 20 }
