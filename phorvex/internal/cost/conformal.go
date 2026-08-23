/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import (
	"fmt"
	"math"
	"sort"
	"sync/atomic"
)

// conformal.go provides the DISTRIBUTIONALLY-ROBUST upper bound C_hi used by the HARD
// feasibility/SLO gate (METHOD-DECISION cost graft, CDR-Cost). C_hi = E[C] +
// conformal-residual-quantile + a hardware-calibrated GPU envelope. Feasibility uses
// C_hi; the objective uses E[C].

const (
	// DefaultGPUEnvelopeMax is the fail-safe used when a deployment has no hardware
	// calibration. Production charts should pass a measured value via --gpu-envelope-max.
	DefaultGPUEnvelopeMax = 1.0

	// MeasuredT4GPUEnvelopeMax is derived from the worst observed vLLM replacement
	// recovery on the production EKS Tesla T4 node: 117s creation-to-Ready divided by
	// the documented 400s top of the model warm-load scale.
	MeasuredT4GPUEnvelopeMax = 117.0 / 400.0
)

var gpuEnvelopeMaxBits atomic.Uint64

func init() {
	gpuEnvelopeMaxBits.Store(math.Float64bits(DefaultGPUEnvelopeMax))
}

// ConfigureGPUEnvelopeMax installs the operator-wide measured GPU reload/warm-up
// envelope. The normalized flow-cost contract is [0,1]; rejecting invalid values
// prevents a typo or NaN from silently disabling the SLO gate.
func ConfigureGPUEnvelopeMax(v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
		return fmt.Errorf("gpu envelope max must be finite and in [0,1], got %v", v)
	}
	gpuEnvelopeMaxBits.Store(math.Float64bits(v))
	return nil
}

// GPUEnvelopeMax returns the configured normalized GPU warm-up envelope.
func GPUEnvelopeMax() float64 {
	return math.Float64frombits(gpuEnvelopeMaxBits.Load())
}

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
	if math.IsNaN(residual) || math.IsInf(residual, 0) {
		return
	}
	if residual < 0 {
		residual = -residual
	}
	c.residuals = append(c.residuals, residual)
	if len(c.residuals) > c.cap {
		c.residuals = c.residuals[len(c.residuals)-c.cap:]
	}
}

// ColdStartSlack is the modest general residual slack used before any cost residual
// has been observed (the measured GPU envelope is applied separately, in CHi, only
// for GPU pods — so non-GPU rotates are not over-pruned at cold-start).
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
