/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import (
	"math"

	"github.com/phorvex/phorvex/internal/model"
)

// rls.go holds the C_flow model: C_flow is nonlinear in the raw pod state but LINEAR in
// engineered features phi(view), so Recursive Least Squares CAN give a closed-form online fit
// from observed rotations (METHOD-DECISION cost winner, RC-DD). The feature vector and the RLS
// recursion live here and the per-tick cost is a dot product.
//
// The live runner feeds this recursion only after a rotation's replacement reaches
// PodReady, keeping action emission latency out of the learned disruption label.

// featureDim is the engineered C_flow feature dimension.
const (
	featureDim               = 6
	RLSForgettingFactor      = 0.99
	RLSInitialCovariance     = 100.0
	RLSRequestRateNormalizer = 200.0
	RLSPredictionMaximum     = 2.0
)

// Features maps a workload view to the C_flow feature vector. The coefficients learned
// over these reproduce, at the prior, today's phase-based flow cost and refine it as
// real disruption is observed.
func Features(view *model.WorkloadView) [featureDim]float64 {
	var f [featureDim]float64
	f[0] = 1 // bias
	// One lookup into the single spec (phaseFlowEncoding, T1-D). featureBit -1 means the
	// phase carries no learned-load prior (bias-only) — draining/unknown, and any
	// out-of-vocabulary phase via the explicit Unknown fallback.
	if bit := phaseEncoding(view.Phase).featureBit; bit >= 0 {
		f[bit] = 1
	}
	if view.Pod.HasGPU {
		f[4] = 1
	}
	if view.Telemetry.ReqRate.Usable() {
		f[5] = satRLS(view.Telemetry.ReqRate.Value / RLSRequestRateNormalizer)
	}
	return f
}

// priorTheta reproduces the P0 phase-based flow prior so nil-data == today's behavior:
// bias 0.15 (idle floor), +cold 0.85, +warm 0.55, idle 0, +gpu 0.45, +load 0.20.
//
// Assembled from phaseFlowEncoding (the single spec, T1-D) so the phase weights cannot
// drift from Features' bit assignment; the three non-phase weights stay named constants.
// Result is byte-identical to the former literal {0.15, 0.85, 0.55, 0.0, 0.45, 0.20}.
func priorTheta() [featureDim]float64 {
	var theta [featureDim]float64
	theta[0] = biasPrior
	for _, p := range model.AllWorkloadPhases {
		// Fail-closed: an absent row must not zero-clobber theta[0] via a zero-value
		// featureBit 0. The completeness test (b) makes an absent row a build failure,
		// so `ok` is defence in depth, not a reachable path.
		if enc, ok := phaseFlowEncoding[p]; ok && enc.featureBit >= 0 {
			theta[enc.featureBit] = enc.priorWeight
		}
	}
	theta[4] = gpuPrior
	theta[5] = loadPrior
	return theta
}

// maxThetaStep bounds how far a SINGLE observation may move any one weight of theta.
//
// The existing clamp in Predict bounds the OUTPUT; nothing bounded the PARAMETER. One pathological
// measurement was therefore enough to reprice a tenant: a pod that took 300s to become Ready because
// its node was draining is indistinguishable, at this layer, from a genuinely expensive rotation. RLS
// with a forgetting factor is designed to track a moving cost, so it will happily follow that outlier
// and then take many clean observations to walk back.
//
// 0.25 is a quarter of the largest prior weight (0.85), so a real trend still converges in a handful
// of observations while a single sample cannot dominate. It is a rate limit, not a correctness bound.
const maxThetaStep = 0.25

// RLS is a recursive-least-squares estimator with a forgetting factor.
type RLS struct {
	theta  [featureDim]float64
	p      [featureDim][featureDim]float64
	ff     float64 // forgetting factor in (0,1]
	primed bool
	// updates counts folded observations. Primed() answers WHETHER; this answers HOW MANY, which
	// is what separates "one lucky match" from "genuinely calibrated" (PHVX-10c).
	updates int
	// frozen suppresses learning: Update becomes a no-op and Predict serves the prior. This is the
	// documented off-switch PHVX-2 requires. It is deliberately NOT the same thing as the engine-wide
	// KillSwitch, which stops ACTUATION and leaves the learner running.
	frozen bool
}

// SetFrozen turns online cost calibration off or back on. Freezing REVERTS theta to the shipped prior
// rather than holding the last learned value, so the effect is the documented, reproducible
// nil-data behaviour rather than a snapshot of whatever was learned before the operator lost trust
// in it. Unfreezing starts from the prior again — this is a safety control, not a pause button.
func (r *RLS) SetFrozen(frozen bool) {
	if frozen && !r.frozen {
		r.theta = priorTheta()
		r.primed = false
		for i := 0; i < featureDim; i++ {
			for j := 0; j < featureDim; j++ {
				r.p[i][j] = 0
			}
			r.p[i][i] = RLSInitialCovariance // restore the diffuse prior covariance
		}
	}
	r.frozen = frozen
}

// Frozen reports whether online calibration is suppressed.
func (r *RLS) Frozen() bool { return r.frozen }

// NewRLS returns an RLS seeded at the flow-cost prior with a diffuse covariance.
func NewRLS() *RLS {
	r := &RLS{ff: RLSForgettingFactor}
	r.theta = priorTheta()
	for i := 0; i < featureDim; i++ {
		r.p[i][i] = RLSInitialCovariance // diffuse prior covariance
	}
	return r
}

// Predict returns phi^T theta (the estimated C_flow), clamped to [0, 2].
func (r *RLS) Predict(f [featureDim]float64) float64 {
	s := 0.0
	for i := 0; i < featureDim; i++ {
		s += f[i] * r.theta[i]
	}
	// NaN-SAFE: a NaN anywhere in phi or theta makes the dot product NaN, and every comparison
	// below would then be false — returning NaN straight into ECost, where the optimizer's
	// `gain > best` is also always false and selection becomes undefined. NaN reads as the
	// conservative maximum; P1Cost.Evaluation additionally classifies and excludes it
	// before optimization so the data failure is metric/audit visible.
	if math.IsNaN(s) {
		return unknownActionFlowMax
	}
	if s < 0 {
		return 0
	}
	if s > RLSPredictionMaximum {
		return RLSPredictionMaximum
	}
	return s
}

func (r *RLS) hasNaNParameter() bool {
	for _, value := range r.theta {
		if math.IsNaN(value) {
			return true
		}
	}
	return false
}

// Update folds one (features, observedCost) sample into theta via the RLS recursion.
// Called when a real rotation's disruption has been measured (offline cadence).
func (r *RLS) Update(f [featureDim]float64, y float64) {
	if r.frozen {
		return // calibration is off: theta stays at the prior (PHVX-2 off-switch)
	}
	if math.IsNaN(y) || math.IsInf(y, 0) {
		return
	}
	for _, value := range f {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return
		}
	}
	// Pf = P f
	var pf [featureDim]float64
	for i := 0; i < featureDim; i++ {
		s := 0.0
		for j := 0; j < featureDim; j++ {
			s += r.p[i][j] * f[j]
		}
		pf[i] = s
	}
	// denom = ff + f^T P f
	denom := r.ff
	for i := 0; i < featureDim; i++ {
		denom += f[i] * pf[i]
	}
	if denom <= 0 {
		return
	}
	// gain K = Pf / denom
	var k [featureDim]float64
	for i := 0; i < featureDim; i++ {
		k[i] = pf[i] / denom
	}
	// innovation
	pred := r.Predict(f)
	e := y - pred
	for i := 0; i < featureDim; i++ {
		step := k[i] * e
		// Rate-limit a single observation (see maxThetaStep). Without this the OUTPUT clamp in
		// Predict is the only guard, and it bounds the symptom rather than the parameter.
		if step > maxThetaStep {
			step = maxThetaStep
		} else if step < -maxThetaStep {
			step = -maxThetaStep
		}
		r.theta[i] += step
	}
	// P = (P - K Pf^T) / ff
	for i := 0; i < featureDim; i++ {
		for j := 0; j < featureDim; j++ {
			r.p[i][j] = (r.p[i][j] - k[i]*pf[j]) / r.ff
		}
	}
	r.primed = true
	r.updates++
}

// Primed reports whether at least one real observation has been folded in (else the
// estimate is the prior — honest "uncalibrated" state).
func (r *RLS) Primed() bool { return r.primed }

// Updates is the number of real observations folded in since process start. In-process state: it
// resets on restart, and that is deliberately visible — a calibrator that never survives long
// enough to prime looks identical to one that never matches unless you can see this reset.
func (r *RLS) Updates() int { return r.updates }

func satRLS(x float64) float64 {
	// NaN-SAFE (see sat() in switching.go): NaN compares false against everything, so without
	// this guard a NaN ReqRate would flow into the feature vector and make C_flow NaN.
	if math.IsNaN(x) {
		return 1
	}
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
