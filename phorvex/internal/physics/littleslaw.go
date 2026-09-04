/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package physics

import (
	"math"

	"github.com/phorvex/phorvex/internal/model"
)

// littlesLaw is the DEFAULT PhysicsProfile (PRD §4.1 physics-model #1: workload
// dynamics). It combines two established, non-invented laws into a residual:
//
//   - Little's-Law flow identity: in steady flow, items-in-system L ≈ arrival λ ×
//     time-in-system W. We use the OBSERVABLE conservation form: requests entering
//     should leave (bytes_in roughly tracks bytes_out within a band; connections do
//     not pile up unboundedly relative to request rate). A large imbalance is a
//     physical inconsistency — the cyber analogue of the power-flow residual in the
//     grid-MTD papers.
//   - Warm-up/throughput sanity: a serving pod with high request rate but collapsed
//     throughput / exploded queue is off its healthy curve.
//
// Every term is a bounded, dimensionless deviation; the residual is their capped
// blend in [0,1]. With no telemetry it returns 0 (honest absence, never invented).
type littlesLaw struct{}

func (littlesLaw) Name() string { return "littles-law" }

func (littlesLaw) Residual(view *model.WorkloadView, _ model.Policy) float64 {
	t := view.Telemetry

	// (1) Flow-conservation residual: bytes in vs bytes out (cAdvisor, infra-universal).
	// Gate on each byte signal's usability and require some byte flow (old >0 semantics).
	flow := 0.0
	if (t.BytesIn.Usable() && t.BytesIn.Value > 0) || (t.BytesOut.Usable() && t.BytesOut.Value > 0) {
		ratio := t.BytesOut.Value / (t.BytesIn.Value + 1.0) // +1 avoids div-by-zero, mild low-volume damping
		// Healthy band is roughly [0.1, 10]; deviation grows as we leave it (log scale).
		dev := math.Abs(math.Log10(clampPos(ratio, 1e-3)))
		flow = clamp01((dev - 1.0) / 3.0) // 0 inside the decade band, ->1 by ~4 decades off
	}

	// (2) Queue/backlog residual: needs BOTH queue depth AND arrival rate. An absent
	// ReqRate is unknown arrival, not zero arrival, so the term is skipped (not fabricated).
	queue := 0.0
	if t.QueueDepth.Usable() && t.ReqRate.Usable() && t.QueueDepth.Value > 0 {
		queue = clamp01((t.QueueDepth.Value - t.ReqRate.Value) / (t.ReqRate.Value + 8.0))
	}

	// (3) Connection fan-out residual. T1-C PHANTOM FIX: ConnCount is real cAdvisor but
	// ReqRate is app-level; with ReqRate absent-as-zero the old code fabricated a "lateral
	// probing / C2" residual on every uninstrumented pod and fed it to LIVE selection.
	// Require ReqRate usable so absence never invents fan-out (no math/band change).
	fanout := 0.0
	if t.ConnCount.Usable() && t.ReqRate.Usable() && t.ConnCount.Value > 0 {
		fanout = clamp01((t.ConnCount.Value - t.ReqRate.Value) / (t.ReqRate.Value + 20.0))
	}

	// (4) Throughput collapse under load (GPU/LLM): needs both GPUUtil and TokensPerSec.
	collapse := 0.0
	if t.GPUUtil.Usable() && t.TokensPerSec.Usable() && t.GPUUtil.Value > 0.5 && t.TokensPerSec.Value >= 0 && t.TokensPerSec.Value < pol_floor {
		collapse = clamp01((pol_floor - t.TokensPerSec.Value) / pol_floor)
	}

	// Blend: max emphasizes the single strongest inconsistency (any one law breaking
	// is meaningful), softened by the mean so multiple mild signals also accumulate.
	mx := maxf(flow, queue, fanout, collapse)
	mean := (flow + queue + fanout + collapse) / 4.0
	return clamp01(0.7*mx + 0.3*mean)
}

// pol_floor is a conservative tokens/sec sanity floor for the throughput-collapse
// term. It is intentionally fixed and small (NOT a paper number); the SLO's real
// MinTokensPerSec is enforced as a hard FEASIBILITY constraint, not here.
const pol_floor = 50.0

// clamp01 is NaN-SAFE. The residual arithmetic above legitimately produces NaN from non-finite
// telemetry — (Inf - Inf) in the fanout term, (-Inf / Inf) in the queue term — and every
// comparison against NaN is false, so a bare clamp would RETURN NaN. That NaN propagates through
// Residual -> risk -> the optimizer, where `gain > best` is also always false and selection
// silently degrades to noop. NaN reads as the neutral LOW end.
func clamp01(x float64) float64 {
	if math.IsNaN(x) {
		return 0
	}
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func clampPos(x, min float64) float64 {
	if x < min {
		return min
	}
	return x
}

func maxf(xs ...float64) float64 {
	m := 0.0
	for _, x := range xs {
		if x > m {
			m = x
		}
	}
	return m
}

func init() { Registry.Register(littlesLaw{}) }
