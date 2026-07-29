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
	if !t.Present {
		return 0
	}

	// (1) Flow-conservation residual: requests in should produce bytes out. If a pod
	// takes traffic in (reqRate>0 or bytesIn>0) but almost nothing leaves, OR data
	// leaves with no matching requests (exfil pattern), that is a flow inconsistency.
	flow := 0.0
	if t.BytesIn > 0 || t.BytesOut > 0 {
		ratio := t.BytesOut / (t.BytesIn + 1.0) // +1 avoids div-by-zero, mild low-volume damping
		// Healthy band is roughly [0.1, 10]; deviation grows as we leave it (log scale).
		dev := math.Abs(math.Log10(clampPos(ratio, 1e-3)))
		flow = clamp01((dev - 1.0) / 3.0) // 0 inside the decade band, ->1 by ~4 decades off
	}

	// (2) Queue/backlog residual: queue depth large relative to arrival rate means
	// items pile up (L >> λ·W stable point).
	queue := 0.0
	if t.QueueDepth > 0 {
		queue = clamp01((t.QueueDepth - t.ReqRate) / (t.ReqRate + 8.0))
	}

	// (3) Connection fan-out residual: connections far exceeding request rate suggests
	// abnormal fan-out (lateral probing / C2 multiplexing).
	fanout := 0.0
	if t.ConnCount > 0 {
		fanout = clamp01((t.ConnCount - t.ReqRate) / (t.ReqRate + 20.0))
	}

	// (4) Throughput collapse under load (GPU/LLM): serving load present but tokens/sec
	// floored.
	collapse := 0.0
	if t.GPUUtil > 0.5 && t.TokensPerSec >= 0 && t.TokensPerSec < pol_floor {
		collapse = clamp01((pol_floor - t.TokensPerSec) / pol_floor)
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
