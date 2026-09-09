/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package physics

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"

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
// PHORVEXSEC-198 / M-115: the Little's-law identity is now computed as ruled — E = λW,
// r = (L−E)/(L+E) — from three typed signals over one window and one boundary, absent where
// a mean sojourn does not exist; every component is aggregated by mean MAGNITUDE over the
// PRESENT components only (no ÷4 dilution, no fixed max/mean blend). With no usable
// component it returns 0 (honest absence, never invented).
type littlesLaw struct{}

func (littlesLaw) Name() string { return "littles-law" }

// FlowWindow / FlowUnits document the shared observation window and units of the three
// Little's-law inputs (ingest/prometheus.go M-115 queries) for the record.
const (
	FlowWindow      = "5m"
	FlowUnits       = "L: requests; lambda: requests/second; W: seconds"
	FlowWStatistic  = "mean-sojourn"
	FlowBasisLittle = "littles-law"
	FlowBasisAbsent = "absent"
	// FlowReasonNotActivated is the absence reason for a workload class MATH has not
	// activated. Availability of the three inputs is NOT activation (M-115 conformance,
	// 2026-09-06): the per-class verdict is the ruling's, and until a class is ruled
	// admissible the component is absent and enters neither the aggregate nor any fact.
	FlowReasonNotActivated = "class-not-activated"
	// QueueReasonDisabled marks the retired queue/backlog term: a rate subtracted from a
	// count, one of M-115's own listed defects. Disabled unconditionally, inputs or not.
	QueueReasonDisabled = "unit-incoherent-disabled"
)

var (
	flowMu      sync.RWMutex
	flowClasses = map[string]struct{}{}
)

// ConfigureFlowActivation installs the set of workload classes (namespaces) whose
// Little's-law residual MATH has activated. Empty (the default) means no class is active.
func ConfigureFlowActivation(classes []string) {
	next := map[string]struct{}{}
	for _, raw := range classes {
		for _, part := range strings.Split(raw, ",") {
			if c := strings.TrimSpace(part); c != "" {
				next[c] = struct{}{}
			}
		}
	}
	flowMu.Lock()
	defer flowMu.Unlock()
	flowClasses = next
}

// FlowActivated reports whether a workload class has been activated by the ruling.
func FlowActivated(class string) bool {
	flowMu.RLock()
	defer flowMu.RUnlock()
	_, ok := flowClasses[class]
	return ok
}

// ActivatedFlowClasses lists the activated classes (for the startup log and the record).
func ActivatedFlowClasses() []string {
	flowMu.RLock()
	defer flowMu.RUnlock()
	out := make([]string, 0, len(flowClasses))
	for c := range flowClasses {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// FlowResidualFor is the residual as the RECORD and the aggregate see it: the ruled
// computation for an activated class, honest absence for every other class. FlowResidual
// itself stays the pure ruled mathematics (the conformance vector runs against it).
func FlowResidualFor(class string, t model.Telemetry) FlowResult {
	if !FlowActivated(class) {
		return FlowResult{Basis: FlowBasisAbsent, Reason: FlowReasonNotActivated}
	}
	return FlowResidual(t)
}

// FlowResult is the M-115 Little's-law flow residual with its full basis, for the record.
type FlowResult struct {
	Present   bool
	Basis     string // littles-law | absent
	Reason    string // absence/invalid reason ("" when present)
	L         float64
	Lambda    float64
	W         float64
	Expected  float64 // E = lambda * W
	Residual  float64 // r = (L-E)/(L+E) in [-1,1]; 0 when L=E=0
	Magnitude float64 // |r| in [0,1]
	Age       time.Duration
}

// Component is one physics residual component with its presence, for present-only
// aggregation (M-115 Q8/Q9): an absent component enters neither numerator nor denominator;
// a measured zero does.
type Component struct {
	Name      string
	Present   bool
	Magnitude float64 // in [0,1] when Present
	Reason    string  // why absent
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// FlowResidual computes the ruled residual (M_115_MATH_RULING.md Q2–Q7):
//
//	E = lambda*W,  r = (L-E)/(L+E) for L+E > 0,  r = 0 for L = E = 0.
//
// Admissible only when all three inputs are Present (fresh), finite and nonnegative —
// otherwise honest absence with an explicit reason. No epsilon, no clipping of invalid
// values, checked finite arithmetic. The per-class admissibility (time-average L, mean W,
// same boundary/population/window) is established by how ingest defines the three signals.
func FlowResidual(t model.Telemetry) FlowResult {
	out := FlowResult{Basis: FlowBasisAbsent}
	switch {
	case !t.MeanSojournSec.Usable():
		out.Reason = "mean-sojourn-unavailable"
		return out
	case !t.InFlightMean.Usable():
		out.Reason = "in-flight-mean-unavailable"
		return out
	case !t.CompletionRate.Usable():
		out.Reason = "completion-rate-unavailable"
		return out
	}
	L, lam, W := t.InFlightMean.Value, t.CompletionRate.Value, t.MeanSojournSec.Value
	if !finite(L) || !finite(lam) || !finite(W) {
		out.Reason = "non-finite-input"
		return out
	}
	if L < 0 || lam < 0 || W < 0 {
		out.Reason = "negative-input"
		return out
	}
	E := lam * W
	if !finite(E) {
		out.Reason = "non-finite-expected"
		return out
	}
	if E == 0 && lam > 0 && W > 0 {
		out.Reason = "underflow-expected"
		return out
	}
	r := 0.0
	if L+E > 0 {
		if math.IsInf(L+E, 1) {
			// M115-MEASUREMENT-v1 §6: finite operands can overflow their sum.
			m := math.Max(L, E)
			r = (L/m - E/m) / (L/m + E/m)
		} else {
			r = (L - E) / (L + E)
		}
	}
	if !finite(r) {
		out.Reason = "non-finite-residual"
		return out
	}
	return FlowResult{Present: true, Basis: FlowBasisLittle, L: L, Lambda: lam, W: W, Expected: E,
		Residual: r, Magnitude: math.Abs(r), Age: t.MeanSojournSec.Age}
}

// Components returns every physics residual component with its presence. The three
// legacy conservation/sanity terms keep their formulas (they are not ruled by M-115); what
// changed is that an inapplicable term is ABSENT rather than a measured zero.
func Components(view *model.WorkloadView) []Component {
	t := view.Telemetry
	var out []Component

	// (0) Little's-law flow residual (M-115), gated on the ruling's per-class activation.
	fr := FlowResidualFor(view.Pod.Namespace, t)
	out = append(out, Component{Name: "flow-littles-law", Present: fr.Present, Magnitude: fr.Magnitude, Reason: fr.Reason})

	// (1) Byte flow-conservation: bytes in vs bytes out (cAdvisor). Needs some byte flow.
	if (t.BytesIn.Usable() && t.BytesIn.Value > 0) || (t.BytesOut.Usable() && t.BytesOut.Value > 0) {
		ratio := t.BytesOut.Value / (t.BytesIn.Value + 1.0)
		dev := math.Abs(math.Log10(clampPos(ratio, 1e-3)))
		out = append(out, Component{Name: "byte-flow", Present: true, Magnitude: clamp01((dev - 1.0) / 3.0)})
	} else {
		out = append(out, Component{Name: "byte-flow", Reason: "byte-flow-unavailable"})
	}

	// (2) Queue/backlog: DISABLED (M-115 conformance, 2026-09-06). Its formula subtracted a
	// RATE from a COUNT — (QueueDepth − ReqRate)/(ReqRate + 8) — which is the same unit
	// incoherence the ticket lists among M-115's defects, so it is not merely absent when its
	// inputs are missing: it never contributes, even when QueueDepth and ReqRate are both
	// present. A replacement is a separate design; reviving this one is not an option.
	out = append(out, Component{Name: "queue", Reason: QueueReasonDisabled})

	// (3) Connection fan-out: needs ConnCount AND ReqRate (never fabricated from absence).
	if t.ConnCount.Usable() && t.ReqRate.Usable() && t.ConnCount.Value > 0 {
		out = append(out, Component{Name: "fanout", Present: true, Magnitude: clamp01((t.ConnCount.Value - t.ReqRate.Value) / (t.ReqRate.Value + 20.0))})
	} else {
		out = append(out, Component{Name: "fanout", Reason: "conn-or-rate-unavailable"})
	}

	// (4) Throughput collapse under load (GPU/LLM): needs GPUUtil AND TokensPerSec.
	if t.GPUUtil.Usable() && t.TokensPerSec.Usable() {
		c := 0.0
		if t.GPUUtil.Value > 0.5 && t.TokensPerSec.Value >= 0 && t.TokensPerSec.Value < pol_floor {
			c = clamp01((pol_floor - t.TokensPerSec.Value) / pol_floor)
		}
		out = append(out, Component{Name: "collapse", Present: true, Magnitude: c})
	} else {
		out = append(out, Component{Name: "collapse", Reason: "gpu-or-tokens-unavailable"})
	}
	return out
}

// Aggregate is the ruled combination (M-115 Q8): the arithmetic mean of the MAGNITUDES of the
// present components; absent components enter neither numerator nor denominator; a measured
// zero does. Empty present set => absent (returned as 0 by Residual, the interface's honest
// absence). Signed residuals are never averaged (opposite directions would cancel).
func Aggregate(cs []Component) (a float64, present bool) {
	n, sum := 0, 0.0
	for _, c := range cs {
		if !c.Present || !finite(c.Magnitude) {
			continue
		}
		sum += c.Magnitude
		n++
	}
	if n == 0 {
		return 0, false
	}
	return clamp01(sum / float64(n)), true
}

func (littlesLaw) Residual(view *model.WorkloadView, _ model.Policy) float64 {
	a, _ := Aggregate(Components(view))
	return a
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
