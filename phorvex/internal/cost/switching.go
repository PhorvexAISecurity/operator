/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package cost

import (
	"math"

	"github.com/phorvex/phorvex/internal/model"
)

// switching is the DEFAULT CostModel: K = normSparsity*C_norm + flowDisruption*C_flow
// (PRD §5.1B), the cost-weight split carried on PhorvexPolicy.Objective.CostWeights.
//
//   - C_norm = "how many variables move" (move as little as possible). A rotate
//     resets pod identity + node placement + image-resident state (many variables);
//     a quarantine flips only the network identity (few variables) — so quarantine
//     is cheaper on C_norm.
//   - C_flow = live disruption. Cold-starting/warm GPU pods are the expensive case
//     (KV-cache rebuild + 60–400s model warm-load); idle/low-traffic pods are cheap.
//
// All terms are dimensionless and bounded; with no telemetry the model falls back to
// phase + workload-kind priors (honest, never a fabricated latency number).
type switching struct{}

func (switching) Name() string { return "switching-cost" }

func (switching) Switching(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	cNorm := normCost(view, move)
	cFlow := flowCost(view, move)
	k := pol.NormSparsity*cNorm + pol.FlowDisruption*cFlow
	if math.IsNaN(k) {
		return NaNFailConservativeCost
	}
	if k < 0 {
		return 0
	}
	return k
}

// normCost: fraction of the (live) exposure variables a move resets. Rotate resets
// pod identity + node placement + in-pod state; quarantine resets only network
// reachability. Normalized by the count of live-tracked variables.
func normCost(view *model.WorkloadView, move model.Move) float64 {
	return normCostP1(view, move)
}

// flowCost: live-disruption cost, dominated by GPU/LLM warm state.
func flowCost(view *model.WorkloadView, move model.Move) float64 {
	// Quarantine does not kill the process (no warm-load to pay back) but does drop
	// the pod's live connections — a modest, phase-independent flow hit.
	if move.Action == model.ActionQuarantine {
		base := 0.25
		if view.Telemetry.ConnCount.Usable() && view.Telemetry.ConnCount.Value > 0 {
			base += 0.15 * sat(view.Telemetry.ConnCount.Value/100.0)
		}
		return clamp01c(base)
	}

	// Rotate (Delete): pay the warm-up back. Phase prior dominates. The prior is one
	// lookup into phaseFlowEncoding (the single spec, T1-D); an out-of-vocabulary phase
	// falls back to the Unknown row (0.5) explicitly, preserving the old fall-through.
	phase := phaseEncoding(view.Phase).switchPrior

	// GPU/LLM pods carry a large warm-load tax on rotate (60–400s reload, KV-cache
	// rebuild). This is the "R6 can't rotate AI safely" cost made explicit.
	gpu := 0.0
	if view.Pod.HasGPU {
		gpu = 0.6
		if view.Telemetry.GPUUtil.Usable() && view.Telemetry.GPUUtil.Value > 0 {
			gpu = 0.4 + 0.5*sat(view.Telemetry.GPUUtil.Value) // busier GPU => costlier to drop
		}
	}

	// Live request load adds dropped-connection cost.
	loadHit := 0.0
	if view.Telemetry.ReqRate.Usable() {
		loadHit = 0.2 * sat(view.Telemetry.ReqRate.Value/200.0)
	}

	return clamp01c(0.55*phase + 0.35*gpu + loadHit)
}

func sat(x float64) float64 {
	// NaN-SAFE: every comparison against NaN is false, so a bare `if x<0 / if x>1` would fall
	// through and RETURN NaN — poisoning ECost and making the optimizer compare NaN costs. A
	// NaN/absent telemetry field must read as NEUTRAL (0), never propagate.
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

func clamp01c(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func init() { Registry.Register(switching{}) }
