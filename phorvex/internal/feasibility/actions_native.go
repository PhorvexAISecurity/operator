/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * Per-action hard laws for the native advanced/AI moves. The action-AGNOSTIC defaults
 * (availability-floor, slo-headroom, anti-over-rotation) ALREADY gate every move incl.
 * these; this file adds the action-SPECIFIC laws the new moves need. Each is one self-
 * registering struct (the completeness invariant's feasibility-reachability arm requires
 * every generatable action be gated). Honest-absent on kind: the AI moves require an AI
 * context, so on a plain K8s pod they are infeasible and never selected (parity preserved).
 */

package feasibility

import "github.com/phorvex/phorvex/internal/model"

// isAIMove reports whether an action is an AI/GPU move that only makes sense on an
// inference/accelerated workload.
func isAIMove(a model.Action) bool {
	switch a {
	case model.ActionWarmSwap, model.ActionMIGRebind, model.ActionModelShardReplace,
		model.ActionKVReset, model.ActionEndpointRotate:
		return true
	}
	return false
}

// aiContextRequired vetoes an AI/GPU move on a workload with NO AI context (no GPU and no
// model id) — you do not warm-swap / KV-reset a plain web server. On kind (plain pods,
// GPUPresent=false, no ModelID) these moves are therefore infeasible and never selected,
// so the default {rotate,quarantine} decision is byte-identical (1.62x + P3 + lead-demo
// parity). An inference pod (ModelID set, or HasGPU) makes them feasible; the handler then
// applies the fine gate (warm-swap requires a Ready shadow, etc.).
type aiContextRequired struct{}

func (aiContextRequired) Name() string { return "ai-context-required" }

func (aiContextRequired) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if !isAIMove(move.Action) {
		return feasible
	}
	if view.Pod.HasGPU || view.Pod.ModelID != "" {
		return feasible
	}
	return Verdict{Feasible: false, Reason: "ai-context-required: " + string(move.Action) + " needs an inference/accelerated workload (no GPU, no model-id) [SP-0-PENDING]"}
}

// migDeviceRequired vetoes a mig-rebind on a pod with no MIG device (there is nothing to
// repartition). On kind there are none => infeasible => never selected.
type migDeviceRequired struct{}

func (migDeviceRequired) Name() string { return "mig-device-required" }

func (migDeviceRequired) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if move.Action != model.ActionMIGRebind {
		return feasible
	}
	if view.Pod.MIGDevice == "" {
		return Verdict{Feasible: false, Reason: "mig-device-required: pod has no MIG device to rebind [SP-0-PENDING]"}
	}
	return feasible
}

func init() {
	Registry.Register(aiContextRequired{})
	Registry.Register(migDeviceRequired{})
}
