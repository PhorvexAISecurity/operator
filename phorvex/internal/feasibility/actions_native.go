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
		model.ActionKVReset, model.ActionEndpointRotate,
		model.ActionAdapterRotate, model.ActionRequestDrain, model.ActionGuardrailRotate, model.ActionKVMigrateInvalidate:
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

// isCodeExecMove reports whether an action injects an ephemeral container — an IRREVERSIBLE
// in-pod CODE-EXECUTION primitive (a shell sharing the victim pod's SA token/network/volumes).
func isCodeExecMove(a model.Action) bool {
	switch a {
	case model.ActionDebugger, model.ActionCustomInject:
		return true
	}
	return false
}

// systemNamespaces are the control-plane namespaces an autonomous actuator must NEVER inject
// code into (the highest-blast-radius weaponization target).
var systemNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true, "kube-apiserver": true,
}

// codeExecGuard (P4c D1/F2) is the action-SPECIFIC HARD law that ephemeral-container injection
// (debugger/custom-inject — the in-pod RCE primitive) previously LACKED: it was gated only by
// the action-agnostic defaults, so it passed on ANY pod once enabled. This vetoes code-exec in
// a system namespace outright (defense-in-depth alongside the SEPARATE opt-in RBAC Role for
// pods/ephemeralcontainers and the busybox-only image hardcoded in the handler). Non-code-exec
// moves are unaffected, so {rotate,quarantine}/AI parity is byte-identical.
type codeExecGuard struct{}

func (codeExecGuard) Name() string { return "code-exec-guard" }

func (codeExecGuard) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if !isCodeExecMove(move.Action) {
		return feasible
	}
	if systemNamespaces[view.Pod.Namespace] {
		return Verdict{Feasible: false, Reason: "code-exec-guard: ephemeral-container injection (" + string(move.Action) + ") DENIED in system namespace " + view.Pod.Namespace + " (in-pod RCE blast-radius)"}
	}
	return feasible
}

func init() {
	Registry.Register(aiContextRequired{})
	Registry.Register(migDeviceRequired{})
	Registry.Register(codeExecGuard{})
}
