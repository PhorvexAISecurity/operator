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
		model.ActionAdapterRotate, model.ActionRequestDrain, model.ActionGuardrailRotate, model.ActionKVMigrateInvalidate,
		model.ActionSensitiveOutputPolicyActivate, model.ActionVoiceMemoryNoteRevoke, model.ActionVoiceRefundPairDeny, model.ActionVoiceOutputPolicyActivate, model.ActionVoiceSessionAdmissionEnforce, model.ActionVoiceMCPToolPin, model.ActionLiteLLMClientRevoke, model.ActionEndpointLeaseRevoke, model.ActionCRMRefundRevoke, model.ActionDatastoreRestore, model.ActionAgentActionDeny:
		return true
	}
	return false
}

// aiContextRequired separates hardware, serving and detector authority. A GPU allocation
// licenses GPU-specific work only; serving actions require an explicit serving declaration,
// and adapter eviction requires its exact UID-bound detector observation.
type aiContextRequired struct{}

func (aiContextRequired) Name() string { return "ai-context-required" }

func (aiContextRequired) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if !isAIMove(move.Action) {
		return feasible
	}
	var available bool
	switch move.Action {
	case model.ActionMIGRebind:
		available = view.Pod.HasGPU
	case model.ActionAdapterRotate:
		available = view.Pod.HasBoundAdapterObservation()
	case model.ActionSensitiveOutputPolicyActivate:
		available = view.Pod.HasBoundSensitiveOutputObservation()
	case model.ActionVoiceMemoryNoteRevoke:
		available = view.Pod.HasBoundVoiceMemoryObservation()
	case model.ActionVoiceRefundPairDeny:
		available = view.Pod.HasBoundVoiceRefundObservation()
	case model.ActionVoiceMCPToolPin:
		available = view.Pod.HasBoundVoiceMCPObservation()
	case model.ActionVoiceOutputPolicyActivate:
		available = view.Pod.HasBoundVoiceOutputObservation()
	case model.ActionVoiceSessionAdmissionEnforce:
		available = view.Pod.HasBoundVoiceAdmissionObservation()
	case model.ActionLiteLLMClientRevoke:
		available = view.Pod.HasBoundLiteLLMClientObservation()
	case model.ActionCRMRefundRevoke:
		available = view.Pod.HasBoundCRMRefundObservation()
	case model.ActionDatastoreRestore:
		available = view.Pod.HasBoundDatastoreRestoreObservation()
	case model.ActionAgentActionDeny:
		available = view.Pod.HasBoundAgentActionDenyObservation()
	case model.ActionEndpointLeaseRevoke:
		available = view.Pod.HasBoundEndpointLeaseObservation()
	default:
		available = view.Pod.HasServingDeclaration()
	}
	if available {
		return feasible
	}
	return Verdict{Feasible: false, Reason: "ai-context-required: " + string(move.Action) + " lacks its required GPU, serving, or detector context"}
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
		return Verdict{Feasible: false, Reason: "mig-device-required: pod has no MIG device to rebind"}
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

// nodeCordonDrainReplaceObservationRequired is the action-SPECIFIC hard law for the node recycle:
// node-cordon-drain-replace is infeasible unless THIS exact Pod carries a trusted, bound node/
// host-escape observation whose NodeName equals the Pod's live node. Without it there is no
// compromised host to recycle, so the (highest-blast-radius) move is never selected. Namespace-
// parametric: the law pins no namespace/node literal — the bound observation + reactive policy
// scope bound which Pods qualify. Non-node-cordon moves are unaffected, so {rotate,quarantine}/AI
// parity is byte-identical.
type nodeCordonDrainReplaceObservationRequired struct{}

func (nodeCordonDrainReplaceObservationRequired) Name() string {
	return "node-cordon-drain-replace-observation-required"
}

func (nodeCordonDrainReplaceObservationRequired) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if move.Action != model.ActionNodeCordonDrainReplace {
		return feasible
	}
	if !view.Pod.HasBoundNodeEscapeObservation() {
		return Verdict{Feasible: false, Reason: "node-cordon-drain-replace-observation-required: no trusted bound node/host-escape observation for this pod"}
	}
	return feasible
}

// networkIsolateObservationRequired is the action-SPECIFIC hard law for the surgical egress
// edge cut: network-isolate is infeasible unless this exact Pod carries a trusted, bound
// network-edge observation (a detector flagged an open C2/exfil/IMDS egress channel). Without
// it there is nothing to cut, so the move is never selected. Namespace-parametric: the law
// pins no namespace — the bound observation + reactive policy scope bound which Pods qualify.
// Non-network-isolate moves are unaffected, so {rotate,quarantine}/AI parity is byte-identical.
type networkIsolateObservationRequired struct{}

func (networkIsolateObservationRequired) Name() string { return "network-isolate-observation-required" }

func (networkIsolateObservationRequired) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if move.Action != model.ActionNetworkIsolate {
		return feasible
	}
	if !view.Pod.HasBoundNetworkIsolateObservation() {
		return Verdict{Feasible: false, Reason: "network-isolate-observation-required: no trusted bound egress-edge observation for this pod"}
	}
	return feasible
}

// credentialRevokeObservationRequired is the action-SPECIFIC hard law for revoking a stolen
// ServiceAccount credential: credential-revoke is infeasible unless this exact Pod carries a
// trusted, bound stolen-credential observation (a detector flagged a leaked SA token being
// reused). Without it there is nothing to revoke, so the move is never selected. Namespace-
// parametric: the law pins no namespace — the bound observation + reactive policy scope bound
// which Pods qualify. Non-credential-revoke moves are unaffected, so {rotate,quarantine}/AI
// parity is byte-identical.
type credentialRevokeObservationRequired struct{}

func (credentialRevokeObservationRequired) Name() string {
	return "credential-revoke-observation-required"
}

func (credentialRevokeObservationRequired) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if move.Action != model.ActionCredentialRevoke {
		return feasible
	}
	if !view.Pod.HasBoundCredentialRevokeObservation() {
		return Verdict{Feasible: false, Reason: "credential-revoke-observation-required: no trusted bound stolen-credential observation for this pod"}
	}
	return feasible
}

func init() {
	Registry.Register(aiContextRequired{})
	Registry.Register(migDeviceRequired{})
	Registry.Register(codeExecGuard{})
	Registry.Register(nodeCordonDrainReplaceObservationRequired{})
	Registry.Register(networkIsolateObservationRequired{})
	Registry.Register(credentialRevokeObservationRequired{})
}
