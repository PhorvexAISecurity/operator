/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package feasibility

import (
	"fmt"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// This file ships the DEFAULT hard-law constraints (PRD §5.1A / FR2 / FR8). Each is
// one self-registering struct; adding another (e.g. VRAM/SM conservation on the GPU
// path) is one more file — zero change here.

// removesReadyReplica reports whether a move drops a Ready serving replica from rotation:
// rotate (Delete kills the pod) and quarantine (detach/freeze removes it from service) DO.
// The in-process AI moves do NOT: kv-reset keeps the pod ALIVE and Ready (handlers_ai:
// "kv-reset: pod ALIVE"); warm-swap cuts over to an already-Ready shadow; endpoint/adapter/
// guardrail rotate change identity/config, not the replica count. Gating those by the
// availability floor is the action-blind bug that makes Phorvex unable to defend a
// SINGLE-replica GPU/LLM server with its gentlest actuator (ready=1-1 < minAvail=1).
func removesReadyReplica(a model.Action) bool { return RemovesReadyReplica(a) }

// RemovesReadyReplica is the exported form, so the SLO disruption bound
// (internal/slo) derives "how many Ready replicas can this action take out" from
// the SAME predicate the availability floor gates on, rather than keeping a second
// copy of the list that would drift the first time an action is added.
func RemovesReadyReplica(a model.Action) bool {
	switch a {
	case model.ActionRotate, model.ActionQuarantine:
		return true
	}
	return false
}

// availabilityFloor enforces readyReplicas-1 >= MinAvailableReplicas for a move that
// REMOVES a Ready serving replica (rotate=Delete kills one; quarantine detaches one). A
// PodDisruptionBudget analogue. Non-removing moves (kv-reset/warm-swap/endpoint-rotate)
// keep the replica Ready, so they are NOT gated here — otherwise the floor would forbid
// the gentle in-process defense on the very single-replica inference pods it suits best.
type availabilityFloor struct{}

func (availabilityFloor) Name() string { return "availability-floor" }

func (availabilityFloor) Check(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict {
	if !removesReadyReplica(move.Action) {
		return feasible // in-process move: the pod stays Ready, availability is unchanged
	}
	// A scanned-but-unavailable PDB inventory is not evidence that no budget
	// applies. All matching budgets are aggregated conservatively for planning;
	// rotate still relies on atomic API Eviction admission at dispatch time.
	if view.Physics.Scanned && view.Physics.PDBObservationAttempted && !view.Physics.PDBObservationAvailable {
		return Verdict{Feasible: false, Reason: "pdb: observation unavailable: " + view.Physics.PDBObservationReason}
	}
	// Kubernetes Eviction does not support a Pod selected by more than one PDB.
	// Refuse rotate before dispatch even if each stale snapshot appears to have
	// headroom; the API remains the final authority for the single-PDB case.
	if move.Action == model.ActionRotate && view.Physics.PDBMatchCount > 1 {
		return Verdict{Feasible: false, Reason: fmt.Sprintf("pdb: overlapping budgets unsupported: matches=%d", view.Physics.PDBMatchCount)}
	}
	if view.Physics.PDBMatched && view.Physics.PDBDisruptionsAllowed < 1 {
		return Verdict{Feasible: false, Reason: fmt.Sprintf("pdb: %d matching budget(s), disruptionsAllowed=%d", view.Physics.PDBMatchCount, view.Physics.PDBDisruptionsAllowed)}
	}
	// For non-Eviction actions this is only a planning veto from observed
	// headroom. It does not reserve a disruption slot or claim atomic PDB safety.
	// Only meaningful when we know the owner's replica counts.
	if view.Pod.DesiredReplicas <= 0 {
		return feasible // bare pod / unknown owner: nothing to compare against
	}
	if view.Pod.ReadyReplicas-1 < pol.MinAvailableReplicas {
		return Verdict{Feasible: false, Reason: fmt.Sprintf(
			"availability: ready=%d-1 < minAvailable=%d", view.Pod.ReadyReplicas, pol.MinAvailableReplicas)}
	}
	return feasible
}

// sloHeadroom forbids a move on a pod already at/over the p99 SLO ceiling (rotating
// it would push the remaining replicas further past budget). 0 = unconstrained.
type sloHeadroom struct{}

func (sloHeadroom) Name() string { return "slo-headroom" }

func (sloHeadroom) Check(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict {
	if pol.P99Ms <= 0 || !view.Telemetry.P99Ms.Usable() || view.Telemetry.P99Ms.Value <= 0 {
		return feasible
	}
	// A quarantine FREEZES one pod (cuts capacity) just like a rotate; both stress
	// the remaining replicas, so both honor the SLO ceiling.
	if view.Telemetry.P99Ms.Value >= float64(pol.P99Ms) {
		return Verdict{Feasible: false, Reason: fmt.Sprintf(
			"slo: p99=%.0fms >= ceiling=%dms (no headroom to absorb the move)", view.Telemetry.P99Ms.Value, pol.P99Ms)}
	}
	return feasible
}

// antiOverRotation is the forensic/evidence-retention guard (FR8): never mutate the
// same pod faster than the window — so we don't wipe attack evidence. It reads the
// pod-identity exposure clock (time since this pod last changed identity).
type antiOverRotation struct{}

func (antiOverRotation) Name() string { return "anti-over-rotation" }

// ExposureVarFor maps an action to the exposure clock it actually resets. It is TOTAL
// over model.MutatingActions with NO catch-all podIdentity default (M-23) — every
// generatable action is cased explicitly, so a NEW action forces an exposure decision
// instead of silently inheriting the podIdentity clock it never resets. The
// TestExposureVarForCompleteness invariant fails the build if a MutatingActions member
// is unmapped or maps outside model.LiveExposureVariables (the clocked set).
//
// [PHVX-67 history] The guard used to read podIdentity for EVERY action. That is only correct for
// actions that REPLACE the pod (rotate/warm-swap/mig-rebind/model-shard-replace → new UID). A
// pod-alive action leaves podIdentity untouched, its clock only grows, and `since < window` is never
// true — so the one per-action brake never engaged. Each action now reads the `phorvex.ai/*-epoch`
// marker its own handler writes. debugger/custom-inject attach an ephemeral container and write no
// durable marker, so they keep the podIdentity clock (a conservative shared clock; they are not
// repeat-rotations). "" (noop/disable/unknown) = ungoverned → the guard fail-OPENs.
func ExposureVarFor(a model.Action) string {
	switch a {
	case model.ActionRotate, model.ActionWarmSwap, model.ActionMIGRebind, model.ActionModelShardReplace,
		model.ActionControllerStop,
		model.ActionK8sObjectRevert,
		model.ActionDatastoreRestore,
		// node-cordon-drain-replace evicts + reschedules the protected pod (a pod replacement, onto a
		// clean node), so it reads the always-on podIdentity freshness floor — the same short same-Pod
		// cooldown as rotate, damping repeated node-recycles triggered on the same pod.
		model.ActionNodeCordonDrainReplace,
		model.ActionAgentActionDeny,
		model.ActionRegistryRollback,
		model.ActionDebugger, model.ActionCustomInject, model.ActionSensitiveOutputPolicyActivate, model.ActionVoiceMemoryNoteRevoke, model.ActionVoiceRefundPairDeny, model.ActionVoiceOutputPolicyActivate, model.ActionVoiceSessionAdmissionEnforce, model.ActionVoiceMCPToolPin, model.ActionLiteLLMClientRevoke, model.ActionEndpointLeaseRevoke, model.ActionCRMRefundRevoke, model.ActionThrottle:
		// Output policy activation is Pod-local but has no Pod epoch annotation:
		// the protected ConfigMap revision is its durable operation clock.
		// Pod identity is the always-on freshness floor here; the emitted intent
		// provides the short same-Pod cooldown until a fresh snapshot arrives.
		return model.VarPodIdentity
	case model.ActionKVReset, model.ActionKVMigrateInvalidate:
		return model.VarSession
	case model.ActionQuarantine, model.ActionNetworkIsolate:
		// network-isolate acts on the same network-reachability dimension as quarantine (it
		// removes an egress channel edge), so it reads the networkIdentity exposure clock. On a
		// never-quarantined pod that clock is absent and the guard fail-OPENs (its first actuation
		// writes no podIdentity/UID change); it shares quarantine's clock to damp rapid
		// network-containment oscillation on the same pod.
		return model.VarNetworkIdentity
	case model.ActionEndpointRotate, model.ActionRouteRotate:
		return model.VarRouteKey
	case model.ActionIdentityRotate, model.ActionCredentialRevoke:
		// credential-revoke acts on the ServiceAccount identity/credential dimension (it
		// invalidates a bearer token), so it reads the identity exposure clock. Its own handler
		// writes no pod epoch marker (it deletes a Secret + patches the SA, the pod is untouched),
		// so on a pod that was never identity-actuated the clock is absent and the anti-over-
		// rotation guard fail-OPENs (its first revocation is always allowed); it shares the
		// identity clock only to damp rapid repeat-revocation on the same pod.
		return model.VarIdentity
	case model.ActionAdapterRotate:
		return model.VarAdapterEpoch
	case model.ActionRequestDrain:
		return model.VarDrainEpoch
	case model.ActionGuardrailRotate:
		return model.VarGuardrailEpoch
	default:
		return ""
	}
}

func (antiOverRotation) Check(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict {
	v := ExposureVarFor(move.Action)
	// Most-recent reset across the observed clock and the pending emit intent (M-23):
	// min over "since" durations == max over reset TIMESTAMPS. Either may be absent.
	since, ok := mostRecentSince(view, v)
	if !ok {
		// FAIL-OPEN (M-23 D1): the pod has no clock for this variable yet. Markers are
		// written BY actuation, so a never-actuated pod has none; fail-CLOSED here would
		// deadlock the very first actuation (the one that creates the marker). A
		// mapped-but-unclocked VARIABLE is a wiring bug — caught at build time by
		// TestExposureVarForCompleteness, not by a runtime veto.
		return feasible
	}
	if since < pol.AntiOverRotationWindow {
		return Verdict{Feasible: false, Reason: fmt.Sprintf(
			"anti-over-rotation: %s unchanged for %s < window=%s (evidence-retention guard)",
			v, since.Round(1e9), pol.AntiOverRotationWindow)}
	}
	return feasible
}

// mostRecentSince returns the smaller of the observed and intent "since" durations for
// v — the more recent of the two resets — and whether EITHER was present.
func mostRecentSince(view *model.WorkloadView, v string) (time.Duration, bool) {
	obs, obsOK := view.ExposureByVariable[v]
	intent, intOK := view.IntentByVariable[v]
	switch {
	case obsOK && intOK:
		if intent < obs {
			return intent, true
		}
		return obs, true
	case obsOK:
		return obs, true
	case intOK:
		return intent, true
	default:
		return 0, false
	}
}

// statefulIntegrity refuses to ROTATE (Delete) a stateful pod — destroying a
// long-running job / single-writer state. The PRD's lead demo: R6 blindly Deletes a
// critical stateful pod and destroys the work; Phorvex instead QUARANTINES (contain,
// preserve state). So a rotate on a stateful pod is infeasible; quarantine is fine.
type statefulIntegrity struct{}

func (statefulIntegrity) Name() string { return "stateful-integrity" }

func (statefulIntegrity) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if move.Action == model.ActionRotate && view.Pod.Stateful {
		return Verdict{Feasible: false, Reason: "stateful-integrity: rotate would destroy single-writer/long-running state; prefer quarantine"}
	}
	return feasible
}

func init() {
	Registry.Register(availabilityFloor{})
	Registry.Register(sloHeadroom{})
	Registry.Register(antiOverRotation{})
	Registry.Register(statefulIntegrity{})
}

// nativeRotationOwner reuses the same validated verdict as the destructive boundary.
type nativeRotationOwner struct{}

func (nativeRotationOwner) Name() string { return "native-rotation-owner" }
func (nativeRotationOwner) Check(v *model.WorkloadView, m model.Move, p model.Policy) Verdict {
	if m.Action != model.ActionRotate || !p.NativeRotate {
		return feasible
	}
	if !v.Pod.RotationOwnership.Eligible {
		reason := v.Pod.RotationOwnership.Reason
		if reason == "" {
			reason = "owner-unresolved"
		}
		return Verdict{Reason: "native-rotation-owner: " + reason}
	}
	return feasible
}
func init() { Registry.Register(nativeRotationOwner{}) }
