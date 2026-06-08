/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package feasibility

import (
	"fmt"

	"github.com/phorvex/phorvex/internal/model"
)

// This file ships the DEFAULT hard-law constraints (PRD §5.1A / FR2 / FR8). Each is
// one self-registering struct; adding another (e.g. VRAM/SM conservation on the GPU
// path) is one more file — zero change here.

// availabilityFloor enforces readyReplicas-1 >= MinAvailableReplicas for a rotate
// (Delete kills one replica; the ReplicaSet respawns, but momentarily availability
// drops). A PodDisruptionBudget analogue. Quarantine also removes a serving replica.
type availabilityFloor struct{}

func (availabilityFloor) Name() string { return "availability-floor" }

func (availabilityFloor) Check(view *model.WorkloadView, _ model.Move, pol model.Policy) Verdict {
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
	if pol.P99Ms <= 0 || !view.Telemetry.Present || view.Telemetry.P99Ms <= 0 {
		return feasible
	}
	// A quarantine FREEZES one pod (cuts capacity) just like a rotate; both stress
	// the remaining replicas, so both honor the SLO ceiling.
	if view.Telemetry.P99Ms >= float64(pol.P99Ms) {
		return Verdict{Feasible: false, Reason: fmt.Sprintf(
			"slo: p99=%.0fms >= ceiling=%dms (no headroom to absorb the move)", view.Telemetry.P99Ms, pol.P99Ms)}
	}
	return feasible
}

// antiOverRotation is the forensic/evidence-retention guard (FR8): never mutate the
// same pod faster than the window — so we don't wipe attack evidence. It reads the
// pod-identity exposure clock (time since this pod last changed identity).
type antiOverRotation struct{}

func (antiOverRotation) Name() string { return "anti-over-rotation" }

func (antiOverRotation) Check(view *model.WorkloadView, _ model.Move, pol model.Policy) Verdict {
	since, ok := view.ExposureByVariable[model.VarPodIdentity]
	if !ok {
		return feasible // no clock yet (first observation): allow
	}
	if since < pol.AntiOverRotationWindow {
		return Verdict{Feasible: false, Reason: fmt.Sprintf(
			"anti-over-rotation: lastMove=%s < window=%s (evidence-retention guard)", since.Round(1e9), pol.AntiOverRotationWindow)}
	}
	return feasible
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
