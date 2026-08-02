/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package feasibility

import "github.com/phorvex/phorvex/internal/model"

// gpuconservation.go holds the PRD Layer-A GPU/accelerator CONSERVATION hard laws for
// the AI product. They read the discovered live view.Physics witness. On a cluster
// without a GPU/DCGM scan (e.g. kind), Physics.GPUPresent is false and they degrade
// to honest-neutral (feasible) — never fabricating a VRAM number. A GPU adapter that
// fills the witness activates them with ZERO change here (the registry first-veto-wins
// gate picks them up automatically).

// vramConservation vetoes a move that would leave the rebind/replacement target without
// enough GPU VRAM (a physically infeasible placement). Honest-absent when no GPU scan.
type vramConservation struct{}

func (vramConservation) Name() string { return "vram-conservation" }

func (vramConservation) Check(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict {
	if !view.Physics.GPUPresent {
		return feasible // no measured VRAM => never veto
	}
	// A rotate/rebind/warm-replace that demands more VRAM than the device fraction leaves
	// is illegal. Covers the GPU-provisioning moves, not just plain rotate.
	if gpuProvisioningMove(move.Action) && view.Physics.VRAMFraction > 1.0 {
		return Verdict{Feasible: false, Reason: "VRAM conservation: replacement exceeds device VRAM allocatable"}
	}
	return feasible
}

// gpuProvisioningMove is any move that provisions/rebinds a GPU placement and so must
// satisfy the VRAM/MIG conservation laws (rotate + the native GPU swaps).
func gpuProvisioningMove(a model.Action) bool {
	switch a {
	case model.ActionRotate, model.ActionWarmSwap, model.ActionMIGRebind, model.ActionModelShardReplace:
		return true
	}
	return false
}

// migValidity vetoes a rotate/rebind whose MIG partition geometry is not a legal layout
// advertised by any node's device plugin (a physically impossible MIG rebind target).
// A pod with no MIG device is trivially valid; on kind there are none => feasible.
type migValidity struct{}

func (migValidity) Name() string { return "mig-validity" }

func (migValidity) Check(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict {
	if view.Pod.MIGDevice == "" || !view.Physics.Scanned {
		return feasible // not a MIG pod, or no scan => honest-absent
	}
	if gpuProvisioningMove(move.Action) && !view.Physics.MIGGeometryValid {
		return Verdict{Feasible: false, Reason: "MIG validity: rebind target is not a legal device-plugin partition geometry"}
	}
	return feasible
}

func init() {
	Registry.Register(vramConservation{})
	Registry.Register(migValidity{})
}
