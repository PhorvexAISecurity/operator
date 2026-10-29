package feasibility

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/statefulrotation"
)

// statefulRotationAdmission is the hard law for the stateful rotation family. It evaluates
// the shared statefulrotation.Admit law on the snapshot observation, so each class is
// feasible exactly when its owner declares it AND the live set can absorb it: owner not
// mid-rollout, every member Ready, quorum headroom kept, and the class's own volume
// preconditions (A: non-leader member on template claims; B: ready snapshot class and Bound
// claims; C: no claims). The native handler re-admits the same law against the live API.
// Non-stateful-family moves are unaffected, so every other action's parity is byte-identical.
type statefulRotationAdmission struct{}

func (statefulRotationAdmission) Name() string { return "stateful-rotation-admission" }

func (statefulRotationAdmission) Check(view *model.WorkloadView, move model.Move, _ model.Policy) Verdict {
	if !model.IsStatefulRotation(move.Action) {
		return feasible
	}
	if ok, why := statefulrotation.Admit(view.Pod.StatefulRotation, view.Pod.Ready, move.Action); !ok {
		return Verdict{Feasible: false, Reason: "stateful-rotation-admission: " + string(move.Action) + ": " + why}
	}
	return feasible
}

func init() { Registry.Register(statefulRotationAdmission{}) }
