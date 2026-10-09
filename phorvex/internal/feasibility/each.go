package feasibility

import "github.com/phorvex/phorvex/internal/model"

// LawVerdict is one registered law's verdict on one move.
type LawVerdict struct {
	Law       string
	Verdict   Verdict
	Relaxable bool // availability/SLO law that EvaluateWithSLOSeparation may relax
}

// EvaluateEach runs every registered law in the same order Evaluate uses, without
// short-circuiting, and with the same fail-closed panic handling. It exists for read-only
// Math Lab gate diagnostics; admission decisions must keep using Evaluate. Laws are pure
// functions of (view, move, policy), so evaluating the ones production never reached does
// not change state, but their results are counterfactual, not what production ran.
func EvaluateEach(view *model.WorkloadView, move model.Move, pol model.Policy) []LawVerdict {
	if move.Action == model.ActionNoop {
		return nil
	}
	laws := Registry.All()
	out := make([]LawVerdict, 0, len(laws))
	for _, c := range laws {
		relaxable := false
		switch c.(type) {
		case availabilityFloor, sloHeadroom, tokensFloor:
			relaxable = true
		}
		out = append(out, LawVerdict{Law: c.Name(), Verdict: checkLaw(c, view, move, pol), Relaxable: relaxable})
	}
	return out
}
