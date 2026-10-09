package feasibility

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestEvaluateEachAgreesWithEvaluateOnTheFirstVeto(t *testing.T) {
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p", DesiredReplicas: 1, ReadyReplicas: 1, Ready: true, Stateful: true}}
	pol := model.Policy{MinAvailableReplicas: 1, AntiOverRotationWindow: 0}
	for _, action := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionKVReset} {
		move := model.Move{Action: action}
		first := Evaluate(view, move, pol)
		each := EvaluateEach(view, move, pol)
		if len(each) != len(Registry.All()) {
			t.Fatalf("%s: %d verdicts for %d laws", action, len(each), len(Registry.All()))
		}
		var firstVeto *LawVerdict
		for i := range each {
			if !each[i].Verdict.Feasible {
				firstVeto = &each[i]
				break
			}
		}
		if first.Feasible != (firstVeto == nil) {
			t.Fatalf("%s: Evaluate feasible=%v but EvaluateEach first veto=%v", action, first.Feasible, firstVeto)
		}
		if firstVeto != nil && firstVeto.Verdict.Reason != first.Reason {
			t.Fatalf("%s: first veto reason %q != %q", action, firstVeto.Verdict.Reason, first.Reason)
		}
	}
	if EvaluateEach(view, model.Move{Action: model.ActionNoop}, pol) != nil {
		t.Fatal("noop must not be evaluated")
	}
}
