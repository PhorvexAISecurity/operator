package feasibility

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// TestCodeExecGuardDeniesSystemNamespace — P4c D1: ephemeral-container injection
// (debugger/custom-inject) is VETOED in a system namespace, allowed elsewhere; non-code-exec
// moves are unaffected (parity).
func TestCodeExecGuardDeniesSystemNamespace(t *testing.T) {
	g := codeExecGuard{}
	view := func(ns string) *model.WorkloadView { return &model.WorkloadView{Pod: model.Pod{Namespace: ns}} }
	cases := []struct {
		ns      string
		action  model.Action
		blocked bool
	}{
		{"kube-system", model.ActionCustomInject, true},
		{"kube-system", model.ActionDebugger, true},
		{"kube-public", model.ActionCustomInject, true},
		{"acme-tenant", model.ActionCustomInject, false}, // non-system ns: code-exec gate doesn't fire (other layers gate it)
		{"kube-system", model.ActionRotate, false},       // non-code-exec move: unaffected
		{"kube-system", model.ActionQuarantine, false},
	}
	for _, c := range cases {
		v := g.Check(view(c.ns), model.Move{Action: c.action}, model.Policy{})
		if v.Feasible == c.blocked {
			t.Errorf("codeExecGuard ns=%s action=%s: feasible=%v, wanted blocked=%v (%s)", c.ns, c.action, v.Feasible, c.blocked, v.Reason)
		}
	}
}

// panickingLaw is a constraint that panics, to prove Evaluate fails CLOSED.
type panickingLaw struct{}

func (panickingLaw) Name() string { return "panicking-law" }
func (panickingLaw) Check(*model.WorkloadView, model.Move, model.Policy) Verdict {
	panic("boom")
}

// TestEvaluateFailsClosedOnLawPanic — P4c fail-closed sweep: a panicking feasibility law
// VETOES the move (infeasible) instead of crashing the tick.
func TestEvaluateFailsClosedOnLawPanic(t *testing.T) {
	v := checkLaw(panickingLaw{}, &model.WorkloadView{Pod: model.Pod{}}, model.Move{Action: model.ActionRotate}, model.Policy{})
	if v.Feasible {
		t.Errorf("a panicking law must fail CLOSED (infeasible), got feasible=%v", v.Feasible)
	}
}
