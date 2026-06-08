/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P2)
 *
 * P2 actuation invariants: what gets SELECTED is exactly what may be EMITTED, so these
 * prove the actuation path can never DoS itself (SLO/feasibility) or exceed budget, and
 * that every decision carries a complete rationale.
 */

package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func sloPolicy(b int) model.Policy {
	p := covPolicy(b)
	p.P99Ms = 200
	return p
}

// mixedFleet has a normal high-value pod, a stateful pod, a freshly-moved pod, a
// single-replica pod, and an SLO-hot pod — every kind of hard-constraint case.
func mixedFleet() []*model.WorkloadView {
	fresh := covView("fresh", true, 20*time.Second, false) // < anti-over-rotation window
	hot := covView("hot", true, 2*time.Hour, false)
	hot.Telemetry = model.Telemetry{Present: true, P99Ms: 250} // over the 200ms ceiling
	solo := covView("solo", true, 2*time.Hour, false)
	solo.Pod.DesiredReplicas = 1
	solo.Pod.ReadyReplicas = 1 // ready-1 < minAvailable => availability veto
	return []*model.WorkloadView{
		covView("normal", true, 2*time.Hour, false),
		covView("db", true, 2*time.Hour, true), // stateful
		fresh,
		hot,
		solo,
	}
}

// INVIOLABILITY AT ACTUATION: no SELECTED move (the ones that would be emitted) may
// ever violate a hard constraint.
func TestNoSelectedMoveViolatesAHardConstraint(t *testing.T) {
	e := NewCoverageEngine()
	ds := e.Decide(mixedFleet(), sloPolicy(5)) // budget big enough to try everything
	for _, d := range ds {
		if !d.Selected {
			continue
		}
		if !d.Feasible || d.Action == model.ActionNoop {
			t.Errorf("selected move on %s is infeasible/noop (would be emitted!): %+v", d.Pod, d)
		}
		switch d.Pod {
		case "db":
			if d.Action == model.ActionRotate {
				t.Errorf("stateful db selected for ROTATE — would destroy state")
			}
		case "fresh", "hot", "solo":
			t.Errorf("pod %s violates a hard constraint but was SELECTED for %s", d.Pod, d.Action)
		}
	}
}

// BUDGET = inviolable top-B truncation, for every B.
func TestSelectedNeverExceedsBudget(t *testing.T) {
	e := NewCoverageEngine()
	views := []*model.WorkloadView{
		covView("a", true, 2*time.Hour, false),
		covView("b", true, 2*time.Hour, false),
		covView("c", true, 2*time.Hour, false),
		covView("d", true, 2*time.Hour, false),
		covView("e", true, 2*time.Hour, false),
	}
	for _, b := range []int{0, 1, 2, 3, 5} {
		ds := e.Decide(views, covPolicy(b))
		if got := countSelected(ds); got > b {
			t.Errorf("budget=%d but %d moves selected (top-B truncation must be inviolable)", b, got)
		}
	}
}

// 100% of decisions carry a complete rationale.
func TestEveryDecisionHasCompleteRationale(t *testing.T) {
	e := NewCoverageEngine()
	ds := e.Decide(mixedFleet(), sloPolicy(3))
	if len(ds) != 5 {
		t.Fatalf("expected a decision per pod, got %d", len(ds))
	}
	for _, d := range ds {
		if d.Engine == "" {
			t.Errorf("%s: missing engine tag", d.Pod)
		}
		if d.Reason == "" {
			t.Errorf("%s: missing Reason", d.Pod)
		}
		if d.R6Counterfactual == "" {
			t.Errorf("%s: missing R6 counterfactual action", d.Pod)
		}
		if d.CounterfactualNote == "" {
			t.Errorf("%s: missing R6 counterfactual NOTE", d.Pod)
		}
		if d.Stage == "" {
			t.Errorf("%s: missing kill-chain stage", d.Pod)
		}
		if d.Selected && len(d.Attribution) == 0 {
			t.Errorf("%s: selected move must carry SHAP attribution", d.Pod)
		}
		if !d.Feasible && d.InfeasibleWhy == "" {
			t.Errorf("%s: infeasible decision must explain why", d.Pod)
		}
	}
}
