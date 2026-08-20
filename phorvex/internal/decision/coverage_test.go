/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func covPolicy(b int) model.Policy {
	return model.Policy{
		Tenant:                 "t",
		DryRun:                 true,
		NormSparsity:           0.4,
		FlowDisruption:         0.6,
		WeightSecrets:          0.8,
		BlastRadiusFromGraph:   true,
		MaxMovesPerTick:        b,
		ProactiveFloor:         time.Hour,
		AntiOverRotationWindow: 5 * time.Minute,
		MinAvailableReplicas:   1,
		EnabledActions:         map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true},
	}
}

func covView(name string, secrets bool, exposure time.Duration, stateful bool) *model.WorkloadView {
	v := &model.WorkloadView{
		Pod: model.Pod{
			Namespace: "ns", Name: name, UID: "u-" + name,
			DesiredReplicas: 3, ReadyReplicas: 3, Ready: true, Stateful: stateful,
		},
		Phase:              model.PhaseWarm,
		BlastRadius:        0.6,
		Neighbors:          []model.NeighborRef{{Key: "ns/crown", Value: 5.0}},
		ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: exposure},
	}
	if secrets {
		v.Pod.MountedSecrets = []string{"creds"}
	}
	return v
}

func countSelected(ds []model.Decision) int {
	n := 0
	for _, d := range ds {
		if d.Selected {
			n++
		}
	}
	return n
}

func TestCoverageBudgetAndPartition(t *testing.T) {
	e := NewCoverageEngine()
	views := []*model.WorkloadView{
		covView("a", true, 2*time.Hour, false),
		covView("b", true, 2*time.Hour, false),
		covView("c", true, 2*time.Hour, false),
	}
	ds := e.Decide(views, covPolicy(2))
	if got := countSelected(ds); got != 2 {
		t.Errorf("budget=2 should select exactly 2 moves, got %d", got)
	}
	// Partition: a selected asset has exactly one action (no asset selected twice — one
	// decision per pod by construction).
	seen := map[string]int{}
	for _, d := range ds {
		if d.Selected {
			seen[d.Namespace+"/"+d.Pod]++
		}
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("asset %s selected %d times (must be 1: one move per asset)", k, n)
		}
	}
}

func TestShadowDecisionDoesNotAdvanceProductionLearning(t *testing.T) {
	e := NewCoverageEngine()
	views := []*model.WorkloadView{covView("a", true, 2*time.Hour, false)}
	pol := covPolicy(1)
	beforeLambda := e.Cost.Dual.Lambda()
	beforePrior := e.Killchain.Memory.PriorMean(pol.Tenant)

	shadow, err := e.DecideShadowChecked(views, pol)
	if err != nil || countSelected(shadow) != 1 {
		t.Fatalf("shadow decision unavailable: selected=%d err=%v", countSelected(shadow), err)
	}
	if got := e.Cost.Dual.Lambda(); got != beforeLambda {
		t.Fatalf("shadow advanced dual state: %v -> %v", beforeLambda, got)
	}
	if got := e.Killchain.Memory.PriorMean(pol.Tenant); got != beforePrior {
		t.Fatalf("shadow advanced kill-chain memory: %v -> %v", beforePrior, got)
	}

	e.Decide(views, pol)
	if got := e.Killchain.Memory.PriorMean(pol.Tenant); got == beforePrior {
		t.Fatal("control production decision did not advance learning; isolation test is vacuous")
	}
}

func TestCoverageZeroDayProactiveNoEvents(t *testing.T) {
	// No SecurityEvents at all, but long exposure (past the proactive floor) => a
	// net-positive move is still selected: detector-INDEPENDENT proactive firing.
	e := NewCoverageEngine()
	v := covView("dweller", true, 3*time.Hour, false) // no Events on the view
	ds := e.Decide([]*model.WorkloadView{v}, covPolicy(3))
	d := ds[0]
	if d.CoverageValue <= 0 || d.ThreatRisk != 0 || d.DecisionValue() != d.CoverageValue {
		t.Fatalf("P1 value fields mixed coverage with deprecated threat risk: %+v", d)
	}
	if !d.Selected || d.Action == model.ActionNoop {
		t.Errorf("long-exposed pod with NO detector event must still get a proactive move (criterion 5); got action=%s selected=%v perDollar=%.3f", d.Action, d.Selected, d.PerDollar)
	}
	if d.Stage == "" || d.Lambda == 0 && d.PerDollar == 0 {
		t.Errorf("P1 decision should carry stage/lambda/perDollar; got stage=%q lambda=%.3f perDollar=%.3f", d.Stage, d.Lambda, d.PerDollar)
	}
}

func TestCoverageStatefulNeverRotated(t *testing.T) {
	e := NewCoverageEngine()
	v := covView("db", true, 2*time.Hour, true) // stateful + high value
	ds := e.Decide([]*model.WorkloadView{v}, covPolicy(3))
	d := ds[0]
	if d.Action == model.ActionRotate {
		t.Errorf("stateful pod must never be rotated (inviolable); got rotate")
	}
}

func TestCoverageAttributionExplainable(t *testing.T) {
	e := NewCoverageEngine()
	v := covView("x", true, 2*time.Hour, false)
	ds := e.Decide([]*model.WorkloadView{v}, covPolicy(3))
	d := ds[0]
	if !d.Selected {
		t.Fatalf("expected a selected move to attribute")
	}
	if len(d.Attribution) == 0 {
		t.Errorf("selected decision must carry SHAP-style attribution terms")
	}
	if d.PerDollar <= 0 {
		t.Errorf("selected decision must have a positive per-dollar coverage ratio")
	}
	// attribution must include at least one cover term and the cost term.
	var sawCover, sawCost bool
	for _, a := range d.Attribution {
		if len(a.Source) > 6 && a.Source[:6] == "cover:" {
			sawCover = true
		}
		if a.Source == "cost:-lambda*C" {
			sawCost = true
		}
	}
	if !sawCover || !sawCost {
		t.Errorf("attribution must decompose into cover + cost terms; got %+v", d.Attribution)
	}
}
