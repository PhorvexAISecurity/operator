/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// basePolicy is a representative resolved policy for the tests.
func basePolicy(b int) model.Policy {
	return model.Policy{
		Tenant:                 "t",
		Namespace:              "ns",
		Mode:                   "dryRun",
		DryRun:                 true,
		Lambda:                 0.6,
		NormSparsity:           0.4,
		FlowDisruption:         0.6,
		WeightSecrets:          0.8,
		BlastRadiusFromGraph:   true,
		MaxMovesPerTick:        b,
		TickInterval:           20 * time.Second,
		AntiOverRotationWindow: 5 * time.Minute,
		ProactiveFloor:         time.Hour,
		MinAvailableReplicas:   1,
		EventDriven:            true,
		EnabledActions:         map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true},
	}
}

// highExposureIdlePod: long-exposed, idle, secret-bearing, replicated, NOT stateful.
func highExposureIdlePod(name string, blast float64, stateful bool) *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{
			Namespace: "ns", Name: name, UID: "uid-" + name,
			MountedSecrets: []string{"creds"}, DesiredReplicas: 3, ReadyReplicas: 3,
			Ready: true, Stateful: stateful,
		},
		Telemetry:   model.Telemetry{Present: true, ReqRate: 0, GPUUtil: 0, P99Ms: 0},
		Phase:       model.PhaseIdle,
		BlastRadius: blast,
		ExposureByVariable: map[string]time.Duration{
			model.VarPodIdentity: 2 * time.Hour, // >> proactiveFloor => high exposure/belief
		},
	}
}

func TestRotateCheapLowBlastPod(t *testing.T) {
	e := NewEngine()
	v := highExposureIdlePod("a", 0.0, false)
	ds := e.Decide([]*model.WorkloadView{v}, basePolicy(3))
	if len(ds) != 1 {
		t.Fatalf("want 1 decision, got %d", len(ds))
	}
	d := ds[0]
	if d.Action != model.ActionRotate {
		t.Errorf("cheap, low-blast, long-exposed idle pod should ROTATE, got %s (net=%.3f)", d.Action, d.Net)
	}
	if !d.Selected {
		t.Errorf("net-positive move within budget should be selected")
	}
	if d.R6Counterfactual != model.ActionRotate {
		t.Errorf("R6 counterfactual should be rotate (blind timer)")
	}
}

func TestStatefulPodQuarantinedNotRotated(t *testing.T) {
	e := NewEngine()
	v := highExposureIdlePod("db", 0.9, true) // stateful + high blast
	ds := e.Decide([]*model.WorkloadView{v}, basePolicy(3))
	d := ds[0]
	if d.Action == model.ActionRotate {
		t.Errorf("stateful pod must NOT be rotated (would destroy state); got rotate")
	}
	if d.Action != model.ActionQuarantine {
		t.Errorf("high-blast stateful pod should be QUARANTINED, got %s (net=%.3f, feasible=%v, why=%q)", d.Action, d.Net, d.Feasible, d.InfeasibleWhy)
	}
}

func TestBudgetCapsSelection(t *testing.T) {
	e := NewEngine()
	views := []*model.WorkloadView{
		highExposureIdlePod("a", 0, false),
		highExposureIdlePod("b", 0, false),
		highExposureIdlePod("c", 0, false),
	}
	ds := e.Decide(views, basePolicy(1)) // budget 1
	selected := 0
	for _, d := range ds {
		if d.Selected {
			selected++
		}
	}
	if selected != 1 {
		t.Errorf("budget=1 should select exactly 1 move, got %d", selected)
	}
}

func TestAntiOverRotationBlocksFreshPod(t *testing.T) {
	e := NewEngine()
	v := highExposureIdlePod("fresh", 0, false)
	// Pod was just rotated 30s ago (< 5m window) => anti-over-rotation must veto rotate.
	v.ExposureByVariable[model.VarPodIdentity] = 30 * time.Second
	ds := e.Decide([]*model.WorkloadView{v}, basePolicy(3))
	d := ds[0]
	if d.Action == model.ActionRotate {
		t.Errorf("fresh pod (30s < 5m window) must not be rotated; anti-over-rotation should veto")
	}
}

func TestNoActionWhenAllInfeasible(t *testing.T) {
	e := NewEngine()
	v := highExposureIdlePod("solo", 0, false)
	v.Pod.DesiredReplicas = 1
	v.Pod.ReadyReplicas = 1 // ready-1 = 0 < minAvailable(1) => availability veto on both moves
	ds := e.Decide([]*model.WorkloadView{v}, basePolicy(3))
	d := ds[0]
	if d.Action != model.ActionNoop {
		t.Errorf("single-replica pod must be noop (availability floor), got %s", d.Action)
	}
	if d.Feasible {
		t.Errorf("decision should be marked infeasible with a reason; why=%q", d.InfeasibleWhy)
	}
}
