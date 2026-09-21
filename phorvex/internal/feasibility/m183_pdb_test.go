package feasibility

import (
	"github.com/phorvex/phorvex/internal/model"
	"strings"
	"testing"
)

func TestM183ReplicaRemovingPlanningUsesObservedPDBHeadroom(t *testing.T) {
	view := &model.WorkloadView{Physics: model.PhysicsWitness{Scanned: true, PDBObservationAttempted: true, PDBObservationAvailable: true, PDBMatched: true, PDBMatchCount: 1, PDBDisruptionsAllowed: 0}}
	for _, action := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		got := (availabilityFloor{}).Check(view, model.Move{Action: action}, model.Policy{})
		if got.Feasible || !strings.Contains(got.Reason, "disruptionsAllowed=0") {
			t.Fatalf("%s=%+v", action, got)
		}
	}
	if got := (availabilityFloor{}).Check(view, model.Move{Action: model.ActionKVReset}, model.Policy{}); !got.Feasible {
		t.Fatalf("non-removing=%+v", got)
	}
	view.Physics.PDBObservationAvailable = false
	view.Physics.PDBObservationReason = "pdb-status-generation-stale"
	if got := (availabilityFloor{}).Check(view, model.Move{Action: model.ActionRotate}, model.Policy{}); got.Feasible || !strings.Contains(got.Reason, "observation unavailable") {
		t.Fatalf("stale=%+v", got)
	}
}

func TestM183RotatePlanningRefusesOverlappingPDBsEvenWithHeadroom(t *testing.T) {
	view := &model.WorkloadView{Physics: model.PhysicsWitness{Scanned: true, PDBObservationAttempted: true, PDBObservationAvailable: true, PDBMatched: true, PDBMatchCount: 2, PDBDisruptionsAllowed: 1}}
	got := (availabilityFloor{}).Check(view, model.Move{Action: model.ActionRotate}, model.Policy{})
	if got.Feasible || !strings.Contains(got.Reason, "overlapping budgets unsupported") {
		t.Fatalf("rotate overlap=%+v", got)
	}
	// Quarantine sees the conservative planning headroom but has no atomic PDB
	// reservation claim; overlap itself is an Eviction API limitation.
	if got := (availabilityFloor{}).Check(view, model.Move{Action: model.ActionQuarantine}, model.Policy{}); !got.Feasible {
		t.Fatalf("quarantine overlap planning=%+v", got)
	}
}
