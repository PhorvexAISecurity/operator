package actionset

import (
	"reflect"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestPreparationRetainsCostExcludedMoveWithoutEvaluatingLegacyCost(t *testing.T) {
	d, pol := testDeps(), testPolicy()
	pol.MaxMovesPerTick = 1
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	v := baseView("missing-load")
	v.Telemetry.ReqRate = model.Signal{}
	before := d.Generate([]*model.WorkloadView{v}, pol)
	if len(before.Candidates) != 0 || len(before.Excluded) != 1 || !before.Excluded[0].CostEvaluated {
		t.Fatalf("fixture must exercise a real legacy cost exclusion: %+v", before)
	}
	preparedDeps := d
	preparedDeps.ECost = func(*model.WorkloadView, model.Move, model.Policy) float64 {
		t.Fatal("preparation evaluated legacy ECost")
		return 0
	}
	preparedDeps.CHi = func(*model.WorkloadView, model.Move, model.Policy) float64 {
		t.Fatal("preparation evaluated legacy CHi")
		return 0
	}
	prepared := preparedDeps.Prepare([]*model.WorkloadView{v}, pol)
	if len(prepared.Candidates) != 1 || prepared.Candidates[0].Action != model.ActionRotate || len(prepared.Candidates[0].CoverKeys) == 0 {
		t.Fatalf("pre-cost rotate/facts missing: %+v", prepared)
	}
	if after := d.Generate([]*model.WorkloadView{v}, pol); !reflect.DeepEqual(before, after) {
		t.Fatal("preparation changed legacy generation")
	}
}

func TestPreparationPreservesActualCapabilityAndAvailabilityVetoes(t *testing.T) {
	for _, gate := range []string{"capability", "availability"} {
		t.Run(gate, func(t *testing.T) {
			d, pol := testDeps(), testPolicy()
			pol.MaxMovesPerTick = 1
			pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
			v := baseView("blocked")
			if gate == "capability" {
				d.Eligible = func(*model.WorkloadView, model.Action, []string) *Eligibility {
					return &Eligibility{Excluded: true, Kind: "capability-unsupported", Detail: "real callback"}
				}
			} else {
				v.Pod.ReadyReplicas = 1
			}
			legacy := d.Generate([]*model.WorkloadView{v}, pol)
			prepared := d.Prepare([]*model.WorkloadView{v}, pol)
			if len(legacy.Candidates) != 0 || len(legacy.Excluded) != 1 || len(prepared.Candidates) != 0 || !reflect.DeepEqual(legacy.Excluded, prepared.Excluded) {
				t.Fatalf("non-cost gate changed: legacy=%+v prepared=%+v", legacy.Excluded, prepared)
			}
		})
	}
}

func TestPreparationRejectsPartialPopulationOnReconCollision(t *testing.T) {
	views := []*model.WorkloadView{baseView("one"), baseView("two")}
	for _, collision := range []bool{false, true} {
		prepared := collisionDeps(collisionRecon{crossBlock: collision}).Prepare(views, testPolicy())
		if prepared.Rejected != collision || (collision && len(prepared.Candidates) != 0) || (!collision && len(prepared.Candidates) == 0) {
			t.Fatalf("collision=%v: %+v", collision, prepared)
		}
	}
}
