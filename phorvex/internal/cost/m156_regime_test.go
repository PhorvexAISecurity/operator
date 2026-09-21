package cost

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func m156View(phase model.WorkloadPhase, signal model.Signal) *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "m156"}, Phase: phase,
		Telemetry: model.Telemetry{ReqRate: signal}}
}

func TestM156MissingAndMeasuredZeroHaveSameRLSFeaturesButDifferentSupport(t *testing.T) {
	missing := m156View(model.PhaseWarm, model.Signal{})
	zero := m156View(model.PhaseWarm, model.PresentSignal(0, "fixture"))
	if Features(missing) != Features(zero) {
		t.Fatal("fixture: zero-valued RLS feature vectors should remain state-compatible")
	}
	c := NewP1Cost()
	pol := model.Policy{NormSparsity: .4, FlowDisruption: .6}
	missingEval := c.Evaluation(missing, model.Move{Action: model.ActionRotate}, pol)
	zeroEval := c.Evaluation(zero, model.Move{Action: model.ActionRotate}, pol)
	if missingEval.FlowRegime != RespawnFlowMissingLoad || !missingEval.FlowFloorApplied ||
		missingEval.FlowConservativeFloor != .7 || !missingEval.FlowUncertaintyApplied {
		t.Fatalf("missing load lost conservative provenance: %+v", missingEval)
	}
	if zeroEval.FlowRegime != RespawnFlowMeasuredLoad || zeroEval.FlowFloorApplied || zeroEval.FlowUncertaintyApplied ||
		!zeroEval.ConformalRegimeApplicable {
		t.Fatalf("measured zero was treated as missing: %+v", zeroEval)
	}
	stale := m156View(model.PhaseWarm, model.Signal{State: model.Stale, Value: 99, Src: "fixture"})
	if got := c.Evaluation(stale, model.Move{Action: model.ActionRotate}, pol); got.FlowRegime != RespawnFlowMissingLoad {
		t.Fatalf("stale request rate was treated as measured: %+v", got)
	}
}

func TestM156SourceOwnedFloorsAndUpperBound(t *testing.T) {
	c := NewP1Cost()
	pol := model.Policy{NormSparsity: .4, FlowDisruption: .6}
	cases := []struct {
		name   string
		phase  model.WorkloadPhase
		signal model.Signal
		regime RespawnFlowRegime
		floor  float64
	}{
		{"cold-missing", model.PhaseColdStarting, model.Signal{}, RespawnFlowMissingLoad, 1},
		{"warm-missing", model.PhaseWarm, model.Signal{}, RespawnFlowMissingLoad, .7},
		{"idle-missing", model.PhaseIdle, model.Signal{}, RespawnFlowMissingLoad, .15},
		{"draining", model.PhaseDraining, model.PresentSignal(12, "fixture"), RespawnFlowDrainingPhase, .2},
		{"unknown", model.PhaseUnknown, model.PresentSignal(12, "fixture"), RespawnFlowUnknownPhase, .5},
		{"unrecognized", model.WorkloadPhase("FuturePhase"), model.PresentSignal(12, "fixture"), RespawnFlowUnknownPhase, .5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eval := c.Evaluation(m156View(tc.phase, tc.signal), model.Move{Action: model.ActionRotate}, pol)
			if eval.FlowRegime != tc.regime || !eval.FlowFloorApplied || eval.FlowConservativeFloor != tc.floor ||
				eval.Flow < tc.floor || !eval.FlowUncertaintyApplied || eval.FlowUncertaintyBound != unknownActionFlowMax {
				t.Fatalf("wrong regime/floor/bound: %+v", eval)
			}
			wantSlack := pol.FlowDisruption * (unknownActionFlowMax - eval.Flow)
			if math.Abs(eval.FlowUncertaintySlack-wantSlack) > 1e-12 {
				t.Fatalf("uncertainty slack=%g want=%g", eval.FlowUncertaintySlack, wantSlack)
			}
			if eval.ConformalRegimeApplicable {
				t.Fatal("unsupported regime claimed conformal applicability")
			}
		})
	}
}

func TestM156KnownPhaseMeasuredZeroRemainsSupported(t *testing.T) {
	c := NewP1Cost()
	pol := model.Policy{NormSparsity: .4, FlowDisruption: .6}
	for _, phase := range []model.WorkloadPhase{model.PhaseColdStarting, model.PhaseWarm, model.PhaseIdle} {
		eval := c.Evaluation(m156View(phase, model.PresentSignal(0, "fixture")), model.Move{Action: model.ActionRotate}, pol)
		if eval.FlowRegime != RespawnFlowMeasuredLoad || eval.FlowFloorApplied || eval.FlowUncertaintyApplied ||
			!eval.ConformalRegimeApplicable {
			t.Fatalf("measured-zero %s acquired unsupported provenance: %+v", phase, eval)
		}
	}
}

func TestM156GenericIdleLearningCannotEraseUnsupportedFloors(t *testing.T) {
	c := NewP1Cost()
	idleMeasured := m156View(model.PhaseIdle, model.PresentSignal(0, "fixture"))
	for i := 0; i < 40; i++ {
		c.ObserveRotation(idleMeasured, 0)
	}
	if !c.Conformal.Calibrated() {
		t.Fatal("fixture: generic conformal window did not become ready")
	}
	pol := model.Policy{NormSparsity: .4, FlowDisruption: .6}
	for _, tc := range []struct {
		phase model.WorkloadPhase
		floor float64
	}{
		{model.PhaseWarm, .7}, {model.PhaseDraining, .2}, {model.PhaseUnknown, .5},
	} {
		eval := c.Evaluation(m156View(tc.phase, model.Signal{}), model.Move{Action: model.ActionRotate}, pol)
		if eval.FlowPredictedMean >= tc.floor {
			t.Fatalf("fixture did not pull raw %s mean below floor: %+v", tc.phase, eval)
		}
		if eval.Flow != tc.floor || !eval.ConformalWindowReady || eval.ConformalRegimeApplicable {
			t.Fatalf("generic learning erased unsupported %s floor/support truth: %+v", tc.phase, eval)
		}
	}
}

func TestM156PredictionAboveFloorIsNeverReduced(t *testing.T) {
	c := NewP1Cost()
	view := m156View(model.PhaseUnknown, model.Signal{})
	for i := 0; i < 20; i++ {
		c.ObserveRotation(view, 1.6)
	}
	eval := c.Evaluation(view, model.Move{Action: model.ActionRotate}, model.Policy{FlowDisruption: 1})
	if eval.FlowPredictedMean <= .5 || eval.Flow != eval.FlowPredictedMean {
		t.Fatalf("floor reduced a prediction above it: %+v", eval)
	}
}

func TestM156MIGRemainsUnsupportedRotationProxy(t *testing.T) {
	c := NewP1Cost()
	view := m156View(model.PhaseWarm, model.PresentSignal(0, "fixture"))
	pol := model.Policy{NormSparsity: .4, FlowDisruption: .6}
	eval := c.Evaluation(view, model.Move{Action: model.ActionMIGRebind}, pol)
	if eval.FlowRegime != RespawnFlowMIGProxy || eval.FlowFloorApplied || !eval.FlowUncertaintyApplied ||
		eval.ConformalRegimeApplicable || eval.GPUEnvelopeApplied {
		t.Fatalf("MIG proxy acquired unsupported guarantees: %+v", eval)
	}
	if want := pol.FlowDisruption * (unknownActionFlowMax - eval.Flow); math.Abs(eval.FlowUncertaintySlack-want) > 1e-12 {
		t.Fatalf("MIG uncertainty slack=%g want=%g", eval.FlowUncertaintySlack, want)
	}
}

func TestM156UncertaintyDoesNotChangeOtherActionFamiliesOrZeroWeight(t *testing.T) {
	c := NewP1Cost()
	missing := m156View(model.PhaseUnknown, model.Signal{})
	for _, action := range model.MutatingActions {
		if flowFamilyForAction(action) == flowRespawn {
			continue
		}
		eval := c.Evaluation(missing, model.Move{Action: action}, model.Policy{NormSparsity: .4, FlowDisruption: .6})
		if eval.FlowRegime != "" || eval.FlowFloorApplied || eval.FlowUncertaintyApplied || eval.FlowUncertaintySlack != 0 {
			t.Fatalf("non-respawn %s acquired M156 provenance: %+v", action, eval)
		}
	}
	eval := c.Evaluation(missing, model.Move{Action: model.ActionRotate}, model.Policy{NormSparsity: 1, FlowDisruption: 0})
	if !eval.FlowUncertaintyApplied || eval.FlowUncertaintySlack != 0 {
		t.Fatalf("zero flow weight changed the uncertainty interpretation: %+v", eval)
	}
}

func TestM156InvalidFlowWeightsCannotEraseTheBound(t *testing.T) {
	view := m156View(model.PhaseUnknown, model.Signal{})
	for _, weight := range []float64{-1, math.Inf(1), math.NaN()} {
		eval := NewP1Cost().Evaluation(view, model.Move{Action: model.ActionRotate}, model.Policy{FlowDisruption: weight})
		if eval.UnactionableCategory != UnactionableNaNCategory || eval.NaNFeature != "policy.flowDisruption" ||
			eval.CHi != NaNFailConservativeCost {
			t.Fatalf("invalid weight %v was not refused conservatively: %+v", weight, eval)
		}
	}
}
