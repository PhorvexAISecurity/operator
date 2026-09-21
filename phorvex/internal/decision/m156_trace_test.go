package decision

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func m156TraceClone(t *testing.T, in *model.DecisionTraceV2) *model.DecisionTraceV2 {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out model.DecisionTraceV2
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func TestM156IndependentValidatorBindsV5ProducerInputs(t *testing.T) {
	view := covView("m156-validator", true, 2*time.Hour, false)
	view.Phase = model.PhaseWarm
	view.Telemetry.ReqRate = model.PresentSignal(0, "fixture")
	pol := decisionTracePolicy(1, true)
	pol.CostCeiling = 10
	decision := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0]
	raw, err := json.Marshal(audit.ToRecord(decision))
	if err != nil {
		t.Fatal(err)
	}
	runEconomicsAuditValidator(t, raw, true)

	for name, mutate := range map[string]func(map[string]any){
		"missing load forged measured": func(record map[string]any) {
			trace := record["decisionTrace"].(map[string]any)
			trace["inputs"].(map[string]any)["requestRate"] = map[string]any{"present": false, "value": 0.0}
		},
		"forged regime": func(record map[string]any) {
			trace := record["decisionTrace"].(map[string]any)
			for _, rawCandidate := range trace["candidates"].([]any) {
				candidate := rawCandidate.(map[string]any)
				if candidate["action"] == string(model.ActionRotate) && candidate["expectedCost"].(map[string]any)["present"] == true {
					candidate["flowRegime"] = "unknown-phase"
					return
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var record map[string]any
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatal(err)
			}
			mutate(record)
			tampered, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			runEconomicsAuditValidator(t, tampered, false)
		})
	}
}

func TestM156TraceOffDecisionRetainsFlowSemantics(t *testing.T) {
	view := covView("m156-trace-off", true, 2*time.Hour, false)
	pol := decisionTracePolicy(1, false)
	decision := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0]
	if decision.Trace != nil || decision.Economics == nil ||
		decision.Economics.FlowCostSemanticsVersion != model.FlowCostSemanticsConservativeRegimeV1 {
		t.Fatalf("trace-off decision lost flow semantics: %+v", decision)
	}
	raw, err := json.Marshal(audit.ToRecord(decision))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if _, exists := record["decisionTrace"]; exists {
		t.Fatal("trace-off record unexpectedly gained a decisionTrace")
	}
	economics, ok := record["economics"].(map[string]any)
	if !ok || economics["flowCostSemanticsVersion"] != model.FlowCostSemanticsConservativeRegimeV1 {
		t.Fatalf("trace-off audit metadata lost flow semantics: %#v", record["economics"])
	}
}

func m156CostedRespawn(t *testing.T, trace *model.DecisionTraceV2, action model.Action) *model.DecisionCandidateV2 {
	t.Helper()
	for i := range trace.Candidates {
		candidate := &trace.Candidates[i]
		if candidate.Action == string(action) && candidate.ExpectedCost.Present {
			return candidate
		}
	}
	t.Fatalf("no costed %s row in %+v", action, trace.Candidates)
	return nil
}

func m156MeasuredTrace(t *testing.T, ceiling float64) *model.DecisionTraceV2 {
	t.Helper()
	view := covView("m156-trace", true, 2*time.Hour, false)
	view.Phase = model.PhaseWarm
	view.Telemetry.ReqRate = model.PresentSignal(0, "fixture")
	pol := decisionTracePolicy(1, true)
	pol.CostCeiling = ceiling
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0].Trace
	if trace == nil {
		t.Fatal("trace disabled")
	}
	return trace
}

func TestM156TraceV5BindsActualInputsAndReconstructsCost(t *testing.T) {
	trace := m156MeasuredTrace(t, 10)
	if trace.SchemaVersion != model.DecisionTraceSchemaV5 ||
		trace.FlowCostSemanticsVersion != model.FlowCostSemanticsConservativeRegimeV1 {
		t.Fatalf("wrong current trace semantics: %+v", trace)
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	rotate := m156CostedRespawn(t, trace, model.ActionRotate)
	if rotate.FlowRegime != "measured-load" || rotate.FlowPredictedMean == nil || !rotate.FlowPredictedMean.Present ||
		rotate.FlowConservativeFloor == nil || rotate.FlowConservativeFloor.Present ||
		rotate.FlowUncertaintyBound == nil || rotate.FlowUncertaintyBound.Present ||
		rotate.FlowUncertaintySlack == nil || rotate.FlowUncertaintySlack.Present ||
		rotate.ConformalWindowReady == nil || !rotate.ConformalWindowReady.Present ||
		rotate.ConformalRegimeApplicable == nil || !rotate.ConformalRegimeApplicable.Present || !rotate.ConformalRegimeApplicable.Value {
		t.Fatalf("incomplete measured-load provenance: %+v", rotate)
	}

	for name, mutate := range map[string]func(*model.DecisionTraceV2){
		"absent load forged measured": func(copy *model.DecisionTraceV2) {
			copy.Inputs.RequestRate = model.OptionalFloat{}
		},
		"unknown regime": func(copy *model.DecisionTraceV2) {
			m156CostedRespawn(t, copy, model.ActionRotate).FlowRegime = "future"
		},
		"forged upper": func(copy *model.DecisionTraceV2) {
			row := m156CostedRespawn(t, copy, model.ActionRotate)
			row.FlowUncertaintyBound.Present = true
			row.FlowUncertaintyBound.Value = 1.5
		},
		"false calibration applicability": func(copy *model.DecisionTraceV2) {
			m156CostedRespawn(t, copy, model.ActionRotate).ConformalRegimeApplicable.Value = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := m156TraceClone(t, trace)
			mutate(copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("forged V5 trace validated")
			}
		})
	}
}

func TestM156TraceV5CostedExclusionCarriesSameProvenance(t *testing.T) {
	trace := m156MeasuredTrace(t, 0.01)
	row := m156CostedRespawn(t, trace, model.ActionRotate)
	if row.SelectionReason != "existing_generator_exclusion" || row.SLOGateResult.Value ||
		row.FlowPredictedMean == nil || row.ConformalRegimeApplicable == nil {
		t.Fatalf("costed exclusion lost V5 provenance: %+v", row)
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestM156HistoricalV4RejectsV5FieldsAndRemainsReadableWithoutThem(t *testing.T) {
	trace := m156MeasuredTrace(t, 10)
	trace.SchemaVersion = model.DecisionTraceSchemaV4
	if err := trace.Validate(); err == nil {
		t.Fatal("historical V4 accepted V5 provenance")
	}
	trace.FlowCostSemanticsVersion = ""
	for i := range trace.Candidates {
		row := &trace.Candidates[i]
		row.FlowPredictedMean = nil
		row.FlowConservativeFloor = nil
		row.FlowRegime = ""
		row.FlowUncertaintyBound = nil
		row.FlowUncertaintySlack = nil
		row.ConformalWindowReady = nil
		row.ConformalRegimeApplicable = nil
	}
	if err := trace.Validate(); err != nil {
		t.Fatalf("historical V4 became unreadable: %v", err)
	}
}
