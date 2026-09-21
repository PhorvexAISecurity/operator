package model

import (
	"encoding/json"
	"math"
	"testing"
)

func TestLegacyTraceVersionsDoNotGainV4WireFields(t *testing.T) {
	for _, version := range []string{DecisionTraceSchemaV2, DecisionTraceSchemaV3} {
		trace := validDecisionTrace()
		trace.SchemaVersion = version
		raw, err := json.Marshal(trace)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"economicsVersion", "disruptionAversion", "effectiveCostCoefficient", "costCoefficientSource", "lambdaDemand", "objectiveCandidateDemand", "objectiveCostContribution"} {
			var object map[string]any
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			if _, exists := object[field]; exists {
				t.Fatalf("%s trace gained V4 field %q: %s", version, field, raw)
			}
			if candidates, ok := object["candidates"].([]any); ok {
				for _, candidate := range candidates {
					if _, exists := candidate.(map[string]any)[field]; exists {
						t.Fatalf("%s candidate gained V4 field %q: %s", version, field, raw)
					}
				}
			}
		}
	}
}

func TestEconomicsDescriptorModesAndDirectValidation(t *testing.T) {
	legacy, err := (Policy{Lambda: 0.6}).Economics(0.25)
	if err != nil || legacy.Version != EconomicsLegacyRuntimeLambdaV1 || legacy.DisruptionAversion.Present ||
		!legacy.LambdaRuntimeLegacy.Present || legacy.LambdaRuntimeLegacy.Value != 0.25 ||
		legacy.EffectiveCostCoefficient != 0.25 || legacy.CoefficientSource != CostCoefficientSourceLambda ||
		legacy.FlowCostSemanticsVersion != FlowCostSemanticsConservativeRegimeV1 {
		t.Fatalf("legacy descriptor = %+v err=%v", legacy, err)
	}
	fixed, err := (Policy{Lambda: 0.6, DisruptionAversionConfigured: true, DisruptionAversion: 0}).Economics(0.25)
	if err != nil || fixed.Version != EconomicsFixedDisruptionAversionV1 || !fixed.DisruptionAversion.Present ||
		!fixed.LambdaRuntimeLegacy.Present || fixed.LambdaRuntimeLegacy.Value != 0.25 ||
		fixed.EffectiveCostCoefficient != 0 || fixed.CoefficientSource != CostCoefficientSourceBeta ||
		fixed.FlowCostSemanticsVersion != FlowCostSemanticsConservativeRegimeV1 {
		t.Fatalf("fixed descriptor = %+v err=%v", fixed, err)
	}
	for _, policy := range []Policy{
		{Lambda: math.NaN()},
		{Lambda: 0.6, DisruptionAversionConfigured: true, DisruptionAversion: math.Inf(1)},
		{Lambda: 0.6, DisruptionAversionConfigured: true, DisruptionAversion: -1},
		{Lambda: 0.6, DisruptionAversionConfigured: true, DisruptionAversion: 10.01},
	} {
		if _, err := policy.Economics(0.25); err == nil {
			t.Fatalf("invalid direct policy validated: %+v", policy)
		}
	}
}

func TestValidateEconomicsMetadataRejectsUnknownAndContradictoryRecords(t *testing.T) {
	valid := &EconomicsMetadata{Version: EconomicsFixedDisruptionAversionV1,
		DisruptionAversion: OptionalFloat{Present: true, Value: 2}, EffectiveCostCoefficient: 2,
		LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: 7}, CoefficientSource: CostCoefficientSourceBeta}
	if err := ValidateEconomicsMetadata(valid); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []*EconomicsMetadata{
		{Version: "future", LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: 7}, EffectiveCostCoefficient: 2},
		{Version: EconomicsFixedDisruptionAversionV1, DisruptionAversion: OptionalFloat{Present: true, Value: 2}, LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: 7}, EffectiveCostCoefficient: 3, CoefficientSource: CostCoefficientSourceBeta},
		{Version: EconomicsLegacyRuntimeLambdaV1, LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: 7}, EffectiveCostCoefficient: 2, CoefficientSource: CostCoefficientSourceLambda},
		{Version: EconomicsLegacyRuntimeLambdaV1, DisruptionAversion: OptionalFloat{Present: true}, LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: 7}, EffectiveCostCoefficient: 7, CoefficientSource: CostCoefficientSourceLambda},
		{Version: EconomicsLegacyRuntimeLambdaV1, LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: -1}, EffectiveCostCoefficient: -1, CoefficientSource: CostCoefficientSourceLambda},
		{Version: EconomicsLegacyRuntimeLambdaV1, LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: 10.01}, EffectiveCostCoefficient: 10.01, CoefficientSource: CostCoefficientSourceLambda},
		{Version: EconomicsLegacyRuntimeLambdaV1, LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: 7}, EffectiveCostCoefficient: 7, CoefficientSource: CostCoefficientSourceLambda, FlowCostSemanticsVersion: "future"},
	} {
		if err := ValidateEconomicsMetadata(bad); err == nil {
			t.Fatalf("contradictory metadata validated: %+v", bad)
		}
	}
}

func TestDecisionTraceV4RejectsEconomicsContradictionsBeforeLegacyV3Checks(t *testing.T) {
	trace := validDecisionTrace()
	trace.SchemaVersion = DecisionTraceSchemaV4
	trace.LambdaDemand = trace.CandidateDemand
	trace.ObjectiveCandidateDemand = trace.CandidateDemand
	trace.EconomicsVersion = EconomicsFixedDisruptionAversionV1
	trace.DisruptionAversion = &OptionalFloat{Present: true, Value: 2}
	trace.EffectiveCostCoefficient = 3
	trace.CostCoefficientSource = CostCoefficientSourceBeta
	if err := trace.Validate(); err == nil {
		t.Fatal("contradictory V4 coefficient validated")
	}
	trace.EffectiveCostCoefficient = 2
	trace.Candidates[1].LambdaContribution = OptionalFloat{}
	trace.Candidates[1].ObjectiveCostContribution = &OptionalFloat{Present: true, Value: 1}
	trace.EconomicsVersion = "future"
	if err := trace.Validate(); err == nil {
		t.Fatal("unknown V4 economics version validated")
	}
}

func TestDecisionTraceRejectsOutOfRangeLegacyRuntimeAndSeed(t *testing.T) {
	for _, mutate := range []func(*DecisionTraceV2){
		func(trace *DecisionTraceV2) { trace.LambdaConfiguredSeed, trace.LambdaConfiguredPolicy = -1, -1 },
		func(trace *DecisionTraceV2) { trace.LambdaRuntime, trace.LambdaRuntimeLegacy = 10.01, 10.01 },
		func(trace *DecisionTraceV2) { trace.DualUpdate.LambdaBefore = -0.01 },
		func(trace *DecisionTraceV2) { trace.DualUpdate.LambdaAfter = 11 },
	} {
		trace := validDecisionTrace()
		mutate(&trace)
		if err := trace.Validate(); err == nil {
			t.Fatalf("out-of-range controller coefficient validated: %+v", trace)
		}
	}
}
