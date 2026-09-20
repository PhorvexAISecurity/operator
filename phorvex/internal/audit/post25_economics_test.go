package audit

import (
	"encoding/json"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestPost25EconomicsAuditSurvivesTraceDisabled(t *testing.T) {
	const lambdaRuntime = 0.123456789
	const beta = 0.00004
	d := model.Decision{
		Engine: "p1-coverage", Lambda: lambdaRuntime,
		Economics: &model.EconomicsMetadata{
			Version:                  model.EconomicsFixedDisruptionAversionV1,
			DisruptionAversion:       model.OptionalFloat{Present: true, Value: beta},
			LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: lambdaRuntime},
			EffectiveCostCoefficient: beta, CoefficientSource: model.CostCoefficientSourceBeta,
		},
	}
	raw, err := json.Marshal(ToRecord(d))
	if err != nil {
		t.Fatal(err)
	}
	var decoded Record
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.DecisionTrace != nil || decoded.Economics == nil || decoded.Economics.Version != model.EconomicsFixedDisruptionAversionV1 ||
		!decoded.Economics.DisruptionAversion.Present || decoded.Economics.DisruptionAversion.Value != beta ||
		decoded.Economics.EffectiveCostCoefficient != beta || !decoded.Economics.LambdaRuntimeLegacy.Present ||
		decoded.Economics.LambdaRuntimeLegacy.Value != lambdaRuntime || decoded.Lambda != 0.1235 {
		t.Fatalf("trace-off economics metadata lost or relabelled: %+v", decoded)
	}
}

func TestPost25EconomicsAuditRejectsContradictoryDescriptor(t *testing.T) {
	record := Record{Lambda: 2, Economics: &model.EconomicsMetadata{
		Version:                  model.EconomicsLegacyRuntimeLambdaV1,
		LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: 2},
		EffectiveCostCoefficient: 1, CoefficientSource: model.CostCoefficientSourceLambda,
	}}
	if _, err := json.Marshal(record); err == nil {
		t.Fatal("contradictory audit descriptor marshalled")
	}
	raw := `{"schemaVersion":"phorvex.audit.v2","lambda":2,"economics":{"version":"future","disruptionAversion":{"present":false,"value":0},"lambdaRuntimeLegacy":{"present":true,"value":2},"effectiveCostCoefficient":1,"coefficientSource":"future"}}`
	if err := json.Unmarshal([]byte(raw), &record); err == nil {
		t.Fatal("unknown audit economics version decoded")
	}

	metadata := &model.EconomicsMetadata{
		Version:                  model.EconomicsFixedDisruptionAversionV1,
		DisruptionAversion:       model.OptionalFloat{Present: true, Value: 0.00004},
		LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: 0.123456789},
		EffectiveCostCoefficient: 0.00004, CoefficientSource: model.CostCoefficientSourceBeta,
	}
	if _, err := json.Marshal(Record{Lambda: 0.1234, Economics: metadata}); err == nil {
		t.Fatal("rounded legacy lambda alias contradiction marshalled")
	}
	if _, err := json.Marshal(Record{Lambda: 0.1235, Economics: metadata}); err != nil {
		t.Fatalf("correct rounded alias rejected: %v", err)
	}
	tampered := `{"schemaVersion":"phorvex.audit.v2","lambda":0.1234,"economics":{"version":"fixed-disruption-aversion-v1","disruptionAversion":{"present":true,"value":0.00004},"lambdaRuntimeLegacy":{"present":true,"value":0.123456789},"effectiveCostCoefficient":0.00004,"coefficientSource":"disruptionAversion"}}`
	if err := json.Unmarshal([]byte(tampered), &record); err == nil {
		t.Fatal("rounded legacy lambda alias contradiction decoded")
	}
}
