package console

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestPost25EconomicsConsoleRejectsRoundedLambdaContradiction(t *testing.T) {
	metadata := model.EconomicsMetadata{
		Version:                  model.EconomicsFixedDisruptionAversionV1,
		DisruptionAversion:       model.OptionalFloat{Present: true, Value: 0.00004},
		LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: 0.123456789},
		EffectiveCostCoefficient: 0.00004, CoefficientSource: model.CostCoefficientSourceBeta,
	}
	if decoded, ok := decodeAuditEconomics(metadata, 0.1235); !ok || decoded.LambdaRuntimeLegacy.Value != 0.123456789 {
		t.Fatalf("valid exact economics unavailable: ok=%t metadata=%+v", ok, decoded)
	}
	if _, ok := decodeAuditEconomics(metadata, 0.1234); ok {
		t.Fatal("console accepted economics metadata contradicting the rounded lambda alias")
	}
}
