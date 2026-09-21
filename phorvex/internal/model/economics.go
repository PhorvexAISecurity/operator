package model

import (
	"fmt"
	"math"
)

const (
	EconomicsLegacyRuntimeLambdaV1     = "legacy-runtime-lambda-v1"
	EconomicsFixedDisruptionAversionV1 = "fixed-disruption-aversion-v1"
	CostCoefficientSourceLambda        = "lambdaRuntimeLegacy"
	CostCoefficientSourceBeta          = "disruptionAversion"
	MaxDisruptionAversion              = 10.0
	// FlowCostSemanticsConservativeRegimeV1 identifies the M156 point-floor and
	// unsupported-regime upper-bound contract. It is also emitted when rich
	// decision tracing is disabled, so the effective cost semantics remain visible.
	FlowCostSemanticsConservativeRegimeV1 = "conservative-regime-v1"
)

// EconomicsMetadata identifies the coefficient used by one frozen decision.
// DisruptionAversion.Present distinguishes an explicit zero from legacy absence.
type EconomicsMetadata struct {
	Version                  string        `json:"version"`
	DisruptionAversion       OptionalFloat `json:"disruptionAversion"`
	LambdaRuntimeLegacy      OptionalFloat `json:"lambdaRuntimeLegacy"`
	EffectiveCostCoefficient float64       `json:"effectiveCostCoefficient"`
	CoefficientSource        string        `json:"coefficientSource"`
	FlowCostSemanticsVersion string        `json:"flowCostSemanticsVersion,omitempty"`
}

// Economics resolves the objective coefficient for one decision. The adaptive
// lambda remains separate state even when the fixed opt-in coefficient is used.
func (p Policy) Economics(lambdaRuntime float64) (EconomicsMetadata, error) {
	if !finiteBoundedCoefficient(p.Lambda) {
		return EconomicsMetadata{}, fmt.Errorf("legacy lambda seed must be finite and between 0 and 10")
	}
	if math.IsNaN(lambdaRuntime) || math.IsInf(lambdaRuntime, 0) || lambdaRuntime < 0 || lambdaRuntime > MaxDisruptionAversion {
		return EconomicsMetadata{}, fmt.Errorf("legacy runtime lambda must be finite and between 0 and 10")
	}
	if !p.DisruptionAversionConfigured {
		return EconomicsMetadata{
			Version:                  EconomicsLegacyRuntimeLambdaV1,
			LambdaRuntimeLegacy:      OptionalFloat{Present: true, Value: lambdaRuntime},
			EffectiveCostCoefficient: lambdaRuntime,
			CoefficientSource:        CostCoefficientSourceLambda,
			FlowCostSemanticsVersion: FlowCostSemanticsConservativeRegimeV1,
		}, nil
	}
	if !finiteBoundedCoefficient(p.DisruptionAversion) {
		return EconomicsMetadata{}, fmt.Errorf("disruption aversion must be finite and between 0 and 10")
	}
	return EconomicsMetadata{
		Version:                  EconomicsFixedDisruptionAversionV1,
		DisruptionAversion:       OptionalFloat{Present: true, Value: p.DisruptionAversion},
		LambdaRuntimeLegacy:      OptionalFloat{Present: true, Value: lambdaRuntime},
		EffectiveCostCoefficient: p.DisruptionAversion,
		CoefficientSource:        CostCoefficientSourceBeta,
		FlowCostSemanticsVersion: FlowCostSemanticsConservativeRegimeV1,
	}, nil
}

// ValidateEconomicsMetadata rejects an unknown or internally contradictory
// audit descriptor. A nil descriptor denotes a pre-economics record.
func ValidateEconomicsMetadata(metadata *EconomicsMetadata) error {
	if metadata == nil {
		return nil
	}
	if !metadata.LambdaRuntimeLegacy.Present || !finiteBoundedCoefficient(metadata.LambdaRuntimeLegacy.Value) {
		return fmt.Errorf("economics metadata must preserve a bounded legacy runtime lambda")
	}
	if !finiteBoundedCoefficient(metadata.EffectiveCostCoefficient) {
		return fmt.Errorf("economics coefficient must be finite and between 0 and 10")
	}
	if metadata.FlowCostSemanticsVersion != "" && metadata.FlowCostSemanticsVersion != FlowCostSemanticsConservativeRegimeV1 {
		return fmt.Errorf("unknown flow-cost semantics version %q", metadata.FlowCostSemanticsVersion)
	}
	switch metadata.Version {
	case EconomicsLegacyRuntimeLambdaV1:
		if metadata.DisruptionAversion.Present || metadata.CoefficientSource != CostCoefficientSourceLambda ||
			metadata.EffectiveCostCoefficient != metadata.LambdaRuntimeLegacy.Value {
			return fmt.Errorf("legacy economics metadata is contradictory")
		}
	case EconomicsFixedDisruptionAversionV1:
		if !metadata.DisruptionAversion.Present || !finiteBoundedCoefficient(metadata.DisruptionAversion.Value) ||
			metadata.CoefficientSource != CostCoefficientSourceBeta ||
			metadata.EffectiveCostCoefficient != metadata.DisruptionAversion.Value {
			return fmt.Errorf("fixed economics metadata is contradictory")
		}
	default:
		return fmt.Errorf("unknown economics version %q", metadata.Version)
	}
	return nil
}

func finiteBoundedCoefficient(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= MaxDisruptionAversion
}
