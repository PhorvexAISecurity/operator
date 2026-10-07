package model

import (
	"encoding/json"
	"fmt"
	"math"
)

const (
	EconomicsIndependentPreferencesV1  = "independent-cost-preferences-v1"
	CostCoefficientSourcePreferences   = "costPreferences"
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
	NormPreference           OptionalFloat `json:"normPreference"`
	FlowPreference           OptionalFloat `json:"flowPreference"`
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
	if p.CostPreferencesConfigured {
		if p.DisruptionAversionConfigured || !finiteBoundedCoefficient(p.NormPreference) || !finiteBoundedCoefficient(p.FlowPreference) {
			return EconomicsMetadata{}, fmt.Errorf("cost preferences must be finite in [0,10] and cannot accompany disruptionAversion")
		}
		return EconomicsMetadata{Version: EconomicsIndependentPreferencesV1, CoefficientSource: CostCoefficientSourcePreferences, NormPreference: OptionalFloat{Present: true, Value: p.NormPreference}, FlowPreference: OptionalFloat{Present: true, Value: p.FlowPreference}, LambdaRuntimeLegacy: OptionalFloat{Present: true, Value: lambdaRuntime}, FlowCostSemanticsVersion: FlowCostSemanticsConservativeRegimeV1}, nil
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
	if metadata.Version != EconomicsIndependentPreferencesV1 && (metadata.NormPreference.Present || metadata.FlowPreference.Present) {
		return fmt.Errorf("scalar economics cannot carry independent preferences")
	}
	switch metadata.Version {
	case EconomicsIndependentPreferencesV1:
		if metadata.DisruptionAversion.Present || metadata.EffectiveCostCoefficient != 0 || metadata.CoefficientSource != CostCoefficientSourcePreferences || !metadata.NormPreference.Present || !metadata.FlowPreference.Present || !finiteBoundedCoefficient(metadata.NormPreference.Value) || !finiteBoundedCoefficient(metadata.FlowPreference.Value) {
			return fmt.Errorf("independent economics metadata is contradictory")
		}
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

// CostPenalty resolves the frozen objective without changing the SLO cost model.
func (m EconomicsMetadata) CostPenalty(norm, flow, expected float64) float64 {
	if m.Version == EconomicsIndependentPreferencesV1 {
		return m.NormPreference.Value*norm + m.FlowPreference.Value*flow
	}
	return m.EffectiveCostCoefficient * expected
}

// Independent preferences have no common scalar coefficient. Omit that unavailable
// field on the wire instead of reporting a misleading numeric zero.
func (m EconomicsMetadata) MarshalJSON() ([]byte, error) {
	type alias EconomicsMetadata
	raw, err := json.Marshal(alias(m))
	if err != nil {
		return raw, err
	}
	var object map[string]json.RawMessage
	if err = json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	if m.Version == EconomicsIndependentPreferencesV1 {
		delete(object, "effectiveCostCoefficient")
	} else {
		delete(object, "normPreference")
		delete(object, "flowPreference")
	}
	return json.Marshal(object)
}

func (m *EconomicsMetadata) UnmarshalJSON(raw []byte) error {
	type alias EconomicsMetadata
	var value alias
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if value.Version == EconomicsIndependentPreferencesV1 {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		if _, present := object["effectiveCostCoefficient"]; present {
			return fmt.Errorf("independent economics cannot carry a scalar coefficient")
		}
	}
	*m = EconomicsMetadata(value)
	return nil
}
