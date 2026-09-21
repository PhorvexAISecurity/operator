package decision

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const DecisionSensitivitySchemaV1 = "phorvex.decision-sensitivity.v1"

// SensitivityRequest describes one bounded counterfactual change. It is a
// shadow-only diagnostic; no result is an adoption recommendation.
type SensitivityRequest struct {
	Parameter string  `json:"parameter"`
	Value     float64 `json:"value"`
	Unit      string  `json:"unit"`
}

type SensitivityDecision struct {
	Namespace        string       `json:"namespace"`
	Pod              string       `json:"pod"`
	BaselineAction   model.Action `json:"baselineAction"`
	VariantAction    model.Action `json:"variantAction"`
	BaselineSelected bool         `json:"baselineSelected"`
	VariantSelected  bool         `json:"variantSelected"`
	BaselineCost     float64      `json:"baselineCost"`
	VariantCost      float64      `json:"variantCost"`
	BaselineBenefit  float64      `json:"baselineModeledBenefit"`
	VariantBenefit   float64      `json:"variantModeledBenefit"`
	BaselineNet      float64      `json:"baselineNet"`
	VariantNet       float64      `json:"variantNet"`
	BaselineFeasible bool         `json:"baselineFeasible"`
	VariantFeasible  bool         `json:"variantFeasible"`
	ActionSwitched   bool         `json:"actionSwitched"`
}

type SensitivityResult struct {
	SchemaVersion  string                `json:"schemaVersion"`
	Parameter      string                `json:"parameter"`
	CanonicalValue float64               `json:"canonicalValue"`
	CanonicalUnit  string                `json:"canonicalUnit"`
	DependenceOnly bool                  `json:"dependenceOnly"`
	Rows           []SensitivityDecision `json:"rows"`
}

// EvaluateSensitivity runs the production decision implementation twice in
// shadow mode over owned frozen copies. It changes exactly one supported input.
func EvaluateSensitivity(engine *CoverageEngine, views []*model.WorkloadView, pol model.Policy, req SensitivityRequest) (SensitivityResult, error) {
	if engine == nil {
		return SensitivityResult{}, fmt.Errorf("sensitivity engine is required")
	}
	if len(views) == 0 {
		return SensitivityResult{}, fmt.Errorf("sensitivity requires a non-empty frozen snapshot")
	}
	if math.IsNaN(req.Value) || math.IsInf(req.Value, 0) {
		return SensitivityResult{}, fmt.Errorf("sensitivity value must be finite")
	}
	baseViews := cloneSensitivityViews(views)
	variantViews := cloneSensitivityViews(views)
	variantPolicy := cloneSensitivityPolicy(pol)
	value, unit, err := applySensitivity(req, variantViews, &variantPolicy)
	if err != nil {
		return SensitivityResult{}, err
	}
	baseline, err := engine.DecideShadowChecked(baseViews, cloneSensitivityPolicy(pol))
	if err != nil {
		return SensitivityResult{}, fmt.Errorf("baseline shadow: %w", err)
	}
	variant, err := engine.DecideShadowChecked(variantViews, variantPolicy)
	if err != nil {
		return SensitivityResult{}, fmt.Errorf("variant shadow: %w", err)
	}
	if len(baseline) != len(variant) {
		return SensitivityResult{}, fmt.Errorf("shadow result cardinality changed")
	}
	result := SensitivityResult{SchemaVersion: DecisionSensitivitySchemaV1, Parameter: req.Parameter,
		CanonicalValue: value, CanonicalUnit: unit, DependenceOnly: true, Rows: make([]SensitivityDecision, 0, len(baseline))}
	for i := range baseline {
		b, v := baseline[i], variant[i]
		if b.Namespace != v.Namespace || b.Pod != v.Pod {
			return SensitivityResult{}, fmt.Errorf("shadow result identity changed")
		}
		result.Rows = append(result.Rows, SensitivityDecision{
			Namespace: b.Namespace, Pod: b.Pod, BaselineAction: b.Action, VariantAction: v.Action,
			BaselineSelected: b.Selected, VariantSelected: v.Selected,
			BaselineCost: b.Cost, VariantCost: v.Cost,
			BaselineBenefit: b.CoveredWeight, VariantBenefit: v.CoveredWeight,
			BaselineNet: b.Net, VariantNet: v.Net,
			BaselineFeasible: b.Feasible, VariantFeasible: v.Feasible,
			ActionSwitched: b.Action != v.Action || b.Selected != v.Selected,
		})
	}
	return result, nil
}

func applySensitivity(req SensitivityRequest, views []*model.WorkloadView, pol *model.Policy) (float64, string, error) {
	seconds := func(value float64, unit string) (float64, error) {
		switch unit {
		case "seconds":
			return value, nil
		case "milliseconds":
			return value / 1000, nil
		default:
			return 0, fmt.Errorf("parameter %q requires seconds or milliseconds", req.Parameter)
		}
	}
	switch {
	case req.Parameter == "recon.dispersion.maximum":
		if req.Unit != "multiplier" || req.Value < 1 || req.Value > 16 {
			return 0, "", fmt.Errorf("dispersion maximum must be a multiplier in [1,16]")
		}
		for _, view := range views {
			view.Physics.DispersionCap = req.Value
		}
		return req.Value, "multiplier", nil
	case req.Parameter == "economics.fixed-beta":
		if req.Unit != "dimensionless" || req.Value < 0 || req.Value > model.MaxDisruptionAversion {
			return 0, "", fmt.Errorf("fixed beta must be dimensionless in [0,10]")
		}
		pol.DisruptionAversionConfigured = true
		pol.DisruptionAversion = req.Value
		return req.Value, "dimensionless", nil
	case req.Parameter == "killchain.exposure-pressure-cap":
		if req.Unit != "ratio" || req.Value <= 0 || req.Value >= 1 {
			return 0, "", fmt.Errorf("exposure pressure cap must be a ratio in (0,1)")
		}
		pol.ExposurePressureCap = req.Value
		return req.Value, "ratio", nil
	case req.Parameter == "killchain.shape":
		if req.Unit != "shape" || req.Value <= 0 || req.Value > 10 {
			return 0, "", fmt.Errorf("killchain shape must be in (0,10]")
		}
		pol.KillChainShape = req.Value
		return req.Value, "shape", nil
	case strings.HasPrefix(req.Parameter, "killchain.sojourn.") && strings.HasSuffix(req.Parameter, ".seconds"):
		value, err := seconds(req.Value, req.Unit)
		if err != nil || value <= 0 || value > 7*24*60*60 {
			return 0, "", fmt.Errorf("killchain sojourn must be in (0,604800] seconds")
		}
		stage := strings.TrimSuffix(strings.TrimPrefix(req.Parameter, "killchain.sojourn."), ".seconds")
		known := false
		for name := range defaultSojournStages() {
			if stage == name {
				known = true
				break
			}
		}
		if !known {
			return 0, "", fmt.Errorf("unknown killchain stage %q", stage)
		}
		if pol.KillChainSojournScaleSeconds == nil {
			pol.KillChainSojournScaleSeconds = map[string]float64{}
		}
		pol.KillChainSojournScaleSeconds[stage] = value
		return value, "seconds", nil
	default:
		return 0, "", fmt.Errorf("unsupported sensitivity parameter %q", req.Parameter)
	}
}

func defaultSojournStages() map[string]struct{} {
	return productionSojournStages()
}

func cloneSensitivityPolicy(in model.Policy) model.Policy {
	out := in
	if in.EnabledActions != nil {
		out.EnabledActions = make(map[model.Action]bool, len(in.EnabledActions))
		for key, value := range in.EnabledActions {
			out.EnabledActions[key] = value
		}
	}
	if in.KillChainSojournScaleSeconds != nil {
		out.KillChainSojournScaleSeconds = make(map[string]float64, len(in.KillChainSojournScaleSeconds))
		for key, value := range in.KillChainSojournScaleSeconds {
			out.KillChainSojournScaleSeconds[key] = value
		}
	}
	return out
}

func cloneSensitivityViews(in []*model.WorkloadView) []*model.WorkloadView {
	out := make([]*model.WorkloadView, len(in))
	for i, view := range in {
		if view == nil {
			continue
		}
		copy := *view
		copy.Pod = view.Pod
		copy.Pod.Labels = cloneStringMap(view.Pod.Labels)
		copy.ExposureByVariable = cloneDurationMap(view.ExposureByVariable)
		copy.IntentByVariable = cloneDurationMap(view.IntentByVariable)
		copy.Events = append([]model.SecurityEventInfo(nil), view.Events...)
		copy.Neighbors = append([]model.NeighborRef(nil), view.Neighbors...)
		out[i] = &copy
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneDurationMap(in map[string]time.Duration) map[string]time.Duration {
	if in == nil {
		return nil
	}
	out := make(map[string]time.Duration, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
