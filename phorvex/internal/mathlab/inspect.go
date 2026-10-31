package mathlab

import (
	"encoding/json"
	"sort"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

// Inspection is the JSON view of one snapshot for the Math Lab registry: the configured
// spec exactly as the CR held it, the effective values the operator resolved from it,
// the learned state the decision read, and the process identity. Effective values come
// from the operator's own resolution (model.Policy), never from re-deriving the spec.
type Inspection struct {
	Schema     string          `json:"schema_version"`
	Digest     string          `json:"snapshot_digest"`
	Header     Header          `json:"header"`
	Configured json.RawMessage `json:"configured_spec"`
	Effective  map[string]any  `json:"effective"`
	Learned    map[string]any  `json:"learned"`
	// Manifest and Overrides are the decision parameter set exactly as this binary resolves
	// it for the recorded policy (source constants and effective policy values).
	Manifest             *model.DecisionParameterManifest `json:"parameter_manifest,omitempty"`
	Overrides            *model.EffectivePolicyOverrides  `json:"policy_overrides,omitempty"`
	Complete             []string                         `json:"unreplayable_fields"`
	EndpointCostEvidence *model.ReplayCostEvidence        `json:"endpoint_cost_evidence,omitempty"`
	EndpointCostMissing  []string                         `json:"endpoint_cost_missing"`
}

// Inspect builds the inspection view.
func Inspect(s *Snapshot) Inspection {
	pol := s.Inputs.Policy
	enabled := make([]string, 0, len(pol.EnabledActions))
	for a, on := range pol.EnabledActions {
		if on {
			enabled = append(enabled, string(a))
		}
	}
	sort.Strings(enabled)
	sojourn := map[string]float64{}
	for k, v := range pol.KillChainSojournScaleSeconds {
		sojourn[k] = v
	}
	eff := map[string]any{
		"spec.mode":                                 pol.Mode,
		"policy.dryRun":                             pol.DryRun,
		"spec.objective.lambda":                     pol.Lambda,
		"spec.objective.disruptionAversion":         optionalValue(pol.DisruptionAversionConfigured, pol.DisruptionAversion),
		"spec.objective.costPreferences.norm":       optionalValue(pol.CostPreferencesConfigured, pol.NormPreference),
		"spec.objective.costPreferences.flow":       optionalValue(pol.CostPreferencesConfigured, pol.FlowPreference),
		"spec.objective.costWeights.normSparsity":   pol.NormSparsity,
		"spec.objective.costWeights.flowDisruption": pol.FlowDisruption,
		"spec.slo.costCeiling":                      cost.EffectiveCostCeiling(pol),
		"spec.slo.minAvailableReplicas":             pol.MinAvailableReplicas,
		"spec.slo.p99Ms":                            pol.P99Ms,
		"spec.slo.minTokensPerSec":                  pol.MinTokensPerSec,
		"spec.budget.maxMovesPerTick":               pol.MaxMovesPerTick,
		"spec.budget.tickInterval":                  pol.TickInterval.String(),
		"spec.budget.antiOverRotationWindow":        pol.AntiOverRotationWindow.String(),
		"spec.budget.proactiveFloor":                pol.ProactiveFloor.String(),
		"spec.budget.maxGracePeriodSeconds":         pol.MaxGracePeriodSeconds,
		"spec.triggers.eventAgeHorizon":             pol.EffectiveEventAgeHorizon().String(),
		"spec.triggers.reactiveOnly":                pol.ReactiveOnly,
		"spec.triggers.eventDriven":                 pol.EventDriven,
		"spec.existential.mayBreachSLO":             pol.MayBreachSLO,
		"spec.brain.killChain.shape":                pol.KillChainShape,
		"spec.brain.killChain.sojournScaleSeconds":  sojourn,
		"spec.belief.exposurePressureCap":           pol.ExposurePressureCap,
		"spec.assetValue.weightSecrets":             pol.WeightSecrets,
		"spec.assetValue.blastRadiusFromGraph":      pol.BlastRadiusFromGraph,
		"spec.actions.enabled":                      enabled,
		"policy.nativeRotate":                       pol.NativeRotate,
		"policy.quarantineCapacityLimit":            pol.QuarantineCapacityLimit,
	}
	learned := map[string]any{"calibrationFrozen": s.Inputs.Engine.CalibrationFrozen, "economicsMode": s.Header.EconomicsMode}
	st := s.Inputs.Engine
	lambda := pol.Lambda
	learned["bucketExists"] = st.HasBucket
	if !st.HasBucket {
		// The owner's first tick: production creates the bucket in this very decision and
		// consumes the configured seed, so the runtime lambda the tick prices with is the seed.
		learned["lambdaSeedPendingConsumption"] = pol.Lambda
	}
	if st.HasBucket {
		if st.Bucket.HasDual {
			lambda = st.Bucket.Dual.RuntimeLegacy
			learned["lambdaRuntime"] = lambda
		}
		if st.Bucket.HasRLS {
			learned["rlsPrimed"] = st.Bucket.RLS.Primed
			learned["rlsUpdates"] = st.Bucket.RLS.Updates
			learned["rlsTheta"] = st.Bucket.RLS.Theta
		}
		if st.Bucket.HasConformal {
			learned["conformalN"] = len(st.Bucket.Conformal.Residuals)
			if c, err := cost.RestoreConformal(st.Bucket.Conformal); err == nil {
				learned["conformalQuantile"] = c.Quantile()
				learned["conformalCalibrated"] = c.Calibrated()
			}
		}
	}
	if st.HasMeta {
		learned["lambdaSeedConsumed"] = st.Meta.LambdaSeedConsumed
		learned["bucketCreatedAt"] = st.Meta.BucketCreatedAt
	}
	if economics, err := pol.Economics(lambda); err == nil {
		learned["effectiveCostCoefficient"] = economics.EffectiveCostCoefficient
		learned["costCoefficientSource"] = economics.CoefficientSource
	}
	out := Inspection{Schema: "math-lab.inspection.v1", Digest: s.Digest, Header: s.Header,
		Configured: json.RawMessage(nonEmptyJSON(s.Inputs.SpecJSON)), Effective: eff, Learned: learned, Complete: Completeness(s)}
	out.EndpointCostEvidence = s.Inputs.EndpointCostEvidence.Clone()
	if out.EndpointCostEvidence == nil {
		out.EndpointCostMissing = []string{"endpoint_cost_evidence:not-recorded"}
	} else {
		out.EndpointCostMissing = append([]string(nil), out.EndpointCostEvidence.Missing...)
	}
	if _, manifest, overrides, err := decision.ParameterSetForPolicy(pol); err == nil {
		out.Manifest, out.Overrides = &manifest, &overrides
	}
	return out
}

func optionalValue(present bool, v float64) any {
	if !present {
		return nil
	}
	return v
}

func nonEmptyJSON(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte("null")
	}
	return raw
}
