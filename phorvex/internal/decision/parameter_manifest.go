package decision

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

const ProductionParameterManifestID = "phorvex-production-decision-parameters"

type parameterDescriptor struct {
	group, unit, domain, source, provenance, limitations, dependency string
}

// ProductionParameterManifest builds the exportable registry from values read
// through the same package-owned constants/accessors as production scoring.
func ProductionParameterManifest() model.DecisionParameterManifest {
	values := map[string]float64{
		"decision.provenance-floor":                 provFloor,
		"economics.fixed-beta.minimum":              0,
		"economics.fixed-beta.maximum":              model.MaxDisruptionAversion,
		"decision.exact-search.work-budget":         exactWorkBudget,
		"decision.local-search.maximum-iterations":  localSearchMaxIter,
		"decision.persistence.dedup-capacity":       defaultPersistenceDedupLimit,
		"platform.co-residency.namespace-count-cap": model.PlatformCoResidencyCap,
		"platform.epss.aggregate-percentile":        model.PlatformEPSSAggregatePercentile,
		"platform.rarity.minimum":                   model.PlatformRarityMinimum,
		"platform.rarity.maximum":                   model.PlatformRarityMaximum,
	}
	for name, value := range recon.ProductionParameters() {
		values[name] = value
	}
	for name, value := range cost.ProductionParameters() {
		values[name] = value
	}
	for name, value := range cost.ProductionNormActionPriors() {
		values[name] = value
	}
	for name, value := range killchain.ProductionParameters() {
		values[name] = value
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	parameters := make([]model.DecisionParameter, 0, len(names))
	for _, name := range names {
		d := describeParameter(name)
		parameters = append(parameters, model.DecisionParameter{
			Name: name, Group: d.group, Unit: d.unit, Domain: d.domain, Default: values[name],
			Source: d.source, Provenance: d.provenance, Limitations: d.limitations,
			DependencyGroup: d.dependency,
		})
	}
	return model.DecisionParameterManifest{
		SchemaVersion: model.DecisionParameterManifestV1,
		ID:            ProductionParameterManifestID,
		Parameters:    parameters,
	}
}

func describeParameter(name string) parameterDescriptor {
	d := parameterDescriptor{
		group: "cost", unit: "dimensionless", domain: "finite, source-defined bounds",
		source: "internal/cost", provenance: model.ParameterExpertPrior,
		limitations: "Shipped source value; no universal optimality or transferability claim.", dependency: "cost-model",
	}
	switch {
	case name == "decision.provenance-floor":
		d = parameterDescriptor{"selection", "ratio", "[0,1]", "internal/decision/coverage.go:provFloor", model.ParameterExpertPrior,
			"Anti-decoy discount floor; not calibrated as an attack probability.", "selection-provenance"}
	case strings.HasPrefix(name, "decision.exact-search.") || strings.HasPrefix(name, "decision.local-search."):
		d = parameterDescriptor{"selection-computation", "operations", "positive integer", "internal/decision/optimality.go and localsearch.go", model.ParameterConfigurationBound,
			"Deterministic computation bound; it is not a quality or optimality calibration.", "selection-algorithm"}
	case name == "decision.persistence.dedup-capacity":
		d = parameterDescriptor{"observed-outcome-learning", "evidence IDs", "positive integer", "internal/decision/persistence_observation.go", model.ParameterConfigurationBound,
			"Non-evicting replay barrier capacity; saturation refuses new learning rather than changing decision evidence.", "persistence-learning"}
	case name == "platform.co-residency.namespace-count-cap":
		d = parameterDescriptor{"dispersion", "running namespaces", "(0,+Inf)", "internal/model/parameters.go:PlatformCoResidencyCap", model.ParameterExpertPrior,
			"Historical namespace-count proxy; does not prove tenancy or device sharing.", "dispersion"}
	case strings.HasPrefix(name, "platform."):
		d = parameterDescriptor{"platform-witness", "dimensionless", "source-defined bounds", "internal/model/parameters.go", model.ParameterDerived,
			"Deterministic witness construction; fleet-relative rarity is not an attacker probability or stable cross-fleet calibration.", "platform-witness"}
	case strings.HasPrefix(name, "recon."):
		d.group, d.source, d.dependency = "recon-fact-weight", "internal/recon", "recon-weighting"
		d.limitations = "Structural fact-weight coefficient; source tests establish mechanics, not calibrated efficacy."
	case strings.HasPrefix(name, "killchain.sojourn."):
		d = parameterDescriptor{"hazard-sojourn", "seconds", "(0,+Inf)", "internal/killchain/hazard.go:NewModel", model.ParameterExpertPrior,
			"Provisional dwell scale; requires workload-specific censored transition measurements.", "killchain-hazard"}
	case strings.HasPrefix(name, "killchain.consequence."):
		d = parameterDescriptor{"hazard-consequence", "ratio", "[0,1]", "internal/killchain/hazard.go:consequence", model.ParameterExpertPrior,
			"Ordinal modeled consequence, not a measured incident probability.", "killchain-hazard"}
	case strings.HasPrefix(name, "killchain."):
		d.group, d.source, d.dependency = "hazard", "internal/killchain", "killchain-hazard"
		d.limitations = "Shipped hazard/belief coefficient; empirical fit remains workload-specific."
	case strings.HasPrefix(name, "economics.fixed-beta."):
		d = parameterDescriptor{"economics", "dimensionless objective coefficient", "[0,10]", "internal/model/economics.go:MaxDisruptionAversion", model.ParameterConfigurationBound,
			"Admission bound only; an explicit policy value is an operator preference, not a fitted optimum.", "objective-economics"}
	case name == "cost.gpu-envelope.configured":
		d = parameterDescriptor{"cost-conformal", "normalized disruption", "[0,1]", "internal/cost/conformal.go:GPUEnvelopeMax", model.ParameterConfigurationBound,
			"Operator-selected deployment value; the shipped fallback is deliberately conservative.", "cost-conformal"}
	case name == "cost.flow.kv-reset-ttft-penalty-fraction":
		d = parameterDescriptor{"cost-flow", "TTFT fraction", "[0,1]", "internal/cost/action_flow.go:measuredKVResetTTFTPenaltyFraction", model.ParameterMeasured,
			"Measured on one retained Qwen/vLLM workload; transfer to other models or hardware is unproven.", "cost-flow"}
	case strings.HasPrefix(name, "cost.lambda."):
		d.group, d.source, d.dependency = "legacy-lambda", "internal/cost/dual.go", "legacy-lambda-controller"
		d.limitations = "Move-count recurrence is not certified as an exact disruption-price dual."
	case strings.HasPrefix(name, "cost.rls."):
		d.group, d.source, d.dependency = "cost-rls", "internal/cost/rls.go", "cost-rls"
		d.limitations = "Online tenant-local estimate; defaults and bounds are not universal calibration."
	case strings.HasPrefix(name, "cost.conformal."):
		d.group, d.source, d.dependency = "cost-conformal", "internal/cost/conformal.go", "cost-conformal"
		d.limitations = "Finite-window residual control; cold start is a configured slack, not a calibrated guarantee."
	case strings.HasPrefix(name, "cost.phase."):
		d.group, d.source, d.dependency = "cost-phase", "internal/cost/phase_encoding.go:phaseFlowEncoding", "cost-flow"
		d.limitations = "Legacy prior preserving behavior; phase-specific live measurements remain incomplete."
	case strings.HasPrefix(name, "cost.flow."):
		d.group, d.source, d.dependency = "cost-flow", "internal/cost/action_flow.go", "cost-flow"
		d.limitations = "Estimated disruption prior unless the entry explicitly names retained measured evidence."
	case strings.HasPrefix(name, "cost.norm.action."):
		d.group, d.source, d.dependency = "cost-norm", "internal/cost/p1cost.go:normCostP1", "cost-normalization"
		d.limitations = "Structural normalization rubric, not a measured service-loss estimate."
	case name == "cost.ready-delay-reference-seconds":
		d.unit, d.source = "seconds", "internal/cost/p1cost.go:ReadyDelayReference"
	case name == "cost.default-ceiling":
		d.source, d.provenance = "internal/model:DefaultCostCeiling", model.ParameterConfigurationBound
	}
	return d
}

// EffectivePolicyParameterSet retains the exact resolved policy inputs that can
// alter scoring or hard feasibility during this tick.
func EffectivePolicyParameterSet(pol model.Policy) (model.EffectivePolicyOverrides, error) {
	if _, err := pol.Economics(pol.Lambda); err != nil {
		return model.EffectivePolicyOverrides{}, err
	}
	for name, value := range map[string]float64{
		"norm sparsity": pol.NormSparsity, "flow disruption": pol.FlowDisruption, "secret weight": pol.WeightSecrets,
	} {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return model.EffectivePolicyOverrides{}, fmt.Errorf("%s must be finite and non-negative", name)
		}
	}
	if pol.EventAgeHorizon < 0 {
		return model.EffectivePolicyOverrides{}, fmt.Errorf("event age horizon must be absent or positive")
	}
	if pol.TickInterval < 0 || pol.AntiOverRotationWindow < 0 || pol.ProactiveFloor < 0 || pol.ExposurePressureScale < 0 {
		return model.EffectivePolicyOverrides{}, fmt.Errorf("policy durations must be absent or non-negative")
	}
	if pol.MaxMovesPerTick < 0 || pol.MinAvailableReplicas < 0 || pol.P99Ms < 0 || pol.MinTokensPerSec < 0 {
		return model.EffectivePolicyOverrides{}, fmt.Errorf("policy count and service thresholds must be non-negative")
	}
	if pol.KillChainShape < 0 || math.IsNaN(pol.KillChainShape) || math.IsInf(pol.KillChainShape, 0) || pol.KillChainShape > 10 {
		return model.EffectivePolicyOverrides{}, fmt.Errorf("killchain shape must be absent or finite in (0,10]")
	}
	shape := pol.KillChainShape
	if shape == 0 {
		shape = killchain.ProductionParameters()["killchain.shape"]
	}
	if pol.ExposurePressureCap < 0 || pol.ExposurePressureCap >= 1 || math.IsNaN(pol.ExposurePressureCap) || math.IsInf(pol.ExposurePressureCap, 0) {
		return model.EffectivePolicyOverrides{}, fmt.Errorf("exposure pressure cap must be absent or finite in (0,1)")
	}
	exposureScale := pol.ExposurePressureScale
	if exposureScale == 0 {
		exposureScale = pol.ProactiveFloor
	}
	if cost.EffectiveCostCeiling(pol) <= 0 || math.IsNaN(cost.EffectiveCostCeiling(pol)) || math.IsInf(cost.EffectiveCostCeiling(pol), 0) {
		return model.EffectivePolicyOverrides{}, fmt.Errorf("effective cost ceiling must be positive and finite")
	}
	fixedBeta := pol.DisruptionAversion
	if !pol.DisruptionAversionConfigured {
		// An absent fixed preference is legacy mode. Its ignored carrier value
		// cannot change the effective-policy identity.
		fixedBeta = 0
	}
	values := []model.EffectivePolicyParameter{
		{Name: "policy.lambda-seed", Unit: "dimensionless", Present: true, Value: pol.Lambda},
		{Name: "policy.fixed-beta", Unit: "dimensionless", Present: pol.DisruptionAversionConfigured, Value: fixedBeta},
		{Name: "policy.norm-sparsity", Unit: "weight", Present: true, Value: pol.NormSparsity},
		{Name: "policy.flow-disruption", Unit: "weight", Present: true, Value: pol.FlowDisruption},
		{Name: "policy.secret-weight", Unit: "weight", Present: true, Value: pol.WeightSecrets},
		{Name: "policy.cost-ceiling", Unit: "normalized disruption", Present: true, Value: cost.EffectiveCostCeiling(pol)},
		{Name: "policy.maximum-moves-per-tick", Unit: "moves", Present: true, Value: float64(pol.MaxMovesPerTick)},
		{Name: "policy.minimum-available-replicas", Unit: "replicas", Present: true, Value: float64(pol.MinAvailableReplicas)},
		{Name: "policy.proactive-floor", Unit: "seconds", Present: true, Value: pol.ProactiveFloor.Seconds()},
		{Name: "policy.tick-interval", Unit: "seconds", Present: true, Value: pol.TickInterval.Seconds()},
		{Name: "policy.anti-over-rotation-window", Unit: "seconds", Present: true, Value: pol.AntiOverRotationWindow.Seconds()},
		{Name: "policy.event-age-horizon", Unit: "seconds", Present: true, Value: pol.EffectiveEventAgeHorizon().Seconds()},
		{Name: "policy.exposure-pressure-scale", Unit: "seconds", Present: pol.ExposurePressureScale > 0, Value: exposureScale.Seconds()},
		{Name: "policy.exposure-pressure-cap", Unit: "ratio", Present: pol.ExposurePressureCap > 0, Value: effectiveExposurePressureCap(pol)},
		{Name: "policy.killchain-shape", Unit: "shape", Present: pol.KillChainShape > 0, Value: shape},
		{Name: "policy.may-breach-slo", Unit: "boolean", Present: true, Value: boolFloat(pol.MayBreachSLO)},
		{Name: "policy.reactive-only", Unit: "boolean", Present: true, Value: boolFloat(pol.ReactiveOnly)},
		{Name: "policy.native-rotate", Unit: "boolean", Present: true, Value: boolFloat(pol.NativeRotate)},
		{Name: "policy.blast-radius-from-graph", Unit: "boolean", Present: true, Value: boolFloat(pol.BlastRadiusFromGraph)},
		{Name: "policy.event-driven", Unit: "boolean", Present: true, Value: boolFloat(pol.EventDriven)},
		{Name: "policy.p99-milliseconds", Unit: "milliseconds", Present: pol.P99Ms > 0, Value: float64(pol.P99Ms)},
		{Name: "policy.minimum-tokens-per-second", Unit: "tokens/second", Present: pol.MinTokensPerSec > 0, Value: float64(pol.MinTokensPerSec)},
	}
	sojournStages := productionSojournStages()
	for stage, value := range pol.KillChainSojournScaleSeconds {
		if value <= 0 || value > 7*24*60*60 || math.IsNaN(value) || math.IsInf(value, 0) {
			return model.EffectivePolicyOverrides{}, fmt.Errorf("killchain sojourn %q must be finite in (0,604800] seconds", stage)
		}
		if _, known := sojournStages[stage]; !known {
			return model.EffectivePolicyOverrides{}, fmt.Errorf("unknown killchain sojourn stage %q", stage)
		}
	}
	production := killchain.ProductionParameters()
	for stage := range sojournStages {
		value, configured := pol.KillChainSojournScaleSeconds[stage]
		if !configured {
			value = production["killchain.sojourn."+stage+".seconds"]
		}
		values = append(values, model.EffectivePolicyParameter{Name: "policy.killchain-sojourn." + stage, Unit: "seconds", Present: configured, Value: value})
	}
	for _, action := range model.MutatingActions {
		values = append(values, model.EffectivePolicyParameter{Name: "policy.action-enabled." + string(action), Unit: "boolean", Present: true, Value: boolFloat(model.ActionEnabled(pol, action))})
	}
	id := fmt.Sprintf("%s/%s@%s:%d", pol.Namespace, pol.PolicyName, pol.PolicyUID, pol.PolicyGeneration)
	if pol.PolicyName == "" && pol.PolicyUID == "" {
		id = pol.Owner()
	}
	o := model.EffectivePolicyOverrides{SchemaVersion: model.DecisionPolicyOverridesV1, ID: id, Values: values}
	if err := o.Validate(); err != nil {
		return model.EffectivePolicyOverrides{}, err
	}
	return o.Canonical(), nil
}

func productionSojournStages() map[string]struct{} {
	out := map[string]struct{}{}
	for name := range killchain.ProductionParameters() {
		if strings.HasPrefix(name, "killchain.sojourn.") && strings.HasSuffix(name, ".seconds") {
			out[strings.TrimSuffix(strings.TrimPrefix(name, "killchain.sojourn."), ".seconds")] = struct{}{}
		}
	}
	return out
}

func effectiveExposurePressureCap(pol model.Policy) float64 {
	if pol.ExposurePressureCap > 0 {
		return pol.ExposurePressureCap
	}
	return killchain.DefaultExposurePressureCap
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func ParameterSetForPolicy(pol model.Policy) (*model.ParameterSetReference, model.DecisionParameterManifest, model.EffectivePolicyOverrides, error) {
	manifest := ProductionParameterManifest().Canonical()
	overrides, err := EffectivePolicyParameterSet(pol)
	if err != nil {
		return nil, model.DecisionParameterManifest{}, model.EffectivePolicyOverrides{}, err
	}
	mh, err := manifest.CanonicalHash()
	if err != nil {
		return nil, model.DecisionParameterManifest{}, model.EffectivePolicyOverrides{}, err
	}
	oh, err := overrides.CanonicalHash()
	if err != nil {
		return nil, model.DecisionParameterManifest{}, model.EffectivePolicyOverrides{}, err
	}
	ref := &model.ParameterSetReference{SchemaVersion: model.DecisionParameterSetV1,
		ManifestID: manifest.ID, ManifestHash: mh, PolicyOverridesID: overrides.ID, PolicyOverridesHash: oh}
	return ref, manifest, overrides, nil
}
