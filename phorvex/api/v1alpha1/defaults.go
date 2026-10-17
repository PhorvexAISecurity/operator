/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package v1alpha1

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const defaultKillChainShape = 2.0

var defaultSojournScaleSeconds = map[string]float64{
	"recon": 1800, "exploit": 600, "persist": 3600, "lateral": 1200, "impact": 600,
	"gpu-side-channel": 300, "model-theft": 180, "llm-jacking": 900, "prompt-inject-persist": 3600,
}

var nonnegativeDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// Code defaults for the decimal-string / Duration knobs. These are FLAGGED design
// proposals that trace the PRD PART 7 example values; they are NEVER inherited from
// R6's self-reported numbers. nil/empty == this default == the documented baseline.
const (
	defaultLambda                      = 0.6
	defaultNormSparsity                = 0.4
	defaultFlowDisruption              = 0.6
	defaultWeightSecrets               = 0.8
	defaultMaxMovesPerTick             = 3
	defaultMaxGracePeriodSeconds int64 = 30
	defaultMinAvailableReplicas        = 1
	defaultTickInterval                = 20 * time.Second
	defaultAntiOverRotation            = 5 * time.Minute
	defaultProactiveFloor              = time.Hour
	defaultEventAgeHorizon             = time.Hour
)

// ParseDecimal parses a decimal string, returning def on empty/invalid input. It is
// the single place Phorvex turns a PRD-convention decimal string into a float.
func ParseDecimal(s string, def float64) float64 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return def
	}
	return v
}

// EffectiveMaxGracePeriodSeconds resolves the native graceful-rotation cap.
// Admission accepts only 1..300. The error return preserves that contract for
// direct Go objects and rolling-upgrade inputs that bypass schema validation;
// invalid explicit values never silently become the default.
func (s *PhorvexPolicySpec) EffectiveMaxGracePeriodSeconds() (int64, error) {
	if s.Budget.MaxGracePeriodSeconds == nil {
		return defaultMaxGracePeriodSeconds, nil
	}
	v := *s.Budget.MaxGracePeriodSeconds
	if v < 1 || v > 300 {
		return 0, fmt.Errorf("maxGracePeriodSeconds %d must be between 1 and 300", v)
	}
	return v, nil
}

// EffectiveTenant returns the tenant identity: Spec.Tenant if set, else the
// policy's namespace.
func (p *PhorvexPolicy) EffectiveTenant() string {
	if p.Spec.Tenant != "" {
		return p.Spec.Tenant
	}
	return p.Namespace
}

// EffectiveLambda is the configured initial seed for P1's per-tenant legacy
// runtime lambda controller (default 0.6).
func (s *PhorvexPolicySpec) EffectiveLambda() float64 {
	return ParseDecimal(s.Objective.Lambda, defaultLambda)
}

// EffectiveDisruptionAversion resolves the optional fixed objective
// coefficient. Presence is returned separately so an explicit zero cannot be
// confused with legacy absence. Invalid values never fall back silently.
func (s *PhorvexPolicySpec) EffectiveDisruptionAversion() (value float64, configured bool, err error) {
	raw := s.Objective.DisruptionAversion
	if raw == "" {
		return 0, false, nil
	}
	if !nonnegativeDecimal.MatchString(raw) {
		return 0, true, fmt.Errorf("disruptionAversion %q must be a decimal between 0 and 10", raw)
	}
	value, parseErr := strconv.ParseFloat(raw, 64)
	if parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > model.MaxDisruptionAversion {
		return 0, true, fmt.Errorf("disruptionAversion %q must be a finite decimal between 0 and 10", raw)
	}
	return value, true, nil
}

// EffectiveCostPreferences resolves the independent fixed objective preferences.
// A present object requires both finite decimal values; missing and invalid values
// never silently become zero. Empty disruptionAversion retains its absence semantics.
func (s *PhorvexPolicySpec) EffectiveCostPreferences() (norm, flow float64, configured bool, err error) {
	prefs := s.Objective.CostPreferences
	if prefs == nil {
		return 0, 0, false, nil
	}
	if s.Objective.DisruptionAversion != "" {
		return 0, 0, true, fmt.Errorf("costPreferences and nonempty disruptionAversion are mutually exclusive")
	}
	parse := func(name, raw string) (float64, error) {
		value, parseErr := strconv.ParseFloat(raw, 64)
		if !nonnegativeDecimal.MatchString(raw) || parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > model.MaxDisruptionAversion {
			return 0, fmt.Errorf("costPreferences.%s %q must be a finite decimal between 0 and 10", name, raw)
		}
		return value, nil
	}
	norm, err = parse("norm", prefs.Norm)
	if err != nil {
		return 0, 0, true, err
	}
	flow, err = parse("flow", prefs.Flow)
	if err != nil {
		return 0, 0, true, err
	}
	return norm, flow, true, nil
}

// EffectiveNormSparsity is the C_norm weight (default 0.4).
func (s *PhorvexPolicySpec) EffectiveNormSparsity() float64 {
	return ParseDecimal(s.Objective.CostWeights.NormSparsity, defaultNormSparsity)
}

// EffectiveFlowDisruption is the C_flow weight (default 0.6).
func (s *PhorvexPolicySpec) EffectiveFlowDisruption() float64 {
	return ParseDecimal(s.Objective.CostWeights.FlowDisruption, defaultFlowDisruption)
}

// EffectiveCostCeiling resolves the independent per-service hard cost ceiling.
// A literal NaN/Inf is intentionally preserved so the decision cost gate can
// classify it as an observable fail-conservative data error instead of silently
// turning a malformed safety limit into the default.
func (s *PhorvexPolicySpec) EffectiveCostCeiling() float64 {
	if s.SLO.CostCeiling == "" {
		return model.DefaultCostCeiling
	}
	v, err := strconv.ParseFloat(s.SLO.CostCeiling, 64)
	if err != nil || v <= 0 {
		return model.DefaultCostCeiling
	}
	return v
}

// EffectiveWeightSecrets is the per-mounted-Secret asset weight (default 0.8).
func (s *PhorvexPolicySpec) EffectiveWeightSecrets() float64 {
	return ParseDecimal(s.AssetValue.WeightSecrets, defaultWeightSecrets)
}

// EffectiveMaxMovesPerTick is the per-tick move budget B (default 3).
func (s *PhorvexPolicySpec) EffectiveMaxMovesPerTick() int {
	if s.Budget.MaxMovesPerTick == nil {
		return defaultMaxMovesPerTick
	}
	if *s.Budget.MaxMovesPerTick < 0 {
		// Admission rejects negative values. Direct Go construction still fails closed
		// to a no-mutation budget rather than turning invalid input into the default.
		return 0
	}
	return *s.Budget.MaxMovesPerTick
}

// EffectiveMinAvailableReplicas is the availability floor (default 1).
func (s *PhorvexPolicySpec) EffectiveMinAvailableReplicas() int {
	if s.SLO.MinAvailableReplicas <= 0 {
		return defaultMinAvailableReplicas
	}
	return s.SLO.MinAvailableReplicas
}

// EffectiveTickInterval is the decision cadence (default 20s).
func (s *PhorvexPolicySpec) EffectiveTickInterval() time.Duration {
	if s.Budget.TickInterval.Duration <= 0 {
		return defaultTickInterval
	}
	return s.Budget.TickInterval.Duration
}

// DefaultExposurePressureCap is p_max for the capped noisy-OR P(hold) (M-143 form A).
// INSUFFICIENT EVIDENCE — provisional 0.5, fit in T3-D. Not a validated value.
const DefaultExposurePressureCap = 0.5

// EffectiveExposurePressureCap returns spec.belief.exposurePressureCap strictly inside
// (0,1), or the provisional default when unset/unparseable (admission rejects the
// unparseable case; this is the rolling-upgrade backstop).
func (s *PhorvexPolicySpec) EffectiveExposurePressureCap() float64 {
	v := ParseDecimal(s.Belief.ExposurePressureCap, DefaultExposurePressureCap)
	if v <= 0 || v >= 1 {
		return DefaultExposurePressureCap
	}
	return v
}

// EffectiveAntiOverRotationWindow is the per-pod re-move floor (default 5m).
func (s *PhorvexPolicySpec) EffectiveAntiOverRotationWindow() time.Duration {
	if s.Budget.AntiOverRotationWindow.Duration <= 0 {
		return defaultAntiOverRotation
	}
	return s.Budget.AntiOverRotationWindow.Duration
}

// EffectiveProactiveFloor is the detection-independent max-exposure floor (default 1h).
func (s *PhorvexPolicySpec) EffectiveProactiveFloor() time.Duration {
	if s.Budget.ProactiveFloor.Duration <= 0 {
		return defaultProactiveFloor
	}
	return s.Budget.ProactiveFloor.Duration
}

// EffectiveEventAgeHorizon is the independent linear SecurityEvent evidence
// horizon. Admission rejects an explicit non-positive value; the fallback also
// preserves old/internal objects that do not carry API presence information.
func (s *PhorvexPolicySpec) EffectiveEventAgeHorizon() time.Duration {
	if s.Triggers.EventAgeHorizon == nil || s.Triggers.EventAgeHorizon.Duration <= 0 {
		return defaultEventAgeHorizon
	}
	return s.Triggers.EventAgeHorizon.Duration
}

// EffectiveMode is the safety mode (default dryRun).
func (s *PhorvexPolicySpec) EffectiveMode() string {
	if s.Mode == "" {
		return ModeDryRun
	}
	return s.Mode
}

// EffectiveKillChainShape returns the positive dimensionless Weibull shape. Empty or
// invalid values preserve NewModel's exact 2.0 default even when an object bypasses CRD validation.
func (s *PhorvexPolicySpec) EffectiveKillChainShape() float64 {
	v, err := strconv.ParseFloat(s.Brain.KillChain.Shape, 64)
	if s.Brain.KillChain.Shape == "" || err != nil || v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return defaultKillChainShape
	}
	return v
}

// EffectiveSojournScaleSeconds resolves every stage independently. A missing or non-positive
// field preserves that stage's exact NewModel default.
func (s *PhorvexPolicySpec) EffectiveSojournScaleSeconds() map[string]float64 {
	out := make(map[string]float64, len(defaultSojournScaleSeconds))
	for stage, value := range defaultSojournScaleSeconds {
		out[stage] = value
	}
	configured := s.Brain.KillChain.SojournScaleSeconds
	overrides := map[string]int64{
		"recon": configured.Recon, "exploit": configured.Exploit,
		"persist": configured.Persist, "lateral": configured.Lateral, "impact": configured.Impact,
		"gpu-side-channel": configured.GPUSideChannel, "model-theft": configured.ModelTheft,
		"llm-jacking": configured.LLMJacking, "prompt-inject-persist": configured.PromptInjectPersist,
	}
	for stage, value := range overrides {
		if value > 0 {
			out[stage] = float64(value)
		}
	}
	return out
}

// IsDryRun reports whether actuation is suppressed by Mode.
func (s *PhorvexPolicySpec) IsDryRun() bool {
	return s.EffectiveMode() != ModeActive
}

// ActionEnabled reports whether action a is in the enabled set. An empty Enabled
// set means both rotate and quarantine are allowed (noop is always allowed).
func (s *PhorvexPolicySpec) ActionEnabled(a ActionType) bool {
	if a == ActionNoop {
		return true
	}
	if len(s.Actions.Enabled) == 0 {
		return a == ActionRotate || a == ActionQuarantine
	}
	for _, e := range s.Actions.Enabled {
		if e == a {
			return true
		}
	}
	return false
}

// AssetLabelWeights resolves the configured label weights. An asset is worth the
// maximum weight matching any of its labels, and 0 if none match: a weight that
// does not parse, or is not positive, can never raise that maximum, so it is left
// out.
func (s *PhorvexPolicySpec) AssetLabelWeights() model.AssetLabelWeights {
	var out model.AssetLabelWeights
	for key, valueWeights := range s.AssetValue.FromLabels {
		for value, raw := range valueWeights {
			if w := ParseDecimal(raw, 0); w > 0 {
				if out.ByLabel == nil {
					out.ByLabel = map[string]map[string]float64{}
				}
				if out.ByLabel[key] == nil {
					out.ByLabel[key] = map[string]float64{}
				}
				out.ByLabel[key][value] = w
			}
		}
	}
	return out
}

// SourceAllowed reports whether a SecurityEvent source feeds the kill-chain belief
// under this policy (empty allowlist accepts all).
func (s *PhorvexPolicySpec) SourceAllowed(source string) bool {
	if len(s.Triggers.KillChainSource) == 0 {
		return true
	}
	for _, src := range s.Triggers.KillChainSource {
		if src == source {
			return true
		}
	}
	return false
}

// ── SLO error budgets (PHVX-60a) ───────────────────────────────────────────────
// Deliberately NO code defaults here. The lambda seed and cost weights have a
// documented baseline that reproduces the PRD example, so falling back is harmless. A
// budget has no such baseline: inventing one would put a denominator under the SLO
// cost model that nobody measured, and every ratio computed from it would look
// authoritative while meaning nothing. Unset therefore means unset.

// BudgetsConfigured reports whether this service has enough SLO budget
// configuration for the budget path to run at all: a window, plus at least one
// dimension budget inside it.
//
// This is the per-service switch. While it is false the SLO cost model stays off
// for the service and behaviour is exactly what it was before the budgets existed.
// The alternative — treating "no budget" as "no remaining budget" — would block
// every action on every unconfigured service and silently stop Phorvex defending
// anything, which is a far worse failure than not yet having the feature.
func (s *PhorvexPolicySpec) BudgetsConfigured() bool {
	if s.SLO.Window.Duration <= 0 {
		return false
	}
	return s.SLO.AvailabilityBudget.Duration > 0 ||
		s.SLO.DisruptionBudgetReplicaSeconds > 0 ||
		ParseDecimal(s.SLO.LatencyBudget, 0) > 0
}

// EffectiveReserveFraction is the share of each total budget withheld from
// Phorvex, clamped to [0,1). Unset, unparseable or out-of-range means no reserve;
// a value at or above 1 would reserve the entire budget and is treated as
// misconfiguration rather than as a way to disable actuation (Mode and the
// kill-switch already do that, explicitly).
func (s *PhorvexPolicySpec) EffectiveReserveFraction() float64 {
	f := ParseDecimal(s.SLO.ReserveFraction, 0)
	if f <= 0 || f >= 1 {
		return 0
	}
	return f
}

// UsableBudget applies the reserve and the consumption already on record:
//
//	usable = (1 - reserveFraction) * total - consumed
//
// Consumed is what actually happened BEFORE the move being scored; the cost of
// that move is the numerator of the ratio, never part of this denominator.
// A negative result is clamped to zero: the budget is spent, not owed.
func (s *PhorvexPolicySpec) UsableBudget(total, consumed float64) float64 {
	usable := (1-s.EffectiveReserveFraction())*total - consumed
	if usable < 0 {
		return 0
	}
	return usable
}
