/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package v1alpha1

import (
	"strconv"
	"time"
)

// Code defaults for the decimal-string / Duration knobs. These are FLAGGED design
// proposals that trace the PRD PART 7 example values; they are NEVER inherited from
// R6's self-reported numbers. nil/empty == this default == the documented baseline.
const (
	defaultLambda               = 0.6
	defaultNormSparsity         = 0.4
	defaultFlowDisruption       = 0.6
	defaultWeightSecrets        = 0.8
	defaultMaxMovesPerTick      = 3
	defaultMinAvailableReplicas = 1
	defaultTickInterval         = 20 * time.Second
	defaultAntiOverRotation     = 5 * time.Minute
	defaultProactiveFloor       = time.Hour
)

// ParseDecimal parses a decimal string, returning def on empty/invalid input. It is
// the single place Phorvex turns a PRD-convention decimal string into a float.
func ParseDecimal(s string, def float64) float64 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return v
}

// EffectiveTenant returns the tenant identity: Spec.Tenant if set, else the
// policy's namespace.
func (p *PhorvexPolicy) EffectiveTenant() string {
	if p.Spec.Tenant != "" {
		return p.Spec.Tenant
	}
	return p.Namespace
}

// EffectiveLambda is the objective cost weight (default 0.6).
func (s *PhorvexPolicySpec) EffectiveLambda() float64 {
	return ParseDecimal(s.Objective.Lambda, defaultLambda)
}

// EffectiveNormSparsity is the C_norm weight (default 0.4).
func (s *PhorvexPolicySpec) EffectiveNormSparsity() float64 {
	return ParseDecimal(s.Objective.CostWeights.NormSparsity, defaultNormSparsity)
}

// EffectiveFlowDisruption is the C_flow weight (default 0.6).
func (s *PhorvexPolicySpec) EffectiveFlowDisruption() float64 {
	return ParseDecimal(s.Objective.CostWeights.FlowDisruption, defaultFlowDisruption)
}

// EffectiveWeightSecrets is the per-mounted-Secret asset weight (default 0.8).
func (s *PhorvexPolicySpec) EffectiveWeightSecrets() float64 {
	return ParseDecimal(s.AssetValue.WeightSecrets, defaultWeightSecrets)
}

// EffectiveMaxMovesPerTick is the per-tick move budget B (default 3).
func (s *PhorvexPolicySpec) EffectiveMaxMovesPerTick() int {
	if s.Budget.MaxMovesPerTick <= 0 {
		// 0 is a legitimate "decide+log only" budget; preserve an explicit 0 only when
		// the field was deliberately set. A negative/unset value falls back to default.
		if s.Budget.MaxMovesPerTick == 0 {
			return defaultMaxMovesPerTick
		}
	}
	return s.Budget.MaxMovesPerTick
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

// EffectiveMode is the safety mode (default dryRun).
func (s *PhorvexPolicySpec) EffectiveMode() string {
	if s.Mode == "" {
		return ModeDryRun
	}
	return s.Mode
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

// AssetWeightFromLabels returns the maximum configured weight matching any of the
// pod's labels (0 if none match).
func (s *PhorvexPolicySpec) AssetWeightFromLabels(labels map[string]string) float64 {
	best := 0.0
	for key, valueWeights := range s.AssetValue.FromLabels {
		if v, ok := labels[key]; ok {
			if w := ParseDecimal(valueWeights[v], 0); w > best {
				best = w
			}
		}
	}
	return best
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
