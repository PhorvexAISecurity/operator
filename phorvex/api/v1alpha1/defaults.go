/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package v1alpha1

import (
	"math"
	"strconv"
	"time"
)

const defaultKillChainShape = 2.0

var defaultSojournScaleSeconds = map[string]float64{
	"recon": 1800, "exploit": 600, "persist": 3600, "lateral": 1200, "impact": 600,
	"gpu-side-channel": 300, "model-theft": 180, "llm-jacking": 900, "prompt-inject-persist": 3600,
}

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

// ── SLO error budgets (PHVX-60a) ───────────────────────────────────────────────
// Deliberately NO code defaults here. Lambda or the cost weights have a documented
// baseline that reproduces the PRD example, so falling back to it is harmless. A
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
