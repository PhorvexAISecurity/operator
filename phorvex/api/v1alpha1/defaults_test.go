/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package v1alpha1

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEffectiveDefaults(t *testing.T) {
	var s PhorvexPolicySpec // all empty => code defaults
	if got := s.EffectiveLambda(); got != 0.6 {
		t.Errorf("lambda default = %v, want 0.6", got)
	}
	if got := s.EffectiveNormSparsity(); got != 0.4 {
		t.Errorf("normSparsity default = %v, want 0.4", got)
	}
	if got := s.EffectiveFlowDisruption(); got != 0.6 {
		t.Errorf("flowDisruption default = %v, want 0.6", got)
	}
	if got := s.EffectiveMaxMovesPerTick(); got != 3 {
		t.Errorf("maxMovesPerTick default = %v, want 3", got)
	}
	if got := s.EffectiveTickInterval(); got != 20*time.Second {
		t.Errorf("tickInterval default = %v, want 20s", got)
	}
	if got := s.EffectiveAntiOverRotationWindow(); got != 5*time.Minute {
		t.Errorf("antiOverRotationWindow default = %v, want 5m", got)
	}
	if got := s.EffectiveProactiveFloor(); got != time.Hour {
		t.Errorf("proactiveFloor default = %v, want 1h", got)
	}
	if got := s.EffectiveMinAvailableReplicas(); got != 1 {
		t.Errorf("minAvailableReplicas default = %v, want 1", got)
	}
	if !s.IsDryRun() {
		t.Errorf("default mode must be dryRun")
	}
}

func TestEffectiveOverrides(t *testing.T) {
	s := PhorvexPolicySpec{
		Objective: ObjectiveSpec{Lambda: "0.9", CostWeights: CostWeights{NormSparsity: "0.2", FlowDisruption: "0.8"}},
		Budget: BudgetSpec{
			MaxMovesPerTick:        5,
			TickInterval:           metav1.Duration{Duration: 30 * time.Second},
			AntiOverRotationWindow: metav1.Duration{Duration: 10 * time.Minute},
			ProactiveFloor:         metav1.Duration{Duration: 2 * time.Hour},
		},
		Mode: ModeActive,
	}
	if s.EffectiveLambda() != 0.9 || s.EffectiveNormSparsity() != 0.2 || s.EffectiveFlowDisruption() != 0.8 {
		t.Errorf("objective overrides not applied")
	}
	if s.EffectiveMaxMovesPerTick() != 5 || s.EffectiveTickInterval() != 30*time.Second {
		t.Errorf("budget overrides not applied")
	}
	if s.IsDryRun() {
		t.Errorf("active mode must not be dry-run")
	}
}

func TestAssetWeightFromLabels(t *testing.T) {
	s := PhorvexPolicySpec{
		AssetValue: AssetValueSpec{
			FromLabels: map[string]LabelValueWeights{
				"data-class": {"restricted": "1.0", "internal": "0.4", "public": "0.1"},
			},
		},
	}
	if got := s.AssetWeightFromLabels(map[string]string{"data-class": "restricted"}); got != 1.0 {
		t.Errorf("restricted weight = %v, want 1.0", got)
	}
	if got := s.AssetWeightFromLabels(map[string]string{"data-class": "public"}); got != 0.1 {
		t.Errorf("public weight = %v, want 0.1", got)
	}
	if got := s.AssetWeightFromLabels(map[string]string{"unrelated": "x"}); got != 0 {
		t.Errorf("unmatched weight = %v, want 0", got)
	}
}

func TestActionEnabled(t *testing.T) {
	empty := PhorvexPolicySpec{}
	if !empty.ActionEnabled(ActionRotate) || !empty.ActionEnabled(ActionQuarantine) || !empty.ActionEnabled(ActionNoop) {
		t.Errorf("empty enabled set should allow rotate, quarantine, noop")
	}
	only := PhorvexPolicySpec{Actions: ActionsSpec{Enabled: []ActionType{ActionRotate}}}
	if !only.ActionEnabled(ActionRotate) || only.ActionEnabled(ActionQuarantine) {
		t.Errorf("explicit enabled=[rotate] should disable quarantine")
	}
}

func TestEffectiveTenant(t *testing.T) {
	p := &PhorvexPolicy{}
	p.Namespace = "team-a"
	if got := p.EffectiveTenant(); got != "team-a" {
		t.Errorf("tenant defaults to namespace, got %q", got)
	}
	p.Spec.Tenant = "vcluster-7"
	if got := p.EffectiveTenant(); got != "vcluster-7" {
		t.Errorf("explicit tenant wins, got %q", got)
	}
}
