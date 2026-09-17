/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package v1alpha1

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/phorvex/phorvex/internal/model"
)

func budgetInt(v int) *int { return &v }

func durationPtr(v time.Duration) *metav1.Duration {
	return &metav1.Duration{Duration: v}
}

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
	if got := s.EffectiveCostCeiling(); got != model.DefaultCostCeiling {
		t.Errorf("costCeiling default = %v, want %v", got, model.DefaultCostCeiling)
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
	if got := s.EffectiveEventAgeHorizon(); got != time.Hour {
		t.Errorf("eventAgeHorizon default = %v, want 1h", got)
	}
	if got := s.EffectiveMinAvailableReplicas(); got != 1 {
		t.Errorf("minAvailableReplicas default = %v, want 1", got)
	}
	if !s.IsDryRun() {
		t.Errorf("default mode must be dryRun")
	}
	if got := s.EffectiveKillChainShape(); got != 2.0 {
		t.Errorf("kill-chain shape default = %v, want 2.0", got)
	}
	wantSojourn := map[string]float64{"recon": 1800, "exploit": 600, "persist": 3600, "lateral": 1200, "impact": 600, "gpu-side-channel": 300, "model-theft": 180, "llm-jacking": 900, "prompt-inject-persist": 3600}
	for stage, want := range wantSojourn {
		if got := s.EffectiveSojournScaleSeconds()[stage]; got != want {
			t.Errorf("%s sojourn default = %v, want %v", stage, got, want)
		}
	}
}

func TestObjectiveDecimalsRejectNonFiniteAPIValues(t *testing.T) {
	for _, input := range []string{"NaN", "+Inf", "-Inf"} {
		if got := ParseDecimal(input, 0.6); got != 0.6 || math.IsNaN(got) || math.IsInf(got, 0) {
			t.Fatalf("ParseDecimal(%q) = %v, want finite default", input, got)
		}
	}
}

func TestEffectiveOverrides(t *testing.T) {
	s := PhorvexPolicySpec{
		Objective: ObjectiveSpec{Lambda: "0.9", CostWeights: CostWeights{NormSparsity: "0.2", FlowDisruption: "0.8"}},
		SLO:       SLOSpec{CostCeiling: "1.7"},
		Budget: BudgetSpec{
			MaxMovesPerTick:        budgetInt(5),
			TickInterval:           metav1.Duration{Duration: 30 * time.Second},
			AntiOverRotationWindow: metav1.Duration{Duration: 10 * time.Minute},
			ProactiveFloor:         metav1.Duration{Duration: 2 * time.Hour},
		},
		Triggers: TriggersSpec{EventAgeHorizon: durationPtr(90 * time.Minute)},
		Mode:     ModeActive,
		Brain: BrainSpec{KillChain: KillChainSpec{
			Shape: "1.5", SojournScaleSeconds: SojournScaleSpec{Recon: 90, ModelTheft: 45},
		}},
	}
	if s.EffectiveLambda() != 0.9 || s.EffectiveNormSparsity() != 0.2 || s.EffectiveFlowDisruption() != 0.8 {
		t.Errorf("objective overrides not applied")
	}
	if s.EffectiveCostCeiling() != 1.7 {
		t.Errorf("cost ceiling override not applied")
	}
	if s.EffectiveMaxMovesPerTick() != 5 || s.EffectiveTickInterval() != 30*time.Second {
		t.Errorf("budget overrides not applied")
	}
	if s.EffectiveEventAgeHorizon() != 90*time.Minute {
		t.Errorf("event horizon override not applied")
	}
	if s.IsDryRun() {
		t.Errorf("active mode must not be dry-run")
	}
	if s.EffectiveKillChainShape() != 1.5 || s.EffectiveSojournScaleSeconds()["recon"] != 90 || s.EffectiveSojournScaleSeconds()["model-theft"] != 45 {
		t.Errorf("kill-chain overrides not applied")
	}
	if s.EffectiveSojournScaleSeconds()["exploit"] != 600 {
		t.Errorf("partial override did not preserve exploit default")
	}
}

func TestEventAgeHorizonPresenceSerializationAndDeepCopy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		value     *metav1.Duration
		wantKey   bool
		wantValue string
		want      time.Duration
	}{
		{name: "omitted", want: time.Hour},
		{name: "positive", value: durationPtr(10 * time.Minute), wantKey: true, wantValue: "10m0s", want: 10 * time.Minute},
		{name: "explicit-zero", value: durationPtr(0), wantKey: true, wantValue: "0s", want: time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := PhorvexPolicySpec{Triggers: TriggersSpec{EventAgeHorizon: tc.value}}
			encoded, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(encoded, &raw); err != nil {
				t.Fatal(err)
			}
			triggers, _ := raw["triggers"].(map[string]any)
			got, found := triggers["eventAgeHorizon"]
			if found != tc.wantKey || (found && got != tc.wantValue) {
				t.Fatalf("serialized eventAgeHorizon=%v found=%t, want %q found=%t: %s", got, found, tc.wantValue, tc.wantKey, encoded)
			}
			if got := spec.EffectiveEventAgeHorizon(); got != tc.want {
				t.Fatalf("effective eventAgeHorizon=%v, want %v", got, tc.want)
			}
			copy := spec.DeepCopy()
			if tc.value != nil {
				if copy.Triggers.EventAgeHorizon == spec.Triggers.EventAgeHorizon {
					t.Fatal("deep copy aliased eventAgeHorizon pointer")
				}
				copy.Triggers.EventAgeHorizon.Duration++
				if copy.Triggers.EventAgeHorizon.Duration == spec.Triggers.EventAgeHorizon.Duration {
					t.Fatal("deep copy mutation changed source")
				}
			}
		})
	}
}

func TestMaxMovesPerTickPresenceRoundTripsAndDeepCopies(t *testing.T) {
	tests := []struct {
		name      string
		jsonInput string
		wantPtr   *int
		want      int
	}{
		{name: "omitted", jsonInput: `{}`, want: 3},
		{name: "zero", jsonInput: `{"budget":{"maxMovesPerTick":0}}`, wantPtr: budgetInt(0), want: 0},
		{name: "positive", jsonInput: `{"budget":{"maxMovesPerTick":2}}`, wantPtr: budgetInt(2), want: 2},
		{name: "negative-direct-construction", wantPtr: budgetInt(-1), want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var spec PhorvexPolicySpec
			if tt.jsonInput != "" {
				if err := json.Unmarshal([]byte(tt.jsonInput), &spec); err != nil {
					t.Fatal(err)
				}
			} else {
				spec.Budget.MaxMovesPerTick = tt.wantPtr
			}
			if (spec.Budget.MaxMovesPerTick == nil) != (tt.wantPtr == nil) {
				t.Fatalf("pointer presence = %t, want %t", spec.Budget.MaxMovesPerTick != nil, tt.wantPtr != nil)
			}
			if tt.wantPtr != nil && *spec.Budget.MaxMovesPerTick != *tt.wantPtr {
				t.Fatalf("decoded maxMovesPerTick = %d, want %d", *spec.Budget.MaxMovesPerTick, *tt.wantPtr)
			}
			if got := spec.EffectiveMaxMovesPerTick(); got != tt.want {
				t.Fatalf("effective maxMovesPerTick = %d, want %d", got, tt.want)
			}

			copy := spec.DeepCopy()
			if (copy.Budget.MaxMovesPerTick == nil) != (spec.Budget.MaxMovesPerTick == nil) {
				t.Fatal("deep copy changed pointer presence")
			}
			if spec.Budget.MaxMovesPerTick != nil {
				if copy.Budget.MaxMovesPerTick == spec.Budget.MaxMovesPerTick {
					t.Fatal("deep copy aliased maxMovesPerTick pointer")
				}
				*copy.Budget.MaxMovesPerTick++
				if *copy.Budget.MaxMovesPerTick == *spec.Budget.MaxMovesPerTick {
					t.Fatal("deep copy mutation changed source")
				}
			}

			encoded, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip PhorvexPolicySpec
			if err := json.Unmarshal(encoded, &roundTrip); err != nil {
				t.Fatal(err)
			}
			if (roundTrip.Budget.MaxMovesPerTick == nil) != (spec.Budget.MaxMovesPerTick == nil) {
				t.Fatalf("JSON round trip changed pointer presence: %s", encoded)
			}
		})
	}

	for _, tc := range []struct {
		name string
		yaml string
		want *int
	}{
		{name: "omitted", yaml: "budget: {}\n"},
		{name: "zero", yaml: "budget:\n  maxMovesPerTick: 0\n", want: budgetInt(0)},
		{name: "positive", yaml: "budget:\n  maxMovesPerTick: 4\n", want: budgetInt(4)},
	} {
		t.Run("yaml-"+tc.name, func(t *testing.T) {
			var spec PhorvexPolicySpec
			if err := yaml.Unmarshal([]byte(tc.yaml), &spec); err != nil {
				t.Fatal(err)
			}
			if (spec.Budget.MaxMovesPerTick == nil) != (tc.want == nil) {
				t.Fatalf("pointer presence = %t, want %t", spec.Budget.MaxMovesPerTick != nil, tc.want != nil)
			}
			if tc.want != nil && *spec.Budget.MaxMovesPerTick != *tc.want {
				t.Fatalf("decoded maxMovesPerTick = %d, want %d", *spec.Budget.MaxMovesPerTick, *tc.want)
			}
		})
	}
}

func TestInvalidKillChainOverridesFallBackDefensively(t *testing.T) {
	s := PhorvexPolicySpec{Brain: BrainSpec{KillChain: KillChainSpec{
		Shape: "NaN", SojournScaleSeconds: SojournScaleSpec{Recon: -10},
	}}}
	if s.EffectiveKillChainShape() != 2 || s.EffectiveSojournScaleSeconds()["recon"] != 1800 {
		t.Fatalf("invalid override escaped defensive defaults: shape=%v scales=%v", s.EffectiveKillChainShape(), s.EffectiveSojournScaleSeconds())
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
