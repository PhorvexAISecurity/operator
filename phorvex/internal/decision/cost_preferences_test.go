package decision

import (
	"encoding/json"
	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	"math"
	"testing"
	"time"
)

func preferencePolicy(norm, flow, lambda float64) model.Policy {
	p := economicsPolicy(0, false, 1)
	p.CostPreferencesConfigured = true
	p.NormPreference = norm
	p.FlowPreference = flow
	p.Lambda = lambda
	return p
}
func TestCostPreferencesRealProducerAndValidator(t *testing.T) {
	for _, w := range [][2]float64{{0, 0}, {.01, .3}, {.3, .01}} {
		var first model.Decision
		for _, lambda := range []float64{0, 10} {
			p := preferencePolicy(w[0], w[1], lambda)
			v := covView("independent", true, 2*time.Hour, false)
			v.Neighbors[0].Value = .5
			d := fixedTraceEngine().Decide([]*model.WorkloadView{v}, p)[0]
			if lambda == 0 {
				first = d
			} else if d.Action != first.Action || d.Selected != first.Selected || d.Net != first.Net {
				t.Fatal("legacy lambda changed independent selection")
			}
			if d.Trace == nil || d.Trace.SchemaVersion != model.DecisionTraceSchemaV8 {
				t.Fatal("missing v8 trace")
			}
			if err := d.Trace.Validate(); err != nil {
				t.Fatal(err)
			}
			if d.Measurements.ProactiveRate.Present {
				t.Fatal("scalar rate must be unavailable")
			}
			evaluated := 0
			for _, c := range d.Trace.Candidates {
				if c.NetGain.Present {
					evaluated++
					want := c.MarginalCoverage.Value*c.Provenance.Value - w[0]*c.CNorm.Value - w[1]*c.CFlow.Value
					if math.Abs(want-c.NetGain.Value) > 1e-9 {
						t.Fatalf("candidate %s gain %g want %g", c.Action, c.NetGain.Value, want)
					}
				}
			}
			if evaluated < 2 {
				t.Fatal("fixture lacks competing scored actions")
			}
			raw, err := json.Marshal(audit.ToRecord(d))
			if err != nil {
				t.Fatal(err)
			}
			runEconomicsAuditValidator(t, raw, true)
			var wire map[string]any
			json.Unmarshal(raw, &wire)
			if _, exists := wire["economics"].(map[string]any)["effectiveCostCoefficient"]; exists {
				t.Fatal("P2 has no scalar coefficient")
			}
			rows := wire["decisionTrace"].(map[string]any)["actionStatus"].([]any)
			rows[0].(map[string]any)["exclusionKind"] = "unknown-exclusion"
			invalidExclusion, _ := json.Marshal(wire)
			runEconomicsAuditValidator(t, invalidExclusion, false)
			json.Unmarshal(raw, &wire)
			wire["decisionTrace"].(map[string]any)["normPreference"].(map[string]any)["value"] = 9
			bad, _ := json.Marshal(wire)
			runEconomicsAuditValidator(t, bad, false)
			t.Logf("norm=%g flow=%g lambda=%g action=%s selected=%t", w[0], w[1], lambda, d.Action, d.Selected)
		}
	}
}
func TestCostPreferencesEditAndHardBudget(t *testing.T) {
	e := fixedTraceEngine()
	p := preferencePolicy(.2, .3, 5)
	v := covView("edited", true, 2*time.Hour, false)
	ds := e.Decide([]*model.WorkloadView{v}, p)
	if len(ds) != 1 || !ds[0].Selected {
		t.Fatal("fixture selected no action")
	}
	p.NormPreference = 0
	p.FlowPreference = 0
	zero := e.Decide([]*model.WorkloadView{v}, p)[0]
	if !zero.Selected || zero.Economics.NormPreference.Value != 0 {
		t.Fatal("same-owner edit ignored")
	}
	p.MaxMovesPerTick = 0
	if e.Decide([]*model.WorkloadView{v}, p)[0].Selected {
		t.Fatal("zero preferences bypassed hard budget")
	}
	p.CostPreferencesConfigured = false
	if e.Decide([]*model.WorkloadView{v}, p)[0].Economics.Version != model.EconomicsLegacyRuntimeLambdaV1 {
		t.Fatal("removal did not restore legacy")
	}
}

func TestCostPreferencesSwappedPreferencesChangeWinner(t *testing.T) {
	// Keep the real generator, security substrate and SLO weights fixed. Only
	// the independent preferences exchange places.
	v := covView("tradeoff", true, 2*time.Hour, false)
	v.Neighbors[0].Value = .5
	a := fixedTraceEngine().Decide([]*model.WorkloadView{v}, preferencePolicy(1.5, 0, 0))[0]
	b := fixedTraceEngine().Decide([]*model.WorkloadView{v}, preferencePolicy(0, 1.5, 0))[0]
	if !a.Selected || !b.Selected || a.Action != model.ActionQuarantine || b.Action != model.ActionRotate {
		t.Fatalf("norm preference selected %s/%t; flow preference selected %s/%t", a.Action, a.Selected, b.Action, b.Selected)
	}
}

func TestCostPreferencesAlternativeAndSharedSetValue(t *testing.T) {
	e := fixedTraceEngine()
	p := preferencePolicy(.2, .3, 10)
	v := covView("alternative", true, 2*time.Hour, false)
	ds := e.Decide([]*model.WorkloadView{v}, p)
	if len(ds) != 1 || !ds[0].Selected {
		t.Fatal("fixture needs selection")
	}
	alt, ok := e.SelectAlternative(p.Owner(), v.Pod.Namespace+"/"+v.Pod.Name, ds[0].Action)
	if !ok || !alt.ObjectivePenalty.Present || math.Abs(alt.Gain-(alt.Marginal-alt.ObjectivePenalty.Value)) > 1e-9 {
		t.Fatalf("alternative lost frozen preference score: %+v ok=%t", alt, ok)
	}
	// Each candidate includes the same fact. A set earns it only once; lambda
	// remains irrelevant when the real assembled candidates hold P2 penalties.
	picks := []actionset.Candidate{{Key: "a", CoverKeys: []string{"shared"}, ECost: 99, ObjectivePenalty: model.OptionalFloat{Present: true, Value: 2}}, {Key: "b", CoverKeys: []string{"shared"}, ECost: 99, ObjectivePenalty: model.OptionalFloat{Present: true, Value: 3}}}
	for _, lambda := range []float64{0, 10} {
		if got := setObjective(picks, map[string]float64{"shared": 8}, func(string) float64 { return 1 }, lambda); got != 3 {
			t.Fatalf("joint fact counted twice or lambda multiplied P2: %g", got)
		}
	}
}

func TestCostPreferencesShadowLeavesFrozenProductionSelection(t *testing.T) {
	e := fixedTraceEngine()
	p := preferencePolicy(.2, .3, 4)
	v := covView("shadow", true, 2*time.Hour, false)
	production := e.Decide([]*model.WorkloadView{v}, p)[0]
	shadowPolicy := p
	shadowPolicy.NormPreference = 10
	shadowPolicy.FlowPreference = 10
	if _, err := e.DecideShadowChecked([]*model.WorkloadView{v}, shadowPolicy); err != nil {
		t.Fatal(err)
	}
	alt, ok := e.SelectAlternative(p.Owner(), v.Pod.Namespace+"/"+v.Pod.Name, production.Action)
	if !ok {
		t.Fatal("shadow overwrote production alternative context")
	}
	for _, c := range production.Trace.Candidates {
		if c.Action == string(alt.Action) {
			want := .2*c.CNorm.Value + .3*c.CFlow.Value
			if !alt.ObjectivePenalty.Present || math.Abs(alt.ObjectivePenalty.Value-want) > 1e-9 {
				t.Fatal("shadow repriced original alternatives")
			}
			return
		}
	}
	t.Fatal("alternative absent from original trace")
}

func TestCostPreferencesTraceRejectsMissingInputsAndAliases(t *testing.T) {
	p := preferencePolicy(.2, .3, 1)
	v := covView("trace", true, 2*time.Hour, false)
	d := fixedTraceEngine().Decide([]*model.WorkloadView{v}, p)[0]
	copy := d.Trace.Canonical()
	copy.NormPreference.Value = 7
	if d.Trace.NormPreference.Value != .2 {
		t.Fatal("canonical aliases preference")
	}
	found := false
	for i := range copy.Candidates {
		if copy.Candidates[i].NormCostContribution != nil {
			copy.Candidates[i].NormCostContribution.Value = 99
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fixture has no priced candidate")
	}
	if err := d.Trace.Validate(); err != nil {
		t.Fatalf("copy mutated original contribution: %v", err)
	}
	for _, change := range []string{"missing-cost", "missing-marginal", "missing-component", "wrong-component", "scalar-zero"} {
		t.Run(change, func(t *testing.T) {
			raw, _ := json.Marshal(d.Trace)
			var trace model.DecisionTraceV2
			if err := json.Unmarshal(raw, &trace); err != nil {
				t.Fatal(err)
			}
			if change == "scalar-zero" {
				var object map[string]any
				json.Unmarshal(raw, &object)
				object["effectiveCostCoefficient"] = 0
				bad, _ := json.Marshal(object)
				if json.Unmarshal(bad, &trace) == nil {
					t.Fatal("wire accepted scalar zero")
				}
				return
			}
			for i := range trace.Candidates {
				c := &trace.Candidates[i]
				if !c.NetGain.Present {
					continue
				}
				switch change {
				case "missing-cost":
					c.ExpectedCost = model.OptionalFloat{}
				case "missing-marginal":
					c.MarginalCoverage = model.OptionalFloat{}
				case "missing-component":
					c.NormCostContribution = nil
				case "wrong-component":
					c.NormCostContribution.Value++
				}
				break
			}
			if err := trace.Validate(); err == nil {
				t.Fatal("invalid P2 trace accepted")
			}
		})
	}
}
