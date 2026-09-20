package decision

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func economicsPolicy(beta float64, configured bool, budget int) model.Policy {
	pol := decisionTracePolicy(budget, true)
	pol.Lambda = 0
	pol.DisruptionAversion = beta
	pol.DisruptionAversionConfigured = configured
	return pol
}

func runEconomicsAuditValidator(t *testing.T, raw []byte, wantPass bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "record.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	validator := filepath.Join("..", "..", "..", "workflow", "fixes", "T0-C", "validator", "audit_trace_validator.py")
	output, err := exec.Command("python3", validator, path, "--strict-v3").CombinedOutput()
	if (err == nil) != wantPass {
		t.Fatalf("validator pass=%t want=%t err=%v\n%s", err == nil, wantPass, err, output)
	}
}

func TestPost25EconomicsIndependentValidatorConsumesRealV4Producer(t *testing.T) {
	var validFixed map[string]any
	for _, tc := range []struct {
		name       string
		configured bool
		beta       float64
	}{
		{name: "explicit-zero", configured: true, beta: 0},
		{name: "small-fixed", configured: true, beta: 0.00004},
		{name: "legacy", configured: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := economicsPolicy(tc.beta, tc.configured, 1)
			decision := fixedTraceEngine().Decide([]*model.WorkloadView{covView("validator-"+tc.name, true, 2*time.Hour, false)}, pol)[0]
			raw, err := json.Marshal(audit.ToRecord(decision))
			if err != nil {
				t.Fatal(err)
			}
			runEconomicsAuditValidator(t, raw, true)
			if tc.name == "small-fixed" {
				if err := json.Unmarshal(raw, &validFixed); err != nil {
					t.Fatal(err)
				}
			}
		})
	}

	mutations := map[string]func(map[string]any){
		"wrong coefficient": func(record map[string]any) {
			record["decisionTrace"].(map[string]any)["effectiveCostCoefficient"] = 0.5
		},
		"tampered audit exact beta": func(record map[string]any) {
			record["economics"].(map[string]any)["effectiveCostCoefficient"] = 0.5
		},
		"missing economics version": func(record map[string]any) {
			delete(record["decisionTrace"].(map[string]any), "economicsVersion")
		},
		"missing objective demand": func(record map[string]any) {
			delete(record["decisionTrace"].(map[string]any), "objectiveCandidateDemand")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(validFixed)
			if err != nil {
				t.Fatal(err)
			}
			var record map[string]any
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatal(err)
			}
			mutate(record)
			tampered, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			runEconomicsAuditValidator(t, tampered, false)
		})
	}
}

func TestPost25EconomicsAbsentLegacyAndExplicitZero(t *testing.T) {
	view := covView("legacy-equivalence", true, 2*time.Hour, false)
	legacy := economicsPolicy(0, false, 1)
	ignoredValue := legacy
	ignoredValue.DisruptionAversion = 9 // absence, not the numeric zero, selects legacy mode

	left := fixedTraceEngine().Decide([]*model.WorkloadView{view}, legacy)
	right := fixedTraceEngine().Decide([]*model.WorkloadView{view}, ignoredValue)
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("absent fixed preference changed legacy output:\nleft=%+v\nright=%+v", left, right)
	}
	if left[0].Economics == nil || left[0].Economics.Version != model.EconomicsLegacyRuntimeLambdaV1 || left[0].Economics.DisruptionAversion.Present {
		t.Fatalf("legacy descriptor is not explicit: %+v", left[0].Economics)
	}

	explicitZero := economicsPolicy(0, true, 1)
	explicitZero.Lambda = 10
	d := fixedTraceEngine().Decide([]*model.WorkloadView{view}, explicitZero)[0]
	if d.Economics == nil || d.Economics.Version != model.EconomicsFixedDisruptionAversionV1 ||
		!d.Economics.DisruptionAversion.Present || d.Economics.DisruptionAversion.Value != 0 ||
		d.Economics.EffectiveCostCoefficient != 0 || d.Lambda != 10 {
		t.Fatalf("explicit zero was confused with absence or lambda: %+v", d)
	}
	if d.Trace == nil || d.Trace.SchemaVersion != model.DecisionTraceSchemaV4 || errString(d.Trace.Validate()) != "" {
		t.Fatalf("explicit-zero V4 trace invalid: trace=%+v err=%s", d.Trace, errString(d.Trace.Validate()))
	}
}

func TestPost25EconomicsActualProducerRanksByFixedPreference(t *testing.T) {
	view := covView("fixed-ranking", true, 2*time.Hour, false)
	view.Neighbors[0].Value = 0.5 // makes rotate higher-value/higher-cost and quarantine lower-value/lower-cost
	zero := economicsPolicy(0, true, 1)
	zeroDecision := fixedTraceEngine().Decide([]*model.WorkloadView{view}, zero)[0]
	if !zeroDecision.Selected || zeroDecision.Cost <= 0 {
		t.Fatalf("fixture has no positive-cost beta-zero selection: %+v", zeroDecision)
	}

	var preferred model.Decision
	found := false
	for _, beta := range []float64{0.25, 0.5, 1, 2, 4, 6, 8, 10} {
		pol := economicsPolicy(beta, true, 1)
		candidate := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0]
		if candidate.Selected && candidate.Action != zeroDecision.Action && candidate.Cost < zeroDecision.Cost {
			preferred, found = candidate, true
			break
		}
	}
	if !found {
		t.Fatalf("real producer exposed no bounded beta that replaces %s/cost=%g with a lower-cost action", zeroDecision.Action, zeroDecision.Cost)
	}
	if preferred.Economics == nil || preferred.Net != preferred.CoverageValue-preferred.Economics.EffectiveCostCoefficient*preferred.Cost ||
		preferred.ProactiveRate != math.Max(0, preferred.PerDollar-preferred.Economics.EffectiveCostCoefficient) {
		t.Fatalf("selected reporting used a coefficient other than the ranking descriptor: %+v", preferred)
	}
	if !hasAttribution(preferred.Attribution, "cost:-disruptionAversion*C") {
		t.Fatalf("fixed preference attribution missing: %+v", preferred.Attribution)
	}
	if preferred.Trace == nil || preferred.Trace.EconomicsVersion != model.EconomicsFixedDisruptionAversionV1 {
		t.Fatalf("fixed preference trace metadata missing: %+v", preferred.Trace)
	}
	for _, row := range preferred.Trace.Candidates {
		if row.ExpectedCost.Present && (row.LambdaContribution.Present || row.ObjectiveCostContribution == nil || !row.ObjectiveCostContribution.Present) {
			t.Fatalf("fixed trace relabelled beta as lambda or omitted its contribution: %+v", row)
		}
	}
	if err := preferred.Trace.Validate(); err != nil {
		t.Fatalf("fixed trace is not independently reconstructable: %v", err)
	}
}

func TestPost25EconomicsCounterfactualLambdaDemandAndFixedCoefficient(t *testing.T) {
	high := covView("demand-high", true, 2*time.Hour, false)
	low := lowValueView("demand-low")
	views := []*model.WorkloadView{high, low}
	var e *CoverageEngine
	var pol model.Policy
	var first model.Decision
	found := false
	for _, beta := range []float64{0.25, 0.5, 1, 2, 4, 6, 8, 10} {
		candidateEngine := fixedTraceEngine()
		candidatePolicy := economicsPolicy(beta, true, 1)
		decisions := candidateEngine.Decide(views, candidatePolicy)
		if decisions[0].Trace.ObjectiveCandidateDemand == 1 && decisions[0].Trace.LambdaDemand == 2 &&
			decisions[0].Trace.MovesSpent == 1 && decisions[0].Trace.DualUpdate.LambdaAfter > 0 {
			e, pol, first, found = candidateEngine, candidatePolicy, decisions[0], true
			break
		}
	}
	if !found || first.Trace.CandidateDemand != first.Trace.LambdaDemand || first.Trace.DualUpdate.Demand != first.Trace.LambdaDemand {
		t.Fatalf("real producer exposed no fixed-beta tick with objectiveDemand=1, lambdaDemand=2 and one spent move")
	}
	coefficient, lambdaAfter := first.Economics.EffectiveCostCoefficient, first.Trace.DualUpdate.LambdaAfter
	second := e.Decide(views, pol)[0]
	if second.Lambda != lambdaAfter || second.Economics.EffectiveCostCoefficient != coefficient ||
		traceObjectiveContribution(first.Trace, first.Action) != traceObjectiveContribution(second.Trace, first.Action) {
		t.Fatalf("legacy lambda movement changed fixed-beta score: first=%+v second=%+v", first, second)
	}

	// A subsequent underloaded tick decays the legacy count-pressure state while
	// beta remains fixed. This exercises both recurrence directions with actual decisions.
	underloaded := pol
	underloaded.MaxMovesPerTick = 3
	third := e.Decide(views[:1], underloaded)[0]
	if third.Trace.DualUpdate.LambdaAfter >= third.Trace.DualUpdate.LambdaBefore ||
		third.Economics.EffectiveCostCoefficient != coefficient || !third.Economics.DisruptionAversion.Present {
		t.Fatalf("underload changed beta or failed to decay legacy state: %+v", third)
	}
}

func TestPost25EconomicsHighBetaNoopAndLegacyLambdaControls(t *testing.T) {
	high := economicsPolicy(10, true, 1)
	pricedOut := fixedTraceEngine().Decide([]*model.WorkloadView{lowValueView("priced-out")}, high)[0]
	if pricedOut.Selected || pricedOut.Action == model.ActionNoop || pricedOut.Trace == nil ||
		pricedOut.Trace.ObjectiveCandidateDemand != 0 || pricedOut.Trace.LambdaDemand <= 0 {
		t.Fatalf("high beta did not produce an honest considered/noop outcome: %+v", pricedOut)
	}
	if !strings.Contains(pricedOut.Reason, model.CostCoefficientSourceBeta) || pricedOut.Trace.NoopReason != "priced-out: no net-positive feasible move" {
		t.Fatalf("high-beta noop explanation is ambiguous: reason=%q trace=%+v", pricedOut.Reason, pricedOut.Trace)
	}

	legacy := economicsPolicy(0, false, 3)
	legacy.Lambda = 0.6
	legacyDecision := fixedTraceEngine().Decide([]*model.WorkloadView{covView("legacy-decay", true, 2*time.Hour, false)}, legacy)[0]
	if legacyDecision.Cost <= 0 || legacyDecision.Trace == nil ||
		legacyDecision.Trace.DualUpdate.LambdaAfter >= legacyDecision.Trace.DualUpdate.LambdaBefore {
		t.Fatalf("actual positive-cost legacy underload did not decay lambda: %+v", legacyDecision)
	}

	recovery := economicsPolicy(0, false, 1)
	recoveryEngine := fixedTraceEngine()
	recoveryViews := []*model.WorkloadView{covView("binding-a", true, 2*time.Hour, false), covView("binding-b", true, 2*time.Hour, false)}
	recovered := recoveryEngine.Decide(recoveryViews, recovery)[0]
	if recovered.Trace == nil || recovered.Trace.DualUpdate.LambdaBefore != 0 || recovered.Trace.DualUpdate.LambdaAfter <= 0 ||
		recovered.Trace.DualUpdate.Demand <= recovered.Trace.DualUpdate.Budget {
		t.Fatalf("zero lambda did not recover under binding demand: %+v", recovered.Trace)
	}
}

func TestPost25EconomicsPatchRemovalAndOwnerIsolation(t *testing.T) {
	e := fixedTraceEngine()
	first := economicsPolicy(1, true, 1)
	first.PolicyUID = "uid-a"
	first.Tenant = "shared-display"
	e.SetOwnerLive(first.Owner(), true)
	d1 := e.Decide([]*model.WorkloadView{covView("patch", true, 2*time.Hour, false)}, first)[0]
	meta1, _ := e.BucketMetaFor(first.Owner())

	patched := first
	patched.DisruptionAversion = 3
	d2 := e.Decide([]*model.WorkloadView{covView("patch", true, 2*time.Hour, false)}, patched)[0]
	meta2, _ := e.BucketMetaFor(first.Owner())
	if d1.Economics.EffectiveCostCoefficient != 1 || d2.Economics.EffectiveCostCoefficient != 3 || meta1.CreationEvent != meta2.CreationEvent {
		t.Fatalf("same-owner beta patch reseeded state or missed next tick: d1=%+v d2=%+v meta=%+v/%+v", d1.Economics, d2.Economics, meta1, meta2)
	}

	removed := patched
	removed.DisruptionAversion, removed.DisruptionAversionConfigured = 0, false
	d3 := e.Decide([]*model.WorkloadView{covView("patch", true, 2*time.Hour, false)}, removed)[0]
	if d3.Economics.Version != model.EconomicsLegacyRuntimeLambdaV1 || d3.Economics.EffectiveCostCoefficient != d3.Lambda {
		t.Fatalf("field removal did not restore current runtime-lambda scoring: %+v", d3)
	}

	second := economicsPolicy(2, true, 1)
	second.PolicyUID = "uid-b"
	second.Tenant = first.Tenant
	e.SetOwnerLive(second.Owner(), true)
	d4 := e.Decide([]*model.WorkloadView{covView("isolated", true, 2*time.Hour, false)}, second)[0]
	meta4, _ := e.BucketMetaFor(second.Owner())
	if d4.Economics.EffectiveCostCoefficient != 2 || second.Owner() == first.Owner() || meta4.OwnerKey == meta1.OwnerKey || meta4.CreationEvent == meta1.CreationEvent {
		t.Fatalf("same-display policies shared identity or beta state: first=%+v second=%+v", meta1, meta4)
	}
}

func TestPost25EconomicsAlternativeShadowUnitConversionAndGates(t *testing.T) {
	view := covView("alternative", true, 2*time.Hour, false)
	e := fixedTraceEngine()
	pol := economicsPolicy(0.5, true, 1)
	decisions := e.Decide([]*model.WorkloadView{view}, pol)
	if len(decisions) != 1 || !decisions[0].Selected {
		t.Fatalf("fixture did not select a primary: %+v", decisions)
	}
	alt, ok := e.SelectAlternative(pol.Owner(), "ns/alternative", decisions[0].Action)
	if !ok || math.Abs(alt.Gain-(alt.Marginal*decisions[0].Provenance-0.5*alt.Cost)) > 1e-12 ||
		!hasAttribution(alt.Attribution, "cost:-disruptionAversion*C") {
		t.Fatalf("alternative did not retain fixed economics: ok=%t alt=%+v", ok, alt)
	}

	before := e.costFor(pol.Owner()).Dual.Lambda()
	shadow, err := e.DecideShadowChecked([]*model.WorkloadView{view}, pol)
	if err != nil || len(shadow) != 1 || shadow[0].Economics == nil || shadow[0].Economics.EffectiveCostCoefficient != 0.5 {
		t.Fatalf("fixed shadow unavailable or mispriced: decisions=%+v err=%v", shadow, err)
	}
	if after := e.costFor(pol.Owner()).Dual.Lambda(); after != before {
		t.Fatalf("shadow moved legacy lambda: %g -> %g", before, after)
	}

	set, ctx := fixedTraceEngine().AssembleSet([]*model.WorkloadView{view}, pol)
	if len(set.Candidates) == 0 {
		t.Fatal("unit-conversion fixture has no producer candidate")
	}
	c := set.Candidates[0]
	marginal := 0.0
	for _, key := range c.CoverKeys {
		marginal += set.FactWeights[key]
	}
	provenance := provFn(ctx, pol.ProactiveFloor.Seconds())(c.Key)
	const k = 2.0
	if objectiveGain(marginal, provenance, 0.5, c.ECost) != objectiveGain(marginal, provenance, 0.5/k, c.ECost*k) {
		t.Fatal("objective changed under an admissible ECost/coefficient unit conversion")
	}

	stateful := covView("stateful", true, 2*time.Hour, true)
	rotateOnly := economicsPolicy(0, true, 1)
	rotateOnly.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	gated := fixedTraceEngine().Decide([]*model.WorkloadView{stateful}, rotateOnly)[0]
	if gated.Selected || gated.Feasible {
		t.Fatalf("fixed beta bypassed the stateful service gate: %+v", gated)
	}
}

func TestPost25EconomicsM99ContainmentRetainsHardGateOrdering(t *testing.T) {
	v, pol := m99Fixture()
	engine := fixedTraceEngine()
	bindRotate(t, engine, v, pol)
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	pol.CostCeiling = 1e-9
	pol.MayBreachSLO = true
	pol.TraceEnabled = true
	pol.DisruptionAversionConfigured = true
	pol.DisruptionAversion = 10

	decisions, err := engine.DecideChecked([]*model.WorkloadView{v}, pol)
	if err != nil {
		t.Fatal(err)
	}
	d := decisions[0]
	if !d.Selected || d.Existential == nil || d.Existential.Result != "selected" ||
		d.Economics == nil || d.Economics.EffectiveCostCoefficient != 10 ||
		d.Trace == nil || d.Trace.SelectorComparator != model.SelectorM99Containment ||
		!strings.Contains(d.Reason, "protected-outcome containment") || strings.Contains(d.Reason, "strict gain") {
		t.Fatalf("fixed preference displaced M99 containment or its audit economics: %+v", d)
	}
	raw, err := json.Marshal(audit.ToRecord(d))
	if err != nil {
		t.Fatal(err)
	}
	runEconomicsAuditValidator(t, raw, true)

	v.Pod.Stateful = true
	blocked, err := fixedTraceEngine().DecideChecked([]*model.WorkloadView{v}, pol)
	if err != nil {
		t.Fatal(err)
	}
	if blocked[0].Selected || blocked[0].Feasible || blocked[0].Existential == nil || blocked[0].Existential.Result != "uncontainable" {
		t.Fatalf("fixed preference or M99 bypassed the stateful hard gate: %+v", blocked[0])
	}
}

func TestPost25EconomicsRejectsInvalidDirectPoliciesBeforeState(t *testing.T) {
	for _, value := range []float64{-1, 10.01, math.NaN(), math.Inf(1)} {
		e := fixedTraceEngine()
		pol := economicsPolicy(value, true, 1)
		if decisions, err := e.DecideChecked([]*model.WorkloadView{covView("invalid", true, 2*time.Hour, false)}, pol); err == nil || decisions != nil {
			t.Fatalf("invalid beta %v was accepted: decisions=%+v err=%v", value, decisions, err)
		}
		if len(e.costByOwner) != 0 || e.aliasOwner != "" {
			t.Fatalf("invalid beta %v allocated owner state", value)
		}
	}
}

func TestPost25EconomicsFrozenCandidateUnitConversion(t *testing.T) {
	set := actionset.ActionSet{FactWeights: map[string]float64{"fact": 2}, Candidates: []actionset.Candidate{{Key: "ns/p", Action: model.ActionRotate, CoverKeys: []string{"fact"}, ECost: 0.75}}}
	states := map[string]*model.ExistentialDecision{"ns/p": {}}
	attack := map[string]bool{"ns/p": true}
	prov := func(string) float64 { return 0.8 }
	left, _, _ := chooseRound(set, states, map[string]bool{}, map[string]bool{}, attack, 0.5, prov, map[string]float64{})
	scaled := set
	scaled.Candidates = append([]actionset.Candidate(nil), set.Candidates...)
	scaled.Candidates[0].ECost *= 2
	right, _, _ := chooseRound(scaled, states, map[string]bool{}, map[string]bool{}, attack, 0.25, prov, map[string]float64{})
	if left != 0 || right != left {
		t.Fatalf("unit conversion changed frozen candidate selection: %d vs %d", left, right)
	}
}

func hasAttribution(terms []model.AttributionTerm, source string) bool {
	for _, term := range terms {
		if term.Source == source {
			return true
		}
	}
	return false
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func traceObjectiveContribution(trace *model.DecisionTraceV2, action model.Action) float64 {
	if trace == nil {
		return math.NaN()
	}
	for _, candidate := range trace.Candidates {
		if candidate.Action == string(action) && candidate.ObjectiveCostContribution != nil && candidate.ObjectiveCostContribution.Present {
			return candidate.ObjectiveCostContribution.Value
		}
	}
	return math.NaN()
}
