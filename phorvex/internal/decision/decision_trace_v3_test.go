/*
 * Phorvex — T0-C (B-5/R-2/R-9): the decision trace records the complete decision
 * path. Fixture battery per fixes/T0-C/03-decision.md B.7: action accounting (R-2),
 * CHi reconstruction (B.1), round semantics (B.2), NaN distinction (B.3),
 * reactive-only honesty (B.4), SLO-gate recording, and the completeness property.
 */

package decision

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
)

func actionStatusRow(t *testing.T, trace *model.DecisionTraceV2, action model.Action) model.DecisionActionStatusV3 {
	t.Helper()
	for _, row := range trace.ActionStatus {
		if row.Action == string(action) {
			return row
		}
	}
	t.Fatalf("no actionStatus row for %q", action)
	return model.DecisionActionStatusV3{}
}

// B.7.1 + B.7.8: every record carries exactly one row per canonical mutating action,
// in canonical order, unique — here with a 2-action policy (13 not-enabled rows).
func TestDecisionTraceV3ActionStatusCompletesCanonicalVocabulary(t *testing.T) {
	view := covView("v3-status", true, 2*time.Hour, false)
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))[0].Trace
	if trace == nil {
		t.Fatal("trace missing")
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	if got, want := len(trace.ActionStatus), len(model.MutatingActions); got != want {
		t.Fatalf("actionStatus rows = %d, want exactly %d", got, want)
	}
	notEnabled := 0
	for i, row := range trace.ActionStatus {
		if row.Action != string(model.MutatingActions[i]) {
			t.Fatalf("row %d = %q, canonical order wants %q", i, row.Action, model.MutatingActions[i])
		}
		if row.Status == model.ActionStatusNotEnabled {
			notEnabled++
			if row.ExclusionKind != model.ExclusionNotEnabled {
				t.Fatalf("not-enabled row %q carries exclusionKind %q", row.Action, row.ExclusionKind)
			}
			continue
		}
		// covPolicy enables rotate+quarantine: those two rows must be accounted.
		if row.Action != string(model.ActionRotate) && row.Action != string(model.ActionQuarantine) {
			t.Fatalf("action %q is not policy-enabled but is not recorded not-enabled: %+v", row.Action, row)
		}
	}
	if notEnabled != len(model.MutatingActions)-2 {
		t.Fatalf("not-enabled rows = %d, want %d", notEnabled, len(model.MutatingActions)-2)
	}
	// The selected action's row reads selected/none (B.3 consistency rule).
	if trace.SelectedAction != string(model.ActionNoop) {
		row := actionStatusRow(t, trace, model.Action(trace.SelectedAction))
		if row.Status != model.ActionStatusSelected || row.ExclusionKind != model.ExclusionNone {
			t.Fatalf("selected action row = %+v", row)
		}
	}
}

// B.7.2: B=2 three-asset tick — coveredRound/evaluationRound semantics and the
// marginal reconstruction law (B.2). Two assets win (rounds 1 and 2); the third is
// unselected with evaluationRound = lastRound. Under the cross-block collision
// regime fact keys are block-owned, so coveredBeforeDecision derives false
// everywhere — but now it is COMPUTED from the recorded rounds, not asserted.
func TestDecisionTraceV3CoveredRoundSemantics(t *testing.T) {
	a := covView("v3-round-a", true, 2*time.Hour, false)
	b := covView("v3-round-b", true, 2*time.Hour, false)
	c := covView("v3-round-c", true, 2*time.Hour, false)
	a.BlastRadius, b.BlastRadius, c.BlastRadius = 0.9, 0.8, 0.1 // deterministic order
	decisions := fixedTraceEngine().Decide([]*model.WorkloadView{a, b, c}, decisionTracePolicy(2, true))
	if len(decisions) != 3 {
		t.Fatalf("decisions = %d", len(decisions))
	}
	selectedRounds := 0
	var other *model.DecisionTraceV2
	for i := range decisions {
		tr := decisions[i].Trace
		if tr == nil {
			t.Fatal("trace missing")
		}
		if err := tr.Validate(); err != nil {
			t.Fatalf("%s/%s: %v", decisions[i].Namespace, decisions[i].Pod, err)
		}
		if decisions[i].Selected {
			selectedRounds++
			// A winner's record carries ITS selection round. Facts covered by the
			// SELECTED action are covered AT that round (coveredRound ==
			// evaluationRound ⇒ not before); facts outside its cover stay absent.
			if !tr.SelectionRound.Present || tr.EvaluationRound != tr.SelectionRound.Value {
				t.Fatalf("winner %s/%s evaluationRound = %d, selectionRound = %+v",
					decisions[i].Namespace, decisions[i].Pod, tr.EvaluationRound, tr.SelectionRound)
			}
			coveredKeys := map[string]bool{}
			for _, cand := range tr.Candidates {
				if cand.Selected {
					for _, k := range cand.CoverKeys {
						coveredKeys[k] = true
					}
				}
			}
			if len(coveredKeys) == 0 {
				t.Fatal("selected candidate covers nothing")
			}
			for _, f := range tr.Facts {
				if coveredKeys[f.FactKey] {
					if !f.CoveredRound.Present || f.CoveredRound.Value != tr.EvaluationRound {
						t.Fatalf("winner covered fact %q coveredRound = %+v, want present %d", f.FactKey, f.CoveredRound, tr.EvaluationRound)
					}
				} else if f.CoveredRound.Present {
					t.Fatalf("fact %q outside the selected cover claims a cover round", f.FactKey)
				}
				if f.CoveredBeforeDecision {
					t.Fatalf("winner fact %q coveredBeforeDecision must derive false (covered AT its round)", f.FactKey)
				}
			}
		} else {
			other = tr
		}
	}
	if selectedRounds != 2 || other == nil {
		t.Fatalf("selected = %d, want 2 selected + 1 unselected", selectedRounds)
	}
	// The unselected asset was evaluated through the last executed round (2).
	if other.EvaluationRound != 2 {
		t.Fatalf("unselected asset evaluationRound = %d, want 2 (lastRound)", other.EvaluationRound)
	}
	for _, f := range other.Facts {
		if f.CoveredRound.Present || f.CoveredBeforeDecision {
			t.Fatalf("unselected asset's fact %q claims coverage under block-owned keys: %+v", f.FactKey, f.CoveredRound)
		}
	}
	// The marginal law is exercised inside Validate (v3): marginal == Σ finalWeight
	// over not-covered-before keys. Reaching here means it held on all three records.
}

// B.7.3: a cold-start GPU rotate carries the full CHi reconstruction quad (B.1) and the
// pinned law reconstructs CostHigh from the recorded terms.
func TestDecisionTraceV3GPUUnprimedRotateCarriesEnvelopeTerms(t *testing.T) {
	view := covView("v3-gpu", true, 2*time.Hour, false)
	view.Pod.HasGPU = true
	pol := decisionTracePolicy(1, true)
	pol.CostCeiling = 100 // keep the SLO gate open: this fixture is about the envelope TERMS
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0].Trace
	if trace == nil {
		t.Fatal("trace missing")
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err) // the CHi law invariant runs here
	}
	var rotate *model.DecisionCandidateV2
	for i := range trace.Candidates {
		if trace.Candidates[i].Action == string(model.ActionRotate) && trace.Candidates[i].ExistingExclusionReason == "" {
			rotate = &trace.Candidates[i]
		}
	}
	if rotate == nil {
		t.Fatal("no generated rotate candidate")
	}
	if !rotate.ConformalQuantile.Present {
		t.Fatalf("rotate row lacks the conformal quantile: %+v", rotate)
	}
	if !rotate.ConformalCalibrated.Present || rotate.ConformalCalibrated.Value {
		t.Fatalf("cold-start bound must record calibrated=false: %+v", rotate.ConformalCalibrated)
	}
	if !rotate.GPUEnvelopeApplied.Present || !rotate.GPUEnvelopeApplied.Value {
		t.Fatalf("GPU rotate must record the configured envelope branch: %+v", rotate.GPUEnvelopeApplied)
	}
	wantSlack := pol.FlowDisruption * cost.GPUEnvelopeMax()
	if !rotate.GPUEnvelopeSlack.Present || rotate.GPUEnvelopeSlack.Value != wantSlack {
		t.Fatalf("envelope slack = %+v, want present %g", rotate.GPUEnvelopeSlack, wantSlack)
	}
	// The pinned law, independently recomputed here (Validate also checks it):
	slack := math.Max(rotate.ConformalQuantile.Value, wantSlack)
	if want := rotate.ExpectedCost.Value + slack; math.Abs(want-rotate.CostHigh.Value) > 1e-9 {
		t.Fatalf("CHi law: %g + %g != %g", rotate.ExpectedCost.Value, slack, rotate.CostHigh.Value)
	}
	// A non-rotate generated row carries no rotate slack terms.
	for i := range trace.Candidates {
		c := &trace.Candidates[i]
		if c.Action != string(model.ActionRotate) && c.ExistingExclusionReason == "" {
			if c.ConformalQuantile.Present || c.GPUEnvelopeSlack.Present {
				t.Fatalf("non-rotate row carries rotate slack terms: %+v", c)
			}
			if !c.GPUEnvelopeApplied.Present || c.GPUEnvelopeApplied.Value {
				t.Fatalf("non-rotate row must record envelope-applied=false: %+v", c.GPUEnvelopeApplied)
			}
		}
	}
}

// B.7.4: a NaN telemetry feature fails closed into status=infeasible +
// exclusionKind=cost-nan — the distinction p1cost.go:24-26 draws deliberately (B.3).
// (View-side NaN: rotate reads reqRate, quarantine reads connCount — p1cost.go:265-279.)
func TestDecisionTraceV3NaNExclusionKeepsDataQualityDistinct(t *testing.T) {
	view := covView("v3-nan", true, 2*time.Hour, false)
	view.Telemetry = model.Telemetry{ReqRate: model.Signal{Value: math.NaN(), State: model.Error}, ConnCount: model.Signal{Value: math.NaN(), State: model.Error}}
	pol := decisionTracePolicy(1, true)
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0].Trace
	if trace == nil {
		t.Fatal("trace missing")
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	nanRows := 0
	for _, row := range trace.ActionStatus {
		if row.ExclusionKind == model.ExclusionCostNaN {
			nanRows++
			if row.Status != model.ActionStatusInfeasible {
				t.Fatalf("cost-nan row reads status %q, want infeasible (B.3)", row.Status)
			}
			if row.Reason == "" {
				t.Fatal("cost-nan row lost the category/detail reason")
			}
		}
	}
	if nanRows != 2 { // covPolicy enables rotate+quarantine; both fail closed
		t.Fatalf("cost-nan rows = %d, want 2 (both enabled actions)", nanRows)
	}
	for _, c := range trace.Candidates {
		if c.ConformalQuantile.Present || c.GPUEnvelopeSlack.Present || c.SLOGateResult.Present {
			t.Fatalf("NaN row carries cost-path terms the fail-closed return never computed: %+v", c)
		}
	}
}

// B.7.5: reactive-only suppression records scored=false + exclusionKind=reactive-only,
// never a bare "candidate" (B.4) — the state 100% of vllm rows are in live.
func TestDecisionTraceV3ReactiveOnlyRowsAreHonest(t *testing.T) {
	view := covView("v3-reactive", true, 2*time.Hour, false) // no foothold, no suspect adapter
	pol := decisionTracePolicy(1, true)
	pol.ReactiveOnly = true
	decision := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0]
	if decision.Trace == nil {
		t.Fatal("trace missing")
	}
	trace := decision.Trace
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	if trace.SelectedAction != string(model.ActionNoop) {
		t.Fatalf("reactive-only asset with no foothold selected %q", trace.SelectedAction)
	}
	for _, action := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		row := actionStatusRow(t, trace, action)
		if row.Status != model.ActionStatusCandidate || row.ExclusionKind != model.ExclusionReactiveOnly || row.Scored {
			t.Fatalf("reactive-only row for %q = %+v, want candidate/reactive-only/scored=false", action, row)
		}
	}
}

// B.7.7: a conformal-slo gate reject records status=conformal-slo, exclusionKind=
// slo-gate, sloGateResult=false, and the effective ceiling at trace level.
func TestDecisionTraceV3ConformalSLOGateReject(t *testing.T) {
	view := covView("v3-slo", true, 2*time.Hour, false)
	pol := decisionTracePolicy(1, true)
	pol.CostCeiling = 1e-9 // below any CHi: every enabled action is gate-rejected
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0].Trace
	if trace == nil {
		t.Fatal("trace missing")
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	if trace.CostCeiling != 1e-9 {
		t.Fatalf("trace costCeiling = %g, want the effective 1e-9", trace.CostCeiling)
	}
	for _, action := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		row := actionStatusRow(t, trace, action)
		if row.Status != model.ActionStatusConformalSLO || row.ExclusionKind != model.ExclusionSLOGate {
			t.Fatalf("gate-rejected row for %q = %+v", action, row)
		}
	}
	gateRows := 0
	for _, c := range trace.Candidates {
		if c.ExistingExclusionReason == "" {
			continue
		}
		if !c.SLOGateResult.Present || c.SLOGateResult.Value {
			t.Fatalf("gate-rejected exclusion lacks sloGateResult=false: %+v", c)
		}
		gateRows++
	}
	if gateRows != 2 {
		t.Fatalf("gate-rejected exclusion rows = %d, want 2", gateRows)
	}
}

// B.7.8: the completeness property over varied policies — exactly 15 rows, canonical
// order, unique, valid — including the B=0 edge (no evaluation pass runs).
func TestDecisionTraceV3ActionStatusPropertyVariedPolicies(t *testing.T) {
	views := []*model.WorkloadView{covView("v3-prop", true, 2*time.Hour, false)}
	policies := []model.Policy{
		decisionTracePolicy(0, true),
		decisionTracePolicy(1, true),
		decisionTracePolicy(3, true),
	}
	onlyRotate := decisionTracePolicy(1, true)
	onlyRotate.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	policies = append(policies, onlyRotate)
	none := decisionTracePolicy(1, true)
	none.EnabledActions = map[model.Action]bool{}
	policies = append(policies, none)

	for pi, pol := range policies {
		trace := fixedTraceEngine().Decide(views, pol)[0].Trace
		if trace == nil {
			t.Fatalf("policy %d: trace missing", pi)
		}
		if err := trace.Validate(); err != nil {
			t.Fatalf("policy %d: %v", pi, err)
		}
		if len(trace.ActionStatus) != len(model.MutatingActions) {
			t.Fatalf("policy %d: %d rows", pi, len(trace.ActionStatus))
		}
		seen := map[string]bool{}
		for i, row := range trace.ActionStatus {
			if row.Action != string(model.MutatingActions[i]) || seen[row.Action] {
				t.Fatalf("policy %d row %d = %q: non-canonical or duplicate", pi, i, row.Action)
			}
			seen[row.Action] = true
			if row.Status == model.ActionStatusNotInstallable {
				t.Fatalf("policy %d: not-installable emitted — capability is never evaluated per-asset", pi)
			}
		}
		if trace.DispatchOutcome == "" {
			t.Fatalf("policy %d: dispatch outcome not recorded", pi)
		}
	}
}

// B.7.9: trace-on/off selection equivalence extended to the v3 fixtures (P-C5).
func TestDecisionTraceV3FixturesAreSelectionEquivalentTraceOnOff(t *testing.T) {
	gpu := covView("v3-eq-gpu", true, 2*time.Hour, false)
	gpu.Pod.HasGPU = true
	corpus := [][]*model.WorkloadView{
		{gpu},
		{covView("v3-eq-a", true, 2*time.Hour, false), covView("v3-eq-b", true, 90*time.Minute, false)},
	}
	pols := []model.Policy{decisionTracePolicy(1, false), decisionTracePolicy(2, false)}
	reactivePol := decisionTracePolicy(1, false)
	reactivePol.ReactiveOnly = true
	pols = append(pols, reactivePol)

	for i, views := range corpus {
		for pi, base := range pols {
			withPol := base
			withPol.TraceEnabled = true
			without := fixedTraceEngine().Decide(views, base)
			with := fixedTraceEngine().Decide(views, withPol)
			if !decisionsEqualSelection(without, with) {
				t.Fatalf("corpus %d policy %d: trace changed selection", i, pi)
			}
		}
	}
}

func decisionsEqualSelection(a, b []model.Decision) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Selected != b[i].Selected || a[i].Action != b[i].Action ||
			a[i].Namespace != b[i].Namespace || a[i].Pod != b[i].Pod {
			return false
		}
	}
	return true
}

// TestDecisionTraceV3ValidateRejectsMalformed pins the negative half of the v3 contract:
// a v3 record missing a field the reconstruction laws depend on, or naming a selected
// action outside the canonical vocabulary, is rejected with an error — never accepted,
// never a panic.
func TestDecisionTraceV3ValidateRejectsMalformed(t *testing.T) {
	base := fixedTraceEngine().Decide([]*model.WorkloadView{covView("v3-neg", true, 2*time.Hour, false)}, decisionTracePolicy(1, true))[0].Trace
	if base == nil {
		t.Fatal("trace missing")
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("well-formed v3 trace must validate: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(tr *model.DecisionTraceV2)
	}{
		{"unknown selected action", func(tr *model.DecisionTraceV2) { tr.SelectedAction = "not-a-move" }},
		{"empty costModelVersion", func(tr *model.DecisionTraceV2) { tr.CostModelVersion = "" }},
		{"zero costCeiling", func(tr *model.DecisionTraceV2) { tr.CostCeiling = 0 }},
		{"truncated actionStatus", func(tr *model.DecisionTraceV2) { tr.ActionStatus = tr.ActionStatus[:len(tr.ActionStatus)-1] }},
		{"missing dispatchOutcome", func(tr *model.DecisionTraceV2) { tr.DispatchOutcome = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := *base
			tr.ActionStatus = append([]model.DecisionActionStatusV3(nil), base.ActionStatus...)
			tc.mutate(&tr)
			if err := tr.Validate(); err == nil {
				t.Fatalf("malformed v3 trace (%s) validated", tc.name)
			}
		})
	}
}
