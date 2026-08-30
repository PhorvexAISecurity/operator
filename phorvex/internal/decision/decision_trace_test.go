package decision

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

var traceTestNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

func decisionTracePolicy(budget int, enabled bool) model.Policy {
	pol := covPolicy(budget)
	pol.Namespace = "ns"
	pol.PolicyName = "defense"
	pol.PolicyUID = "policy-uid"
	pol.TickID = "tick-fixed"
	pol.BrainImage = "registry/phorvex:sha-test"
	pol.GitSHA = "0123456789abcdef"
	pol.TraceEnabled = enabled
	return pol
}

func fixedTraceEngine() *CoverageEngine {
	e := NewCoverageEngine()
	e.Now = func() time.Time { return traceTestNow }
	return e
}

func decisionsWithoutTrace(in []model.Decision) []model.Decision {
	out := append([]model.Decision(nil), in...)
	for i := range out {
		out[i].Trace = nil
	}
	return out
}

func traceByAsset(t *testing.T, decisions []model.Decision) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, decision := range decisions {
		if decision.Trace == nil {
			t.Fatalf("%s/%s has no trace", decision.Namespace, decision.Pod)
		}
		raw, err := json.Marshal(decision.Trace)
		if err != nil {
			t.Fatal(err)
		}
		out[decision.Namespace+"/"+decision.Pod] = string(raw)
	}
	return out
}

func TestDecisionTraceCandidateCompletenessSelectionAndMissingTelemetry(t *testing.T) {
	view := covView("trace", true, 2*time.Hour, false)
	// A bundle-level answer without per-query provenance must not turn an
	// unobserved request rate into a measured zero in the trace.
	view.Telemetry = model.Telemetry{Present: true, ReqRate: 0}
	decisions := fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("trace missing: %+v", decisions)
	}
	trace := decisions[0].Trace
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	if trace.Inputs.RequestRate.Present {
		t.Fatal("missing request-rate series was serialized as a measured zero")
	}
	if trace.Inputs.ImageRarity.Present || trace.Inputs.CVSS.Present {
		t.Fatal("absent physics inputs were serialized as measured neutral values")
	}
	if got, want := len(trace.Candidates), 2; got != want {
		t.Fatalf("candidate/exclusion completeness = %d, want %d enabled actions", got, want)
	}
	selected := 0
	for _, candidate := range trace.Candidates {
		if candidate.Selected {
			selected++
			if candidate.CandidateKey != trace.SelectedCandidateKey || candidate.Action != trace.SelectedAction {
				t.Fatalf("selected reference mismatch: %+v", candidate)
			}
		}
	}
	if selected != 1 {
		t.Fatalf("selected candidate count = %d", selected)
	}

	view.Telemetry.PresentSignals = map[string]bool{"reqRate": true}
	view.Physics.ImageRarity, view.Physics.ImageRarityPresent = 1, true
	measured := fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))[0].Trace
	if !measured.Inputs.RequestRate.Present || measured.Inputs.RequestRate.Value != 0 {
		t.Fatalf("measured zero lost presence: %+v", measured.Inputs.RequestRate)
	}
	if !measured.Inputs.ImageRarity.Present || measured.Inputs.ImageRarity.Value != 1 {
		t.Fatalf("measured neutral rarity lost presence: %+v", measured.Inputs.ImageRarity)
	}
}

func TestDecisionTraceNoopAndCurrentExclusionAreHonest(t *testing.T) {
	view := covView("stateful", true, 2*time.Hour, true)
	pol := decisionTracePolicy(1, true)
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	decision := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)[0]
	if decision.Trace == nil || decision.Trace.SelectedAction != string(model.ActionNoop) {
		t.Fatalf("expected traced noop: %+v", decision)
	}
	if err := decision.Trace.Validate(); err != nil {
		t.Fatal(err)
	}
	if decision.Trace.NoopReason == "" || len(decision.Trace.Candidates) != 1 {
		t.Fatalf("noop/exclusion not represented: %+v", decision.Trace)
	}
	candidate := decision.Trace.Candidates[0]
	if !candidate.Feasible.Present || candidate.Feasible.Value || candidate.ExistingExclusionReason == "" {
		t.Fatalf("current feasibility result not recorded: %+v", candidate)
	}
	if !candidate.NotClassifiedByCurrentModel {
		t.Fatal("unknown runtime capability was fabricated as classified")
	}
}

func TestTraceEnabledAndDisabledAreSelectionEquivalentOnFrozenCorpus(t *testing.T) {
	disabled, enabled := fixedTraceEngine(), fixedTraceEngine()
	basePolicy, tracePolicy := decisionTracePolicy(2, false), decisionTracePolicy(2, true)
	corpus := [][]*model.WorkloadView{
		{covView("a", true, 2*time.Hour, false), covView("b", false, 30*time.Minute, false), covView("c", false, 5*time.Minute, false)},
		{covView("a", true, 3*time.Hour, false), covView("b", false, 90*time.Minute, false), covView("c", true, 2*time.Hour, false)},
		{covView("a", true, 4*time.Hour, false), covView("b", true, 2*time.Hour, true), covView("c", false, 15*time.Minute, false)},
		{covView("a", true, 5*time.Hour, false), covView("b", false, 10*time.Minute, false), covView("c", true, 3*time.Hour, false)},
	}
	for i, views := range corpus {
		without := disabled.Decide(views, basePolicy)
		with := enabled.Decide(views, tracePolicy)
		if !reflect.DeepEqual(without, decisionsWithoutTrace(with)) {
			t.Fatalf("frozen corpus tick %d changed selection with trace enabled\nwithout=%+v\nwith=%+v", i, without, with)
		}
		for _, decision := range with {
			if decision.Trace == nil {
				t.Fatalf("tick %d decision %s has no trace", i, decision.Pod)
			}
			if err := decision.Trace.Validate(); err != nil {
				t.Fatalf("tick %d decision %s is not independently valid: %v", i, decision.Pod, err)
			}
		}
	}
}

func TestDecisionTraceDoesNotMutateInputSnapshot(t *testing.T) {
	views := []*model.WorkloadView{covView("immutable", true, 2*time.Hour, false)}
	views[0].Pod.Labels = map[string]string{"app": "api", "irrelevant": "x"}
	before, err := json.Marshal(views)
	if err != nil {
		t.Fatal(err)
	}
	fixedTraceEngine().Decide(views, decisionTracePolicy(1, true))
	after, err := json.Marshal(views)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("trace generation mutated its input\nbefore=%s\nafter=%s", before, after)
	}
}

func TestDecisionTraceIsStableAcrossPodAndMapReordering(t *testing.T) {
	a := covView("a", true, 2*time.Hour, false)
	b := covView("b", true, 2*time.Hour, false)
	a.BlastRadius, b.BlastRadius = 0.9, 0.1 // avoid an optimizer tie; tracing must not alter selection
	a.Pod.Labels = map[string]string{"z": "3", "a": "1", "m": "2"}
	b.Pod.Labels = map[string]string{"m": "2", "z": "3", "a": "1"}

	forward := fixedTraceEngine().Decide([]*model.WorkloadView{a, b}, decisionTracePolicy(1, true))
	reverse := fixedTraceEngine().Decide([]*model.WorkloadView{b, a}, decisionTracePolicy(1, true))
	if !reflect.DeepEqual(traceByAsset(t, forward), traceByAsset(t, reverse)) {
		t.Fatalf("pod/map reordering changed normalized traces\nforward=%v\nreverse=%v", traceByAsset(t, forward), traceByAsset(t, reverse))
	}
}

func TestIrrelevantLabelDoesNotChangeTraceOrSelection(t *testing.T) {
	base := covView("labels", true, 2*time.Hour, false)
	base.Pod.Labels = map[string]string{"app": "api"}
	withLabel := covView("labels", true, 2*time.Hour, false)
	withLabel.Pod.Labels = map[string]string{"app": "api", "unrelated.example/test": "ignored"}

	left := fixedTraceEngine().Decide([]*model.WorkloadView{base}, decisionTracePolicy(1, true))
	right := fixedTraceEngine().Decide([]*model.WorkloadView{withLabel}, decisionTracePolicy(1, true))
	if !reflect.DeepEqual(decisionsWithoutTrace(left), decisionsWithoutTrace(right)) {
		t.Fatal("irrelevant label changed the selected decision")
	}
	if !reflect.DeepEqual(traceByAsset(t, left), traceByAsset(t, right)) {
		t.Fatal("irrelevant label changed normalized trace content")
	}
}

func TestDecisionTraceFactsCandidatesAndCoverKeysSerializeInStableOrder(t *testing.T) {
	view := covView("order", true, 2*time.Hour, false)
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))[0].Trace
	raw, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	var normalized model.DecisionTraceV2
	if err := json.Unmarshal(raw, &normalized); err != nil {
		t.Fatal(err)
	}
	if !sort.SliceIsSorted(normalized.Facts, func(i, j int) bool { return normalized.Facts[i].FactKey < normalized.Facts[j].FactKey }) {
		t.Fatalf("facts are not sorted: %+v", normalized.Facts)
	}
	for _, candidate := range normalized.Candidates {
		if !sort.StringsAreSorted(candidate.CoverKeys) {
			t.Fatalf("cover keys are not sorted: %+v", candidate)
		}
		if candidate.NetGain.Present {
			want := candidate.MarginalCoverage.Value*candidate.Provenance.Value - candidate.LambdaContribution.Value
			if want != candidate.NetGain.Value {
				t.Fatalf("candidate gain does not reconstruct: %+v", candidate)
			}
		}
	}
}
