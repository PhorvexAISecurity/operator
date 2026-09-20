package decision

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type coveringActionsRecon struct {
	facts []recon.Fact
	cover map[model.Action][]string
}

func (*coveringActionsRecon) Name() string { return "covering-actions-differential" }

func (r *coveringActionsRecon) AssetFacts(_ *model.WorkloadView, _ recon.FactContext) recon.AssetFacts {
	return recon.AssetFacts{Facts: r.facts, CoverByAction: r.cover}
}

func coveringActionsFixture(reverseInsertion bool) *coveringActionsRecon {
	asset := "ns/covering"
	fact := func(kind string, weight float64) recon.Fact {
		return recon.Fact{Scope: recon.ScopePod, Asset: asset, Kind: kind, Weight: weight}
	}
	shared := fact("shared", 4)
	rotateOnly := fact("rotate-only", 3)
	unsupported := fact("unsupported", 2)
	disabled := fact("disabled", 1)
	zero := fact("zero-weight", 0)
	uncovered := fact("uncovered", 9)

	entries := []struct {
		action model.Action
		keys   []string
	}{
		{model.ActionRotate, []string{shared.Key(), shared.Key(), rotateOnly.Key(), zero.Key()}},
		{model.ActionQuarantine, []string{shared.Key()}},
		{model.ActionIdentityRotate, []string{shared.Key(), unsupported.Key()}},
		{model.ActionKVReset, []string{shared.Key(), disabled.Key(), disabled.Key()}},
	}
	cover := make(map[model.Action][]string, len(entries))
	if reverseInsertion {
		for i := len(entries) - 1; i >= 0; i-- {
			cover[entries[i].action] = append([]string(nil), entries[i].keys...)
		}
	} else {
		for _, entry := range entries {
			cover[entry.action] = append([]string(nil), entry.keys...)
		}
	}
	return &coveringActionsRecon{
		facts: []recon.Fact{shared, shared, zero, uncovered, disabled, rotateOnly, unsupported},
		cover: cover,
	}
}

func legacyCoveringActions(cover map[model.Action][]string, factKey string) []string {
	var out []string
	for _, action := range model.MutatingActions {
		for _, key := range cover[action] {
			if key == factKey {
				out = append(out, string(action))
				break
			}
		}
	}
	return out
}

func runCoveringActionsProducer(t testing.TB, profile *coveringActionsRecon, traceEnabled bool) []model.Decision {
	t.Helper()
	engine := fixedTraceEngine()
	engine.Recon = profile
	policy := decisionTracePolicy(1, traceEnabled)
	policy.EnabledActions = map[model.Action]bool{
		model.ActionRotate:     true,
		model.ActionQuarantine: true,
	}
	view := covView("covering", true, 2*time.Hour, false)
	decisions, err := engine.DecideChecked([]*model.WorkloadView{view}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 {
		t.Fatalf("got %d decisions, want one", len(decisions))
	}
	return decisions
}

func TestCoveringActionsIndexMatchesOriginalFullProducer(t *testing.T) {
	profile := coveringActionsFixture(false)
	withTrace := runCoveringActionsProducer(t, profile, true)
	withoutTrace := runCoveringActionsProducer(t, coveringActionsFixture(false), false)
	if !reflect.DeepEqual(withoutTrace, decisionsWithoutTrace(withTrace)) {
		t.Fatalf("trace production changed the real decision\nwithout=%+v\nwith=%+v", withoutTrace, decisionsWithoutTrace(withTrace))
	}
	trace := withTrace[0].Trace
	if trace == nil || !withTrace[0].Selected {
		t.Fatalf("real DecideChecked positive path did not select or trace: %+v", withTrace[0])
	}

	seen := map[string]int{}
	for _, row := range trace.Facts {
		seen[row.FactKey]++
		want := legacyCoveringActions(profile.cover, row.FactKey)
		if !reflect.DeepEqual(row.CoveringActions, want) {
			t.Fatalf("fact %q covering actions = %v, original producer wants %v", row.FactKey, row.CoveringActions, want)
		}
	}
	sharedKey := profile.facts[0].Key()
	if seen[sharedKey] != 2 {
		t.Fatalf("duplicate fact rows were not preserved: %v", seen)
	}
	if seen[profile.facts[2].Key()] != 0 || seen[profile.facts[3].Key()] != 0 {
		t.Fatalf("zero-weight or uncovered facts escaped the weighted domain: %v", seen)
	}
	wantShared := []string{string(model.ActionRotate), string(model.ActionQuarantine), string(model.ActionIdentityRotate), string(model.ActionKVReset)}
	if got := legacyCoveringActions(profile.cover, sharedKey); !reflect.DeepEqual(got, wantShared) {
		t.Fatalf("fixture lost canonical disabled/unsupported action ordering: got %v want %v", got, wantShared)
	}

	actualWire, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	var original model.DecisionTraceV2
	if err := json.Unmarshal(actualWire, &original); err != nil {
		t.Fatal(err)
	}
	for i := range original.Facts {
		original.Facts[i].CoveringActions = legacyCoveringActions(profile.cover, original.Facts[i].FactKey)
	}
	originalWire, err := json.Marshal(&original)
	if err != nil {
		t.Fatal(err)
	}
	if string(actualWire) != string(originalWire) {
		t.Fatal("indexed trace wire differs from the original covering-actions producer")
	}
}

func TestCoveringActionsIndexOwnershipAndMapOrder(t *testing.T) {
	forwardProfile := coveringActionsFixture(false)
	forward := runCoveringActionsProducer(t, forwardProfile, true)[0].Trace
	reverse := runCoveringActionsProducer(t, coveringActionsFixture(true), true)[0].Trace
	forwardWire, err := json.Marshal(forward)
	if err != nil {
		t.Fatal(err)
	}
	reverseWire, err := json.Marshal(reverse)
	if err != nil {
		t.Fatal(err)
	}
	if string(forwardWire) != string(reverseWire) {
		t.Fatal("cover-map insertion order changed the trace")
	}

	sharedKey := forwardProfile.facts[0].Key()
	var duplicateRows []int
	for i := range forward.Facts {
		if forward.Facts[i].FactKey == sharedKey {
			duplicateRows = append(duplicateRows, i)
		}
	}
	if len(duplicateRows) != 2 {
		t.Fatalf("got duplicate row indexes %v", duplicateRows)
	}
	first, second := duplicateRows[0], duplicateRows[1]
	originalSecond := append([]string(nil), forward.Facts[second].CoveringActions...)
	originalSource := append([]string(nil), forwardProfile.cover[model.ActionRotate]...)
	forward.Facts[first].CoveringActions[0] = "mutated-output"
	if !reflect.DeepEqual(forward.Facts[second].CoveringActions, originalSecond) {
		t.Fatal("duplicate output facts share a covering-actions slice")
	}
	if !reflect.DeepEqual(forwardProfile.cover[model.ActionRotate], originalSource) {
		t.Fatal("mutating an output fact changed the source cover map")
	}
	forwardProfile.cover[model.ActionRotate][0] = "mutated-source"
	if !reflect.DeepEqual(forward.Facts[second].CoveringActions, originalSecond) {
		t.Fatal("mutating the source cover map changed an existing output fact")
	}

	if got := newCoveringActionIndex(model.MutatingActions, nil).actionsFor("absent"); got != nil {
		t.Fatalf("nil cover did not preserve a nil output slice: %#v", got)
	}
	if decisions := runCoveringActionsProducer(t, &coveringActionsRecon{}, true); len(decisions) != 1 || decisions[0].Trace == nil || len(decisions[0].Trace.Facts) != 0 {
		t.Fatalf("empty fact/cover input changed producer behavior: %+v", decisions)
	}
	if decisions, err := fixedTraceEngine().DecideChecked(nil, decisionTracePolicy(1, true)); err != nil || len(decisions) != 0 {
		t.Fatalf("empty asset input = (%+v, %v), want empty success", decisions, err)
	}
}

func TestCoveringActionIndexDuplicatePositionsAndWideFallback(t *testing.T) {
	const key = "pod|ns/p|fact"
	duplicateActions := []model.Action{model.ActionRotate, model.ActionRotate}
	duplicate := newCoveringActionIndex(duplicateActions, map[model.Action][]string{model.ActionRotate: {key, key}})
	if got, want := duplicate.actionsFor(key), []string{string(model.ActionRotate), string(model.ActionRotate)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("duplicate canonical action positions = %v, want %v", got, want)
	}

	actions := make([]model.Action, 65)
	cover := make(map[model.Action][]string, len(actions))
	want := make([]string, len(actions))
	for i := range actions {
		actions[i] = model.Action(fmt.Sprintf("future-action-%02d", i))
		want[i] = string(actions[i])
		cover[actions[i]] = []string{key, key}
	}
	wide := newCoveringActionIndex(actions, cover)
	actions[0] = "mutated-source-action"
	cover[model.Action("future-action-00")][0] = "mutated-source-key"
	if got := wide.actionsFor(key); !reflect.DeepEqual(got, want) {
		t.Fatalf("wide action index = %v, want all 65 ordered positions", got)
	}
	first := wide.actionsFor(key)
	second := wide.actionsFor(key)
	first[0] = "mutated-output"
	if !reflect.DeepEqual(second, want) {
		t.Fatal("wide fallback outputs share storage")
	}
}

var coveringActionsBenchmarkSink [][]string

func benchmarkCoveringFixture(facts int) (map[model.Action][]string, []string) {
	keys := make([]string, facts)
	for i := range keys {
		keys[i] = fmt.Sprintf("pod|ns/p-%d|fact", i)
	}
	cover := make(map[model.Action][]string)
	for actionIndex, action := range model.MutatingActions {
		for i, key := range keys {
			if (i+actionIndex)%3 == 0 {
				cover[action] = append(cover[action], key)
				if i%17 == 0 {
					cover[action] = append(cover[action], key)
				}
			}
		}
	}
	return cover, keys
}

func BenchmarkCoveringActionsConstruction(b *testing.B) {
	for _, facts := range []int{32, 1000} {
		cover, keys := benchmarkCoveringFixture(facts)
		b.Run(fmt.Sprintf("facts=%d/original", facts), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				out := make([][]string, len(keys))
				for j, key := range keys {
					out[j] = legacyCoveringActions(cover, key)
				}
				coveringActionsBenchmarkSink = out
			}
		})
		b.Run(fmt.Sprintf("facts=%d/indexed", facts), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				index := newCoveringActionIndex(model.MutatingActions, cover)
				out := make([][]string, len(keys))
				for j, key := range keys {
					out[j] = index.actionsFor(key)
				}
				coveringActionsBenchmarkSink = out
			}
		})
	}
}
