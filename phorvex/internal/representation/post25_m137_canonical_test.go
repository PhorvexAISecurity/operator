package representation

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func frozenCanonical[T any](xs []T) []T {
	sort.Slice(xs, func(i, j int) bool {
		a, _ := json.Marshal(xs[i])
		b, _ := json.Marshal(xs[j])
		return string(a) < string(b)
	})
	out := make([]T, 0, len(xs))
	prev := ""
	for _, x := range xs {
		b, _ := json.Marshal(x)
		if string(b) != prev {
			out = append(out, x)
			prev = string(b)
		}
	}
	return out
}

func frozenFreeze(in model.RepresentationSnapshot) model.RepresentationSnapshot {
	weights := in.Weights.Values
	in.Weights.Values = nil
	b, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	var out model.RepresentationSnapshot
	if err = json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	out.Weights.Values = make(map[string]float64, len(weights))
	for k, v := range weights {
		out.Weights.Values[k] = v
	}
	return out
}

func TestPost25M137CanonicalPrecomputedKeysPreserveOrderAndDedup(t *testing.T) {
	scope := model.ProtectedScope{Tenant: "t", Asset: "a", Version: "v", Property: "p"}
	items := []model.RepresentationFact{
		{Key: "z", Scope: scope, Actionability: []string{"b", "a"}},
		{Key: "a", Scope: scope, Reason: "value,{quoted}:\\suffix"},
		{Key: "z", Scope: scope, Actionability: []string{"b", "a"}},
		{Key: "m", Scope: scope, Reason: "bad\xffvalue"},
	}
	want := frozenCanonical(append([]model.RepresentationFact(nil), items...))
	got := canonical(items)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical output changed\nwant=%#v\n got=%#v", want, got)
	}
	if items[0].Key != "z" || items[1].Key != "a" {
		t.Fatal("canonical mutated caller order")
	}
}

func TestPost25M137TypedFreezePreservesLegacyCopySemantics(t *testing.T) {
	s := fixture()
	s.Ref = "bad\xffref"
	s.Weights.Values["raw\xffkey"] = 4
	s.Weights.InvalidValues = map[string]string{"bad\xffkey": "bad\xffvalue"}
	s.Covers.Sets = [][]string{{"one", "two"}}
	s.Candidates.Sets = [][]string{{"three"}}
	s.Facts[0].Actionability = []string{"coverable-now", "other"}
	want := frozenFreeze(s)
	got := Freeze(s)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("freeze output changed\nwant=%#v\n got=%#v", want, got)
	}
	s.Claim.DetectorSet[0] = "changed"
	s.Facts[0].Actionability[0] = "changed"
	s.Weights.Values[Key("t", "fact")] = 99
	s.Weights.InvalidValues["bad\xffkey"] = "changed"
	s.Covers.Sets[0][0] = "changed"
	s.Candidates.Sets[0][0] = "changed"
	if !reflect.DeepEqual(got, want) {
		t.Fatal("typed freeze retained a nested alias")
	}
}
