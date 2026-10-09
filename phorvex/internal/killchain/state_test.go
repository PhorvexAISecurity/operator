package killchain

import (
	"math"
	"reflect"
	"testing"
)

func TestStageClockOwnerEntriesRoundTrip(t *testing.T) {
	src := NewStageClock()
	src.Observe("o1", "vllm", "a", "u1", StageRecon, 40)
	src.Observe("o1", "vllm", "a", "u1", StageExploit, 90) // transition: entry=90
	src.Observe("o1", "vllm", "b", "u2", StageRecon, 15)
	src.Observe("o2", "vllm", "c", "u3", StageRecon, 5)

	entries := src.OwnerEntries("o1")
	if len(entries) != 2 || entries[0].Name != "a" || entries[0].Stage != StageExploit || entries[0].EntryExpSec != 90 {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	dst := NewStageClock()
	if err := dst.RestoreOwnerEntries("o1", entries); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dst.OwnerEntries("o1"), entries) {
		t.Fatal("restored entries differ")
	}
	if len(dst.OwnerEntries("o2")) != 0 {
		t.Fatal("restore leaked another owner")
	}
	for _, tc := range []struct {
		name  string
		uid   string
		stage Stage
		exp   float64
	}{{"a", "u1", StageExploit, 130}, {"a", "u1", StagePersist, 130}, {"b", "u2", StageRecon, 60}, {"b", "u9", StageRecon, 60}} {
		if got, want := dst.Peek("o1", "vllm", tc.name, tc.uid, tc.stage, tc.exp), src.Peek("o1", "vllm", tc.name, tc.uid, tc.stage, tc.exp); got != want {
			t.Fatalf("%+v: dwell %v != %v", tc, got, want)
		}
	}
	if err := dst.RestoreOwnerEntries("o1", entries); err == nil {
		t.Fatal("restore overwrote existing owner state")
	}
	if err := NewStageClock().RestoreOwnerEntries("o1", []StageClockEntry{{Namespace: "n", Name: "x", EntryExpSec: math.NaN()}}); err == nil {
		t.Fatal("nan entry accepted")
	}
}

func TestConjugateOwnerStateRoundTripDoesNotSeed(t *testing.T) {
	src := NewConjugateMemory()
	if st := src.OwnerState("o1"); st.Tracked {
		t.Fatal("untracked owner reported tracked")
	}
	if src.Tracked("o1") {
		t.Fatal("OwnerState seeded an untracked owner")
	}
	src.Observe("o1", 0.7)
	st := src.OwnerState("o1")
	dst, err := RestoreConjugateMemory("o1", st)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dst.OwnerState("o1"), st) {
		t.Fatal("restored conjugate state differs")
	}
	a1, b1 := src.PriorPeek("o1")
	a2, b2 := dst.PriorPeek("o1")
	if a1 != a2 || b1 != b2 {
		t.Fatalf("prior (%v,%v) != (%v,%v)", a2, b2, a1, b1)
	}
	if dst.Tracked("other") {
		t.Fatal("restore created another owner")
	}
	bad := st
	bad.Alpha = math.Inf(1)
	if _, err := RestoreConjugateMemory("o1", bad); err == nil {
		t.Fatal("infinite prior accepted")
	}
}
