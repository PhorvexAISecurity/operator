package wire_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/wire"
)

func TestProblemsFindsWhatCBORCannotCarry(t *testing.T) {
	type hidden struct {
		Visible  string
		internal string //nolint:unused // the field under test
		Hook     func()
		Any      any
		Secret   string `json:"-"`
		Carried  string `json:"-" cbor:"Carried"`
		At       time.Time
		Children []struct{ Ch chan int }
	}
	got := strings.Join(wire.Problems(hidden{}), "\n")
	for _, want := range []string{"hidden.internal: unexported", "hidden.Hook: func", "hidden.Any: interface",
		`hidden.Secret: json:"-" field needs a cbor tag`, "Ch: chan"} {
		if !strings.Contains(got, want) {
			t.Errorf("problems miss %q:\n%s", want, got)
		}
	}
	for _, clean := range []string{"Visible", "Carried", "hidden.At"} {
		if strings.Contains(got, clean) {
			t.Errorf("problems wrongly flag %s:\n%s", clean, got)
		}
	}
}

func TestCodecKeepsWhatJSONAndGobLose(t *testing.T) {
	type sample struct {
		NaN, Inf float64
		Empty    []string
		Nil      []string
		EmptyMap map[string]int
		At       time.Time
	}
	in := sample{NaN: math.NaN(), Inf: math.Inf(-1), Empty: []string{}, EmptyMap: map[string]int{},
		At: time.Date(2026, 10, 17, 1, 2, 3, 456789123, time.UTC)}
	raw, err := wire.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out sample
	if err := wire.Decode(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !math.IsNaN(out.NaN) || !math.IsInf(out.Inf, -1) {
		t.Fatalf("non-finite floats changed: %v %v", out.NaN, out.Inf)
	}
	if out.Empty == nil || out.Nil != nil || out.EmptyMap == nil {
		t.Fatalf("empty and nil collections must stay distinct: %#v", out)
	}
	if !out.At.Equal(in.At) {
		t.Fatalf("time precision lost: %v != %v", out.At, in.At)
	}
}

func TestCodecCarriesFieldsHiddenFromJSON(t *testing.T) {
	in := model.VoiceMemoryObservation{CallerID: "caller-7"}
	raw, err := wire.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out model.VoiceMemoryObservation
	if err := wire.Decode(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.CallerID != "caller-7" {
		t.Fatalf("CallerID lost on the wire: %q", out.CallerID)
	}
	audit, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), "caller-7") {
		t.Fatalf("CallerID must stay out of decision evidence JSON: %s", audit)
	}
}

func TestCodecIsDeterministic(t *testing.T) {
	in := map[string]int{"b": 2, "a": 1, "c": 3}
	first, err := wire.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := wire.Encode(in)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("map encoding is not deterministic")
		}
	}
}
