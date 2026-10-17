package brainpb_test

import (
	"encoding"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/brainpb"
	"github.com/phorvex/phorvex/internal/model"
)

// wireTypes are the domain values brain.proto carries as CBOR.
var wireTypes = []any{
	[]*model.WorkloadView(nil),
	model.Policy{},
	brainapi.Capture{},
	[]model.Decision(nil),
	model.Alternative{},
	[]model.PolicyEpoch(nil),
	model.PersistenceObservation{},
	model.PersistenceOperationBinding{},
	model.PersistenceObservationResult{},
}

// TestWireTypesRoundTripStructurally fails on any field CBOR would drop or could
// not restore: unexported fields, interfaces, functions and channels, and fields
// hidden from JSON without an explicit cbor tag.
func TestWireTypesRoundTripStructurally(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var problems []string
	for _, v := range wireTypes {
		problems = append(problems, wireProblems(reflect.TypeOf(v), reflect.TypeOf(v).String(), seen)...)
	}
	if len(problems) > 0 {
		t.Fatalf("types crossing the brain wire would not survive CBOR:\n  %s", strings.Join(problems, "\n  "))
	}
}

var (
	cborMarshaler   = reflect.TypeOf((*cbor.Marshaler)(nil)).Elem()
	cborUnmarshaler = reflect.TypeOf((*cbor.Unmarshaler)(nil)).Elem()
	binMarshaler    = reflect.TypeOf((*encoding.BinaryMarshaler)(nil)).Elem()
	binUnmarshaler  = reflect.TypeOf((*encoding.BinaryUnmarshaler)(nil)).Elem()
	timeType        = reflect.TypeOf(time.Time{})
)

// codesItself reports whether CBOR encodes t through its own methods.
func codesItself(t reflect.Type) bool {
	p := reflect.PointerTo(t)
	return t == timeType ||
		(t.Implements(cborMarshaler) || p.Implements(cborMarshaler)) && p.Implements(cborUnmarshaler) ||
		(t.Implements(binMarshaler) || p.Implements(binMarshaler)) && p.Implements(binUnmarshaler)
}

func wireProblems(t reflect.Type, path string, seen map[reflect.Type]bool) []string {
	if seen[t] {
		return nil
	}
	seen[t] = true
	if codesItself(t) {
		return nil
	}
	switch t.Kind() {
	case reflect.Func, reflect.Chan, reflect.UnsafePointer, reflect.Interface:
		return []string{path + ": " + t.Kind().String() + " cannot cross the wire"}
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return wireProblems(t.Elem(), path+"[]", seen)
	case reflect.Map:
		return append(wireProblems(t.Key(), path+"{key}", seen), wireProblems(t.Elem(), path+"{}", seen)...)
	case reflect.Struct:
		var out []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fieldPath := t.String() + "." + f.Name
			switch {
			case !f.IsExported() && !f.Anonymous:
				out = append(out, fieldPath+": unexported field is dropped")
				continue
			case f.Tag.Get("json") == "-" && f.Tag.Get("cbor") == "":
				out = append(out, fieldPath+`: json:"-" field needs a cbor tag`)
				continue
			case f.Tag.Get("cbor") == "-":
				out = append(out, fieldPath+": cbor:\"-\" field is dropped")
				continue
			}
			out = append(out, wireProblems(f.Type, fieldPath, seen)...)
		}
		return out
	}
	return nil
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
	raw, err := brainpb.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out sample
	if err := brainpb.Decode(raw, &out); err != nil {
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
	raw, err := brainpb.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out model.VoiceMemoryObservation
	if err := brainpb.Decode(raw, &out); err != nil {
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
	first, err := brainpb.Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := brainpb.Encode(in)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("map encoding is not deterministic")
		}
	}
}
