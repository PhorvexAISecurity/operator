package wire

import (
	"encoding"
	"reflect"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Problems lists every field of the given values' types that CBOR would drop or
// could not restore: unexported fields, interfaces, functions and channels, and
// fields hidden from JSON without an explicit cbor tag. A service's tests call it
// with every type its messages carry.
func Problems(values ...any) []string {
	seen := map[reflect.Type]bool{}
	var problems []string
	for _, v := range values {
		problems = append(problems, wireProblems(reflect.TypeOf(v), reflect.TypeOf(v).String(), seen)...)
	}
	return problems
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
