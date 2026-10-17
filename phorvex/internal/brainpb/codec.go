package brainpb

import (
	"github.com/fxamacker/cbor/v2"
)

// Domain values travel as CBOR (RFC 8949). Unlike JSON it carries NaN and the
// infinities the decision inputs may hold; unlike gob it keeps an empty slice or
// map distinct from a nil one, so a decision serializes to the same audit JSON on
// either side of the wire. Times keep nanosecond precision. Field names follow the
// struct's `cbor` tag, else its `json` tag, else the Go name; a field hidden from
// JSON (`json:"-"`) needs an explicit `cbor` tag to cross the wire.
var (
	encMode = mustEncMode()
	decMode = mustDecMode()
)

func mustEncMode() cbor.EncMode {
	mode, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, Time: cbor.TimeRFC3339Nano}.EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}

func mustDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}

// Encode serializes one domain value for a bytes field (see brain.proto).
func Encode(v any) ([]byte, error) { return encMode.Marshal(v) }

// Decode deserializes a bytes field into v, which must be a pointer.
func Decode(raw []byte, v any) error { return decMode.Unmarshal(raw, v) }

// MaxMessageBytes bounds one brain service message. A Decide start carries every
// view of a tenant tick, which exceeds gRPC's 4 MiB default on large fleets.
const MaxMessageBytes = 64 << 20
