package brainpb_test

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/wire"
)

// wireTypes are the domain values brain.proto carries as CBOR.
var wireTypes = []any{
	[]*model.WorkloadView(nil),
	model.Policy{},
	brainapi.Capture{},
	brainapi.ParameterSet{},
	brainapi.RejectedTick{},
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
	if problems := wire.Problems(wireTypes...); len(problems) > 0 {
		t.Fatalf("types crossing the brain wire would not survive CBOR:\n  %s", strings.Join(problems, "\n  "))
	}
}
