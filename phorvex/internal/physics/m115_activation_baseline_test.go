package physics

import (
	"github.com/phorvex/phorvex/internal/model"
	"testing"
)

// Runs unchanged on a52a3a5 (before activation) and the reviewed implementation.
func TestM115HistoricalUnapprovedClass(t *testing.T) {
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "m115-unapproved-fixture"}, Telemetry: model.Telemetry{InFlightMean: model.PresentSignal(15, "fixture"), CompletionRate: model.PresentSignal(5, "fixture"), MeanSojournSec: model.PresentSignal(1, "fixture")}}
	found := false
	for _, c := range Components(v) {
		if c.Name == "flow-littles-law" {
			found = true
			if c.Present {
				t.Fatalf("unapproved class contributes: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("flow component not recorded")
	}
}
