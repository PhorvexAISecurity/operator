package decision

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/physics"
)

func TestM115RecordPresenceRoundTrip(t *testing.T) {
	prev := physics.ActivatedFlowClasses()
	t.Cleanup(func() { physics.ConfigureFlowActivation(prev) })
	records := map[string]audit.Record{}
	for _, tc := range []struct {
		name    string
		active  bool
		L       float64
		present bool
		r       float64
	}{
		{"absent", false, 15, false, 0}, {"measured-zero", true, 5, true, 0}, {"nonzero", true, 15, true, 0.5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			physics.ConfigureFlowActivation(nil)
			if tc.active {
				physics.ConfigureFlowActivation([]string{"ns"})
			}
			v := covView("pod", true, 2*time.Hour, false)
			v.Telemetry = model.Telemetry{InFlightMean: model.PresentSignal(tc.L, "fixture"), CompletionRate: model.PresentSignal(5, "fixture"), MeanSojournSec: model.PresentSignal(1, "fixture")}
			record := flowRecord(v)
			wire := audit.ToRecord(model.Decision{Trace: &model.DecisionTraceV2{
				Inputs: model.DecisionModelInputsV2{Flow: record},
			}})
			encoded, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			var decoded audit.Record
			if err = json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.DecisionTrace == nil {
				t.Fatal("audit serializer dropped the trace")
			}
			got := decoded.DecisionTrace.Inputs.Flow
			if got.Present != tc.present || got.Residual.Present != tc.present || got.Residual.Value != tc.r || got.Aggregate.Present != tc.present {
				t.Fatalf("%s", encoded)
			}
			if !tc.present && got.Reason != physics.FlowReasonNotActivated {
				t.Fatalf("missing absence reason: %s", encoded)
			}
			records[tc.name] = decoded
		})
	}
	if path := os.Getenv("M115_RECORD_OUTPUT"); path != "" {
		b, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestM115InactiveInputsDoNotChangeDecisions(t *testing.T) {
	prev := physics.ActivatedFlowClasses()
	t.Cleanup(func() { physics.ConfigureFlowActivation(prev) })
	physics.ConfigureFlowActivation(nil)
	pol := covPolicy(2)
	pol.TraceEnabled = true
	run := func(withRaw bool) []byte {
		e := NewCoverageEngine()
		e.Now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
		v := covView("served", true, 2*time.Hour, false)
		if withRaw {
			v.Telemetry.InFlightMean = model.PresentSignal(150, "fixture")
			v.Telemetry.CompletionRate = model.PresentSignal(5, "fixture")
			v.Telemetry.MeanSojournSec = model.PresentSignal(1, "fixture")
		}
		ds := e.Decide([]*model.WorkloadView{v}, pol)
		if len(ds) == 0 {
			t.Fatal("empty replay")
		}
		b, err := json.Marshal(ds)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, b := run(false), run(true)
	if string(a) != string(b) {
		t.Fatalf("unactivated Little inputs changed decision/fact/trace: %s vs %s", a, b)
	}
}
