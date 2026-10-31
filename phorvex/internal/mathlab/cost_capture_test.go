package mathlab

import (
	"bytes"
	"encoding/gob"
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

func TestOptionalCostCaptureFrozenAndLegacyReplayUnchanged(t *testing.T) {
	legacy, err := Decode(recordTick(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	inspected := Inspect(legacy)
	if inspected.EndpointCostEvidence != nil || !reflect.DeepEqual(inspected.EndpointCostMissing, []string{"endpoint_cost_evidence:not-recorded"}) {
		t.Fatal(inspected.EndpointCostMissing)
	}
	// Encode a structural pre-extension Inputs value: this proves absence at the
	// gob schema boundary, rather than merely encoding a new nil field.
	old := struct {
		SpecJSON []byte
		Policy   model.Policy
		Views    []*model.WorkloadView
		Engine   decision.OwnerState
	}{legacy.Inputs.SpecJSON, legacy.Inputs.Policy, legacy.Inputs.Views, legacy.Inputs.Engine}
	var stream bytes.Buffer
	enc := gob.NewEncoder(&stream)
	for _, v := range []any{old, legacy.Outcome, *legacy.Final} {
		if err := enc.Encode(v); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := assemble(legacy.Header, stream.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Inputs.EndpointCostEvidence != nil {
		t.Fatal("old file synthesized cost evidence")
	}
	results, err := Replay(decoded, ReplayOptions{Arms: []Arm{{ID: "baseline"}}})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != StatusOK || results[0].Baseline == nil || !results[0].Baseline.Reproduced {
		t.Fatalf("old replay changed: %+v", results)
	}

	ce := decision.NewCoverageEngine()
	pol, spec := fixturePolicy()
	sink := &memorySink{}
	rec, err := NewRecorder(Config{Policies: []string{"vllm/vllm-defense"}, GPUEnvelopeMax: cost.GPUEnvelopeMax()}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &model.ReplayCostEvidence{Schema: model.ReplayCostEvidenceSchema, EndpointLossStatus: "unavailable", Missing: []string{"endpoint-loss-intervals:not-recorded"}, ReplicaHistory: model.ReplicaHistorySnapshot{Entries: []model.ReplicaHistoryEntry{{ID: "move", Outcome: "right_censored", Censored: true}}}}
	capture := rec.Begin(ce, spec, fleet(), pol, time.Now(), evidence)
	evidence.Missing[0] = "changed"
	evidence.ReplicaHistory.Entries[0].ID = "changed"
	decisions, decideErr := ce.DecideChecked(fleet(), pol)
	capture.Decided(decisions, decideErr)
	capture.Finalize(decisions)
	capture.Close()
	if len(sink.items) != 1 {
		t.Fatal("capture missing")
	}
	raw, err = assemble(sink.items[0].Header, sink.items[0].Stream)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.Inputs.EndpointCostEvidence; got == nil || got.Missing[0] != "endpoint-loss-intervals:not-recorded" || got.ReplicaHistory.Entries[0].ID != "move" || !got.ReplicaHistory.Entries[0].Censored {
		t.Fatal(got)
	}
	inspection := Inspect(decoded)
	inspection.EndpointCostEvidence.ReplicaHistory.Entries[0].ID = "mutated inspector"
	inspection.EndpointCostMissing[0] = "mutated missing"
	if decoded.Inputs.EndpointCostEvidence.ReplicaHistory.Entries[0].ID != "move" || decoded.Inputs.EndpointCostEvidence.Missing[0] != "endpoint-loss-intervals:not-recorded" {
		t.Fatal("inspector aliases stored evidence")
	}
}
