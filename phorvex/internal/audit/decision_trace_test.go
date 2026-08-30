package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestAuditRecordCarriesVersionedDecisionTrace(t *testing.T) {
	trace := &model.DecisionTraceV2{
		SchemaVersion: model.DecisionTraceSchemaV2,
		DecisionID: "decision", TickID: "tick", Timestamp: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
		BrainImage: "registry/phorvex:sha-test", GitSHA: "abcdef", DecisionEngine: "p1-coverage",
		PolicyUID: "policy-uid", AssetUID: "pod-uid", SelectedAction: string(model.ActionNoop),
		TieBreakReason: "notApplicable", NoopReason: "priced-out",
	}
	record := ToRecord(model.Decision{Action: model.ActionNoop, Trace: trace})
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	nested, ok := fields["decisionTrace"]
	if !ok {
		t.Fatalf("audit record omitted decisionTrace: %s", raw)
	}
	var decoded model.DecisionTraceV2
	if err := json.Unmarshal(nested, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != model.DecisionTraceSchemaV2 || decoded.DecisionID != "decision" {
		t.Fatalf("nested trace changed on audit serialization: %+v", decoded)
	}
}
