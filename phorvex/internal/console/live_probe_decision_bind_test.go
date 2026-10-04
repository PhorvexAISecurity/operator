package console

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
)

// The live audit grows ~35 MB/min, so a decision re-read from the 16 MiB tail at finalize time is
// already gone. A Voice worker must bind the decision's evidence from the exact row it matched.
func TestVoiceMemoryWaitBindsDecisionAtMatchTime(t *testing.T) {
	s, record, snap, _, _ := voiceMemoryWaitFixture(t)
	decision, err := s.waitVoiceMemoryDecisionWithTiming(context.Background(), record, snap, "event-uid", 50*time.Millisecond, 5*time.Millisecond)
	if err != nil || !decision.Selected {
		t.Fatalf("fixture decision not selected: %+v err=%v", decision, err)
	}
	if record.DecisionEvidence == nil || record.DecisionEvidence.Correlation != "exact-decision-id" ||
		record.DecisionEvidence.DecisionID != decision.DecisionID || record.DecisionEvidence.Action != decision.Action {
		t.Fatalf("matched decision row was not bound to the attack record: %+v", record.DecisionEvidence)
	}
	if len(record.DecisionTraceEvidence) != 1 {
		t.Fatalf("decision trace evidence = %d", len(record.DecisionTraceEvidence))
	}
}

// LiteLLM binds from the exact verified audit interval the availability close read; the matched
// rows must keep the complete record of each selected decision and prefer its actuated row.
func TestAvailabilityMatchedRecordsKeepsSelectedRows(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	selected := caseTraceValidTrace(now, true, false)
	other := caseTraceValidTrace(now, true, false)
	other.DecisionID = "decision-other"
	rows := []audit.Record{
		{Kind: "phorvex.decision", Time: now, Namespace: "litellm", Action: "rotate", Selected: true, Reason: "selected", DecisionTrace: selected},
		{Kind: "phorvex.decision", Time: now.Add(time.Second), Namespace: "litellm", Action: "rotate", Selected: true, Actuated: true, Reason: "actuated", DecisionTrace: selected},
		{Kind: "phorvex.decision", Time: now, Namespace: "litellm", Action: "rotate", Selected: true, Reason: "unrelated", DecisionTrace: other},
		{Kind: "phorvex.maintenance", Time: now, Namespace: "litellm"},
	}
	var raw []byte
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, append(b, '\n')...)
	}
	got := availabilityMatchedRecords(raw, []availabilityDecision{{DecisionID: selected.DecisionID, Selected: true}})
	rec, ok := got[selected.DecisionID]
	if !ok || !rec.Actuated || rec.Reason != "actuated" {
		t.Fatalf("selected decision row not kept (or actuated row not preferred): %+v ok=%v", rec, ok)
	}
	if _, ok := got["decision-other"]; ok || len(got) != 1 {
		t.Fatalf("unrequested decision kept: %v", got)
	}
	if none := availabilityMatchedRecords(raw, []availabilityDecision{{DecisionID: selected.DecisionID}}); len(none) != 0 {
		t.Fatalf("unselected target row must not bind: %v", none)
	}
}
