package decision

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestDecisionTraceActionVocabularyKeepsHistoricalRows(t *testing.T) {
	legacyActions, err := model.DecisionTraceActions("")
	if err != nil || len(legacyActions) != 15 {
		t.Fatalf("legacy action vocabulary: %d actions, error %v", len(legacyActions), err)
	}
	currentActions, err := model.DecisionTraceActions(model.DecisionActionVocabularyOutput16)
	if err != nil || len(currentActions) != 16 || !slices.Equal(currentActions, model.MutatingActions) {
		t.Fatalf("current action vocabulary differs from the emitted optimizer order: %v, error %v", currentActions, err)
	}
	if !slices.Equal(legacyActions, currentActions[:15]) || currentActions[15] != model.ActionSensitiveOutputPolicyActivate {
		t.Fatalf("historical vocabulary changed: %v", legacyActions)
	}
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{covView("vocab", true, 2*time.Hour, false)}, decisionTracePolicy(1, true))[0].Trace
	if trace == nil || trace.ActionVocabularyVersion != model.DecisionActionVocabularyOutput16 {
		t.Fatalf("new production trace lacks named action vocabulary: %+v", trace)
	}
	if err := trace.Validate(); err != nil {
		t.Fatalf("new trace invalid: %v", err)
	}
	currentJSON, err := json.Marshal(trace)
	if err != nil || !strings.Contains(string(currentJSON), `"actionVocabularyVersion":"v2-output16"`) {
		t.Fatalf("new trace did not serialize its vocabulary marker: %v, %s", err, currentJSON)
	}

	legacy := *trace
	legacy.ActionVocabularyVersion = ""
	legacy.ActionStatus = append([]model.DecisionActionStatusV3(nil), trace.ActionStatus[:15]...)
	if err := legacy.Validate(); err != nil {
		t.Fatalf("unmarked historical 15-row trace rejected: %v", err)
	}
	legacyJSON, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(legacyJSON), "actionVocabularyVersion") {
		t.Fatalf("historical trace gained a marker: %v, %s", err, legacyJSON)
	}
	var restored model.DecisionTraceV2
	if err := json.Unmarshal(legacyJSON, &restored); err != nil {
		t.Fatalf("historical trace JSON decode: %v", err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("historical trace JSON validation: %v", err)
	}
	emptyMarkerJSON := bytes.Replace(legacyJSON, []byte(`"schemaVersion":`), []byte(`"actionVocabularyVersion":"","schemaVersion":`), 1)
	if err := json.Unmarshal(emptyMarkerJSON, &restored); err != nil {
		t.Fatalf("empty legacy marker JSON decode: %v", err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("empty legacy marker must have the same 15-action meaning as omission: %v", err)
	}

	unknown := legacy
	unknown.ActionVocabularyVersion = "unknown"
	if err := unknown.Validate(); err == nil || !strings.Contains(err.Error(), "actionVocabularyVersion") {
		t.Fatalf("unknown vocabulary accepted: %v", err)
	}
	markedMissing := legacy
	markedMissing.ActionVocabularyVersion = model.DecisionActionVocabularyOutput16
	if err := markedMissing.Validate(); err == nil || !strings.Contains(err.Error(), "actionStatus carries 15 rows") {
		t.Fatalf("marked 16-action trace with 15 rows accepted: %v", err)
	}
	legacyExtra := *trace
	legacyExtra.ActionVocabularyVersion = ""
	if err := legacyExtra.Validate(); err == nil || !strings.Contains(err.Error(), "actionStatus carries 16 rows") {
		t.Fatalf("unmarked 16-action trace accepted: %v", err)
	}
	wrongOrder := legacy
	wrongOrder.ActionStatus = append([]model.DecisionActionStatusV3(nil), legacy.ActionStatus...)
	wrongOrder.ActionStatus[0], wrongOrder.ActionStatus[1] = wrongOrder.ActionStatus[1], wrongOrder.ActionStatus[0]
	if err := wrongOrder.Validate(); err == nil || !strings.Contains(err.Error(), "canonical order") {
		t.Fatalf("historical wrong-order rows accepted: %v", err)
	}
	legacySelectedNew := legacy
	legacySelectedNew.SelectedAction = string(model.ActionSensitiveOutputPolicyActivate)
	if err := legacySelectedNew.Validate(); err == nil || !strings.Contains(err.Error(), "outside actionVocabularyVersion") {
		t.Fatalf("new action selected under legacy vocabulary: %v", err)
	}
	legacyCandidateNew := legacy
	legacyCandidateNew.Candidates = append([]model.DecisionCandidateV2(nil), legacy.Candidates...)
	legacyCandidateNew.Candidates = append(legacyCandidateNew.Candidates, model.DecisionCandidateV2{
		CandidateKey:            legacy.AssetNamespace + "/" + legacy.AssetName + "|" + string(model.ActionSensitiveOutputPolicyActivate),
		Action:                  string(model.ActionSensitiveOutputPolicyActivate),
		ExistingExclusionReason: "test-only-excluded",
	})
	if err := legacyCandidateNew.Validate(); err == nil || !strings.Contains(err.Error(), "outside actionVocabularyVersion") {
		t.Fatalf("new action candidate under legacy vocabulary: %v", err)
	}
}
