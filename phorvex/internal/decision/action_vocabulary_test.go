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
	outputActions, err := model.DecisionTraceActions(model.DecisionActionVocabularyOutput16)
	if err != nil || len(outputActions) != 16 || outputActions[15] != model.ActionSensitiveOutputPolicyActivate {
		t.Fatalf("historical 16-action vocabulary changed: %v, error %v", outputActions, err)
	}
	voiceActions, err := model.DecisionTraceActions(model.DecisionActionVocabularyVoice17)
	if err != nil || len(voiceActions) != 17 || voiceActions[16] != model.ActionVoiceMemoryNoteRevoke || !slices.Equal(voiceActions[:16], outputActions) {
		t.Fatalf("historical Voice vocabulary changed: %v, error %v", voiceActions, err)
	}
	liteActions, err := model.DecisionTraceActions(model.DecisionActionVocabularyLiteLLM17)
	if err != nil || len(liteActions) != 17 || liteActions[16] != model.ActionLiteLLMClientRevoke || !slices.Equal(liteActions[:16], outputActions) {
		t.Fatalf("historical LiteLLM vocabulary changed: %v, error %v", liteActions, err)
	}
	priorActions, err := model.DecisionTraceActions(model.DecisionActionVocabularyLive18)
	if err != nil || len(priorActions) != 18 || !slices.Equal(priorActions[:16], outputActions) ||
		priorActions[16] != model.ActionVoiceMemoryNoteRevoke || priorActions[17] != model.ActionLiteLLMClientRevoke {
		t.Fatalf("historical combined vocabulary changed: %v, error %v", priorActions, err)
	}
	refundActions, err := model.DecisionTraceActions(model.DecisionActionVocabularyLive19)
	if err != nil || len(refundActions) != 19 || !slices.Equal(refundActions[:18], priorActions) || refundActions[18] != model.ActionVoiceRefundPairDeny {
		t.Fatalf("historical refund action vocabulary changed: %v, error %v", refundActions, err)
	}
	outputPolicyActions, err := model.DecisionTraceActions(model.DecisionActionVocabularyLive20)
	if err != nil || len(outputPolicyActions) != 20 ||
		!slices.Equal(outputPolicyActions[:19], refundActions) || outputPolicyActions[19] != model.ActionVoiceOutputPolicyActivate {
		t.Fatalf("historical output-policy vocabulary changed: %v, error %v", outputPolicyActions, err)
	}
	currentActions, err := model.DecisionTraceActions(model.DecisionActionVocabularyLive21)
	if err != nil || len(currentActions) != 21 || !slices.Equal(currentActions, model.MutatingActions) ||
		!slices.Equal(currentActions[:20], outputPolicyActions) || currentActions[20] != model.ActionVoiceMCPToolPin {
		t.Fatalf("combined current action vocabulary differs from the emitted optimizer order: %v, error %v", currentActions, err)
	}
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{covView("vocab", true, 2*time.Hour, false)}, decisionTracePolicy(1, true))[0].Trace
	if trace == nil || trace.ActionVocabularyVersion != model.DecisionActionVocabularyLive21 {
		t.Fatalf("new production trace lacks named action vocabulary: %+v", trace)
	}
	if err := trace.Validate(); err != nil {
		t.Fatalf("new trace invalid: %v", err)
	}
	currentJSON, err := json.Marshal(trace)
	if err != nil || !strings.Contains(string(currentJSON), `"actionVocabularyVersion":"v7-live21"`) {
		t.Fatalf("new trace did not serialize its vocabulary marker: %v, %s", err, currentJSON)
	}
	output := *trace
	output.ActionVocabularyVersion = model.DecisionActionVocabularyOutput16
	output.ActionStatus = append([]model.DecisionActionStatusV3(nil), trace.ActionStatus[:16]...)
	if err := output.Validate(); err != nil {
		t.Fatalf("historical 16-row trace rejected: %v", err)
	}
	voiceHistorical := *trace
	voiceHistorical.ActionVocabularyVersion = model.DecisionActionVocabularyVoice17
	voiceHistorical.ActionStatus = append([]model.DecisionActionStatusV3(nil), trace.ActionStatus[:17]...)
	if err := voiceHistorical.Validate(); err != nil {
		t.Fatalf("historical Voice17 trace rejected: %v", err)
	}
	liteHistorical := *trace
	liteHistorical.ActionVocabularyVersion = model.DecisionActionVocabularyLiteLLM17
	liteHistorical.ActionStatus = append(append([]model.DecisionActionStatusV3(nil), trace.ActionStatus[:16]...), trace.ActionStatus[17])
	if err := liteHistorical.Validate(); err != nil {
		t.Fatalf("historical LiteLLM17 trace rejected: %v", err)
	}
	outputPolicyHistorical := *trace
	outputPolicyHistorical.ActionVocabularyVersion = model.DecisionActionVocabularyLive20
	outputPolicyHistorical.ActionStatus = append([]model.DecisionActionStatusV3(nil), trace.ActionStatus[:20]...)
	if err := outputPolicyHistorical.Validate(); err != nil {
		t.Fatalf("historical Live20 trace rejected: %v", err)
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
	if err := legacyExtra.Validate(); err == nil || !strings.Contains(err.Error(), "actionStatus carries 21 rows") {
		t.Fatalf("unmarked 21-action trace accepted: %v", err)
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
