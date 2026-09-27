package console

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voicememorypolicy"
)

func TestVoiceMemoryRecoveryRequiresExactSelectionAndAppend(t *testing.T) {
	const depUID = "11111111-1111-4111-8111-111111111111"
	const policyUID = "22222222-2222-4222-8222-222222222222"
	const cmUID = "33333333-3333-4333-8333-333333333333"
	const caller = "+15551234567"
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const eventUID = "44444444-4444-4444-8444-444444444444"
	before := voiceMemorySnapshot{DeploymentUID: depUID, PolicyUID: policyUID, PolicyGeneration: 4, ConfigMapUID: cmUID,
		Rule: voicememorypolicy.Rule{Version: 1, DeploymentUID: depUID, PolicyUID: policyUID,
			SourceSHA256: voiceMemorySourceSHA256, Entries: []voicememorypolicy.Entry{}}}
	selected := voiceMemoryDecision{Action: string(model.ActionVoiceMemoryNoteRevoke), DecisionID: "decision-7", TickID: "tick-7", Selected: true, Actuated: true}
	op := voiceMemoryOperationID(policyUID, depUID, eventUID, selected.TickID, selected.DecisionID)
	after := before
	var err error
	after.Rule, err = voicememorypolicy.Append(before.Rule, voicememorypolicy.Entry{CallerID: caller, NoteSHA256: digest}, op)
	if err != nil || !voiceMemoryExactActuation(selected, before, after, eventUID, caller, digest) {
		t.Fatalf("exact recovery failed: %v", err)
	}
	if voiceMemoryExactActuation(selected, before, after, "wrong-event", caller, digest) {
		t.Fatal("wrong event credited")
	}
	wronge := after
	wronge.ConfigMapUID = "55555555-5555-4555-8555-555555555555"
	if voiceMemoryExactActuation(selected, before, wronge, eventUID, caller, digest) {
		t.Fatal("replacement ConfigMap credited")
	}
	wronge = after
	wronge.Rule.Entries = append([]voicememorypolicy.Entry(nil), after.Rule.Entries...)
	wronge.Rule.Entries[0].OperationID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if voiceMemoryExactActuation(selected, before, wronge, eventUID, caller, digest) {
		t.Fatal("entry from another operation credited")
	}
	wronge = after
	wronge.Rule.Revision++
	if voiceMemoryExactActuation(selected, before, wronge, eventUID, caller, digest) {
		t.Fatal("superseding revision credited")
	}
	wronge = after
	wronge.PolicyGeneration++
	if voiceMemoryExactActuation(selected, before, wronge, eventUID, caller, digest) {
		t.Fatal("changed policy generation credited")
	}
}

func TestVoiceMemoryMaintenanceDoesNotCreditWrongRecovery(t *testing.T) {
	now := time.Now().UTC()
	const depUID = "11111111-1111-4111-8111-111111111111"
	const policyUID = "22222222-2222-4222-8222-222222222222"
	record := &attackRecord{Pod: "voice-bot-1", TargetUID: "pod-uid", ObservationEnd: now.Add(2 * time.Minute).Format(time.RFC3339Nano)}
	snap := voiceMemorySnapshot{DeploymentUID: depUID, PolicyUID: policyUID,
		Rule: voicememorypolicy.Rule{Revision: 1}}
	selected := voiceMemoryDecision{DecisionID: "decision-7", TickID: "tick-7", Selected: true, SelectedAt: now}
	row := voiceMemoryMaintenance{SchemaVersion: audit.SchemaVersionCurrent, Kind: "phorvex.maintenance", Time: now.Add(time.Second),
		Receipt: voiceMemoryJournalName(depUID, 2), Operation: string(model.ActionVoiceMemoryNoteRevoke),
		Namespace: "voice", Policy: voiceMemoryPolicyName, PolicyUID: policyUID, TargetName: record.Pod, TargetUID: record.TargetUID,
		Outcome: "confirmed", Effect: "Voice memory rule confirmed on current serving Pods"}
	if !voiceMemoryMaintenanceMatches(row, record, snap, selected) {
		t.Fatal("exact maintenance row refused")
	}
	wrong := row
	wrong.Receipt = voiceMemoryJournalName(depUID, 3)
	if voiceMemoryMaintenanceMatches(wrong, record, snap, selected) {
		t.Fatal("other revision credited")
	}
	wrong = row
	wrong.PolicyUID = "other-policy"
	if voiceMemoryMaintenanceMatches(wrong, record, snap, selected) {
		t.Fatal("other policy credited")
	}
	wrong = row
	wrong.TargetUID = "other-pod"
	if voiceMemoryMaintenanceMatches(wrong, record, snap, selected) {
		t.Fatal("other Pod credited")
	}
	wrong = row
	wrong.Time = now.Add(-time.Second)
	if voiceMemoryMaintenanceMatches(wrong, record, snap, selected) {
		t.Fatal("maintenance preceding selected decision credited")
	}
}
