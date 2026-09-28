package console

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func voiceMemoryWaitFixture(t *testing.T) (*Server, *attackRecord, voiceMemorySnapshot, voiceMemoryMaintenance, string) {
	t.Helper()
	now := time.Now().UTC()
	record := &attackRecord{Pod: "voice-bot-a", TargetUID: "pod-uid", started: now.Add(-time.Second),
		ObservationEnd: now.Add(voiceMemoryRunTimeout).Format(time.RFC3339Nano)}
	snap := voiceMemorySnapshot{PolicyUID: "policy-uid", DeploymentUID: "deployment-uid"}
	trace := caseTraceValidTrace(now, true, false)
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = "voice", record.Pod, record.TargetUID
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = "voice", voiceMemoryPolicyName, snap.PolicyUID
	trace.SelectedAction = string(model.ActionVoiceMemoryNoteRevoke)
	trace.Candidates[1].Action = trace.SelectedAction
	trace.DispatchOutcome = model.DispatchError
	row := audit.Record{Kind: "phorvex.decision", Time: now, Namespace: "voice", Pod: record.Pod,
		Action: trace.SelectedAction, Selected: true, DispatchOutcome: model.DispatchError, DecisionTrace: trace,
		Events: []model.EventEvidence{{EventUID: "event-uid", TargetPodUID: record.TargetUID, TrustVerdict: "trusted", Weight: 1}}}
	if err := trace.Validate(); err != nil {
		t.Fatalf("invalid delayed-recovery selection fixture: %v", err)
	}
	path := writeDecisionAudit(t, row)
	maintenance := voiceMemoryMaintenance{SchemaVersion: audit.SchemaVersionCurrent, Kind: "phorvex.maintenance",
		Time: now.Add(time.Second), Receipt: voiceMemoryJournalName(snap.DeploymentUID, 1),
		Operation: trace.SelectedAction, Namespace: "voice", Policy: voiceMemoryPolicyName, PolicyUID: snap.PolicyUID,
		TargetName: record.Pod, TargetUID: record.TargetUID, Outcome: "confirmed",
		Effect: "Voice memory rule confirmed on current serving Pods"}
	return NewServer(Config{AuditPath: path}), record, snap, maintenance, path
}

func appendVoiceMemoryMaintenance(path string, row voiceMemoryMaintenance) error {
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	closeErr := f.Close()
	return errors.Join(err, closeErr)
}

func TestVoiceMemoryWaitCreditsRecoveryBeyondPreviousWindow(t *testing.T) {
	s, record, snap, maintenance, path := voiceMemoryWaitFixture(t)
	// The exact selected dispatch failed initially. Its real audit confirmation
	// arrives after the old cutoff, while the longer window is still following it.
	written := make(chan error, 1)
	timer := time.AfterFunc(350*time.Millisecond, func() { written <- appendVoiceMemoryMaintenance(path, maintenance) })
	defer timer.Stop()
	old, err := s.waitVoiceMemoryDecisionWithTiming(context.Background(), record, snap, "event-uid", 200*time.Millisecond, 5*time.Millisecond)
	if err != nil || !old.Selected || old.Actuated || old.Recovered {
		t.Fatalf("old window should retain only unconfirmed selection: %+v err=%v", old, err)
	}
	longer, err := s.waitVoiceMemoryDecisionWithTiming(context.Background(), record, snap, "event-uid", 400*time.Millisecond, 5*time.Millisecond)
	if err := <-written; err != nil {
		t.Fatalf("confirmation producer: %v", err)
	}
	if err != nil || !longer.Selected || !longer.Actuated || !longer.Recovered ||
		longer.DecisionID != old.DecisionID || longer.TickID != old.TickID {
		t.Fatalf("delayed exact recovery not credited: %+v err=%v", longer, err)
	}
}

func TestVoiceMemoryWaitTimeoutDoesNotCreditUnrelatedConfirmation(t *testing.T) {
	s, record, snap, maintenance, path := voiceMemoryWaitFixture(t)
	maintenance.Receipt = voiceMemoryJournalName(snap.DeploymentUID, 2)
	if err := appendVoiceMemoryMaintenance(path, maintenance); err != nil {
		t.Fatal(err)
	}
	decision, err := s.waitVoiceMemoryDecisionWithTiming(context.Background(), record, snap, "event-uid", 50*time.Millisecond, 5*time.Millisecond)
	if err != nil || !decision.Selected || decision.Actuated || decision.Recovered {
		t.Fatalf("wrong operation became actuation at timeout: %+v err=%v", decision, err)
	}
}

func TestVoiceMemoryWaitTimeoutWithoutExactEventRemainsUnknown(t *testing.T) {
	s, record, snap, _, _ := voiceMemoryWaitFixture(t)
	decision, err := s.waitVoiceMemoryDecisionWithTiming(context.Background(), record, snap, "different-event", 50*time.Millisecond, 5*time.Millisecond)
	if err == nil || decision.Selected || decision.Actuated || decision.Recovered {
		t.Fatalf("missing exact selection became a verdict: %+v err=%v", decision, err)
	}
}

func TestVoiceMemoryWaitParentDeadlineStillBoundsRecovery(t *testing.T) {
	s, record, snap, _, _ := voiceMemoryWaitFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	decision, err := s.waitVoiceMemoryDecisionWithTiming(ctx, record, snap, "event-uid", time.Second, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || !decision.Selected || decision.Actuated || decision.Recovered {
		t.Fatalf("parent deadline lost or false confirmation: %+v err=%v", decision, err)
	}
}
