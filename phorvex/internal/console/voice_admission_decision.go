package console

import (
	"context"
	"errors"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Server) waitVoiceAdmissionDecision(ctx context.Context, record *attackRecord, before voiceAdmissionSnapshot, eventUID string) (voiceMCPDecision, error) {
	proxy := voiceMCPSnapshot{PolicyUID: before.PolicyUID}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	var noop voiceMCPDecision
	for {
		rows, e := s.readDecisionWindow(ctx, "")
		if e == nil {
			for _, row := range rows {
				if !voiceMCPMatchedAudit(row, record, proxy, eventUID) {
					continue
				}
				trace := row.DecisionTrace
				if row.Selected {
					matched := row
					bindDecisionRecord(record, &matched)
					return voiceMCPDecision{voiceMemoryDecision: voiceMemoryDecision{Action: row.Action, DecisionID: trace.DecisionID, TickID: trace.TickID, SelectedAt: row.Time, Selected: true,
						Actuated: row.Actuated && row.DispatchOutcome == model.DispatchEmitted && trace.DispatchOutcome == model.DispatchEmitted}}, nil
				}
				if row.Action == "noop" {
					noop = voiceMCPDecision{voiceMemoryDecision: voiceMemoryDecision{Action: row.Action, DecisionID: trace.DecisionID, TickID: trace.TickID, SelectedAt: row.Time}, NoopReason: voiceMCPBoundedDiagnostic(trace.NoopReason)}
					for _, a := range trace.ActionStatus {
						if a.Action == voiceAdmissionAction {
							noop.ActionExclusion = voiceMCPBoundedDiagnostic(a.Status + ":" + a.ExclusionKind + ":" + a.Reason)
						}
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return noop, ctx.Err()
		case <-timer.C:
			return noop, errors.New("exact admission decision not selected; event-bound NOOP retained")
		case <-ticker.C:
		}
	}
}
func voiceAdmissionJournalMatches(cm *corev1.ConfigMap, before voiceAdmissionSnapshot, decision voiceMCPDecision, event *attackStimulusEvidence, first voiceAdmissionReply, record *attackRecord) (voiceadmissionpolicy.Receipt, error) {
	var empty voiceadmissionpolicy.Receipt
	if cm == nil || cm.Namespace != "phorvex-system" || cm.Name != voiceadmissionpolicy.JournalName || cm.UID == "" || cm.Labels[voiceadmissionpolicy.JournalLabel] != "v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || event == nil || first.Loss == nil {
		return empty, errors.New("admission journal authority missing")
	}
	j, e := voiceadmissionpolicy.ParseJournal(cm.Data["receipts.json"])
	if e != nil || len(j.Receipts) != 1 {
		return empty, errors.New("admission protected journal incomplete")
	}
	r := j.Receipts[0]
	op, e := voiceadmissionpolicy.OperationID(before.DeploymentUID, before.ConfigMapUID, before.PolicyUID, before.PolicyGeneration, event.EventUID, decision.TickID, decision.DecisionID, before.RuleSHA256)
	if e != nil || r.Phase != "terminal-full" || r.OperationID != op || r.PolicyName != voiceMemoryPolicyName || r.PolicyUID != before.PolicyUID || r.PolicyGeneration != before.PolicyGeneration || r.DeploymentUID != before.DeploymentUID ||
		r.TargetName != record.Pod || r.TargetPodUID != record.TargetUID || r.EventName != event.EventName || r.EventUID != event.EventUID || r.CreatorIdentity != before.EventCreator || r.TickID != decision.TickID || r.SelectionDecisionID != decision.DecisionID ||
		r.ConfigMapUID != before.ConfigMapUID || r.SourceConfigMapUID != before.WrapperCMUID || r.SessionID != first.Loss.Session.SessionID || r.RunSHA256 != first.RunSHA256 || r.ReceiptSHA256 != voiceMCPSHA(voiceAdmissionCanonical(first.Loss.Session)) || r.ProviderEvidenceSHA256 != voiceMCPSHA(voiceAdmissionCanonical(first.Loss.Provider)) || r.Prior.SHA256() != before.RuleSHA256 {
		return empty, errors.New("admission protected journal correlation differs")
	}
	return r, nil
}
func voiceAdmissionBarrier(before, after voiceAdmissionSnapshot, r voiceadmissionpolicy.Receipt) bool {
	if !voiceAdmissionSame(before, after, false) || after.RuleSHA256 != r.Desired.SHA256() || after.Rule.Mode != voiceadmissionpolicy.ModeEnforce || after.Rule.Revision != 1 || after.Rule.OperationID != r.OperationID || len(r.PodReceipts) != len(after.Pins) || len(after.States) != len(after.Pins) {
		return false
	}
	seen := map[string]bool{}
	for _, state := range r.PodReceipts {
		if seen[state.PodUID] || !state.Settled || state.TransitionPending || state.PendingUnsigned != 0 || state.ActiveUnsigned != 0 {
			return false
		}
		seen[state.PodUID] = true
	}
	for _, state := range after.States {
		if !seen[state.PodUID] || !state.Settled || state.TransitionPending || state.PendingUnsigned != 0 || state.ActiveUnsigned != 0 {
			return false
		}
	}
	return true
}
func (s *Server) waitVoiceAdmissionEffect(ctx context.Context, p voiceAdmissionProfile, before voiceAdmissionSnapshot, decision voiceMCPDecision, event *attackStimulusEvidence, first voiceAdmissionReply, record *attackRecord) (voiceAdmissionSnapshot, voiceadmissionpolicy.Receipt, error) {
	timer := time.NewTimer(120 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		kube, e := clientForContext("")
		if e == nil {
			cm, e := kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, voiceadmissionpolicy.JournalName, metav1.GetOptions{})
			if e == nil {
				receipt, e := voiceAdmissionJournalMatches(cm, before, decision, event, first, record)
				if e == nil {
					after, e := s.voiceAdmissionSnapshot(ctx, p)
					if e == nil && voiceAdmissionBarrier(before, after, receipt) {
						return after, receipt, nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return voiceAdmissionSnapshot{}, voiceadmissionpolicy.Receipt{}, ctx.Err()
		case <-timer.C:
			return voiceAdmissionSnapshot{}, voiceadmissionpolicy.Receipt{}, errors.New("admission journal or serving barrier unresolved")
		case <-ticker.C:
		}
	}
}
