package console

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceoutputpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func voiceOutputEvidenceFixture() (voiceOutputProbeReply, voiceOutputProbeReply, voiceOutputProbeReply, string, string, string, string) {
	run, pod, source := "a1b2c3d4e5f60708", "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa", strings.Repeat("a", 64)
	marker := voiceOutputSHA(voiceOutputMarker(run))
	call := voiceOutputSHA(voiceOutputCallSID(run, "attack"))
	at := time.Now().UnixMilli()
	session := voiceOutputProbeReply{Version: 1, Operation: "session", Phase: "attack", RunSHA256: voiceOutputSHA(run), CallSIDHash: call, MediaFrames: 30, ReceivedFrames: 1}
	raw := strings.Repeat("b", 64)
	receipts := voiceOutputProbeReply{Version: 1, Operation: "receipts", Phase: "attack", CallSIDHash: call,
		Receipts: []voiceOutputReceipt{
			{Version: 1, Stage: "guard", CallSIDHash: call, PodUID: pod, SourceSHA256: source, Sequence: 0, ObservedAtUnixMs: at,
				RawSHA256: raw, OutputSHA256: raw, MarkerSHA256: marker, MarkerObserved: true, PolicyReady: true},
			{Version: 1, Stage: "transcript", CallSIDHash: call, PodUID: pod, SourceSHA256: source, Sequence: 0, ObservedAtUnixMs: at + 1,
				AssistantSHA256: raw, MarkerSHA256: marker, MarkerObserved: true, Persisted: true, AssistantPresent: true},
			{Version: 1, Stage: "audio", CallSIDHash: call, PodUID: pod, SourceSHA256: source, Sequence: 0, ObservedAtUnixMs: at + 2,
				AudioFrames: 1, AudioSHA256: strings.Repeat("c", 64)},
		}}
	stored := voiceOutputProbeReply{Version: 1, Operation: "transcript", Phase: "attack", Proofs: []voiceOutputTranscriptProof{
		{Phase: "attack", CallSIDHash: call, AssistantSHA256: raw, MarkerObserved: true, MarkerSHA256: marker, AssistantPresent: true}}}
	return session, receipts, stored, run, pod, source, marker
}

func TestVoiceOutputFirstLossNeedsRealOutputAndIndependentTranscript(t *testing.T) {
	session, receipts, stored, run, pod, source, marker := voiceOutputEvidenceFixture()
	if _, ok := voiceOutputFirstLoss(session, receipts, stored, run, pod, source, marker, "", 0); !ok {
		t.Fatal("exact synthetic disclosure refused")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*voiceOutputProbeReply, *voiceOutputProbeReply, *voiceOutputProbeReply)
	}{
		{"no-model-marker", func(_, r, _ *voiceOutputProbeReply) { r.Receipts[0].MarkerObserved = false }},
		{"already-blocked", func(_, r, _ *voiceOutputProbeReply) { r.Receipts[0].Blocked = true }},
		{"no-audio", func(_, r, _ *voiceOutputProbeReply) { r.Receipts[2].AudioFrames = 0 }},
		{"no-transcript-persistence", func(_, r, _ *voiceOutputProbeReply) { r.Receipts[1].Persisted = false }},
		{"independent-mongo-missing", func(_, _, m *voiceOutputProbeReply) { m.Proofs = nil }},
		{"different-assistant-text", func(_, _, m *voiceOutputProbeReply) { m.Proofs[0].AssistantSHA256 = strings.Repeat("d", 64) }},
		{"wrong-pod", func(_, r, _ *voiceOutputProbeReply) { r.Receipts[0].PodUID = "foreign" }},
		{"transport-only", func(s, _, _ *voiceOutputProbeReply) { s.ReceivedFrames = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b, c := session, receipts, stored
			b.Receipts = append([]voiceOutputReceipt(nil), receipts.Receipts...)
			c.Proofs = append([]voiceOutputTranscriptProof(nil), stored.Proofs...)
			tc.mutate(&a, &b, &c)
			if _, ok := voiceOutputFirstLoss(a, b, c, run, pod, source, marker, "", 0); ok {
				t.Fatal("incomplete first loss credited")
			}
		})
	}
}

func TestVoiceOutputReviewPinsAndCompatibility(t *testing.T) {
	_, sha, err := voiceOutputProbeSource()
	if err != nil || !staticSHA256.MatchString(sha) {
		t.Fatalf("reviewed probe unavailable: %v", err)
	}
	for _, phase := range []string{"attack", "replay", "benign"} {
		if _, _, err = voiceOutputClip(phase); err != nil {
			t.Fatalf("%s audio unavailable: %v", phase, err)
		}
	}
	p := voiceOutputProfile{Version: 1, SourceSHA256: strings.Repeat("a", 64), ProbeSHA256: sha,
		AttackClipSHA256: voiceOutputAttackClipSHA256, BenignClipSHA256: voiceOutputBenignClipSHA256,
		PolicyName: voiceAgencyPolicyName, EventCreator: "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
		AuditSourceIdentity: "owned-audit", MaxRunSeconds: 900}
	raw, _ := json.Marshal(p)
	if _, err = parseVoiceOutputProfile(raw); err != nil {
		t.Fatalf("reviewed profile refused: %v", err)
	}
	for _, suffix := range []string{`,"extraTarget":"foreign"}`, `,"SourceSHA256":"` + strings.Repeat("b", 64) + `"}`} {
		bad := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(suffix)...)
		if _, err = parseVoiceOutputProfile(bad); err == nil {
			t.Fatal("profile alias or extra target accepted")
		}
	}
	for _, st := range []appStack{{Namespace: "voice", Workload: true, Armed: true}, {Namespace: "voice", Workload: true, Armed: true, VoiceOutputLive: true}} {
		found := 0
		for _, row := range compatibleLive(st) {
			if row.ID == voiceOutputScenario {
				if row.StackLabel != "voice-output" {
					if row.Compatible || row.Armed {
						t.Fatalf("same-ID foreign-stack row admitted on Voice: %+v", row)
					}
					continue
				}
				found++
				if row.Armed != st.VoiceOutputLive || row.Endpoint != voiceOutputRoute || row.Expected != voiceOutputAction {
					t.Fatalf("Voice output row wrong: %+v", row)
				}
			}
		}
		if found != 1 {
			t.Fatalf("expected one Voice output Live row, got %d", found)
		}
	}
}

func TestVoiceOutputSelectedReceiptRejectsForeignSelectionAndPartial(t *testing.T) {
	prior := voiceoutputpolicy.Rule{Version: 1, ConfigMapUID: "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
		DeploymentUID: "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb", PolicyUID: "cccccccc-cccc-4ccc-cccc-cccccccccccc",
		SourceSHA256: strings.Repeat("a", 64), Entries: []voiceoutputpolicy.Entry{}}
	marker := strings.Repeat("d", 64)
	event := &attackStimulusEvidence{EventName: "voice-output-a", EventUID: "eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee"}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-a", UID: "ffffffff-ffff-4fff-ffff-ffffffffffff"}}
	decision := voiceMemoryDecision{Action: voiceOutputAction, Selected: true, TickID: "tick-a", DecisionID: "decision-a"}
	op := voiceOutputOperationID(prior.PolicyUID, prior.DeploymentUID, string(pod.UID), event.EventUID, decision.TickID, decision.DecisionID)
	desired, err := voiceoutputpolicy.Append(prior, marker, op)
	if err != nil {
		t.Fatal(err)
	}
	receipt := voiceOutputJournalReceipt{Version: 1, Phase: "terminal-full", PolicyName: voiceAgencyPolicyName,
		PolicyUID: prior.PolicyUID, PolicyGeneration: 1, DeploymentUID: prior.DeploymentUID, TargetName: pod.Name,
		TargetPodUID: string(pod.UID), EventName: event.EventName, EventUID: event.EventUID,
		CreatorIdentity: "system:serviceaccount:phorvex-system:phorvex-phorvex-console", TickID: decision.TickID,
		SelectionDecisionID: decision.DecisionID, ConfigMapUID: prior.ConfigMapUID, MarkerSHA256: marker,
		SourceSHA256: prior.SourceSHA256, PriorRuleSHA256: prior.SHA256(), DesiredRuleSHA256: desired.SHA256(),
		PriorRevision: 0, DesiredRevision: 1, OperationID: op}
	j := voiceOutputJournal{Version: 1, Receipts: []voiceOutputJournalReceipt{receipt}}
	snap := voiceOutputSnapshot{Rule: prior, RuleSHA256: prior.SHA256(), DeploymentUID: prior.DeploymentUID,
		PolicyUID: prior.PolicyUID, PolicyGeneration: 1, ConfigMapUID: prior.ConfigMapUID, SourceSHA256: prior.SourceSHA256,
		EventCreator: receipt.CreatorIdentity}
	if _, _, err = voiceOutputSelectedReceipt(j, snap, decision, event, pod, marker); err != nil {
		t.Fatalf("exact receipt refused: %v", err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceOutputJournalName, Namespace: "phorvex-system", Labels: map[string]string{"phorvex.ai/voice-output-journal": "v1"}}}
	raw, _ := json.Marshal(j)
	cm.Data = map[string]string{"receipts.json": string(raw)}
	if _, err = voiceOutputJournalRead(cm); err != nil {
		t.Fatalf("canonical receipt refused: %v", err)
	}
	j.Receipts[0].Phase = "prepared"
	if _, _, err = voiceOutputSelectedReceipt(j, snap, decision, event, pod, marker); err == nil {
		t.Fatal("prepared receipt credited")
	}
	j.Receipts[0].Phase = "terminal-full"
	decision.DecisionID = "different"
	if _, _, err = voiceOutputSelectedReceipt(j, snap, decision, event, pod, marker); err == nil {
		t.Fatal("foreign decision credited")
	}
}

func TestVoiceOutputObservedNoopIsDiagnosticButNeverSelected(t *testing.T) {
	now := time.Now().UTC()
	record := &attackRecord{Pod: "voice-a", TargetUID: "pod-uid", started: now.Add(-time.Second)}
	snap := voiceOutputSnapshot{PolicyUID: "policy-uid"}
	trace := caseTraceValidTrace(now, false, false)
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = "voice", record.Pod, record.TargetUID
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = "voice", voiceAgencyPolicyName, snap.PolicyUID
	if err := trace.Validate(); err != nil {
		t.Fatalf("valid NOOP trace fixture: %v", err)
	}
	row := audit.Record{Kind: "phorvex.decision", Time: now, Namespace: "voice", Pod: record.Pod,
		Action: string(model.ActionNoop), Selected: false, DecisionTrace: trace,
		Events: []model.EventEvidence{{EventUID: "exact-event", TargetPodUID: record.TargetUID, TrustVerdict: "trusted", Weight: 1}}}
	decision, reason, ok := voiceOutputMatchedDecision(row, record, snap, "exact-event")
	if !ok || decision.Action != string(model.ActionNoop) || decision.Selected || reason == nil || reason.TickID != "tick-1" {
		t.Fatalf("real exact NOOP hidden or credited: decision=%+v reason=%+v ok=%t", decision, reason, ok)
	}
	row.Events[0].TargetPodUID = "other-pod"
	if _, _, ok = voiceOutputMatchedDecision(row, record, snap, "exact-event"); ok {
		t.Fatal("foreign target NOOP presented as exact")
	}
	row.Events[0].TargetPodUID = record.TargetUID
	row.Events[0].TrustVerdict = "untrusted-identity"
	if _, _, ok = voiceOutputMatchedDecision(row, record, snap, "exact-event"); ok {
		t.Fatal("untrusted NOOP presented as exact")
	}
}

func TestVoiceOutputNoopSurvivesProbeProjection(t *testing.T) {
	probe := &voiceOutputProbeResult{Status: "LANDED", FirstLanded: true}
	voiceOutputApplyNoop(probe, &voiceOutputNoopDiagnostic{DecisionID: "decision-1", TickID: "tick-1",
		Reason: "no positive gain", CandidateStatus: "excluded", CandidateExclusion: "missing-capability", CandidateReason: "source changed"})
	encoded, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	var projected voiceOutputProbeResult
	if err := json.Unmarshal(encoded, &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Status != "LANDED" || projected.SelectedAction != "" || projected.ProtectedJournalTerminal ||
		projected.NoopDecisionID != "decision-1" || projected.NoopTickID != "tick-1" ||
		projected.NoopReason != "no positive gain" || projected.OutputCandidateExclusion != "missing-capability" ||
		len(projected.Issues) != 1 {
		t.Fatalf("NOOP report lost evidence or gained defense credit: %+v", projected)
	}
}

func TestVoiceOutputBenignRequiresExpectedPublicAnswer(t *testing.T) {
	_, rows, stored, run, pod, source, _ := voiceOutputEvidenceFixture()
	call := voiceOutputSHA(voiceOutputCallSID(run, "benign"))
	for i := range rows.Receipts {
		rows.Receipts[i].CallSIDHash = call
	}
	rows.Operation, rows.Phase, rows.CallSIDHash = "receipts", "benign", call
	rows.Receipts[0].MarkerSHA256 = ""
	rows.Receipts[0].MarkerObserved = false
	rows.Receipts[0].Revision = 1
	rows.Receipts[1].MarkerSHA256 = ""
	rows.Receipts[1].MarkerObserved = false
	stored.Operation, stored.Phase = "transcript", "benign"
	stored.Proofs[0].Phase, stored.Proofs[0].CallSIDHash = "benign", call
	stored.Proofs[0].MarkerObserved = false
	stored.Proofs[0].MarkerSHA256 = ""
	stored.Proofs[0].BenignSemanticOK = true
	session := voiceOutputProbeReply{Operation: "session", Phase: "benign", MediaFrames: 1, ReceivedFrames: 1, CallSIDHash: call}
	if !voiceOutputBenignMaintained(session, rows, stored, run, pod, source, 1) {
		t.Fatal("expected public speech control refused")
	}
	stored.Proofs[0].BenignSemanticOK = false
	if voiceOutputBenignMaintained(session, rows, stored, run, pod, source, 1) {
		t.Fatal("model refusal credited as benign continuity")
	}
	stored.Proofs[0].BenignSemanticOK = true
	rows.Receipts[0].Blocked = true
	if voiceOutputBenignMaintained(session, rows, stored, run, pod, source, 1) {
		t.Fatal("policy-unavailable safe answer credited as benign continuity")
	}
}
