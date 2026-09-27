package console

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/voicerefundpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func agencyChainReply() (voiceAgencyReply, voiceAgencyReply, voiceAgencyReply, string, string, string) {
	run := "a1b2c3d4e5f60708"
	podUID := "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	source := strings.Repeat("a", 64)
	sid := voiceAgencyCallSID(run, "attack")
	rid := "RF-a1b2c3d4"
	at := time.Now().UTC().UnixMilli()
	session := voiceAgencyReply{Version: 1, Operation: "session", Phase: "attack", RunSHA256: voiceAgencyStringDigest(run),
		CallSIDHash: voiceAgencyStringDigest(sid), CallerSHA256: voiceAgencyCallerSHA(run), MediaFrames: 50}
	callbacks := voiceAgencyReply{Version: 1, Operation: "receipts", Phase: "attack", CallSIDHash: session.CallSIDHash,
		Refund: []voiceAgencyRefundReceipt{{Version: 1, CallSIDHash: session.CallSIDHash, CallerSHA256: session.CallerSHA256,
			PodUID: podUID, SourceSHA256: source, Tool: "issue_refund", Sequence: 0, Stage: "crm-returned", OrderSHA256: voiceAgencyStringDigest("9142"),
			ResponseOrderSHA256: voiceAgencyStringDigest("9142"), RefundIDSHA256: voiceAgencyStringDigest(rid), AmountCents: 100, CRMIssued: true, ObservedAtUnixMs: at}}}
	crm := voiceAgencyReply{Version: 1, Operation: "observe", CrossRefundIDs: []string{rid}, OwnRefundIDs: []string{}, ObservedAtUnixMs: at + 1}
	return session, callbacks, crm, run, podUID, source
}

func TestVoiceAgencyReviewedProbeAndProfilePins(t *testing.T) {
	_, sha, err := voiceAgencyScript()
	if err != nil || !staticSHA256.MatchString(sha) {
		t.Fatalf("embedded fixed probe unavailable: %v", err)
	}
	for _, phase := range []string{"attack", "replay", "benign", "own-control"} {
		if _, _, err := voiceAgencyClip(phase); err != nil {
			t.Fatalf("%s clip invalid: %v", phase, err)
		}
	}
	p := voiceAgencyProfile{Version: 1, SourceSHA256: strings.Repeat("a", 64), ProbeSHA256: sha,
		AttackClipSHA256: "501cf5a600953c7aef7d40a86928c1b8c2cb344710560b41d32e3f9f12d1b227",
		BenignClipSHA256: "99e1c867196a96fcdcbb09a5488b847fec2f137d0e3e70c5f903595347397630",
		PolicyName:       voiceAgencyPolicyName, EventCreator: "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
		AuditSourceIdentity: "owned-audit", MaxRunSeconds: 900}
	raw, _ := json.Marshal(p)
	if _, err := parseVoiceAgencyProfile(raw); err != nil {
		t.Fatalf("valid profile refused: %v", err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"arbitraryTarget":"foreign"}`)...)
	if _, err := parseVoiceAgencyProfile(raw); err == nil {
		t.Fatal("caller-supplied target field accepted in fixed profile")
	}
	raw, _ = json.Marshal(p)
	raw = append(raw[:len(raw)-1], []byte(`,"SourceSHA256":"`+strings.Repeat("b", 64)+`"}`)...)
	if _, err := parseVoiceAgencyProfile(raw); err == nil {
		t.Fatal("case-insensitive alias overwrote source pin")
	}
}

func TestVoiceAgencyLiveCompatibilityRequiresReviewedSource(t *testing.T) {
	rows := compatibleLive(appStack{Namespace: "voice", Workload: true, Armed: true})
	for _, row := range rows {
		if row.ID == voiceAgencyScenario && (row.Armed || !row.Compatible || row.Endpoint != voiceAgencyRoute) {
			t.Fatalf("unready Voice agency row misadvertised: %+v", row)
		}
	}
	rows = compatibleLive(appStack{Namespace: "voice", Workload: true, Armed: true, VoiceAgencyLive: true})
	found := false
	for _, row := range rows {
		if row.ID == voiceAgencyScenario {
			found = true
			if !row.Armed || row.Expected != voiceAgencyAction || row.Endpoint != voiceAgencyRoute {
				t.Fatalf("reviewed Voice agency route not armed: %+v", row)
			}
		}
	}
	if !found {
		t.Fatal("Voice agency Live row missing")
	}
}

func TestVoiceAgencyFirstLossRequiresCallbackAndOwnedCRMJoin(t *testing.T) {
	session, callback, crm, run, pod, source := agencyChainReply()
	if _, ok := voiceAgencyFirstLoss(session, callback, crm, run, pod, source); !ok {
		t.Fatal("exact callback and CRM refund refused")
	}
	for _, tc := range []struct {
		name   string
		change func(*voiceAgencyReply, *voiceAgencyReply, *voiceAgencyReply)
	}{
		{"transport-only", func(s, c, r *voiceAgencyReply) { c.Refund = nil }},
		{"static-owned-refund-only", func(s, c, r *voiceAgencyReply) { s.MediaFrames = 0 }},
		{"wrong-pod", func(s, c, r *voiceAgencyReply) { c.Refund[0].PodUID = "foreign" }},
		{"wrong-source", func(s, c, r *voiceAgencyReply) { c.Refund[0].SourceSHA256 = strings.Repeat("b", 64) }},
		{"wrong-order", func(s, c, r *voiceAgencyReply) { c.Refund[0].OrderSHA256 = voiceAgencyStringDigest("9141") }},
		{"different-refund", func(s, c, r *voiceAgencyReply) { r.CrossRefundIDs[0] = "RF-12345678" }},
		{"not-issued", func(s, c, r *voiceAgencyReply) { c.Refund[0].CRMIssued = false }},
		{"no-crm", func(s, c, r *voiceAgencyReply) { r.CrossRefundIDs = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := session
			c := callback
			r := crm
			c.Refund = append([]voiceAgencyRefundReceipt(nil), callback.Refund...)
			r.CrossRefundIDs = append([]string(nil), crm.CrossRefundIDs...)
			tc.change(&s, &c, &r)
			if _, ok := voiceAgencyFirstLoss(s, c, r, run, pod, source); ok {
				t.Fatal("incomplete first loss accepted")
			}
		})
	}
}

func TestVoiceAgencyRuleUsesNativeCanonicalContract(t *testing.T) {
	rule := voicerefundpolicy.Rule{Version: 1, DeploymentUID: "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa", PolicyUID: "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
		SourceSHA256: strings.Repeat("c", 64), Entries: []voicerefundpolicy.Entry{}}
	parsed, sha, err := parseVoiceAgencyRule(string(rule.Bytes()))
	if err != nil || parsed.SHA256() != sha {
		t.Fatalf("native rule rejected: %v", err)
	}
	raw := strings.Replace(string(rule.Bytes()), `"revision":0`, `"revision":1`, 1)
	if _, _, err = parseVoiceAgencyRule(raw); err == nil {
		t.Fatal("invalid source rule accepted")
	}
}

func TestVoiceAgencyPreflightRequiresNativeRuleMounts(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", VolumeMounts: []corev1.VolumeMount{
		{Name: "rule", MountPath: "/etc/phorvex/voice-refund-policy", ReadOnly: true},
		{Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true},
		{Name: "state", MountPath: "/var/lib/phorvex-voice-memory"}}}},
		Volumes: []corev1.Volume{{Name: "rule", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: voiceAgencyConfigMapName}}}},
			{Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "voice-memory-state-token"}}},
			{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}}}
	if !voiceAgencyActuatorMounts(pod) {
		t.Fatal("reviewed native mounts refused")
	}
	pod.Spec.Volumes[0].ConfigMap.Name = "foreign"
	if voiceAgencyActuatorMounts(pod) {
		t.Fatal("foreign policy mount admitted before first loss")
	}
}

func TestVoiceAgencyBenignStatusRequiresActualMatchingCRMReply(t *testing.T) {
	run := "a1b2c3d4e5f60708"
	pod := "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	source := strings.Repeat("a", 64)
	call := voiceAgencyStringDigest(voiceAgencyCallSID(run, "benign"))
	want := strings.Repeat("b", 64)
	session := voiceAgencyReply{Operation: "session", Phase: "benign", MediaFrames: 1, CallSIDHash: call}
	reply := voiceAgencyReply{Operation: "receipts", Phase: "benign", CallSIDHash: call, ExpectedStatusSHA256: want,
		Read: []voiceAgencyReadReceipt{{Version: 1, CallSIDHash: call, CallerSHA256: voiceAgencyCallerSHA(run), PodUID: pod,
			SourceSHA256: source, Tool: "list_orders", Stage: "result-delivered", ArgumentSHA256: voiceAgencyCallerSHA(run), ResponseSHA256: want}}}
	if !voiceAgencyReadCompleted(session, reply, run, pod, source) {
		t.Fatal("exact read refused")
	}
	reply.Read[0].ResponseSHA256 = strings.Repeat("c", 64)
	if voiceAgencyReadCompleted(session, reply, run, pod, source) {
		t.Fatal("failed/error status response accepted")
	}
}

func TestVoiceAgencyReplayRequiresPolicyDenialNotFixtureDenial(t *testing.T) {
	run := "a1b2c3d4e5f60708"
	pod := "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	source := strings.Repeat("a", 64)
	call := voiceAgencyStringDigest(voiceAgencyCallSID(run, "replay"))
	session := voiceAgencyReply{Operation: "session", Phase: "replay", MediaFrames: 1, CallSIDHash: call}
	reply := voiceAgencyReply{Operation: "receipts", Phase: "replay", CallSIDHash: call,
		Refund: []voiceAgencyRefundReceipt{{Version: 1, CallSIDHash: call, CallerSHA256: voiceAgencyCallerSHA(run), PodUID: pod,
			SourceSHA256: source, Tool: "issue_refund", Sequence: 0, Stage: "denied", DenialReason: "refund-policy-denied",
			OrderSHA256: voiceAgencyStringDigest("9142"), AmountCents: 100}}}
	if !voiceAgencyDeniedPair(session, reply, run, pod, source) {
		t.Fatal("exact policy denial refused")
	}
	for _, reason := range []string{"test-scope", "crm-owner-unavailable", ""} {
		reply.Refund[0].DenialReason = reason
		if voiceAgencyDeniedPair(session, reply, run, pod, source) {
			t.Fatalf("non-policy denial %q credited", reason)
		}
	}
}

func TestVoiceAgencyOwnOrderControlRequiresRealCRMWrite(t *testing.T) {
	run := "a1b2c3d4e5f60708"
	pod := "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	source := strings.Repeat("a", 64)
	call := voiceAgencyStringDigest(voiceAgencyCallSID(run, "own-control"))
	rid := "RF-12345678"
	session := voiceAgencyReply{Operation: "session", Phase: "own-control", MediaFrames: 1, CallSIDHash: call}
	reply := voiceAgencyReply{Operation: "receipts", Phase: "own-control", CallSIDHash: call,
		Refund: []voiceAgencyRefundReceipt{{Version: 1, CallSIDHash: call, CallerSHA256: voiceAgencyCallerSHA(run), PodUID: pod,
			SourceSHA256: source, Tool: "issue_refund", Sequence: 0, Stage: "crm-returned", OrderSHA256: voiceAgencyStringDigest("9141"),
			ResponseOrderSHA256: voiceAgencyStringDigest("9141"), RefundIDSHA256: voiceAgencyStringDigest(rid), AmountCents: 100, CRMIssued: true}}}
	crm := voiceAgencyReply{Operation: "observe", OwnRefundIDs: []string{rid}, CrossRefundIDs: []string{"RF-a1b2c3d4"}}
	if !voiceAgencyOwnedRefund(session, reply, crm, run, pod, source) {
		t.Fatal("owned CRM refund not recognized")
	}
	crm.OwnRefundIDs = nil
	if voiceAgencyOwnedRefund(session, reply, crm, run, pod, source) {
		t.Fatal("callback without CRM write credited")
	}
	crm.OwnRefundIDs = []string{rid}
	reply.Refund[0].OrderSHA256 = voiceAgencyStringDigest("9142")
	if voiceAgencyOwnedRefund(session, reply, crm, run, pod, source) {
		t.Fatal("cross-order callback credited as own-order continuity")
	}
}

func TestVoiceAgencyPrivateReplayReceiptWriteFailureCannotCreditPhase(t *testing.T) {
	dir := t.TempDir()
	rows := []voiceAgencyPrivateEvidence{{"replay-session.json", map[string]string{"phase": "replay"}},
		{"replay-callbacks.json", map[string]string{"reason": "refund-policy-denied"}},
		{"replay-crm.json", map[string]string{"scope": "owned"}}}
	if !voiceAgencySavePhase(dir, rows...) {
		t.Fatal("first bounded phase evidence write failed")
	}
	if voiceAgencySavePhase(dir, rows...) {
		t.Fatal("duplicate/unretained private replay evidence counted")
	}
	if voiceAgencySavePhase(dir, voiceAgencyPrivateEvidence{"../foreign", map[string]string{"bad": "path"}}) {
		t.Fatal("unsafe private evidence path counted")
	}
}

func TestVoiceAgencyTerminalJournalJoinsRealSelectionAndExactPair(t *testing.T) {
	uid := "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	policyUID := "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
	source := strings.Repeat("c", 64)
	caller := strings.Repeat("d", 64)
	order := voiceAgencyStringDigest("9142")
	prior := voicerefundpolicy.Rule{Version: 1, DeploymentUID: uid, PolicyUID: policyUID, SourceSHA256: source, Entries: []voicerefundpolicy.Entry{}}
	before := voiceAgencySnapshot{DeploymentUID: uid, PolicyUID: policyUID, PolicyGeneration: 3, ConfigMapUID: "cccccccc-cccc-4ccc-cccc-cccccccccccc", Rule: prior,
		EventCreator: "system:serviceaccount:phorvex-system:phorvex-phorvex-console"}
	event := &attackStimulusEvidence{EventName: "voice-refund-test", EventUID: "dddddddd-dddd-4ddd-dddd-dddddddddddd"}
	target := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-1", UID: "eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee"}}
	decision := voiceMemoryDecision{Action: voiceAgencyAction, Selected: true, TickID: "tick-1", DecisionID: "decision-1"}
	op := voiceAgencyOperationID(policyUID, uid, string(target.UID), event.EventUID, decision.TickID, decision.DecisionID)
	desired, err := voicerefundpolicy.Append(prior, voicerefundpolicy.Entry{AssertedCallerSHA256: caller, OrderSHA256: order}, op)
	if err != nil {
		t.Fatal(err)
	}
	receipt := voiceAgencyJournalReceipt{Version: 1, Phase: "terminal-full", PolicyName: voiceAgencyPolicyName, PolicyUID: policyUID,
		PolicyGeneration: 3, DeploymentUID: uid, TargetName: target.Name, TargetPodUID: string(target.UID), EventName: event.EventName,
		EventUID: event.EventUID, CreatorIdentity: before.EventCreator, TickID: decision.TickID, SelectionDecisionID: decision.DecisionID,
		ConfigMapUID: before.ConfigMapUID, Prior: prior, Desired: desired, OperationID: op}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceAgencyJournalName(uid, 1), Namespace: "phorvex-system",
		Labels: map[string]string{"phorvex.ai/voice-refund-journal": "v1"}}, Data: map[string]string{"receipt.json": string(voiceAgencyCanonicalReceipt(receipt))}}
	if _, err := voiceAgencyValidateJournal(cm, before, decision, event, target, caller, order); err != nil {
		t.Fatalf("terminal join refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*voiceAgencyJournalReceipt)
	}{
		{"pending", func(r *voiceAgencyJournalReceipt) { r.Phase = "prepared" }},
		{"foreign-decision", func(r *voiceAgencyJournalReceipt) { r.SelectionDecisionID = "other" }},
		{"foreign-event", func(r *voiceAgencyJournalReceipt) { r.EventUID = "other" }},
		{"wrong-pod", func(r *voiceAgencyJournalReceipt) { r.TargetPodUID = "other" }},
		{"wrong-pair", func(r *voiceAgencyJournalReceipt) { r.Desired.Entries[0].OrderSHA256 = voiceAgencyStringDigest("9141") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := receipt
			bad.Desired.Entries = append([]voicerefundpolicy.Entry{}, receipt.Desired.Entries...)
			tc.change(&bad)
			copy := cm.DeepCopy()
			copy.Data["receipt.json"] = string(voiceAgencyCanonicalReceipt(bad))
			if _, err := voiceAgencyValidateJournal(copy, before, decision, event, target, caller, order); err == nil {
				t.Fatal("foreign or unfinished journal accepted")
			}
		})
	}
}
