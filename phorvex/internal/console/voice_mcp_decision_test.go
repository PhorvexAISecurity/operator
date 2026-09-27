package console

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestVoiceMCPJournalJoinsExactSelectedDecisionAndSource(t *testing.T) {
	before := voiceMCPSnapshot{DeploymentUID: "deployment", PolicyUID: "policy", PolicyGeneration: 4,
		ConfigMapUID: "rule-uid", SourceConfigMapUID: "source-uid", MCPServiceUID: "service-uid",
		MCPPodName: "mcp-pod", MCPPodUID: "mcp-pod-uid", MCPDeploymentUID: "mcp-deployment",
		MCPConfigMapUID: "mcp-source-uid", MCPSourceSHA256: voiceMCPStringSHA("server"),
		MCPApprovedImage: "registry.example/mcp@sha256:" + voiceMCPStringSHA("image"),
		EventCreator:     "system:serviceaccount:phorvex-system:phorvex-phorvex-console"}
	before.Rule = voiceMCPRule{Version: 1, DeploymentUID: before.DeploymentUID, PolicyUID: before.PolicyUID,
		SourceSHA256: voiceMCPStringSHA("voice"), Entries: []voiceMCPEntry{}}
	decision := voiceMCPDecision{voiceMemoryDecision: voiceMemoryDecision{Action: voiceMCPAction, TickID: "tick", DecisionID: "decision", Selected: true}}
	event := &attackStimulusEvidence{EventName: "event", EventUID: "event-uid"}
	target := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-pod", UID: types.UID("voice-pod-uid")}}
	runSHA, observedSHA := voiceMCPStringSHA("run"), voiceMCPStringSHA("bad descriptor")
	op := voiceMCPOperationID(before, string(target.UID), event.EventUID, runSHA, decision.TickID, decision.DecisionID)
	desired, err := voiceMCPAppend(before.Rule, op)
	if err != nil {
		t.Fatal(err)
	}
	receipt := voiceMCPJournalReceipt{Version: 1, Phase: "terminal-full", PolicyName: voiceMCPPolicyName,
		PolicyUID: before.PolicyUID, PolicyGeneration: before.PolicyGeneration, DeploymentUID: before.DeploymentUID,
		TargetName: target.Name, TargetPodUID: string(target.UID), EventName: event.EventName, EventUID: event.EventUID,
		RunSHA256: runSHA, CreatorIdentity: before.EventCreator, TickID: decision.TickID,
		SelectionDecisionID: decision.DecisionID, ConfigMapUID: before.ConfigMapUID, SourceConfigMapUID: before.SourceConfigMapUID,
		MCPServiceName: "mcp-server", MCPServiceUID: before.MCPServiceUID, MCPPodName: before.MCPPodName,
		MCPPodUID: before.MCPPodUID, MCPDeploymentUID: before.MCPDeploymentUID, MCPConfigMapUID: before.MCPConfigMapUID,
		MCPSourceSHA256: before.MCPSourceSHA256, MCPApprovedImage: before.MCPApprovedImage,
		ObservedDescriptorSHA256: observedSHA, ToolName: "store_directory", Prior: before.Rule,
		Desired: desired, OperationID: op}
	toCM := func(value voiceMCPJournalReceipt) *corev1.ConfigMap {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		var canonical any
		if e = json.Unmarshal(b, &canonical); e != nil {
			t.Fatal(e)
		}
		b, e = json.Marshal(canonical)
		if e != nil {
			t.Fatal(e)
		}
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceMCPJournalName(before.DeploymentUID, 1),
			Namespace: "phorvex-system", UID: types.UID("journal-uid"), Labels: map[string]string{"phorvex.ai/voice-mcp-journal": "v1"}},
			Data: map[string]string{"receipt.json": string(b)}}
	}
	if _, err = voiceMCPValidateJournal(toCM(receipt), before, decision, event, target, runSHA, observedSHA); err != nil {
		t.Fatalf("exact terminal receipt refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*voiceMCPJournalReceipt)
	}{
		{"prepared", func(r *voiceMCPJournalReceipt) { r.Phase = "prepared" }},
		{"wrong tick", func(r *voiceMCPJournalReceipt) { r.TickID = "other" }},
		{"wrong decision", func(r *voiceMCPJournalReceipt) { r.SelectionDecisionID = "other" }},
		{"wrong event", func(r *voiceMCPJournalReceipt) { r.EventUID = "other" }},
		{"wrong target", func(r *voiceMCPJournalReceipt) { r.TargetPodUID = "other" }},
		{"wrong image", func(r *voiceMCPJournalReceipt) { r.MCPApprovedImage = "other" }},
		{"wrong desired", func(r *voiceMCPJournalReceipt) { r.Desired.OperationID = voiceMCPStringSHA("other") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := receipt
			changed.Desired.Entries = append([]voiceMCPEntry{}, receipt.Desired.Entries...)
			tc.edit(&changed)
			if _, e := voiceMCPValidateJournal(toCM(changed), before, decision, event, target, runSHA, observedSHA); e == nil {
				t.Fatal("forged or partial journal credited")
			}
		})
	}
}
