package voiceadmissionpolicy

import (
	"strings"
	"testing"
)

func testPreparedReceipt(t *testing.T) Receipt {
	t.Helper()
	prior := testRule()
	op, err := OperationID(testUID, testUID, testUID, 1, testUID, "tick", "selection", prior.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	desired, err := Enforce(prior, op)
	if err != nil {
		t.Fatal(err)
	}
	return Receipt{Version: 1, Phase: "prepared", PolicyName: "voice-defense", PolicyUID: testUID, PolicyGeneration: 1, DeploymentUID: testUID, TargetName: "voice-bot", TargetPodUID: testUID, EventName: "actual-loss", EventUID: testUID, CreatorIdentity: Creator, TickID: "tick", SelectionDecisionID: "selection", ConfigMapUID: testUID, SourceConfigMapUID: testUID, SessionID: testUID, RunSHA256: strings.Repeat("a", 64), ReceiptSHA256: strings.Repeat("b", 64), ProviderEvidenceSHA256: strings.Repeat("c", 64), Prior: prior, Desired: desired, OperationID: op, PodReceipts: []State{}}
}

func TestProtectedJournalPreservesOriginalSelectionAndOneWayHistory(t *testing.T) {
	r := testPreparedReceipt(t)
	j := Journal{Version: 1, Receipts: []Receipt{r}}
	if _, err := ParseJournal(string(j.Bytes())); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Receipt){func(r *Receipt) { r.SelectionDecisionID = "new-selection" }, func(r *Receipt) { r.EventUID = "22222222-2222-4222-8222-222222222222" }, func(r *Receipt) { r.Desired = r.Prior }, func(r *Receipt) { r.Phase = "terminal-full" }, func(r *Receipt) { r.Prior = r.Desired }} {
		bad := r
		change(&bad)
		if _, err := ParseJournal(string((Journal{Version: 1, Receipts: []Receipt{bad}}).Bytes())); err == nil {
			t.Fatal("protected history drift accepted")
		}
	}
	if _, err := ParseJournal(string((Journal{Version: 1, Receipts: []Receipt{r, r}}).Bytes())); err == nil {
		t.Fatal("second operation can occupy one-way journal")
	}
	r.Phase = "terminal-full"
	s := testState()
	s.OperationID = r.OperationID
	s.RuleSHA256 = r.Desired.SHA256()
	r.PodReceipts = []State{s}
	if _, err := ParseJournal(string((Journal{Version: 1, Receipts: []Receipt{r}}).Bytes())); err != nil {
		t.Fatal(err)
	}
	r.PodReceipts[0].ActiveUnsigned = 1
	if _, err := ParseJournal(string((Journal{Version: 1, Receipts: []Receipt{r}}).Bytes())); err == nil {
		t.Fatal("terminal history claimed an active unsigned session settled")
	}
}
