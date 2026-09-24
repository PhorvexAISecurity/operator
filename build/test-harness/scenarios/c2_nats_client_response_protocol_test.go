package scenarios

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

func responseTestReceipt(kind, phase, status, subject, digest string) natsResponseObserverReceipt {
	r := natsResponseObserverReceipt{Kind: kind, Phase: phase, Status: status, Subject: subject,
		Nonce: "0123456789abcdef01234567", PodUID: "pod-owned-uid", ServerID: "N" + strings.Repeat("A", 55)}
	if kind == "subscription" {
		r.Flushed = true
	} else if status == "EXACT_PAYLOAD_RECEIVED" {
		r.PayloadBytes = 24
		r.PayloadSHA256 = digest
		r.NonceHeaderMatches = true
		r.PayloadHashMatches = true
	}
	return r
}

func responseTestLog(rows ...natsResponseObserverReceipt) []byte {
	var b bytes.Buffer
	for _, r := range rows {
		raw, _ := json.Marshal(r)
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func TestNATSResponseReceiptJoinsExactTwoPhasePodAndBroker(t *testing.T) {
	id := natsResponseObserverIdentity{Nonce: "0123456789abcdef01234567", PodUID: "pod-owned-uid",
		SubjectM0: "cat.response.0123456789abcdef01234567.m0", SubjectM1: "cat.response.0123456789abcdef01234567.m1",
		PayloadM0SHA256: strings.Repeat("a", 64), PayloadM1SHA256: strings.Repeat("b", 64),
		ServerIDs: map[string]bool{"N" + strings.Repeat("A", 55): true}}
	rows := []natsResponseObserverReceipt{
		responseTestReceipt("subscription", "M0", "READY", id.SubjectM0, ""),
		responseTestReceipt("subscription", "M1", "READY", id.SubjectM1, ""),
		responseTestReceipt("observation", "M0", "EXACT_PAYLOAD_RECEIVED", id.SubjectM0, id.PayloadM0SHA256),
		responseTestReceipt("observation", "M1", "EXACT_PAYLOAD_RECEIVED", id.SubjectM1, id.PayloadM1SHA256),
	}
	for n := 2; n <= 4; n++ {
		got, err := validateNATSResponseLog(responseTestLog(rows[:n]...), id, n)
		if err != nil || len(got) != n {
			t.Fatalf("valid prefix %d refused: %v", n, err)
		}
	}
	mutations := []func([]natsResponseObserverReceipt){
		func(r []natsResponseObserverReceipt) { r[2].PodUID = "same-name-replacement" },
		func(r []natsResponseObserverReceipt) { r[3].ServerID = "N" + strings.Repeat("B", 55) },
		func(r []natsResponseObserverReceipt) { r[2], r[3] = r[3], r[2] },
		func(r []natsResponseObserverReceipt) {
			r[2].Status = "TIMEOUT_UNKNOWN"
			r[2].PayloadSHA256 = ""
			r[2].PayloadBytes = 0
			r[2].NonceHeaderMatches = false
			r[2].PayloadHashMatches = false
		},
		func(r []natsResponseObserverReceipt) { r[3].PayloadSHA256 = strings.Repeat("c", 64) },
		func(r []natsResponseObserverReceipt) { r[1].Flushed = false },
	}
	for i, mutate := range mutations {
		copy := append([]natsResponseObserverReceipt(nil), rows...)
		mutate(copy)
		if _, err := validateNATSResponseLog(responseTestLog(copy...), id, 4); err == nil {
			t.Errorf("wrong two-phase identity/control %d accepted", i)
		}
	}
	copy := append([]natsResponseObserverReceipt(nil), rows...)
	copy[3] = responseTestReceipt("observation", "M1", "TIMEOUT_UNKNOWN", id.SubjectM1, "")
	if got, err := validateNATSResponseLog(responseTestLog(copy...), id, 4); err != nil || got[3].Status != "TIMEOUT_UNKNOWN" {
		t.Fatalf("M1 timeout should remain unknown: %+v %v", got, err)
	}
	bad := bytes.Replace(responseTestLog(rows...), []byte(`"podUID":"pod-owned-uid"`), []byte(`"podUID":"pod-owned-uid","podUID":"pod-owned-uid"`), 1)
	if _, err := validateNATSResponseLog(bad, id, 4); err == nil {
		t.Fatal("duplicate receipt authority accepted")
	}
}

func TestNATSResponsePeerReceiptCannotBeSubstitutedForSource(t *testing.T) {
	const nonce = "0123456789abcdef01234567"
	id := natsResponseObserverIdentity{Nonce: nonce, PodUID: "legitimate-peer-uid",
		SubjectM0: "cat.response." + nonce + ".m0", SubjectM1: "cat.response." + nonce + ".m1",
		PayloadM0SHA256: strings.Repeat("a", 64), PayloadM1SHA256: strings.Repeat("b", 64),
		ServerIDs: map[string]bool{"N" + strings.Repeat("A", 55): true}}
	rows := []natsResponseObserverReceipt{
		responseTestReceipt("subscription", "M0", "READY", id.SubjectM0, ""),
		responseTestReceipt("subscription", "M1", "READY", id.SubjectM1, ""),
		responseTestReceipt("observation", "M0", "EXACT_PAYLOAD_RECEIVED", id.SubjectM0, id.PayloadM0SHA256),
		responseTestReceipt("observation", "M1", "EXACT_PAYLOAD_RECEIVED", id.SubjectM1, id.PayloadM1SHA256),
	}
	for i := range rows {
		rows[i].PodUID = "legitimate-peer-uid"
	}
	if got, err := validateNATSResponseLog(responseTestLog(rows...), id, 4); err != nil || len(got) != 4 {
		t.Fatalf("exact original peer receipt refused: %v", err)
	}
	id.PodUID = "source-uid"
	if _, err := validateNATSResponseLog(responseTestLog(rows...), id, 4); err == nil {
		t.Fatal("legitimate peer receipt credited to source Pod")
	}
	rows[3].Status = "TIMEOUT_UNKNOWN"
	rows[3].PayloadSHA256 = ""
	rows[3].PayloadBytes = 0
	rows[3].NonceHeaderMatches, rows[3].PayloadHashMatches = false, false
	id.PodUID = "legitimate-peer-uid"
	if got, err := validateNATSResponseLog(responseTestLog(rows...), id, 4); err != nil || got[3].Status != "TIMEOUT_UNKNOWN" {
		t.Fatalf("missing peer M1 receipt hidden: %v", err)
	}
}

func responseTestRequest() natsResponseSignalRequest {
	return natsResponseSignalRequest{Schema: natsResponseSchema, RunID: "run-7", Nonce: "0123456789abcdef01234567",
		Namespace: "phorvex-nats-exposure-fixture", NamespaceUID: types.UID("fixture-ns-uid"), ClientPod: "nats-client-0123456789abcdef01234567",
		ClientPodUID: types.UID("client-uid"), PeerPodUID: types.UID("peer-uid"), PolicyName: "nats-response-0123456789abcdef01234567",
		PolicyUID: types.UID("policy-uid"), PolicyGeneration: 1, ManagerPodUID: types.UID("manager-uid"),
		ManagerContainerID: "container://manager", M0ReceiptSHA256: strings.Repeat("a", 64),
		PeerM0ReceiptSHA256: strings.Repeat("d", 64)}
}

func TestNATSResponseSignalBarrierIsOneShotAndExact(t *testing.T) {
	out := t.TempDir()
	r := responseTestRequest()
	if err := writeNATSResponseRequest(out, r); err != nil {
		t.Fatal(err)
	}
	if err := writeNATSResponseRequest(out, r); err == nil {
		t.Fatal("second request published over prior intent")
	}
	if _, err := os.Stat(filepath.Join(out, "nats-response-signal-request.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("ordinary refused replay should not make another temp write")
	}
	if err := validateNATSResponseRequest(r); err != nil {
		t.Fatal(err)
	}
	r.ClientPodUID = r.PeerPodUID
	if err := validateNATSResponseRequest(r); err == nil {
		t.Fatal("same source and legitimate Pod UID accepted")
	}
	r = responseTestRequest()
	r.PeerM0ReceiptSHA256 = "foreign"
	if err := validateNATSResponseRequest(r); err == nil {
		t.Fatal("unbound peer M0 prefix accepted")
	}
}

func TestNATSResponseDecisionRefusesDuplicateAndLinkedFile(t *testing.T) {
	r := responseTestRequest()
	d := natsResponseSignalDecision{Schema: natsResponseSchema, RunID: r.RunID, Nonce: r.Nonce,
		NamespaceUID: r.NamespaceUID, ClientPodUID: r.ClientPodUID, PeerPodUID: r.PeerPodUID,
		PolicyUID: r.PolicyUID, PolicyGeneration: r.PolicyGeneration, ManagerPodUID: r.ManagerPodUID,
		ManagerContainerID: r.ManagerContainerID, M0ReceiptSHA256: r.M0ReceiptSHA256,
		PeerM0ReceiptSHA256: r.PeerM0ReceiptSHA256,
		EventName:           "owned-event", EventUID: "event-uid",
		AttackID: "attack-1", DecisionID: "decision-1", DecisionTraceSHA256: strings.Repeat("b", 64), DecisionEvidenceSHA256: strings.Repeat("c", 64),
		SelectedAction: "quarantine", DispatchOutcome: "emitted", EffectStatus: "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED", EventCleanupStatus: "CONFIRMED_ABSENT"}
	out := t.TempDir()
	path := filepath.Join(out, "nats-response-signal-decision.json")
	raw, _ := json.Marshal(d)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readNATSResponseDecision(out, r); err != nil || got.DecisionID != d.DecisionID {
		t.Fatalf("exact decision rejected: %+v %v", got, err)
	}
	noop := d
	noop.SelectedAction, noop.DispatchOutcome, noop.EffectStatus = "noop", "not-attempted", "NOT_DISPATCHED"
	noopRaw, _ := json.Marshal(noop)
	if err := os.WriteFile(path, noopRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readNATSResponseDecision(out, r); err != nil || got.SelectedAction != "noop" {
		t.Fatalf("trusted-event no-op barrier refused: %+v %v", got, err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"runId":"run-7"`), []byte(`"runId":"run-7","runId":"run-7"`), 1),
		bytes.Replace(raw, []byte(`"clientPodUID":"client-uid"`), []byte(`"clientPodUID":"other-uid"`), 1),
		bytes.Replace(raw, []byte(`"peerM0ReceiptSHA256":"`+r.PeerM0ReceiptSHA256+`"`), []byte(`"peerM0ReceiptSHA256":"`+strings.Repeat("e", 64)+`"`), 1),
		bytes.Replace(raw, []byte(`"policyUID":"policy-uid"`), []byte(`"PolicyUID":"policy-uid"`), 1),
		bytes.Replace(raw, []byte(`"effectStatus":"OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED"`), []byte(`"effectStatus":"UNKNOWN"`), 1),
		bytes.Replace(raw, []byte(`"selectedAction":"quarantine"`), []byte(`"selectedAction":"rotate"`), 1),
	} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readNATSResponseDecision(out, r); err == nil {
			t.Fatal("ambiguous or different decision identity accepted")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside.json"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSResponseDecision(out, r); err == nil {
		t.Fatal("symlink decision accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(out, "second-name.json")
	if err := os.WriteFile(linked, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(linked, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSResponseDecision(out, r); err == nil {
		t.Fatal("hardlinked decision accepted")
	}
}
