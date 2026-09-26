package console

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestNATSResponseRequestRefusesAmbiguousAndLinkedInput(t *testing.T) {
	out := t.TempDir()
	name := filepath.Join(out, "nats-response-signal-request.json")
	want := natsResponseRequestWire{Schema: natsResponseSchema, RunID: "run-7", Nonce: strings.Repeat("a", 24),
		Namespace: natsFixtureNamespace, NamespaceUID: "namespace-uid", ClientPod: "client", ClientPodUID: "client-uid",
		PeerPodUID: "peer-uid", PolicyName: "nats-response-" + strings.Repeat("a", 24), PolicyUID: "policy-uid",
		PolicyGeneration: 3, ManagerPodUID: "manager-uid", ManagerContainerID: "containerd://manager",
		M0ReceiptSHA256: strings.Repeat("b", 64), PeerM0ReceiptSHA256: strings.Repeat("f", 64)}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readNATSResponseRequest(out, "run-7"); err != nil || got.ClientPodUID != want.ClientPodUID {
		t.Fatalf("valid owned request refused: %+v %v", got, err)
	}
	if err := os.Link(name, filepath.Join(out, "extra-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSResponseRequest(out, "run-7"); err == nil {
		t.Fatal("hardlinked request admitted")
	}
	if err := os.Remove(filepath.Join(out, "extra-link")); err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(raw), `"schema":"nats-client-response-v1"`, `"schema":"nats-client-response-v1","schema":"nats-client-response-v1"`, 1)
	if err := os.WriteFile(name, []byte(duplicate), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSResponseRequest(out, "run-7"); err == nil {
		t.Fatal("duplicate request key admitted")
	}
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSResponseRequest(out, "run-8"); err == nil {
		t.Fatal("other run's request admitted")
	}
}

func TestNATSDecisionVocabularyPreservesHistoricalWHYReceipts(t *testing.T) {
	legacy, err := model.DecisionTraceActions("")
	if err != nil || len(legacy) != 15 {
		t.Fatal("frozen legacy action vocabulary unavailable")
	}
	current, err := model.DecisionTraceActions(model.DecisionActionVocabularyOutput16)
	if err != nil || len(current) != 16 {
		t.Fatal("named current action vocabulary unavailable")
	}
	rows := func(actions []model.Action) []natsDecisionActionStatus {
		out := make([]natsDecisionActionStatus, len(actions))
		for i, action := range actions {
			out[i].Action = string(action)
		}
		return out
	}
	if !natsDecisionVocabularyValid("", rows(legacy), nil, "quarantine") ||
		!natsDecisionVocabularyValid(model.DecisionActionVocabularyOutput16, rows(current), nil, "quarantine") {
		t.Fatal("valid retained legacy or named current WHY rejected")
	}
	if natsDecisionVocabularyValid(model.DecisionActionVocabularyOutput16, rows(legacy), nil, "quarantine") ||
		natsDecisionVocabularyValid("", rows(current), nil, "quarantine") ||
		natsDecisionVocabularyValid("unknown", rows(current), nil, "quarantine") {
		t.Fatal("wrong marker or row count accepted")
	}
	newAction := string(model.ActionSensitiveOutputPolicyActivate)
	if natsDecisionVocabularyValid("", rows(legacy), []natsDecisionCandidate{{Action: newAction}}, "quarantine") ||
		natsDecisionVocabularyValid("", rows(legacy), nil, newAction) {
		t.Fatal("new action accepted under historical unmarked vocabulary")
	}
}

func TestNATSDecisionProducerRefusesV2NewActionBeforeWritingWHY(t *testing.T) {
	r := natsResponseRequest{Namespace: natsFixtureNamespace, ClientPod: "client", ClientPodUID: "client-uid",
		PolicyName: "policy", PolicyUID: "policy-uid"}
	trace := caseTraceValidTrace(time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), false, false)
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = r.Namespace, r.PolicyName, r.PolicyUID
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = r.Namespace, r.ClientPod, r.ClientPodUID
	trace.DispatchOutcome = model.DispatchNotAttempted
	trace.ActionStatus = nil
	actions, err := model.DecisionTraceActions("")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		trace.ActionStatus = append(trace.ActionStatus, model.DecisionActionStatusV3{Action: string(action), Status: model.ActionStatusNotEnabled, ExclusionKind: model.ExclusionNotEnabled})
	}
	trace.Candidates[0].Action = string(model.ActionSensitiveOutputPolicyActivate)
	if err := trace.Validate(); err != nil {
		t.Fatalf("v2 edge fixture did not reach publisher: %v", err)
	}
	out := t.TempDir()
	rec := &audit.Record{Action: string(model.ActionNoop), DispatchOutcome: model.DispatchNotAttempted, DecisionTrace: trace}
	created := &attackStimulusEvidence{EventName: "owned-event", EventUID: "event-uid"}
	if _, err := publishNATSDecisionEvidence(out, r, rec, strings.Repeat("a", 64), created, nil); err == nil {
		t.Fatal("producer wrote unmarked v2 WHY with a new candidate action")
	}
	if _, err := os.Stat(filepath.Join(out, "nats-response-decision-evidence.json")); !os.IsNotExist(err) {
		t.Fatal("invalid v2 vocabulary left a WHY receipt")
	}
}

func TestNATSResponseReaderRefusesFIFOAndMetadataDrift(t *testing.T) {
	out := t.TempDir()
	name := "nats-response-signal-request.json"
	path := filepath.Join(out, name)
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSResponseSizedFile(out, name, 4096); err == nil {
		t.Fatal("FIFO accepted as run-owned receipt")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("receipt"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if sameNATSResponseFileState(before, after) {
		t.Fatal("same-inode metadata/content drift accepted")
	}
	if got, err := readNATSResponseSizedFile(out, name, 4096); err != nil || string(got) != "changed" {
		t.Fatalf("stable regular file refused: %q %v", got, err)
	}
}

func TestNATSResponseDecisionPublicationIsOneShotAndDigestBound(t *testing.T) {
	out := t.TempDir()
	d := natsResponseDecision{Schema: natsResponseSchema, RunID: "run-7", Nonce: strings.Repeat("a", 24),
		EventUID: "event-uid", DecisionID: "decision-id", DecisionEvidenceSHA256: strings.Repeat("f", 64),
		PeerM0ReceiptSHA256: strings.Repeat("e", 64),
		EventCleanupStatus:  "CONFIRMED_ABSENT"}
	if err := publishNATSResponseDecision(out, d); err != nil {
		t.Fatal(err)
	}
	if err := publishNATSResponseDecision(out, d); err == nil {
		t.Fatal("second decision publication admitted")
	}
	if _, err := os.Stat(filepath.Join(out, "nats-response-signal-decision.json")); err != nil {
		t.Fatal(err)
	}
	d.DecisionEvidenceSHA256 = "INVALID"
	if err := publishNATSResponseDecision(t.TempDir(), d); err == nil {
		t.Fatal("invalid evidence digest admitted")
	}
}

func TestNATSResponseQuarantineOperationIsCapacityIdentity(t *testing.T) {
	got := natsQuarantineOperationID("policy-uid", natsFixtureNamespace, "client-uid")
	if got != "4697b6f5162851ed7542951926aaf72c4030ee7d" {
		t.Fatalf("capacity operation contract drifted: %q", got)
	}
	if got == "decision-id" {
		t.Fatal("optimizer decision ID cannot substitute for capacity operation")
	}
}

func TestNATSResponsePhoenixControllerOwner(t *testing.T) {
	uid := types.UID("amtd-uid")
	ref := metav1.OwnerReference{APIVersion: "amtd.r6security.com/v1beta1", Kind: "AdaptiveMovingTargetDefense", Name: "owned-amtd", UID: uid}
	if natsAMTDController(ref, "owned-amtd", uid) {
		t.Fatal("non-controller owner reference admitted")
	}
	falseValue, trueValue := false, true
	ref.Controller = &falseValue
	if natsAMTDController(ref, "owned-amtd", uid) {
		t.Fatal("explicit false controller admitted")
	}
	ref.Controller = &trueValue
	if !natsAMTDController(ref, "owned-amtd", uid) || natsAMTDController(ref, "owned-amtd", types.UID("replaced")) {
		t.Fatal("exact controller ownership contract differs")
	}
}

// This identity is from the admitted round-20 Phoenix API projection, not a
// native-quarantine fixture: it had one AMTD-owned Phoenix NetworkPolicy.
func TestNATSResponseRound20PhoenixProducedIdentity(t *testing.T) {
	r := natsResponseRequest{Nonce: "cat-token-18f24007963d4f63", Namespace: "voice",
		ClientPod:    "cat-token-18f24007963d4f63-84d977f4b7-g6rt5",
		ClientPodUID: "49c0cb67-e62c-45f7-a162-a0f1a006ad56",
		PeerPodUID:   "5a759951-5ac4-466c-bf41-5a31911ac342",
		PolicyUID:    "6c5219a8-fd9d-4da0-854d-3427b1cfd4d9"}
	e := &natsQuarantineEffect{GeneratedEventName: "phorvex-quarantine-9s44f", GeneratedEventUID: "16b79401-f96e-457f-98f5-ef0d3e3c753a",
		OperationID: "74d0a47acc55c040fdfba61c9db5c03dec047285", AMTDName: "phorvex-voice-cat-token-18f24007963d4f63",
		AMTDUID:                  "d5b4bd56-09cf-48be-8644-5ba876a75621",
		PhoenixNetworkPolicyName: "voice-cat-token-18f24007963d4f63-84d977f4b7-g6rt5-policy",
		PhoenixNetworkPolicyUID:  "5e8b850a-e4bc-470a-b8a4-f18ce5c91ba7", SourcePodUID: r.ClientPodUID, PeerPodUID: r.PeerPodUID}
	if !natsQuarantineEffectMatches(e, r) {
		t.Fatal("actual Phoenix identity projection rejected")
	}
	recreated := *e
	recreated.PhoenixNetworkPolicyUID = ""
	if natsQuarantineEffectMatches(&recreated, r) {
		t.Fatal("unbound Phoenix policy admitted")
	}
	recreated = *e
	recreated.OperationID = "c04f66483136278b978c16d3b6fe81f7" // optimizer decision ID is not capacity operation ID.
	if natsQuarantineEffectMatches(&recreated, r) {
		t.Fatal("decision ID substituted for generated operation")
	}
}

func TestNATSResponseTerminalJoinsPacketDecisionAndCleanup(t *testing.T) {
	out := t.TempDir()
	nonce := strings.Repeat("a", 24)
	write := func(name string, v any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	req := natsResponseRequestWire{Schema: natsResponseSchema, RunID: "run-7", Nonce: nonce, Namespace: natsFixtureNamespace, NamespaceUID: "namespace-uid",
		ClientPod: "client", ClientPodUID: "client-uid", PeerPodUID: "peer-uid", PolicyName: "nats-response-" + nonce, PolicyUID: "policy-uid", PolicyGeneration: 3,
		ManagerPodUID: "manager-uid", ManagerContainerID: "containerd://manager"}
	m0Hash, m1Hash := natsSHA([]byte("phorvex-owned-nats-response:"+nonce+":M0")), natsSHA([]byte("phorvex-owned-nats-response:"+nonce+":M1"))
	makePrefix := func(uid string) ([]natsResponseReceipt, []byte) {
		t.Helper()
		rows := []map[string]any{
			{"kind": "subscription", "phase": "M0", "status": "READY", "subject": "cat.response." + nonce + ".m0", "nonce": nonce, "podUID": uid, "serverID": "NATS-SERVER", "flushed": true},
			{"kind": "subscription", "phase": "M1", "status": "READY", "subject": "cat.response." + nonce + ".m1", "nonce": nonce, "podUID": uid, "serverID": "NATS-SERVER", "flushed": true},
			{"kind": "observation", "phase": "M0", "status": "EXACT_PAYLOAD_RECEIVED", "subject": "cat.response." + nonce + ".m0", "nonce": nonce, "podUID": uid, "serverID": "NATS-SERVER", "payloadBytes": 32, "payloadSHA256": m0Hash, "nonceHeaderMatches": true, "payloadHashMatches": true},
		}
		var raw []byte
		outRows := make([]natsResponseReceipt, len(rows))
		for i, row := range rows {
			line, err := json.Marshal(row)
			if err != nil || json.Unmarshal(line, &outRows[i]) != nil {
				t.Fatal("invalid producer-shaped observer receipt")
			}
			raw = append(raw, line...)
			raw = append(raw, '\n')
		}
		return outRows, raw
	}
	sourceM0, sourceRaw := makePrefix(req.ClientPodUID)
	peerM0, peerRaw := makePrefix(req.PeerPodUID)
	req.M0ReceiptSHA256, req.PeerM0ReceiptSHA256 = natsSHA(sourceRaw), natsSHA(peerRaw)
	for name, raw := range map[string][]byte{"nats-response-m0-prefix.jsonl": sourceRaw, "nats-response-peer-m0-prefix.jsonl": peerRaw} {
		if err := os.WriteFile(filepath.Join(out, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	requestRaw := write("nats-response-signal-request.json", req)
	d := natsResponseDecision{Schema: natsResponseSchema, RunID: req.RunID, Nonce: nonce, NamespaceUID: req.NamespaceUID, ClientPodUID: req.ClientPodUID,
		PeerPodUID: req.PeerPodUID, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration, ManagerPodUID: req.ManagerPodUID,
		ManagerContainerID: req.ManagerContainerID, M0ReceiptSHA256: req.M0ReceiptSHA256, PeerM0ReceiptSHA256: req.PeerM0ReceiptSHA256,
		EventName: "event", EventUID: "event-uid", AttackID: "attack",
		DecisionID: "decision", DecisionTraceSHA256: strings.Repeat("c", 64), SelectedAction: "quarantine", DispatchOutcome: "emitted",
		EffectStatus: "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED", EventCleanupStatus: "CONFIRMED_ABSENT"}
	why := natsDecisionEvidence{Schema: "nats-client-response-decision-evidence-v1", RunID: req.RunID, NamespaceUID: req.NamespaceUID,
		ClientPodUID: req.ClientPodUID, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration, ManagerPodUID: req.ManagerPodUID,
		ManagerContainerID: req.ManagerContainerID, M0ReceiptSHA256: req.M0ReceiptSHA256, PeerM0ReceiptSHA256: req.PeerM0ReceiptSHA256,
		EventName: d.EventName, EventUID: d.EventUID,
		DecisionID: d.DecisionID, DecisionTraceSHA256: d.DecisionTraceSHA256, BrainImageSHA256: strings.Repeat("e", 64), SelectedAction: d.SelectedAction, DispatchOutcome: d.DispatchOutcome,
		ObjectEffect: &natsQuarantineEffect{GeneratedEventName: "phorvex-quarantine-abcde", GeneratedEventUID: "generated-uid",
			OperationID: natsQuarantineOperationID(req.PolicyUID, req.Namespace, req.ClientPodUID),
			AMTDName:    "phorvex-" + req.Namespace + "-" + nonce, AMTDUID: "amtd-uid",
			PhoenixNetworkPolicyName: req.Namespace + "-" + req.ClientPod + "-policy", PhoenixNetworkPolicyUID: "phoenix-np-uid",
			SourcePodUID: req.ClientPodUID, PeerPodUID: req.PeerPodUID}, Claim: "OBJECT_EFFECT_AND_PACKET_OUTCOME_SEPARATE_SECURITY_NOT_EVALUATED",
		ActionStatus: []natsDecisionActionStatus{}}
	legacyActions, err := model.DecisionTraceActions("")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range legacyActions {
		why.ActionStatus = append(why.ActionStatus, natsDecisionActionStatus{Action: string(action), Status: model.ActionStatusNotEnabled,
			ExclusionKind: model.ExclusionNotEnabled})
	}
	whyRaw := write("nats-response-decision-evidence.json", why)
	d.DecisionEvidenceSHA256 = natsSHA(whyRaw)
	write("nats-response-signal-decision.json", d)
	phase := func(suffix, payload string, n int) natsResultPhase {
		p := natsResultPhase{Stream: "stream-" + suffix, Subject: "cat.response." + nonce + "." + suffix, PayloadSHA256: payload,
			Protocol: natsResultProtocol{Stream: "stream-" + suffix, Subject: "cat.response." + nonce + "." + suffix,
				Consumer: "consumer-" + suffix + "-" + nonce, Nonce: nonce, Phase: strings.ToUpper(suffix),
				WriterServerID: "NATS-SERVER", AdversaryServerID: "NATS-SERVER", SubscriptionFlushed: true, PayloadSHA256: payload,
				StoredPayloadSHA256: payload, LegitimatePayloadSHA256: payload, AdversaryPayloadSHA256: payload,
				AdversaryObservation: "EXACT_PAYLOAD_RECEIVED", Objective: "REACHED", Validity: "VALID", Cleanup: "CONFIRMED_ABSENT",
				PubAckSequence: 1, PublishAttempted: true, LegitimateAcked: true},
			Observer: append([]natsResponseReceipt(nil), sourceM0...), PeerObserver: append([]natsResponseReceipt(nil), peerM0...)}
		if n == 4 {
			newRow := func(uid string) natsResponseReceipt {
				return natsResponseReceipt{Kind: "observation", Phase: "M1", Status: "EXACT_PAYLOAD_RECEIVED",
					Subject: "cat.response." + nonce + ".m1", Nonce: nonce, PodUID: uid, ServerID: "NATS-SERVER",
					PayloadBytes: 32, PayloadSHA256: payload, NonceHeaderMatches: true, PayloadHashMatches: true}
			}
			p.Observer = append(p.Observer, newRow(req.ClientPodUID))
			p.PeerObserver = append(p.PeerObserver, newRow(req.PeerPodUID))
		}
		return p
	}
	httpReceipt := func(kind, pod string) natsResultServiceReceipt {
		r := natsResultServiceReceipt{AddressKind: kind, ServiceUID: "service-uid", PodUID: pod, ServerID: "NATS-SERVER", Status: "HTTP_200", ObservedAt: "2026-09-24T00:00:00Z"}
		if kind == "SERVICE" {
			r.EndpointSliceUID = "slice-uid"
			if pod == req.ClientPodUID {
				r.EndpointMemberUIDs = []string{req.ClientPodUID, req.PeerPodUID}
				r.EndpointMembers = []natsResultServiceMember{
					{PodUID: req.ClientPodUID, PodName: req.ClientPod, PodIP: "10.0.0.1", OwnerKind: "ReplicaSet", OwnerUID: "rs-uid", ContainerID: "container://client", ImageID: "sha256:observer", Ready: true},
					{PodUID: req.PeerPodUID, PodName: "peer", PodIP: "10.0.0.2", OwnerKind: "ReplicaSet", OwnerUID: "rs-uid", ContainerID: "container://peer", ImageID: "sha256:observer", Ready: true}}
			} else {
				r.EndpointMemberUIDs = []string{req.PeerPodUID}
				r.EndpointMembers = []natsResultServiceMember{{PodUID: req.PeerPodUID, PodName: "peer", PodIP: "10.0.0.2", OwnerKind: "ReplicaSet", OwnerUID: "rs-uid", ContainerID: "container://peer", ImageID: "sha256:observer", Ready: true}}
			}
		}
		return r
	}
	a := natsResponseArtifact{Schema: "nats-client-response-artifact-v1", RunID: req.RunID, Nonce: nonce, Namespace: natsFixtureNamespace, NamespaceUID: req.NamespaceUID, ClusterUID: "cluster-uid",
		Fixture: natsResultFixture{Name: req.PolicyName, NamespaceUID: req.NamespaceUID, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration, PolicySpecSHA256: strings.Repeat("e", 64), ServiceUID: "service-uid", ReplicaSetUID: "rs-uid",
			Client: natsResultPod{Name: req.ClientPod, UID: req.ClientPodUID, IP: "10.0.0.1", ContainerID: "container://client", ImageID: "sha256:observer"},
			Peer:   natsResultPod{Name: "peer", UID: req.PeerPodUID, IP: "10.0.0.2", ContainerID: "container://peer", ImageID: "sha256:observer"}},
		Route:         json.RawMessage(`{"clusterUID":"cluster-uid","brokers":[{"serverID":"NATS-SERVER"}]}`),
		ManagerPodUID: req.ManagerPodUID, ManagerContainerID: req.ManagerContainerID, ManagerImageID: "image@sha256:" + strings.Repeat("d", 64),
		M0: phase("m0", m0Hash, 3), M1: phase("m1", m1Hash, 4), SignalRequestSHA256: natsSHA(requestRaw), Decision: &d,
		ServiceBefore: httpReceipt("SERVICE", req.ClientPodUID), PeerBefore: httpReceipt("PEER_DIRECT", req.PeerPodUID),
		ServiceAfter: httpReceipt("SERVICE", req.PeerPodUID), PeerAfter: httpReceipt("PEER_DIRECT", req.PeerPodUID),
		InitialDisclosure: "EXPOSED", OngoingAccess: "CONTINUING_EXPOSURE", LegitimateService: "AVAILABLE", SecurityOutcome: "CONTAINMENT_NOT_ACHIEVED",
		Validity: "MEASUREMENT_COMPLETE", Cleanup: "CONFIRMED_ABSENT", CapacityReservationStatus: "UNRECONCILED_POSSIBLE", Repeatability: "UNKNOWN", ObservedAt: "2026-09-24T00:00:00Z"}
	checks := natsResultCleanupChecks{true, true, true, true, true, true, true, true, true, true, true}
	writePair := func() {
		t.Helper()
		raw := write("nats-response.json", a)
		write("nats-response-terminal.json", natsResponseTerminal{Schema: "nats-client-response-terminal-v1", RunID: req.RunID, Nonce: nonce, NamespaceUID: req.NamespaceUID,
			ArtifactSHA256: natsSHA(raw), Cleanup: "CONFIRMED_ABSENT", CapacityReservationStatus: a.CapacityReservationStatus, Repeatability: a.Repeatability, Checks: checks, ObservedAt: "2026-09-24T00:00:01Z"})
	}
	writePair()
	got, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace)
	if err != nil || !got.Accepted || got.SecurityEfficacy != "CONTAINMENT_NOT_ACHIEVED" || got.DecisionTrace == nil ||
		got.CapacityReservationStatus != "UNRECONCILED_POSSIBLE" || got.Repeatability != "UNKNOWN" {
		t.Fatalf("joined negative observation refused: %+v %v", got, err)
	}
	originalAfter := a.ServiceAfter
	a.ServiceAfter.PodUID = "replacement-uid"
	a.ServiceAfter.EndpointMemberUIDs = []string{req.PeerPodUID, "replacement-uid"}
	a.ServiceAfter.EndpointMembers = append(append([]natsResultServiceMember(nil), originalAfter.EndpointMembers...),
		natsResultServiceMember{PodUID: "replacement-uid", PodName: req.PolicyName + "-replacement", PodIP: "10.0.0.3",
			OwnerKind: "ReplicaSet", OwnerUID: "rs-uid", ContainerID: "container://replacement", ImageID: "sha256:observer", Ready: true})
	writePair()
	if got, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err != nil || !got.Accepted {
		t.Fatalf("exact RS-owned post-response replacement refused: %+v %v", got, err)
	}
	a.ServiceAfter.EndpointMembers[1].OwnerUID = "foreign-rs"
	writePair()
	if got, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err == nil && got.Accepted {
		t.Fatal("foreign replacement Service respondent admitted")
	}
	a.ServiceAfter = originalAfter
	a.M1.PeerObserver[3].PayloadSHA256 = strings.Repeat("0", 64)
	writePair()
	if got, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err == nil && got.Accepted {
		t.Fatal("missing exact legitimate peer M1 payload admitted")
	}
	a.M1.PeerObserver[3].PayloadSHA256 = m1Hash
	if err := os.WriteFile(filepath.Join(out, "nats-response-peer-m0-prefix.jsonl"), append(append([]byte(nil), peerRaw...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	writePair()
	if got, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err == nil && got.Accepted {
		t.Fatal("drifted original peer M0 prefix admitted")
	}
	if err := os.WriteFile(filepath.Join(out, "nats-response-peer-m0-prefix.jsonl"), peerRaw, 0600); err != nil {
		t.Fatal(err)
	}
	a.Validity = "INCONCLUSIVE"
	a.SignalRequestSHA256 = ""
	a.Fixture.PolicySpecSHA256 = ""
	writePair()
	partial, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace)
	if err != nil || partial.Accepted || !partial.CleanupVerified || partial.SecurityEfficacy != "NOT_EVALUATED" ||
		partial.DecisionTrace == nil || partial.DecisionStatus != "RUN_OWNED_WHY_BARRIER_UNVERIFIED" {
		t.Fatalf("partial decision WHY hidden or over-credited: %+v %v", partial, err)
	}
	a.Validity = "MEASUREMENT_COMPLETE"
	a.SignalRequestSHA256 = natsSHA(requestRaw)
	a.Fixture.PolicySpecSHA256 = strings.Repeat("e", 64)
	a.ServiceAfter = httpReceipt("SERVICE", req.ClientPodUID) // The source may remain served when CNI enforcement is absent.
	a.ServiceAfter.EndpointMembers[0].OwnerKind = "AdaptiveMovingTargetDefense"
	a.ServiceAfter.EndpointMembers[0].OwnerUID = why.ObjectEffect.AMTDUID
	writePair()
	if got, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err != nil || !got.Accepted {
		t.Fatalf("exact source Service route refused: %+v %v", got, err)
	}
	a.ServiceAfter.EndpointMemberUIDs = []string{req.PeerPodUID}
	writePair()
	if got, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err == nil && got.Accepted {
		t.Fatal("Service response from a Pod absent from exact EndpointSlice admitted")
	}
	a.ServiceAfter.EndpointMemberUIDs = []string{req.ClientPodUID}
	writePair()
	if got, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err == nil && got.Accepted {
		t.Fatal("Service route without original legitimate peer admitted")
	}
	a.ServiceAfter.EndpointMemberUIDs = []string{req.ClientPodUID, req.PeerPodUID}
	a.M1.Observer[3].PayloadSHA256 = strings.Repeat("e", 64)
	writePair()
	if _, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err == nil {
		t.Fatal("M1 content drift admitted")
	}
	a.M1.Observer[3].PayloadSHA256 = m1Hash
	writePair()
	termPath := filepath.Join(out, "nats-response-terminal.json")
	termRaw, err := os.ReadFile(termPath)
	if err != nil {
		t.Fatal(err)
	}
	var term natsResponseTerminal
	if err := json.Unmarshal(termRaw, &term); err != nil {
		t.Fatal(err)
	}
	term.ArtifactSHA256 = strings.Repeat("0", 64)
	write("nats-response-terminal.json", term)
	if _, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err == nil {
		t.Fatal("unbound terminal receipt admitted")
	}
	writePair()
	nested, err := os.ReadFile(termPath)
	if err != nil {
		t.Fatal(err)
	}
	duplicated := strings.Replace(string(nested), `"namespacePreserved":true`, `"namespacePreserved":true,"namespacePreserved":false`, 1)
	if duplicated == string(nested) {
		t.Fatal("nested terminal test did not inject duplicate")
	}
	if err := os.WriteFile(termPath, []byte(duplicated), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSResponseResult(out, req.RunID, natsFixtureNamespace); err == nil {
		t.Fatal("duplicate nested cleanup claim admitted")
	}
}
