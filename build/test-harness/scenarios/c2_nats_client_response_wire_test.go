package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/natsexposure"
	"k8s.io/apimachinery/pkg/types"
)

// TestNATSResponseEmitWireFixture deliberately uses the production writers and
// receipt decoder. It is a two-stage cross-module fixture: the console's own
// producer publishes decision/WHY between prepare and finish. No fixture bytes
// are accepted as live Kubernetes or manager authority.
func TestNATSResponseEmitWireFixture(t *testing.T) {
	out, phase := os.Getenv("NATS_RESPONSE_WIRE_OUT"), os.Getenv("NATS_RESPONSE_WIRE_PHASE")
	if out == "" && phase == "" {
		t.Skip("cross-module wire fixture not requested")
	}
	if out == "" || (phase != "prepare" && phase != "finish") {
		t.Fatal("NATS_RESPONSE_WIRE_OUT and prepare|finish phase required")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	if phase == "prepare" {
		emitNATSResponseWirePrepare(t, out)
		return
	}
	emitNATSResponseWireFinish(t, out)
}

func natsResponseWireRows(nonce, podUID, server string, want int) ([]byte, []natsResponseObserverReceipt) {
	subjects, payloads := natsResponseSubjects(nonce), natsResponsePayloads(nonce)
	rows := []natsResponseObserverReceipt{
		{Kind: "subscription", Phase: "M0", Status: "READY", Subject: subjects[0], Nonce: nonce, PodUID: podUID, ServerID: server, Flushed: true},
		{Kind: "subscription", Phase: "M1", Status: "READY", Subject: subjects[1], Nonce: nonce, PodUID: podUID, ServerID: server, Flushed: true},
		{Kind: "observation", Phase: "M0", Status: "EXACT_PAYLOAD_RECEIVED", Subject: subjects[0], Nonce: nonce, PodUID: podUID, ServerID: server,
			PayloadBytes: len(payloads[0]), PayloadSHA256: natsSHA(payloads[0]), NonceHeaderMatches: true, PayloadHashMatches: true},
		{Kind: "observation", Phase: "M1", Status: "EXACT_PAYLOAD_RECEIVED", Subject: subjects[1], Nonce: nonce, PodUID: podUID, ServerID: server,
			PayloadBytes: len(payloads[1]), PayloadSHA256: natsSHA(payloads[1]), NonceHeaderMatches: true, PayloadHashMatches: true},
	}
	var raw []byte
	for _, row := range rows[:want] {
		b, _ := json.Marshal(row)
		raw = append(raw, b...)
		raw = append(raw, '\n')
	}
	return raw, rows[:want]
}

func emitNATSResponseWirePrepare(t *testing.T, out string) {
	t.Helper()
	r := responseTestRequest()
	server := "N" + strings.Repeat("A", 55)
	sourceRaw, _ := natsResponseWireRows(r.Nonce, string(r.ClientPodUID), server, 3)
	peerRaw, _ := natsResponseWireRows(r.Nonce, string(r.PeerPodUID), server, 3)
	var err error
	r.M0ReceiptSHA256, err = natsResponsePersistM0Prefix(out, sourceRaw)
	if err != nil {
		t.Fatal(err)
	}
	r.PeerM0ReceiptSHA256, err = natsResponsePersistPeerM0Prefix(out, peerRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNATSResponseRequest(out, r); err != nil {
		t.Fatal(err)
	}
}

func emitNATSResponseWireFinish(t *testing.T, out string) {
	t.Helper()
	var r natsResponseSignalRequest
	requestRaw, err := readNATSResponseFile(out, "nats-response-signal-request.json")
	if err != nil || json.Unmarshal(requestRaw, &r) != nil || validateNATSResponseRequest(r) != nil {
		t.Fatal("prepared request unavailable")
	}
	d, err := readNATSResponseDecision(out, r)
	if err != nil {
		t.Fatal(err)
	}
	whyRaw, err := readNATSResponseFile(out, "nats-response-decision-evidence.json")
	if err != nil || natsSHA(whyRaw) != d.DecisionEvidenceSHA256 {
		t.Fatal("console-produced WHY missing or digest mismatch")
	}
	server := "N" + strings.Repeat("A", 55)
	var phases [2]natsResponsePhaseArtifact
	for i, label := range []string{"M0", "M1"} {
		want := 3
		if i == 1 {
			want = 4
		}
		sourceRaw, _ := natsResponseWireRows(r.Nonce, string(r.ClientPodUID), server, want)
		peerRaw, _ := natsResponseWireRows(r.Nonce, string(r.PeerPodUID), server, want)
		identity := func(uid types.UID) natsResponseObserverIdentity {
			subjects, payloads := natsResponseSubjects(r.Nonce), natsResponsePayloads(r.Nonce)
			return natsResponseObserverIdentity{Nonce: r.Nonce, PodUID: uid, SubjectM0: subjects[0], SubjectM1: subjects[1],
				PayloadM0SHA256: natsSHA(payloads[0]), PayloadM1SHA256: natsSHA(payloads[1]), ServerIDs: map[string]bool{server: true}}
		}
		source, sourceErr := validateNATSResponseLog(sourceRaw, identity(r.ClientPodUID), want)
		peer, peerErr := validateNATSResponseLog(peerRaw, identity(r.PeerPodUID), want)
		if sourceErr != nil || peerErr != nil {
			t.Fatalf("producer receipt invalid: %v %v", sourceErr, peerErr)
		}
		if i == 0 && (natsSHA(sourceRaw) != r.M0ReceiptSHA256 || natsSHA(peerRaw) != r.PeerM0ReceiptSHA256) {
			t.Fatal("prepared prefix bytes differ")
		}
		subjects, payloads := natsResponseSubjects(r.Nonce), natsResponsePayloads(r.Nonce)
		stream := "response-" + strings.ToLower(label) + "-" + r.Nonce
		consumer := "consumer-" + strings.ToLower(label) + "-" + r.Nonce
		hash := natsSHA(payloads[i])
		protocol := natsexposure.Receipt{Stream: stream, Subject: subjects[i], Consumer: consumer, Nonce: r.Nonce,
			WriterServerID: server, AdversaryServerID: server, SubscriptionFlushed: true, PublishAttempted: true,
			PubAckSequence: 1, PayloadSHA256: hash, AdversaryPayloadSHA256: hash, LegitimatePayloadSHA256: hash,
			StoredPayloadSHA256: hash, LegitimateAcked: true, AdversaryObservation: "EXACT_PAYLOAD_RECEIVED",
			Objective: "REACHED", Validity: "VALID", Cleanup: "CONFIRMED_ABSENT", Phase: label}
		phases[i] = natsResponsePhaseArtifact{Stream: stream, Subject: subjects[i], PayloadSHA256: hash,
			Protocol: protocol, Observer: source, PeerObserver: peer}
	}
	memberUIDs := []types.UID{r.ClientPodUID, r.PeerPodUID}
	members := []natsResponseServiceMember{
		{PodUID: r.ClientPodUID, PodName: r.ClientPod, PodIP: "192.0.2.7", OwnerKind: "ReplicaSet", OwnerUID: "rs-uid",
			ContainerID: "containerd://client", ImageID: "image@sha256:" + strings.Repeat("a", 64), Ready: true},
		{PodUID: r.PeerPodUID, PodName: "peer", PodIP: "192.0.2.8", OwnerKind: "ReplicaSet", OwnerUID: "rs-uid",
			ContainerID: "containerd://peer", ImageID: "image@sha256:" + strings.Repeat("a", 64), Ready: true},
	}
	health := func(kind string, uid types.UID) natsResponseServiceReceipt {
		receipt := natsResponseServiceReceipt{AddressKind: kind, ServiceUID: "service-uid", PodUID: uid,
			ServerID: server, Status: "HTTP_200", ObservedAt: "2026-09-24T00:00:00Z"}
		if kind == "SERVICE" {
			receipt.EndpointSliceUID, receipt.EndpointMemberUIDs, receipt.EndpointMembers = "slice-uid", memberUIDs, members
		}
		return receipt
	}
	security, capacity, repeatability := "NOT_EVALUATED", "NOT_APPLICABLE", "NOT_EVALUATED"
	if d.SelectedAction == "quarantine" {
		security, capacity, repeatability = "CONTAINMENT_NOT_ACHIEVED", "UNRECONCILED_POSSIBLE", "UNKNOWN"
	}
	a := natsResponseArtifact{Schema: natsResponseArtifactSchema, RunID: r.RunID, Nonce: r.Nonce,
		Namespace: r.Namespace, NamespaceUID: r.NamespaceUID, ClusterUID: "cluster-uid",
		Fixture: natsResponseFixture{Name: r.PolicyName, NamespaceUID: r.NamespaceUID, ServiceUID: "service-uid",
			PolicyUID: r.PolicyUID, PolicyGen: r.PolicyGeneration, PolicySpecSHA256: strings.Repeat("e", 64), ReplicaSetUID: "rs-uid",
			Client: natsResponsePodIdentity{Name: r.ClientPod, UID: r.ClientPodUID, IP: "192.0.2.7", ContainerID: "containerd://client", ImageID: "image@sha256:" + strings.Repeat("a", 64)},
			Peer:   natsResponsePodIdentity{Name: "peer", UID: r.PeerPodUID, IP: "192.0.2.8", ContainerID: "containerd://peer", ImageID: "image@sha256:" + strings.Repeat("a", 64)}},
		Route:         natsRouteIdentity{ClusterUID: "cluster-uid", Brokers: []natsBrokerIdentity{{ServerID: server}}},
		ManagerPodUID: r.ManagerPodUID, ManagerContainerID: r.ManagerContainerID,
		ManagerImageID: "image@sha256:" + strings.Repeat("d", 64), M0: phases[0], M1: phases[1],
		SignalRequestSHA256: natsSHA(requestRaw), Decision: &d,
		ServiceBefore: health("SERVICE", r.ClientPodUID), PeerBefore: health("PEER_DIRECT", r.PeerPodUID),
		ServiceAfter: health("SERVICE", r.PeerPodUID), PeerAfter: health("PEER_DIRECT", r.PeerPodUID),
		InitialDisclosure: "EXPOSED", OngoingAccess: "CONTINUING_EXPOSURE", LegitimateService: "AVAILABLE",
		SecurityOutcome: security, Validity: "MEASUREMENT_COMPLETE", Cleanup: "CONFIRMED_ABSENT",
		CapacityReservationStatus: capacity, Repeatability: repeatability}
	checks := natsResponseCleanupChecks{NamespacePreserved: true, ConfigMapAbsent: true, DeploymentAbsent: true,
		ReplicaSetAbsent: true, ServiceAbsent: true, PDBAbsent: true, PolicyAbsent: true, OriginalPodsAbsent: true,
		StreamsAbsent: true, SecurityEventAbsent: true, PhoenixChildrenAbsent: true}
	if err := writeNATSResponseArtifact(out, a, checks); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nats-response.json", "nats-response-terminal.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
}
