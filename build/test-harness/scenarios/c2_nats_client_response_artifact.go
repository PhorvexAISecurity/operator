package scenarios

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/natsexposure"
	"k8s.io/apimachinery/pkg/types"
)

const natsResponseArtifactSchema = "nats-client-response-artifact-v1"
const natsResponseTerminalSchema = "nats-client-response-terminal-v1"

// These are evidence fields, not scored generic benchmark metrics. In
// particular, a missing M1 receipt is UNKNOWN rather than proof of defense.
type natsResponsePhaseArtifact struct {
	Stream        string                        `json:"stream"`
	Subject       string                        `json:"subject"`
	PayloadSHA256 string                        `json:"payloadSHA256"`
	Protocol      natsexposure.Receipt          `json:"protocol"`
	Observer      []natsResponseObserverReceipt `json:"observer"`
	PeerObserver  []natsResponseObserverReceipt `json:"peerObserver"`
}

type natsResponseServiceReceipt struct {
	AddressKind        string                      `json:"addressKind"`
	ServiceUID         types.UID                   `json:"serviceUID"`
	EndpointSliceUID   types.UID                   `json:"endpointSliceUID,omitempty"`
	EndpointMemberUIDs []types.UID                 `json:"endpointMemberUIDs,omitempty"`
	EndpointMembers    []natsResponseServiceMember `json:"endpointMembers,omitempty"`
	PodUID             types.UID                   `json:"podUID"`
	ServerID           string                      `json:"serverID"`
	Status             string                      `json:"status"`
	ObservedAt         string                      `json:"observedAt"`
}

// A service member is an API-observed, first-incarnation fixture process. A
// post-quarantine ReplicaSet replacement may carry service traffic, but never
// substitutes for either original Pod's M0/M1 message receipt.
type natsResponseServiceMember struct {
	PodUID       types.UID `json:"podUID"`
	PodName      string    `json:"podName"`
	PodIP        string    `json:"podIP"`
	OwnerKind    string    `json:"ownerKind"`
	OwnerUID     types.UID `json:"ownerUID"`
	ContainerID  string    `json:"containerID"`
	ImageID      string    `json:"imageID"`
	Ready        bool      `json:"ready"`
	RestartCount int32     `json:"restartCount"`
}

type natsResponseArtifact struct {
	Schema              string                      `json:"schema"`
	RunID               string                      `json:"runId"`
	Nonce               string                      `json:"nonce"`
	Namespace           string                      `json:"namespace"`
	NamespaceUID        types.UID                   `json:"namespaceUID"`
	ClusterUID          types.UID                   `json:"clusterUID"`
	Fixture             natsResponseFixture         `json:"fixture"`
	Route               natsRouteIdentity           `json:"route"`
	ManagerPodUID       types.UID                   `json:"managerPodUID"`
	ManagerContainerID  string                      `json:"managerContainerID"`
	ManagerImageID      string                      `json:"managerImageID"`
	M0                  natsResponsePhaseArtifact   `json:"m0"`
	SignalRequestSHA256 string                      `json:"signalRequestSHA256"`
	Decision            *natsResponseSignalDecision `json:"decision,omitempty"`
	M1                  natsResponsePhaseArtifact   `json:"m1"`
	ServiceBefore       natsResponseServiceReceipt  `json:"serviceBefore"`
	PeerBefore          natsResponseServiceReceipt  `json:"peerBefore"`
	ServiceAfter        natsResponseServiceReceipt  `json:"serviceAfter"`
	PeerAfter           natsResponseServiceReceipt  `json:"peerAfter"`
	InitialDisclosure   string                      `json:"initialDisclosure"`
	OngoingAccess       string                      `json:"ongoingAccess"`
	LegitimateService   string                      `json:"legitimateService"`
	SecurityOutcome     string                      `json:"securityOutcome"`
	Validity            string                      `json:"validity"`
	Cleanup             string                      `json:"cleanup"`
	// The protected Phoenix capacity ledger is outside fixture ownership. Even
	// exact API child cleanup cannot prove its reservation released.
	CapacityReservationStatus string `json:"capacityReservationStatus"`
	Repeatability             string `json:"repeatability"`
	ObservedAt                string `json:"observedAt"`
}

type natsResponseCleanupChecks struct {
	NamespacePreserved    bool `json:"namespacePreserved"`
	ConfigMapAbsent       bool `json:"configMapAbsent"`
	DeploymentAbsent      bool `json:"deploymentAbsent"`
	ReplicaSetAbsent      bool `json:"replicaSetAbsent"`
	ServiceAbsent         bool `json:"serviceAbsent"`
	PDBAbsent             bool `json:"pdbAbsent"`
	PolicyAbsent          bool `json:"policyAbsent"`
	OriginalPodsAbsent    bool `json:"originalPodsAbsent"`
	StreamsAbsent         bool `json:"streamsAbsent"`
	SecurityEventAbsent   bool `json:"securityEventAbsent"`
	PhoenixChildrenAbsent bool `json:"phoenixChildrenAbsent"`
}

type natsResponseTerminal struct {
	Schema                    string                    `json:"schema"`
	RunID                     string                    `json:"runId"`
	Nonce                     string                    `json:"nonce"`
	NamespaceUID              types.UID                 `json:"namespaceUID"`
	ArtifactSHA256            string                    `json:"artifactSHA256"`
	Cleanup                   string                    `json:"cleanup"`
	CapacityReservationStatus string                    `json:"capacityReservationStatus"`
	Repeatability             string                    `json:"repeatability"`
	Checks                    natsResponseCleanupChecks `json:"checks"`
	ObservedAt                string                    `json:"observedAt"`
}

func (c natsResponseCleanupChecks) allConfirmed() bool {
	return c.NamespacePreserved && c.ConfigMapAbsent && c.DeploymentAbsent && c.ReplicaSetAbsent &&
		c.ServiceAbsent && c.PDBAbsent && c.PolicyAbsent && c.OriginalPodsAbsent &&
		c.StreamsAbsent && c.SecurityEventAbsent && c.PhoenixChildrenAbsent
}

func writeNATSResponseArtifact(out string, artifact natsResponseArtifact, checks natsResponseCleanupChecks) error {
	if artifact.Schema != natsResponseArtifactSchema || artifact.RunID == "" || artifact.Nonce == "" ||
		artifact.NamespaceUID == "" || artifact.ClusterUID == "" || artifact.Fixture.NamespaceUID != artifact.NamespaceUID ||
		artifact.InitialDisclosure != "EXPOSED" && artifact.InitialDisclosure != "UNKNOWN" ||
		artifact.OngoingAccess != "CONTINUING_EXPOSURE" && artifact.OngoingAccess != "UNKNOWN" ||
		artifact.LegitimateService != "AVAILABLE" && artifact.LegitimateService != "UNAVAILABLE" && artifact.LegitimateService != "UNKNOWN" ||
		artifact.SecurityOutcome != "CONTAINMENT_NOT_ACHIEVED" && artifact.SecurityOutcome != "NOT_EVALUATED" ||
		artifact.Validity != "MEASUREMENT_COMPLETE" && artifact.Validity != "INCONCLUSIVE" ||
		artifact.Cleanup != "CONFIRMED_ABSENT" && artifact.Cleanup != "UNCONFIRMED" && artifact.Cleanup != "NOT_STARTED" ||
		artifact.CapacityReservationStatus != "UNRECONCILED_POSSIBLE" && artifact.CapacityReservationStatus != "NOT_APPLICABLE" && artifact.CapacityReservationStatus != "UNKNOWN" ||
		artifact.Repeatability != "UNKNOWN" && artifact.Repeatability != "NOT_EVALUATED" ||
		(artifact.Decision != nil && artifact.Decision.SelectedAction == "quarantine" &&
			(artifact.CapacityReservationStatus != "UNRECONCILED_POSSIBLE" || artifact.Repeatability != "UNKNOWN")) ||
		(artifact.Decision != nil && artifact.Decision.SelectedAction == "noop" && artifact.CapacityReservationStatus != "NOT_APPLICABLE") ||
		(artifact.Decision == nil && (artifact.CapacityReservationStatus != "UNKNOWN" || artifact.Repeatability != "UNKNOWN")) ||
		(artifact.Cleanup == "CONFIRMED_ABSENT" && !checks.allConfirmed()) ||
		(artifact.Validity == "MEASUREMENT_COMPLETE" && !natsResponseCompleteArtifact(artifact)) ||
		(artifact.SecurityOutcome == "CONTAINMENT_NOT_ACHIEVED" &&
			(artifact.OngoingAccess != "CONTINUING_EXPOSURE" || artifact.Decision == nil || artifact.Decision.SelectedAction == "noop" ||
				artifact.Decision.EffectStatus != "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED")) {
		return errors.New("NATS response artifact states inconsistent")
	}
	artifact.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(artifact)
	if err != nil || len(raw) > 64<<10 {
		return errors.New("NATS response artifact invalid or oversized")
	}
	if err := writeNATSResponseExclusive(filepath.Join(out, "nats-response.json"), raw); err != nil {
		return err
	}
	terminal := natsResponseTerminal{Schema: natsResponseTerminalSchema, RunID: artifact.RunID,
		Nonce: artifact.Nonce, NamespaceUID: artifact.NamespaceUID, ArtifactSHA256: natsSHA(raw),
		Cleanup: artifact.Cleanup, CapacityReservationStatus: artifact.CapacityReservationStatus,
		Repeatability: artifact.Repeatability, Checks: checks, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	terminalRaw, err := json.Marshal(terminal)
	if err != nil || len(terminalRaw) > 4096 {
		return errors.New("NATS response terminal invalid or oversized")
	}
	return writeNATSResponseExclusive(filepath.Join(out, "nats-response-terminal.json"), terminalRaw)
}

func natsResponseCompleteArtifact(a natsResponseArtifact) bool {
	if a.Cleanup != "CONFIRMED_ABSENT" || a.Decision == nil || a.InitialDisclosure != "EXPOSED" ||
		a.OngoingAccess != "CONTINUING_EXPOSURE" || a.LegitimateService != "AVAILABLE" ||
		len(a.M0.Observer) != 3 || len(a.M1.Observer) != 4 ||
		len(a.M0.PeerObserver) != 3 || len(a.M1.PeerObserver) != 4 ||
		a.M0.Observer[2].Status != "EXACT_PAYLOAD_RECEIVED" || a.M1.Observer[3].Status != "EXACT_PAYLOAD_RECEIVED" ||
		a.M0.PeerObserver[2].Status != "EXACT_PAYLOAD_RECEIVED" || a.M1.PeerObserver[3].Status != "EXACT_PAYLOAD_RECEIVED" ||
		a.M0.Observer[2].PodUID != string(a.Fixture.Client.UID) ||
		a.M1.Observer[3].PodUID != string(a.Fixture.Client.UID) ||
		a.M0.PeerObserver[2].PodUID != string(a.Fixture.Peer.UID) ||
		a.M1.PeerObserver[3].PodUID != string(a.Fixture.Peer.UID) ||
		a.SignalRequestSHA256 == "" || a.ManagerPodUID == "" || a.ManagerContainerID == "" ||
		a.Fixture.PolicyUID == "" || a.Fixture.ServiceUID == "" ||
		a.ServiceBefore.Status != "HTTP_200" || a.ServiceAfter.Status != "HTTP_200" ||
		a.PeerBefore.Status != "HTTP_200" || a.PeerAfter.Status != "HTTP_200" ||
		a.PeerBefore.PodUID != a.Fixture.Peer.UID || a.PeerAfter.PodUID != a.Fixture.Peer.UID ||
		a.ServiceBefore.EndpointSliceUID == "" || a.ServiceAfter.EndpointSliceUID == "" ||
		!natsResponseServiceEvidenceComplete(a.ServiceBefore) || !natsResponseServiceEvidenceComplete(a.ServiceAfter) ||
		a.Decision.EventCleanupStatus != "CONFIRMED_ABSENT" {
		return false
	}
	payloads := natsResponsePayloads(a.Nonce)
	if !natsResponseLocalProtocolExact(a.M0.Protocol, payloads[0]) ||
		!natsResponseLocalProtocolExact(a.M1.Protocol, payloads[1]) {
		return false
	}
	return (a.Decision.SelectedAction == "noop" && a.Decision.DispatchOutcome == "not-attempted" &&
		a.Decision.EffectStatus == "NOT_DISPATCHED" && a.SecurityOutcome == "NOT_EVALUATED") ||
		(a.Decision.SelectedAction == "quarantine" && a.Decision.DispatchOutcome == "emitted" &&
			a.Decision.EffectStatus == "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED" &&
			a.SecurityOutcome == "CONTAINMENT_NOT_ACHIEVED")
}

func natsResponseServiceEvidenceComplete(r natsResponseServiceReceipt) bool {
	if len(r.EndpointMemberUIDs) < 1 || len(r.EndpointMemberUIDs) > 2 ||
		len(r.EndpointMembers) != len(r.EndpointMemberUIDs) ||
		!sort.SliceIsSorted(r.EndpointMemberUIDs, func(i, j int) bool { return r.EndpointMemberUIDs[i] < r.EndpointMemberUIDs[j] }) {
		return false
	}
	responded := false
	for i, uid := range r.EndpointMemberUIDs {
		member := r.EndpointMembers[i]
		if uid == "" || member.PodUID != uid || member.PodName == "" || member.PodIP == "" ||
			member.OwnerKind == "" || member.OwnerUID == "" || member.ContainerID == "" || member.ImageID == "" ||
			!member.Ready || member.RestartCount != 0 || (i > 0 && uid == r.EndpointMemberUIDs[i-1]) {
			return false
		}
		responded = responded || uid == r.PodUID
	}
	return responded
}

// An artifact is published once. A later process may inspect it but cannot
// rewrite either the observed measurement or its digest-bound terminal.
func writeNATSResponseExclusive(path string, raw []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(tmp, path); err != nil {
		return err
	}
	if err = os.Remove(tmp); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
