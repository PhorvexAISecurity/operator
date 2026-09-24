package scenarios

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/natsexposure"
	"k8s.io/apimachinery/pkg/types"
)

// RunNATSClientResponse is one unscored, server-owned case. It never chooses
// an action or creates a signal itself: the console callback independently
// joins M0 to an authenticated manager decision and publishes one immutable
// run-private decision barrier before M1 may be created.
func RunNATSClientResponse(ctx context.Context, env *core.Env) (runErr error) {
	if env == nil || env.Config.NATSExposureFixture == nil || env.Config.NATSExposureFixture.Mode != "client-response" ||
		env.Config.Namespace != natsResponseFixtureNamespace || env.NamespaceUID() == "" || env.Config.OutDir == "" ||
		env.NATSFenceIdentity == "" {
		return errors.New("NATS response exact named-suite authority unavailable")
	}
	f := env.Config.NATSExposureFixture
	artifact := natsResponseArtifact{Schema: natsResponseArtifactSchema, RunID: f.RunID, Nonce: f.Nonce,
		Namespace: env.Config.Namespace, NamespaceUID: env.NamespaceUID(), ClusterUID: types.UID(f.ClusterUID),
		Fixture: natsResponseFixture{NamespaceUID: env.NamespaceUID()}, InitialDisclosure: "UNKNOWN",
		OngoingAccess: "UNKNOWN", LegitimateService: "UNKNOWN", SecurityOutcome: "NOT_EVALUATED",
		Validity: "INCONCLUSIVE", Cleanup: "NOT_STARTED", CapacityReservationStatus: "UNKNOWN", Repeatability: "UNKNOWN"}
	fixture := natsResponseFixture{Name: natsResponseName(f.Nonce), NamespaceUID: env.NamespaceUID()}
	var protocols [2]natsexposure.Receipt
	var observedM1 bool
	var controlsHealthy bool
	defer func() {
		// Cleanup is owed even after the run context expires. It owns only exact
		// created UIDs and remains bounded by the established harness budget.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), core.DefaultCleanupTimeout)
		checks, cleanupErr := natsResponseCleanup(cleanupCtx, env, fixture, artifact.Decision, protocols)
		cancel()
		if cleanupErr != nil {
			runErr = errors.Join(runErr, cleanupErr)
		}
		if cleanupErr == nil && checks.allConfirmed() {
			artifact.Cleanup = "CONFIRMED_ABSENT"
		} else {
			artifact.Cleanup = "UNCONFIRMED"
		}
		if runErr == nil && artifact.Cleanup == "CONFIRMED_ABSENT" &&
			artifact.InitialDisclosure == "EXPOSED" && observedM1 && controlsHealthy &&
			artifact.Decision != nil && artifact.M0.Protocol.Cleanup == "CONFIRMED_ABSENT" &&
			artifact.M1.Protocol.Cleanup == "CONFIRMED_ABSENT" {
			artifact.Validity = "MEASUREMENT_COMPLETE"
			if artifact.Decision.SelectedAction == "quarantine" &&
				artifact.Decision.EffectStatus == "OBJECT_EFFECT_OBSERVED_PACKET_UNVERIFIED" {
				// The same original connection still received the new payload.
				// This does not attribute cause to CNI or generalize to fresh flows.
				artifact.SecurityOutcome = "CONTAINMENT_NOT_ACHIEVED"
			}
		}
		artifact.Fixture = fixture
		writeErr := writeNATSResponseArtifact(env.Config.OutDir, artifact, checks)
		runErr = errors.Join(runErr, writeErr)
	}()

	manager, err := natsResponseManager(ctx, env)
	if err != nil {
		return err
	}
	artifact.ManagerPodUID, artifact.ManagerContainerID, artifact.ManagerImageID = manager.PodUID, manager.ContainerID, manager.ImageID
	route, err := captureNATSRoute(ctx, env)
	if err != nil {
		return err
	}
	artifact.Route = route
	if err := requireNATSRoute(ctx, env, route); err != nil {
		return err
	}
	fixture, admittedPolicy, err := createNATSResponseFixture(ctx, env, route)
	artifact.Fixture = fixture
	if err != nil {
		return err
	}
	pods, rsUID, err := natsResponseAwaitConsumers(ctx, env, fixture)
	if err != nil {
		return err
	}
	if err := natsResponseAssignSource(ctx, env, &fixture, pods, rsUID); err != nil {
		return err
	}
	artifact.Fixture = fixture
	if _, err := natsResponseAwaitInitialControls(ctx, env, fixture, admittedPolicy); err != nil {
		return err
	}
	artifact.ServiceBefore, artifact.PeerBefore, err = natsResponseProbeControls(ctx, env, fixture, admittedPolicy, route, true)
	if err != nil {
		return fmt.Errorf("NATS response pre-M0 legitimate Service unavailable: %w", err)
	}
	if current, err := natsResponseManager(ctx, env); err != nil || current != manager {
		return errors.New("NATS response manager process changed before M0")
	}

	// The library's local actor checks JetStream PubAck, ACK, stored bytes and
	// exact stream deletion. The remote client remains a separate Pod/log oracle.
	barrierM0 := func(barrierCtx context.Context, _ natsexposure.Receipt) error {
		if _, _, err := natsResponseWaitLog(barrierCtx, env, fixture, route, 2, 25*time.Second, false); err != nil {
			return err
		}
		if _, _, err := natsResponseWaitPeerLog(barrierCtx, env, fixture, route, 2, 25*time.Second); err != nil {
			return err
		}
		if _, err := natsResponseCurrentControls(barrierCtx, env, fixture, admittedPolicy, true); err != nil {
			return err
		}
		return requireNATSRoute(barrierCtx, env, route)
	}
	protocols[0], err = natsResponsePublishPhase(ctx, env, route, "M0", barrierM0)
	artifact.M0 = natsResponsePhaseArtifact{Stream: protocols[0].Stream, Subject: protocols[0].Subject,
		PayloadSHA256: protocols[0].PayloadSHA256, Protocol: protocols[0]}
	if err != nil || !natsResponseLocalProtocolExact(protocols[0], natsResponsePayloads(f.Nonce)[0]) {
		return errors.Join(err, errors.New("NATS response M0 local protocol or stream cleanup unconfirmed"))
	}
	m0Raw, rows, err := natsResponseWaitLog(ctx, env, fixture, route, 3, 30*time.Second, false)
	if err != nil {
		return err
	}
	artifact.M0.Observer = rows
	peerM0Raw, peerM0Rows, err := natsResponseWaitPeerLog(ctx, env, fixture, route, 3, 30*time.Second)
	if err != nil {
		return err
	}
	artifact.M0.PeerObserver = peerM0Rows
	if rows[2].Status != "EXACT_PAYLOAD_RECEIVED" {
		return errors.New("NATS response original remote client M0 disclosure absent")
	}
	if peerM0Rows[2].Status != "EXACT_PAYLOAD_RECEIVED" {
		return errors.New("NATS response original legitimate peer M0 message absent")
	}
	if _, err := natsResponseCurrentControls(ctx, env, fixture, admittedPolicy, true); err != nil {
		return err
	}
	if current, err := natsResponseManager(ctx, env); err != nil || current != manager {
		return errors.New("NATS response manager process changed after M0")
	}
	m0SHA, err := natsResponsePersistM0Prefix(env.Config.OutDir, m0Raw)
	if err != nil {
		return err
	}
	peerM0SHA, err := natsResponsePersistPeerM0Prefix(env.Config.OutDir, peerM0Raw)
	if err != nil {
		return err
	}
	artifact.InitialDisclosure = "EXPOSED"
	request := natsResponseSignalRequest{Schema: natsResponseSchema, RunID: f.RunID, Nonce: f.Nonce,
		Namespace: env.Config.Namespace, NamespaceUID: env.NamespaceUID(), ClientPod: fixture.Client.Name,
		ClientPodUID: fixture.Client.UID, PeerPodUID: fixture.Peer.UID, PolicyName: fixture.Name,
		PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGen,
		ManagerPodUID: manager.PodUID, ManagerContainerID: manager.ContainerID,
		M0ReceiptSHA256: m0SHA, PeerM0ReceiptSHA256: peerM0SHA}
	if err := writeNATSResponseRequest(env.Config.OutDir, request); err != nil {
		return err
	}
	requestRaw, err := readNATSResponseFile(env.Config.OutDir, "nats-response-signal-request.json")
	if err != nil {
		return err
	}
	artifact.SignalRequestSHA256 = natsSHA(requestRaw)
	decision, err := natsResponseWaitDecision(ctx, env.Config.OutDir, request)
	if err != nil {
		return err
	}
	artifact.Decision = &decision
	if decision.SelectedAction == "quarantine" {
		artifact.CapacityReservationStatus, artifact.Repeatability = "UNRECONCILED_POSSIBLE", "UNKNOWN"
	} else {
		artifact.CapacityReservationStatus, artifact.Repeatability = "NOT_APPLICABLE", "NOT_EVALUATED"
	}
	if current, err := natsResponseManager(ctx, env); err != nil || current != manager {
		return errors.New("NATS response manager process changed at M1 barrier")
	}
	if _, err := natsResponseCurrentControls(ctx, env, fixture, admittedPolicy, false); err != nil {
		return err
	}
	if err := requireNATSRoute(ctx, env, route); err != nil {
		return err
	}
	// A fresh M1 stream is created only after the independently joined exact
	// event/decision/effect barrier. An earlier M1 packet cannot be credited.
	barrierM1 := func(barrierCtx context.Context, _ natsexposure.Receipt) error {
		currentRaw, _, err := natsResponseObserverLog(barrierCtx, env, fixture, route, 3, decision.SelectedAction == "quarantine")
		if err != nil || !bytes.Equal(currentRaw, m0Raw) {
			return errors.New("NATS response original client M0 prefix changed or premature M1 receipt appeared")
		}
		currentPeerRaw, _, err := natsResponsePeerLog(barrierCtx, env, fixture, route, 3)
		if err != nil || !bytes.Equal(currentPeerRaw, peerM0Raw) {
			return errors.New("NATS response original peer M0 prefix changed or premature M1 receipt appeared")
		}
		if _, err := natsResponseCurrentControls(barrierCtx, env, fixture, admittedPolicy, false); err != nil {
			return err
		}
		if current, err := natsResponseManager(barrierCtx, env); err != nil || current != manager {
			return errors.New("NATS response manager process changed before M1 publish")
		}
		return requireNATSRoute(barrierCtx, env, route)
	}
	protocols[1], err = natsResponsePublishPhase(ctx, env, route, "M1", barrierM1)
	artifact.M1 = natsResponsePhaseArtifact{Stream: protocols[1].Stream, Subject: protocols[1].Subject,
		PayloadSHA256: protocols[1].PayloadSHA256, Protocol: protocols[1]}
	if err != nil || !natsResponseLocalProtocolExact(protocols[1], natsResponsePayloads(f.Nonce)[1]) {
		return errors.Join(err, errors.New("NATS response M1 local protocol or stream cleanup unconfirmed"))
	}
	_, m1Rows, err := natsResponseWaitLog(ctx, env, fixture, route, 4, 5*time.Minute, decision.SelectedAction == "quarantine")
	if err != nil {
		return err
	}
	artifact.M1.Observer = m1Rows
	_, peerM1Rows, err := natsResponseWaitPeerLog(ctx, env, fixture, route, 4, 5*time.Minute)
	if err != nil {
		return err
	}
	artifact.M1.PeerObserver = peerM1Rows
	if m1Rows[3].Status != "EXACT_PAYLOAD_RECEIVED" {
		return errors.New("NATS response M1 same-connection objective unknown")
	}
	if peerM1Rows[3].Status != "EXACT_PAYLOAD_RECEIVED" {
		return errors.New("NATS response original legitimate peer M1 message unknown")
	}
	observedM1, artifact.OngoingAccess = true, "CONTINUING_EXPOSURE"
	artifact.ServiceAfter, artifact.PeerAfter, err = natsResponseProbeControls(ctx, env, fixture, admittedPolicy, route, false)
	if err != nil {
		return fmt.Errorf("NATS response post-M1 legitimate Service unavailable: %w", err)
	}
	controlsHealthy, artifact.LegitimateService = true, "AVAILABLE"
	if current, err := natsResponseManager(ctx, env); err != nil || current != manager {
		return errors.New("NATS response manager process changed after M1")
	}
	return requireNATSRoute(ctx, env, route)
}

func natsResponseLocalProtocolExact(receipt natsexposure.Receipt, payload []byte) bool {
	return receipt.Validity == "VALID" && receipt.Cleanup == "CONFIRMED_ABSENT" &&
		receipt.SubscriptionFlushed && receipt.PublishAttempted && receipt.PubAckSequence == 1 &&
		receipt.LegitimateAcked && receipt.StoredPayloadSHA256 == natsSHA(payload) &&
		receipt.LegitimatePayloadSHA256 == natsSHA(payload) && receipt.PayloadSHA256 == natsSHA(payload) &&
		receipt.AdversaryObservation == "EXACT_PAYLOAD_RECEIVED" && receipt.Objective == "REACHED"
}
