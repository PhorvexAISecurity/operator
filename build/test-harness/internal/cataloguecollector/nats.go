package cataloguecollector

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/jetstreamprobe"
)

const (
	natsScenario = "c2-nats-jetstream-durability"
	natsDefender = "d-nomtd"
)

var natsProfileMode = map[string]string{
	"nats-no-action":      "no-action",
	"nats-member-restart": "member-restart",
	"nats-quorum-pause":   "quorum-pause",
}

func validateNATSAuthority(profileID string, a *NATSRunIdentity) error {
	wantMode, ok := natsProfileMode[profileID]
	if !ok || a == nil || a.Mode != wantMode {
		return errors.New("profile mode or identity authority differs")
	}
	if !safeNonce(a.FixtureNonce) || a.NodeName == "" || !uuidText(a.NodeUID) || a.ConnectedMember != "c2-nats-js-0" || a.StorageClass == "" || !uuidText(a.StorageClassUID) {
		return errors.New("nonce, node, connected member, or storage class authority invalid")
	}
	for name, values := range map[string][]string{
		"podUIDs":          a.PodUIDs,
		"pvcUIDs":          a.PVCUIDs,
		"pvUIDs":           a.PVUIDs,
		"storePathSHA256s": a.StorePathSHA256s,
		"initialServerIDs": a.InitialServerIDs,
	} {
		if len(values) != 3 || !uniqueStrings(values) {
			return fmt.Errorf("%s must contain three unique values", name)
		}
	}
	for _, values := range [][]string{a.PodUIDs, a.PVCUIDs, a.PVUIDs} {
		for _, value := range values {
			if !uuidText(value) {
				return errors.New("workload or volume UID authority invalid")
			}
		}
	}
	for _, value := range a.StorePathSHA256s {
		if len(value) != 64 || !isHash(value) {
			return errors.New("store path hash authority invalid")
		}
	}
	for _, value := range a.InitialServerIDs {
		if len(value) < 16 || value[0] != 'N' {
			return errors.New("server identity authority invalid")
		}
	}
	return nil
}

func decodeNATS(m core.Metric, profileID string, authority *NATSRunIdentity) (NATSJetStreamSummary, error) {
	if m.Scenario != natsScenario || m.Defender != natsDefender || m.AnchorOnly {
		return NATSJetStreamSummary{}, errors.New("scenario, defender, or anchor identity differs")
	}
	if !m.OracleAchieved || m.DefensiveActions != 0 || m.FalseDefensiveActions != -1 {
		return NATSJetStreamSummary{}, errors.New("NATS oracle or defensive-action sentinel differs")
	}
	if err := validateNATSAuthority(profileID, authority); err != nil {
		return NATSJetStreamSummary{}, err
	}
	e := m.BenchmarkEvidence
	if err := validateNATSCommonEvidence(e, authority); err != nil {
		return NATSJetStreamSummary{}, err
	}
	raw := []byte(e["oracleReceiptJSON"])
	if len(raw) == 0 || len(raw) > 64<<10 {
		return NATSJetStreamSummary{}, errors.New("oracle receipt byte bound invalid")
	}
	digestKey := map[string]string{"no-action": "protocolReceiptSHA256", "member-restart": "restartReceiptSHA256", "quorum-pause": "quorumReceiptSHA256"}[authority.Mode]
	if e[digestKey] != sum(raw) {
		return NATSJetStreamSummary{}, errors.New("oracle receipt digest differs")
	}
	state := m.MeasurementState()
	summary := NATSJetStreamSummary{
		IdentityAuthority:          "supplied-run-index",
		Mode:                       authority.Mode,
		FixtureNonce:               authority.FixtureNonce,
		ReceiptSHA256:              e[digestKey],
		ProtocolStatus:             "complete",
		Replicas:                   3,
		PodUIDs:                    append([]string(nil), authority.PodUIDs...),
		VolumeUIDs:                 volumeUIDs(authority),
		InitialServerIDs:           append([]string(nil), authority.InitialServerIDs...),
		CleanupComplete:            state.Cleanup.Complete,
		CleanupVerified:            state.Cleanup.Verified,
		SecurityOutcome:            "not-measured",
		InstalledDispatchProven:    false,
		DirectNativeActuatorProven: false,
	}
	var err error
	switch authority.Mode {
	case "no-action":
		var receipt jetstreamprobe.NoActionOracleReceipt
		if err = strictJSON(raw, &receipt); err == nil {
			err = validateNoActionReceipt(receipt, authority, e, &summary)
		}
	case "member-restart":
		var receipt jetstreamprobe.RestartOracleReceipt
		if err = strictJSON(raw, &receipt); err == nil {
			err = validateRestartReceipt(receipt, authority, e, &summary)
		}
	case "quorum-pause":
		var receipt jetstreamprobe.QuorumOracleReceipt
		if err = strictJSON(raw, &receipt); err == nil {
			err = validateQuorumReceipt(receipt, authority, e, &summary)
		}
	default:
		err = errors.New("unsupported NATS mode")
	}
	if err != nil {
		return NATSJetStreamSummary{}, err
	}
	return summary, nil
}

func validateNATSCommonEvidence(e map[string]string, a *NATSRunIdentity) error {
	want := map[string]string{
		"mode": a.Mode, "fixtureNonce": a.FixtureNonce, "nodeName": a.NodeName, "nodeUID": a.NodeUID,
		"connectedMember": a.ConnectedMember, "storageClass": a.StorageClass, "storageClassUID": a.StorageClassUID,
		"fixtureImage":       "docker.io/library/nats@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927",
		"fixtureNATSVersion": "2.10.29", "probeLibrary": "github.com/nats-io/nats.go@v1.47.0",
		"natsReconnectPolicy": "MaxReconnects(0)", "oracleStatus": "complete", "securityOutcome": "not-measured",
		"cveOutcome": "not-measured", "installedDispatchProven": "false", "directNativeActuatorProven": "false",
		"costObservation": "resource-requests-only", "cpuRequestMillicores": "75", "memoryRequestBytes": "100663296",
		"restartScope": "exact-non-client-member-c2-nats-js-2",
	}
	for key, value := range want {
		if e[key] != value {
			return fmt.Errorf("evidence %s differs", key)
		}
	}
	for i := range 3 {
		for key, value := range map[string]string{
			fmt.Sprintf("pod%dUID", i):          a.PodUIDs[i],
			fmt.Sprintf("pvc%dUID", i):          a.PVCUIDs[i],
			fmt.Sprintf("pv%dUID", i):           a.PVUIDs[i],
			fmt.Sprintf("store%dPathSHA256", i): a.StorePathSHA256s[i],
			fmt.Sprintf("server%dID", i):        a.InitialServerIDs[i],
		} {
			if e[key] != value {
				return fmt.Errorf("evidence %s differs from supplied identity", key)
			}
		}
	}
	if _, err := canonicalNonnegativeInt(e, "elapsedMillis"); err != nil {
		return err
	}
	return nil
}

func validateNoActionReceipt(r jetstreamprobe.NoActionOracleReceipt, a *NATSRunIdentity, e map[string]string, s *NATSJetStreamSummary) error {
	if e["suiteVersion"] != "post25-nats-jetstream-durability-v1" || e["availabilityOutcome"] != "protocol-available" || e["stateOutcome"] != "acknowledged-A-and-B-contiguous" {
		return errors.New("no-action outcome identity differs")
	}
	if e["actionAttempted"] != "false" || e["actionCompleted"] != "false" || e["actionCount"] != "0" {
		return errors.New("no-action action count differs")
	}
	if err := validateReplication(r.Baseline); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	stream, subject := natsNames(a.FixtureNonce)
	if err := validateMessageChain(r.MessageA, r.DeliveryA, &r.StoredA, 1, stream, subject, a.FixtureNonce+"-a", payloadHash("synthetic-nats-durability-a")); err != nil {
		return fmt.Errorf("message A: %w", err)
	}
	if err := validateMessageChain(r.MessageB, r.DeliveryB, nil, 2, stream, subject, a.FixtureNonce+"-b", payloadHash("synthetic-nats-durability-b")); err != nil {
		return fmt.Errorf("message B: %w", err)
	}
	if err := validateFinalState(r.FinalState, stream, 2); err != nil {
		return err
	}
	if e["messageASequence"] != "1" || e["messageBSequence"] != "2" {
		return errors.New("no-action sequence evidence differs")
	}
	fillFinal(s, r.FinalState)
	s.MessageASequence, s.MessageBSequence = 1, 2
	return nil
}

func validateRestartReceipt(r jetstreamprobe.RestartOracleReceipt, a *NATSRunIdentity, e map[string]string, s *NATSJetStreamSummary) error {
	if e["suiteVersion"] != "post25-nats-jetstream-durability-v1" || e["availabilityOutcome"] != "protocol-restored-after-one-non-client-member-child-restart" || e["availabilityDuringRestart"] != "unobserved" || e["stateOutcome"] != "acknowledged-A-stored-across-restart-and-B-contiguous" {
		return errors.New("restart outcome identity differs")
	}
	if e["actionAttempted"] != "true" || e["actionCompleted"] != "true" || e["actionCount"] != "1" || e["restartScope"] != "exact-non-client-member-c2-nats-js-2" {
		return errors.New("restart action count or scope differs")
	}
	if err := validateReplication(r.Baseline); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	if err := validateReplication(r.Recovered); err != nil || !sameReplicationMembers(r.Baseline, r.Recovered) {
		return errors.New("recovered replica identity differs")
	}
	stream, subject := natsNames(a.FixtureNonce)
	if err := validateMessageChain(r.MessageA, r.DeliveryA, &r.StoredBefore, 1, stream, subject, a.FixtureNonce+"-a", payloadHash("synthetic-nats-durability-a")); err != nil {
		return fmt.Errorf("message A before restart: %w", err)
	}
	if r.StoredAfter != r.StoredBefore {
		return errors.New("stored message A changed across restart")
	}
	b := r.Restart
	if b.Member != "c2-nats-js-2" || !b.ActionAttempted || !b.ActionSent || !b.ActionCompleted || b.ElapsedNanos <= 0 || b.OldProcessID != a.InitialServerIDs[2] || b.NewProcessID == "" || b.NewProcessID == b.OldProcessID || contains(a.InitialServerIDs, b.NewProcessID) || b.WorkloadUIDBefore != a.PodUIDs[2] || b.WorkloadUIDAfter != a.PodUIDs[2] || b.VolumeUIDBefore != a.PVCUIDs[2]+"/"+a.PVUIDs[2] || b.VolumeUIDAfter != b.VolumeUIDBefore || b.StorePathHashBefore != a.StorePathSHA256s[2] || b.StorePathHashAfter != b.StorePathHashBefore {
		return errors.New("restart boundary identity differs")
	}
	if r.RecoveryElapsedNanos <= 0 || e["member"] != b.Member || e["oldServerID"] != b.OldProcessID || e["newServerID"] != b.NewProcessID || e["podReplacementCount"] != "0" || e["volumeChangeCount"] != "0" || !sameCanonicalInt(e["restartBoundaryElapsedNanos"], b.ElapsedNanos) || !sameCanonicalInt(e["replicaRecoveryElapsedNanos"], r.RecoveryElapsedNanos) {
		return errors.New("restart duration or identity evidence differs")
	}
	if err := validateMessageChain(r.MessageB, r.DeliveryB, nil, 2, stream, subject, a.FixtureNonce+"-b", payloadHash("synthetic-nats-durability-b")); err != nil {
		return fmt.Errorf("message B: %w", err)
	}
	if err := validateFinalState(r.FinalState, stream, 2); err != nil {
		return err
	}
	if e["messageASequence"] != "1" || e["messageBSequence"] != "2" {
		return errors.New("restart sequence evidence differs")
	}
	fillFinal(s, r.FinalState)
	s.MessageASequence, s.MessageBSequence = 1, 2
	s.ActionAttempted, s.ActionCompleted, s.ActionCount = true, true, 1
	s.RestartBoundaryNanos, s.ReplicaRecoveryNanos = b.ElapsedNanos, r.RecoveryElapsedNanos
	return nil
}

func validateQuorumReceipt(r jetstreamprobe.QuorumOracleReceipt, a *NATSRunIdentity, e map[string]string, s *NATSJetStreamSummary) error {
	if e["suiteVersion"] != "post25-nats-jetstream-quorum-v1" || e["availabilityOutcome"] != "connected-transport-reachable-jetstream-publication-status-retained" || e["stateOutcome"] != "acknowledged-A-retained-X-reconciled-same-ID-and-Y-contiguous" || e["clientFailoverOutcome"] != "not-measured" || e["leaderFailoverOutcome"] != "not-measured" {
		return errors.New("quorum outcome identity differs")
	}
	if e["actionAttempted"] != "true" || e["actionCompleted"] != "true" || e["actionCount"] != "2" || e["pauseAttemptCount"] != "2" || e["pauseSentCount"] != "2" || e["pauseConfirmedCount"] != "2" || e["resumeConfirmedCount"] != "2" || e["quorumPauseScope"] != "exact-non-client-members-c2-nats-js-1-and-2" {
		return errors.New("quorum action counts or scope differ")
	}
	if err := validateReplication(r.Baseline); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	if err := validateReplication(r.Recovered); err != nil || !sameReplicationMembers(r.Baseline, r.Recovered) {
		return errors.New("recovered replica identity differs")
	}
	stream, subject := natsNames(a.FixtureNonce)
	if err := validateMessageChain(r.MessageA, r.DeliveryA, &r.StoredABefore, 1, stream, subject, a.FixtureNonce+"-a", payloadHash("synthetic-nats-durability-a")); err != nil {
		return fmt.Errorf("message A before pause: %w", err)
	}
	if r.StoredAAfter != r.StoredABefore {
		return errors.New("stored message A changed across quorum loss")
	}
	if err := validatePause(r.Pause, r.DuringPause, a); err != nil {
		return err
	}
	xID, xHash := a.FixtureNonce+"-x", payloadHash("synthetic-nats-quorum-ambiguous-x")
	if r.ReconciledX.Stream != stream || r.ReconciledX.Sequence != 2 || r.ReconciledX.MessageID != xID || r.ReconciledX.PayloadHash != xHash {
		return errors.New("same-ID reconciliation differs")
	}
	if r.DuringPause.Publish.Acknowledged {
		initialAck := r.DuringPause.Publish.Ack
		if initialAck == nil || initialAck.Stream != stream || initialAck.Sequence != 2 || initialAck.MessageID != xID || initialAck.PayloadHash != xHash || initialAck.Duplicate || !r.ReconciledX.Duplicate || r.ReconciledX.Sequence != initialAck.Sequence {
			return errors.New("acknowledged initial X did not reconcile as duplicate")
		}
	} else if r.DuringPause.Publish.Ack != nil || r.DuringPause.Publish.ErrorClass != "timeout-unknown" {
		return errors.New("unknown initial X publication state differs")
	}
	if err := validateMessageChain(r.ReconciledX, r.DeliveryX, &r.StoredX, 2, stream, subject, xID, xHash); err != nil {
		return fmt.Errorf("message X: %w", err)
	}
	if err := validateMessageChain(r.MessageY, r.DeliveryY, &r.StoredY, 3, stream, subject, a.FixtureNonce+"-y", payloadHash("synthetic-nats-quorum-recovered-y")); err != nil {
		return fmt.Errorf("message Y: %w", err)
	}
	if err := validateFinalState(r.FinalState, stream, 3); err != nil {
		return err
	}
	publicationStatus := "unknown"
	if r.DuringPause.Publish.Acknowledged {
		publicationStatus = "acknowledged"
	}
	if r.RecoveryElapsedNanos <= 0 || e["messageASequence"] != "1" || e["messageXSequence"] != "2" || e["messageYSequence"] != "3" || e["duringPausePublishAcknowledged"] != strconv.FormatBool(r.DuringPause.Publish.Acknowledged) || e["duringPausePublishErrorClass"] != r.DuringPause.Publish.ErrorClass || e["duringPausePingReachable"] != "true" || !sameCanonicalInt(e["quorumPauseObservedNanos"], r.Pause.ObservedPauseNanos) || !sameCanonicalInt(e["replicaRecoveryElapsedNanos"], r.RecoveryElapsedNanos) {
		return errors.New("quorum sequence, observation, or duration evidence differs")
	}
	fillFinal(s, r.FinalState)
	s.MessageASequence, s.MessageXSequence, s.MessageYSequence = 1, 2, 3
	s.ActionAttempted, s.ActionCompleted, s.ActionCount = true, true, 2
	s.ReplicaRecoveryNanos = r.RecoveryElapsedNanos
	s.QuorumPauseObservedNanos, s.QuorumPauseMaximumNanos = r.Pause.ObservedPauseNanos, r.Pause.MaximumPauseNanos
	s.DuringPausePublicationStatus = publicationStatus
	s.DuringPausePublicationErrorClass = r.DuringPause.Publish.ErrorClass
	s.DuringPausePingReachable = r.DuringPause.Ping.Reachable
	s.PausedMembers = []string{r.Pause.Members[0].Member, r.Pause.Members[1].Member}
	return nil
}

func validatePause(p jetstreamprobe.QuorumPauseReceipt, o jetstreamprobe.QuorumObservationReceipt, a *NATSRunIdentity) error {
	if p.ConnectedMember != a.ConnectedMember || p.MaximumPauseNanos <= 0 || p.MaximumPauseNanos > int64(10*time.Second) || p.ObservedPauseNanos <= 0 || p.ObservedPauseNanos > p.MaximumPauseNanos || p.ObservationCalls != 1 || len(p.Members) != 2 {
		return errors.New("quorum pause envelope differs")
	}
	pubStart, err1 := time.Parse(time.RFC3339Nano, o.Publish.StartedAtUTC)
	pubEnd, err2 := time.Parse(time.RFC3339Nano, o.Publish.FinishedAtUTC)
	pingStart, err3 := time.Parse(time.RFC3339Nano, o.Ping.StartedAtUTC)
	pingEnd, err4 := time.Parse(time.RFC3339Nano, o.Ping.FinishedAtUTC)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || pubEnd.Before(pubStart) || pingStart.Before(pubEnd) || pingEnd.Before(pingStart) || p.ObservationStartedAtUTC != o.Publish.StartedAtUTC || p.ObservationFinishedAtUTC != o.Ping.FinishedAtUTC || o.Publish.AttemptCount != 1 || !o.Ping.Reachable || o.Ping.ErrorClass != "" || o.Ping.Error != "" {
		return errors.New("quorum observation timing or one-send transport receipt differs")
	}
	if o.Publish.MessageID != a.FixtureNonce+"-x" || o.Publish.PayloadHash != payloadHash("synthetic-nats-quorum-ambiguous-x") || o.Publish.Acknowledged != (o.Publish.Ack != nil) || o.Publish.Acknowledged == (o.Publish.ErrorClass != "") {
		return errors.New("quorum publication identity or outcome is contradictory")
	}
	if (o.Publish.Acknowledged && o.Publish.Error != "") || (!o.Publish.Acknowledged && o.Publish.Error == "") {
		return errors.New("quorum publication diagnostic presence differs from outcome")
	}
	seen := map[string]bool{}
	var overlapStart, overlapEnd time.Time
	for _, m := range p.Members {
		ordinal := -1
		if m.Member == "c2-nats-js-1" {
			ordinal = 1
		} else if m.Member == "c2-nats-js-2" {
			ordinal = 2
		}
		if ordinal < 0 || seen[m.Member] || m.ServerIDBefore != a.InitialServerIDs[ordinal] || m.ServerIDAfter != m.ServerIDBefore || m.PID <= 1 || m.PIDStartTimeTicks == 0 || m.Generation == 0 || m.WorkloadUIDBefore != a.PodUIDs[ordinal] || m.WorkloadUIDAfter != m.WorkloadUIDBefore || m.VolumeUIDBefore != a.PVCUIDs[ordinal]+"/"+a.PVUIDs[ordinal] || m.VolumeUIDAfter != m.VolumeUIDBefore || m.StorePathHashBefore != a.StorePathSHA256s[ordinal] || m.StorePathHashAfter != m.StorePathHashBefore || !m.ResumeArmedBeforePause || !m.PauseAttempted || !m.PauseSent || !m.PauseConfirmed || !m.ResumeRequested || !m.ResumeConfirmed {
			return errors.New("paused member identity or action receipt differs")
		}
		paused, e1 := time.Parse(time.RFC3339Nano, m.PausedAtUTC)
		still, e2 := time.Parse(time.RFC3339Nano, m.StillPausedAtUTC)
		resumed, e3 := time.Parse(time.RFC3339Nano, m.ResumedAtUTC)
		if e1 != nil || e2 != nil || e3 != nil || paused.After(pubStart) || still.Before(pingEnd) || resumed.Before(still) || resumed.Sub(paused) > time.Duration(p.MaximumPauseNanos) {
			return errors.New("paused member nanosecond bracket differs")
		}
		if overlapStart.IsZero() || paused.After(overlapStart) {
			overlapStart = paused
		}
		if overlapEnd.IsZero() || still.Before(overlapEnd) {
			overlapEnd = still
		}
		seen[m.Member] = true
	}
	if overlapEnd.Sub(overlapStart).Nanoseconds() != p.ObservedPauseNanos {
		return errors.New("quorum pause overlap nanoseconds differ")
	}
	return nil
}

func validateReplication(r jetstreamprobe.ReplicationReceipt) error {
	if err := validateCluster(r.Stream); err != nil {
		return fmt.Errorf("stream cluster: %w", err)
	}
	if err := validateCluster(r.Consumer); err != nil {
		return fmt.Errorf("consumer cluster: %w", err)
	}
	if !sameClusterNames(r.Stream, r.Consumer) || r.Stream.Cluster != r.Consumer.Cluster {
		return errors.New("stream and consumer member identity differs")
	}
	return nil
}

func validateCluster(r jetstreamprobe.ClusterReceipt) error {
	if r.Cluster != "post25-nats-js" || r.Replicas != 3 || len(r.Members) != 3 {
		return errors.New("cluster name or replica count differs")
	}
	want := map[string]bool{"c2-nats-js-0": true, "c2-nats-js-1": true, "c2-nats-js-2": true}
	seen, leaders := map[string]bool{}, 0
	for _, m := range r.Members {
		if !want[m.Name] || seen[m.Name] || !m.Current || m.Offline || m.Lag != 0 {
			return errors.New("member identity or current state differs")
		}
		seen[m.Name] = true
		if m.Leader {
			leaders++
			if r.Leader != m.Name {
				return errors.New("leader identity differs")
			}
		}
	}
	if leaders != 1 || !seen[r.Leader] {
		return errors.New("cluster must have one exact leader")
	}
	return nil
}

func validateMessageChain(ack jetstreamprobe.PubAckReceipt, delivery jetstreamprobe.DeliveryReceipt, stored *jetstreamprobe.StoredReceipt, sequence uint64, stream, subject, messageID, hash string) error {
	if ack.Stream != stream || ack.Sequence != sequence || ack.MessageID != messageID || ack.PayloadHash != hash {
		return errors.New("PubAck identity differs")
	}
	if sequence != 2 || !strings.HasSuffix(messageID, "-x") {
		if ack.Duplicate {
			return errors.New("unexpected duplicate PubAck")
		}
	}
	if delivery.StreamSequence != sequence || delivery.ConsumerSequence != sequence || delivery.Deliveries != 1 || delivery.MessageID != messageID || delivery.PayloadHash != hash {
		return errors.New("consumer ACK/delivery identity differs")
	}
	if stored != nil && (stored.StreamSequence != sequence || stored.Subject != subject || stored.MessageID != messageID || stored.PayloadHash != hash) {
		return errors.New("stored message identity differs")
	}
	return nil
}

func validateFinalState(r jetstreamprobe.StateReceipt, stream string, last uint64) error {
	if r.Stream != stream || r.Consumer != "durability-main" || r.Replicas != 3 || r.DuplicateWindow != 120*time.Second || r.Messages != last || r.FirstSequence != 1 || r.LastSequence != last || r.AckFloor != last || r.AckPending != 0 || r.ConsumerPending != 0 || r.ConsumerRedelivered != 0 {
		return errors.New("final stream/consumer state differs")
	}
	return nil
}

func fillFinal(s *NATSJetStreamSummary, r jetstreamprobe.StateReceipt) {
	s.Stream, s.Consumer = r.Stream, r.Consumer
	s.FinalMessages, s.FinalFirstSequence, s.FinalLastSequence = r.Messages, r.FirstSequence, r.LastSequence
	s.FinalAckFloor, s.FinalAckPending = r.AckFloor, r.AckPending
	s.FinalConsumerPending, s.FinalConsumerRedelivered = r.ConsumerPending, r.ConsumerRedelivered
}

func natsNames(nonce string) (string, string) {
	return "DURABILITY_" + strings.ToUpper(strings.ReplaceAll(nonce, "-", "_")), "durability." + nonce
}

func volumeUIDs(a *NATSRunIdentity) []string {
	out := make([]string, 3)
	for i := range out {
		out[i] = a.PVCUIDs[i] + "/" + a.PVUIDs[i]
	}
	return out
}

func sameReplicationMembers(a, b jetstreamprobe.ReplicationReceipt) bool {
	return a.Stream.Cluster == b.Stream.Cluster && a.Consumer.Cluster == b.Consumer.Cluster && sameClusterNames(a.Stream, b.Stream) && sameClusterNames(a.Consumer, b.Consumer)
}

func sameClusterNames(a, b jetstreamprobe.ClusterReceipt) bool {
	if len(a.Members) != len(b.Members) {
		return false
	}
	left, right := map[string]bool{}, map[string]bool{}
	for _, m := range a.Members {
		left[m.Name] = true
	}
	for _, m := range b.Members {
		right[m.Name] = true
	}
	if len(left) != len(right) {
		return false
	}
	for name := range left {
		if !right[name] {
			return false
		}
	}
	return true
}

func payloadHash(value string) string {
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", h[:])
}

func canonicalNonnegativeInt(e map[string]string, key string) (int64, error) {
	v := e[key]
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != v {
		return 0, fmt.Errorf("evidence %s is not a canonical nonnegative integer", key)
	}
	return n, nil
}

func sameCanonicalInt(value string, want int64) bool {
	return want >= 0 && value == strconv.FormatInt(want, 10)
}

func safeNonce(v string) bool {
	if len(v) < 8 || len(v) > 128 || v[0] == '-' || v[len(v)-1] == '-' {
		return false
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func uuidText(v string) bool {
	if len(v) != 36 || v[8] != '-' || v[13] != '-' || v[18] != '-' || v[23] != '-' {
		return false
	}
	for i, r := range v {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func uniqueStrings(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
