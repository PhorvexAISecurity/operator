package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This fixture uses the producer's create-once writer and typed wire structs.
// The audit row and authenticated seal are coordinator/audit-source outputs;
// consumer tests must supply those independently rather than treating fixture
// bytes as an authenticated source.
func emitPodTokenNoopFixture(dir string) error {
	const runID = "run-1"
	const nonce = "0123456789abcdef01234567"
	const name = "pod-token-" + nonce
	const sourceName = name + "-source"
	const peerName = name + "-peer"
	const sourceUID = "11111111-1111-4111-8111-111111111111"
	const peerUID = "22222222-2222-4222-8222-222222222222"
	const creator = "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector"
	base := time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC)
	at := func(n int) string { return base.Add(time.Duration(n) * time.Second).Format(time.RFC3339Nano) }
	hash := strings.Repeat("a", 64)
	request := podTokenRequest{Schema: "pod-bound-token-request-v1", RunID: runID, Nonce: nonce,
		ClusterUID: "33333333-3333-4333-8333-333333333333", Namespace: "voice", NamespaceUID: "44444444-4444-4444-8444-444444444444",
		SourcePodName: sourceName, SourcePodUID: sourceUID, DeploymentUID: "55555555-5555-4555-8555-555555555555", ReplicaSetUID: "66666666-6666-4666-8666-666666666666",
		PeerPodName: peerName, PeerPodUID: peerUID, ServiceName: name, ServiceUID: "77777777-7777-4777-8777-777777777777",
		PolicyName: name, PolicyUID: "88888888-8888-4888-8888-888888888888", PolicyGeneration: 1, PolicySpecSHA256: hash,
		ManagerPodUID: "99999999-9999-4999-8999-999999999999", ManagerContainerID: "containerd://manager", ManagerImageID: "manager@sha256:" + hash,
		ProfileSHA256: hash, SourceBeforeHTTP: 200, PeerBeforeHTTP: 200, ServiceBeforeHTTP: 200,
		SourceExpiry: at(1200), RequestedAt: at(30), SourceCaptureID: strings.Repeat("b", 32), PeerCaptureID: strings.Repeat("c", 32),
		MetricStatus: "MISSING_REQUEST_RATE", MetricSourcePodName: sourceName, PodMonitorUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", MetricQuerySHA256: hash}
	reqSHA, err := writePodTokenFile(dir, podTokenRequestFile, request)
	if err != nil {
		return err
	}
	event := podTokenEvent{UID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Kind: "phorvex.attack.pod-bound-api-auth", Creator: creator, SourcePodUID: sourceUID, TrustVerified: true}
	decision := podTokenDecision{ID: "decision-noop", SelectedAction: "noop", DispatchOutcome: "not-attempted", CostCeiling: 1.2, RotateStatus: "infeasible", RotateReason: "measured request rate unavailable", RequestRateStatus: "MISSING_REQUEST_RATE", QuarantineStatus: "infeasible", AuditCoverage: "COMPLETE"}
	operation := podTokenOperation{TerminationStatus: "NOT_DISPATCHED"}
	barrier := podTokenBarrier{Schema: "pod-bound-token-barrier-v1", RunID: runID, Nonce: nonce, RequestSHA256: reqSHA, Event: event, Decision: decision, Operation: operation, DecisionRowSHA: hash, ObservedAt: at(40)}
	barrierSHA, err := writePodTokenFile(dir, podTokenBarrierFile, barrier)
	if err != nil {
		return err
	}
	end := podTokenObservationEnd{Schema: "pod-bound-token-observation-end-v1", RunID: runID, Nonce: nonce, RequestSHA256: reqSHA, BarrierSHA256: barrierSHA, ObservationEndedAt: at(80)}
	endSHA, err := writePodTokenFile(dir, "pod-bound-token-observation-end.json", end)
	if err != nil {
		return err
	}
	_, err = writePodTokenFile(dir, "pod-bound-token-observation-committed.json", map[string]any{
		"schema": "pod-bound-token-observation-committed-v1", "runID": runID, "nonce": nonce,
		"observationEndSHA256": endSHA, "requestSHA256": reqSHA, "barrierSHA256": barrierSHA, "sourceIdentity": "fixture-audit-source",
		"commitment": map[string]any{"segment": map[string]any{"id": "fixture-segment", "generation": "fixture-generation", "size": 1024, "anchor": strings.Repeat("d", 32)}, "startOffset": 0, "endOffset": 256, "windowSHA256": hash, "capturedAtUnixNano": base.Add(82 * time.Second).UnixNano()},
	})
	if err != nil {
		return err
	}
	_, err = writePodTokenFile(dir, "pod-bound-token-event-cleanup.json", podTokenEventCleanupReceipt{Schema: "pod-bound-token-event-cleanup-v1", RunID: runID, Nonce: nonce, EventUID: event.UID, Status: "CONFIRMED_ABSENT", ObservedAt: at(90)})
	if err != nil {
		return err
	}
	uidByResource := map[string]string{"serviceaccounts": "sa-uid", "deployments": request.DeploymentUID, "services": request.ServiceUID, "poddisruptionbudgets": "pdb-uid", "roles": "role-uid", "rolebindings": "binding-uid", "phorvexpolicies": request.PolicyUID, "podmonitors": request.PodMonitorUID}
	resources := []string{"serviceaccounts", "deployments", "services", "poddisruptionbudgets", "roles", "rolebindings", "phorvexpolicies", "podmonitors"}
	var phaseBytes []byte
	phaseAt := 10
	phase := func(op, resource, object, uid string) error {
		row, err := json.Marshal(map[string]string{"schema": "pod-bound-token-phase-v1", "runID": runID, "nonce": nonce, "operation": op, "resource": resource, "name": object, "uid": uid, "at": at(phaseAt)})
		phaseAt++
		if err != nil {
			return err
		}
		phaseBytes = append(phaseBytes, append(row, '\n')...)
		return nil
	}
	for _, resource := range resources {
		if err := phase("CREATE_INTENT", resource, name, ""); err != nil {
			return err
		}
		if err := phase("CREATE_ACK", resource, name, uidByResource[resource]); err != nil {
			return err
		}
	}
	if err := phase("PATCH_INTENT", "pods", sourceName, sourceUID); err != nil {
		return err
	}
	if err := phase("PATCH_ACK", "pods", sourceName, sourceUID); err != nil {
		return err
	}
	phaseAt = 85
	for _, resource := range resources {
		if err := phase("DELETE_INTENT", resource, name, uidByResource[resource]); err != nil {
			return err
		}
		if err := phase("DELETE_ACK", resource, name, uidByResource[resource]); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, podTokenPhaseFile), phaseBytes, 0600); err != nil {
		return err
	}
	var replayBytes []byte
	for _, row := range []struct {
		phase          string
		status, second int
		capture        string
	}{{"source-before", 200, 27, request.SourceCaptureID}, {"peer-before", 200, 28, request.PeerCaptureID}, {"source-after", 200, 50, request.SourceCaptureID}, {"peer-after", 200, 51, request.PeerCaptureID}} {
		encoded, err := json.Marshal(map[string]any{"schema": "pod-bound-token-replay-v1", "runID": runID, "nonce": nonce, "phase": row.phase, "http": row.status, "at": at(row.second), "captureID": row.capture})
		if err != nil {
			return err
		}
		replayBytes = append(replayBytes, append(encoded, '\n')...)
	}
	if err := os.WriteFile(filepath.Join(dir, "pod-bound-token-replays.jsonl"), replayBytes, 0600); err != nil {
		return err
	}
	stages := make([]podTokenStage, len(podTokenStageNames))
	for i, stage := range podTokenStageNames {
		stages[i] = podTokenStage{Name: stage, Status: "CONFIRMED", ObservedAt: at([]int{1, 26, 29, 41, 42, 43, 44, 55, 110}[i])}
	}
	result := podTokenResult{Schema: "pod-bound-token-result-v1", RunID: runID, Nonce: nonce, TerminalStatus: "COMPLETE", SecurityEfficacy: "NOT_EVALUATED", SignalMode: "explicit-injected-typed-event", Stages: stages,
		Admission: podTokenAdmission{ClusterUID: request.ClusterUID, Namespace: "voice", NamespaceUID: request.NamespaceUID, ManagerPodUID: request.ManagerPodUID, ManagerContainerID: request.ManagerContainerID, ManagerImageID: request.ManagerImageID, DeploymentUID: request.DeploymentUID, ReplicaSetUID: request.ReplicaSetUID, PolicyUID: request.PolicyUID, PolicyGeneration: 1, PolicySpecSHA256: hash, SourcePodUID: sourceUID, PeerPodUID: peerUID, ServiceUID: request.ServiceUID, ProfileSHA256: hash, Available: true},
		Event:     event, Decision: decision, Operation: operation,
		Replay:    podTokenReplay{SourceBeforeHTTP: 200, SourceAfterHTTP: 200, SourceExpiry: request.SourceExpiry, SourceAfterAt: at(50), PeerBeforeHTTP: 200, PeerAfterHTTP: 200, ServiceBeforeHTTP: 200, ServiceAfterHTTP: 200, SameSourceHandle: true, SamePeerHandle: true, SourceBeforeCaptureID: request.SourceCaptureID, SourceAfterCaptureID: request.SourceCaptureID, PeerBeforeCaptureID: request.PeerCaptureID, PeerAfterCaptureID: request.PeerCaptureID, ServiceMemberPodUID: peerUID, ServiceAfterAt: at(52), ServiceAfterServiceUID: request.ServiceUID, ServiceAfterEndpointSliceUID: "slice-uid", ServiceMemberReady: true, ServiceMemberOwnerDeploymentUID: request.DeploymentUID},
		Telemetry: podTokenTelemetry{ProducerStatus: request.MetricStatus, SourcePodName: sourceName, PodMonitorUID: request.PodMonitorUID, QuerySHA256: request.MetricQuerySHA256},
		Cleanup:   podTokenCleanup{Status: "CONFIRMED_ABSENT", InventorySHA256: hash, Absent: true}}
	artifact := podTokenArtifact{Result: result, RequestSHA256: reqSHA, BarrierSHA256: barrierSHA, PhaseJournalSHA256: podTokenHash(phaseBytes), ObservationEndedAt: at(80)}
	artifactSHA, err := writePodTokenFile(dir, podTokenArtifactFile, artifact)
	if err != nil {
		return err
	}
	_, err = writePodTokenFile(dir, podTokenTerminalFile, podTokenTerminal{Schema: "pod-bound-token-terminal-v1", RunID: runID, Nonce: nonce, ArtifactSHA256: artifactSHA, CleanupStatus: "CONFIRMED_ABSENT", ProtectedReservationAbsent: true, FinishedAt: at(120)})
	return err
}

func TestPodTokenProducerNoopProtocolFixture(t *testing.T) {
	dir := t.TempDir()
	if out := os.Getenv("POD_TOKEN_TESTDATA_OUT"); out != "" {
		dir = out
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := emitPodTokenNoopFixture(dir); err != nil {
		t.Fatal(err)
	}
	var artifact podTokenArtifact
	raw, err := os.ReadFile(filepath.Join(dir, podTokenArtifactFile))
	if err != nil || json.Unmarshal(raw, &artifact) != nil || artifact.Result.MechanismObserved || artifact.Result.TerminalStatus != "COMPLETE" || len(artifact.PhaseJournalSHA256) != 64 {
		t.Fatal("producer no-op fixture lost its negative mechanism or terminal binding")
	}
}
