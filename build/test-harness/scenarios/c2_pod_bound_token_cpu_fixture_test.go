package scenarios

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// This is a deterministic local protocol fixture, not a claim about a live
// manager. It uses the same create-once writer and ordered replay/phase
// emitters as RunPodBoundTokenCase. The selected audit projection is checked
// independently by the console against a local authenticated audit source.
func TestPodTokenCPUPositiveProducerReceipt(t *testing.T) {
	const runID, nonce, ns = "run-cpu-1", "0123456789abcdef01234567", "phorvex-catalogue-cpu"
	const sourceUID = "11111111-1111-4111-8111-111111111111"
	const peerUID = "22222222-2222-4222-8222-222222222222"
	const depUID = "55555555-5555-4555-8555-555555555555"
	const svcUID = "77777777-7777-4777-8777-777777777777"
	const policyUID = "88888888-8888-4888-8888-888888888888"
	const eventUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	base := time.Date(2026, 9, 24, 18, 0, 0, 0, time.UTC)
	at := func(seconds int) time.Time { return base.Add(time.Duration(seconds) * time.Second) }
	stamp := func(seconds int) string { return at(seconds).Format(time.RFC3339Nano) }
	fixtureDir := filepath.Join("..", "testdata", "pod_bound_token_cpu_positive")
	projectionRaw, err := os.ReadFile(filepath.Join(fixtureDir, "audit-projection.json"))
	if err != nil {
		t.Fatal(err)
	}
	var projection struct {
		Raw       json.RawMessage   `json:"raw"`
		Decision  podTokenDecision  `json:"decision"`
		Operation podTokenOperation `json:"operation"`
		RowSHA256 string            `json:"rowSHA256"`
	}
	if err := json.Unmarshal(projectionRaw, &projection); err != nil || podTokenHash(projection.Raw) != projection.RowSHA256 || projection.Operation.TerminationStatus != "REQUEST_CONFIRMED" || projection.Decision.SelectedAction != "rotate" {
		t.Fatal("local selected audit projection unavailable")
	}
	out := t.TempDir()
	env := &core.Env{ScenarioName: "c2-pod-bound-api-auth-response-cpu", Config: config.TargetConfig{Namespace: ns, OutDir: out, PodBoundTokenFixture: &config.PodBoundTokenFixtureConfig{RunID: runID, Nonce: nonce}}}
	name := "pod-token-" + nonce
	sourceName, peerName := name+"-source", name+"-peer"
	sha := strings.Repeat("a", 64)
	request := podTokenRequest{Schema: "pod-bound-token-request-v1", CaseID: env.ScenarioName, RunID: runID, Nonce: nonce, ClusterUID: "33333333-3333-4333-8333-333333333333", Namespace: ns, NamespaceUID: "44444444-4444-4444-8444-444444444444", SourcePodName: sourceName, SourcePodUID: sourceUID, DeploymentUID: depUID, ReplicaSetUID: "66666666-6666-4666-8666-666666666666", PeerPodName: peerName, PeerPodUID: peerUID, ServiceName: name, ServiceUID: svcUID, PDBUID: "pdb-uid", PolicyName: name, PolicyUID: policyUID, PolicyGeneration: 1, PolicySpecSHA256: sha, ManagerPodUID: "99999999-9999-4999-8999-999999999999", ManagerContainerID: "containerd://manager", ManagerImageID: "manager@sha256:" + sha, ProfileSHA256: sha, SourceBeforeHTTP: 200, PeerBeforeHTTP: 200, ServiceBeforeHTTP: 200, SourceExpiry: stamp(1200), PeerExpiry: stamp(1200), SourceBeforeRequestAt: stamp(54), SourceBeforeAt: stamp(55), PeerBeforeRequestAt: stamp(55), PeerBeforeAt: stamp(56), RequestedAt: stamp(60), SourceCaptureID: strings.Repeat("b", 32), PeerCaptureID: strings.Repeat("c", 32), MetricStatus: "MEASURED_FRESH", MetricFirstAt: stamp(30), MetricSecondAt: stamp(50), MetricFirstValue: 1, MetricSecondValue: 4, MetricSourcePodName: sourceName, PodMonitorUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", MetricQuerySHA256: sha}
	requestSHA, err := writePodTokenFile(out, podTokenRequestFile, request)
	if err != nil {
		t.Fatal(err)
	}
	resources := []struct{ resource, uid string }{{"serviceaccounts", "sa-uid"}, {"deployments", depUID}, {"services", svcUID}, {"poddisruptionbudgets", "pdb-uid"}, {"roles", "role-uid"}, {"rolebindings", "binding-uid"}, {"phorvexpolicies", policyUID}, {"podmonitors", request.PodMonitorUID}}
	for i, item := range resources {
		if err := podTokenCreatePhase(env, "CREATE_INTENT", item.resource, name, "", at(10+2*i)); err != nil {
			t.Fatal(err)
		}
		if err := podTokenCreatePhase(env, "CREATE_ACK", item.resource, name, types.UID(item.uid), at(11+2*i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := podTokenCreatePhase(env, "PATCH_INTENT", "pods", sourceName, sourceUID, at(26)); err != nil {
		t.Fatal(err)
	}
	if err := podTokenCreatePhase(env, "PATCH_ACK", "pods", sourceName, sourceUID, at(27)); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		phase              string
		status, start, end int
		capture            string
	}{{"source-before", 200, 54, 55, request.SourceCaptureID}, {"peer-before", 200, 55, 56, request.PeerCaptureID}, {"source-after", 401, 79, 80, request.SourceCaptureID}, {"peer-after", 200, 80, 81, request.PeerCaptureID}} {
		if err := podTokenReplayPhase(env, row.phase, row.status, at(row.end), row.capture, at(row.start)); err != nil {
			t.Fatal(err)
		}
	}
	event := podTokenEvent{UID: eventUID, Kind: "phorvex.attack.pod-bound-api-auth", Creator: "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector-cpu", SourcePodUID: sourceUID, TrustVerified: true}
	barrier := podTokenBarrier{Schema: "pod-bound-token-barrier-v1", RunID: runID, Nonce: nonce, RequestSHA256: requestSHA, Event: event, Decision: projection.Decision, Operation: projection.Operation, DecisionRowSHA: projection.RowSHA256, ObservedAt: stamp(74)}
	barrierSHA, err := writePodTokenFile(out, podTokenBarrierFile, barrier)
	if err != nil {
		t.Fatal(err)
	}
	if err := podTokenCreatePhase(env, "ORIGINAL_POD_ABSENT", "pods", sourceName, sourceUID, at(75)); err != nil {
		t.Fatal(err)
	}
	end := podTokenObservationEnd{Schema: "pod-bound-token-observation-end-v1", RunID: runID, Nonce: nonce, RequestSHA256: requestSHA, BarrierSHA256: barrierSHA, ObservationEndedAt: stamp(100)}
	endSHA, err := writePodTokenFile(out, "pod-bound-token-observation-end.json", end)
	if err != nil {
		t.Fatal(err)
	}
	commitment, _ := json.Marshal(map[string]any{"segment": map[string]any{"id": "fixture-segment", "generation": "fixture-generation", "size": 1024, "anchor": strings.Repeat("d", 32)}, "startOffset": 0, "endOffset": 256, "windowSHA256": sha, "capturedAtUnixNano": at(102).UnixNano()})
	if _, err := writePodTokenFile(out, "pod-bound-token-observation-committed.json", podTokenObservationCommitted{Schema: "pod-bound-token-observation-committed-v1", RunID: runID, Nonce: nonce, ObservationEndSHA256: endSHA, RequestSHA256: requestSHA, BarrierSHA256: barrierSHA, SourceIdentity: "fixture-audit-source", Commitment: commitment}); err != nil {
		t.Fatal(err)
	}
	for i, item := range resources {
		if err := podTokenCreatePhase(env, "DELETE_INTENT", item.resource, name, types.UID(item.uid), at(105+2*i)); err != nil {
			t.Fatal(err)
		}
		if err := podTokenCreatePhase(env, "DELETE_ACK", item.resource, name, types.UID(item.uid), at(106+2*i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writePodTokenFile(out, "pod-bound-token-event-cleanup.json", podTokenEventCleanupReceipt{Schema: "pod-bound-token-event-cleanup-v1", RunID: runID, Nonce: nonce, EventUID: eventUID, Status: "CONFIRMED_ABSENT", ObservedAt: stamp(125)}); err != nil {
		t.Fatal(err)
	}
	result := podTokenResult{Schema: "pod-bound-token-result-v1", CaseID: request.CaseID, RunID: runID, Nonce: nonce, TerminalStatus: "COMPLETE", SecurityEfficacy: "NOT_EVALUATED", SignalMode: "explicit-injected-typed-event"}
	stageNames := []string{"ADMISSION", "OWNED_FIXTURE", "CREDENTIAL_AND_ROUTE_BASELINE", "AUDIT_START", "SOLE_TYPED_SIGNAL", "BRAIN_DECISION", "NATIVE_OPERATION", "INDEPENDENT_OUTCOME", "CLEANUP"}
	stageTimes := []int{1, 26, 59, 71, 72, 73, 74, 85, 130}
	for i, name := range stageNames {
		result.Stages = append(result.Stages, podTokenStage{Name: name, Status: "CONFIRMED", ObservedAt: stamp(stageTimes[i])})
	}
	result.Admission = podTokenAdmission{ClusterUID: request.ClusterUID, Namespace: ns, NamespaceUID: request.NamespaceUID, ManagerPodUID: request.ManagerPodUID, ManagerContainerID: request.ManagerContainerID, ManagerImageID: request.ManagerImageID, DeploymentUID: depUID, ReplicaSetUID: request.ReplicaSetUID, PolicyUID: policyUID, PolicyGeneration: 1, PolicySpecSHA256: sha, SourcePodUID: sourceUID, PeerPodUID: peerUID, ServiceUID: svcUID, PDBUID: request.PDBUID, ProfileSHA256: sha, Available: true}
	result.Event = event
	result.Decision = projection.Decision
	result.Operation = projection.Operation
	fixtureSource := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: sourceName, Namespace: ns, UID: types.UID(sourceUID)}}
	env.Kube = fake.NewSimpleClientset(fixtureSource)
	if err := env.Kube.CoreV1().Pods(ns).Delete(context.Background(), sourceName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	result.Operation.OriginalPodAbsent = podTokenOriginalAbsent(context.Background(), env, podTokenFixture{source: *fixtureSource})
	result.Replay = podTokenReplay{SourceBeforeHTTP: 200, SourceBeforeRequestAt: request.SourceBeforeRequestAt, SourceBeforeAt: request.SourceBeforeAt, SourceAfterHTTP: 401, SourceAfterRequestAt: stamp(79), SourceAfterAt: stamp(80), SourceExpiry: request.SourceExpiry, PeerBeforeHTTP: 200, PeerBeforeRequestAt: request.PeerBeforeRequestAt, PeerBeforeAt: request.PeerBeforeAt, PeerAfterHTTP: 200, PeerAfterRequestAt: stamp(80), PeerAfterAt: stamp(81), PeerExpiry: request.PeerExpiry, ServiceBeforeHTTP: 200, ServiceAfterHTTP: 200, SameSourceHandle: true, SamePeerHandle: true, SourceBeforeCaptureID: request.SourceCaptureID, SourceAfterCaptureID: request.SourceCaptureID, PeerBeforeCaptureID: request.PeerCaptureID, PeerAfterCaptureID: request.PeerCaptureID, ServiceMemberPodUID: peerUID, ServiceAfterAt: stamp(82), ServiceAfterServiceUID: svcUID, ServiceAfterEndpointSliceUID: "slice-uid", ServiceMemberReady: true, ServiceMemberOwnerDeploymentUID: depUID}
	result.Telemetry = podTokenTelemetry{ProducerStatus: request.MetricStatus, FirstAt: request.MetricFirstAt, SecondAt: request.MetricSecondAt, FirstValue: request.MetricFirstValue, SecondValue: request.MetricSecondValue, SourcePodName: sourceName, PodMonitorUID: request.PodMonitorUID, QuerySHA256: sha}
	result.Cleanup = podTokenCleanup{Status: "CONFIRMED_ABSENT", InventorySHA256: sha, Absent: true}
	result.MechanismObserved = podTokenMechanismObserved(result, sourceUID, true, true, nil)
	if !result.MechanismObserved {
		t.Fatal("production positive response predicate refused local fixture")
	}
	late := result
	late.Replay.SourceExpiry = stamp(105)
	if podTokenMechanismObserved(late, sourceUID, true, true, nil) {
		t.Fatal("late source 401 credited by producer")
	}
	peerOutage := result
	peerOutage.Replay.PeerAfterHTTP = 503
	if podTokenMechanismObserved(peerOutage, sourceUID, true, true, nil) {
		t.Fatal("peer outage credited by producer")
	}
	phases, err := os.ReadFile(filepath.Join(out, podTokenPhaseFile))
	if err != nil {
		t.Fatal(err)
	}
	artifact := podTokenArtifact{Result: result, RequestSHA256: requestSHA, BarrierSHA256: barrierSHA, PhaseJournalSHA256: podTokenHash(phases), ObservationEndedAt: end.ObservationEndedAt}
	artifactSHA, err := writePodTokenFile(out, podTokenArtifactFile, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePodTokenFile(out, podTokenTerminalFile, podTokenTerminal{Schema: "pod-bound-token-terminal-v1", RunID: runID, Nonce: nonce, ArtifactSHA256: artifactSHA, CleanupStatus: "CONFIRMED_ABSENT", ProtectedReservationAbsent: true, FinishedAt: stamp(135)}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{podTokenRequestFile, podTokenBarrierFile, podTokenArtifactFile, podTokenTerminalFile, podTokenPhaseFile, "pod-bound-token-replays.jsonl", "pod-bound-token-observation-end.json", "pod-bound-token-observation-committed.json", "pod-bound-token-event-cleanup.json"} {
		produced, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(fixtureDir, name)
		if os.Getenv("UPDATE_CPU_TOKEN_POSITIVE_FIXTURE") == "1" {
			if err := os.WriteFile(path, produced, 0600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		committed, err := os.ReadFile(path)
		if err != nil || string(committed) != string(produced) {
			t.Fatalf("CPU positive producer receipt %s changed: %v", name, err)
		}
	}
}
