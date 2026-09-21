package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/report"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func completeVoiceWSReceipt(uid string, frames int) voiceWSReceipt {
	sequences := make([]int, frames)
	for i := range sequences {
		sequences[i] = i + 1
	}
	return voiceWSReceipt{Version: 1, ServiceURL: "http://c2-voice-ws-target:8080", SessionID: "voice-1", StartedAtUTC: "2026-09-21T00:00:00Z", EndedAtUTC: "2026-09-21T00:00:01Z", TwiMLStatus: 200, TwiMLSHA256: strings.Repeat("a", 64), WebSocketURL: "ws://c2-voice-ws-target:8080/ws", TargetPodUID: uid, Outcome: "completed", ExpectedFrames: frames, ReceivedSequences: sequences, EndMarker: true, CloseCode: 1000}
}

func TestVoiceWSReceiptRequiresExactCompletion(t *testing.T) {
	valid := completeVoiceWSReceipt("old-uid", 3)
	if !voiceWSReceiptCompleted(valid) {
		t.Fatal("exact completed receipt rejected")
	}
	for name, mutate := range map[string]func(*voiceWSReceipt){
		"missing-end":   func(r *voiceWSReceipt) { r.EndMarker = false },
		"wrong-close":   func(r *voiceWSReceipt) { r.CloseCode = 1006 },
		"gap":           func(r *voiceWSReceipt) { r.ReceivedSequences = []int{1, 3}; r.Gaps = 1 },
		"duplicate":     func(r *voiceWSReceipt) { r.ReceivedSequences = []int{1, 2, 2}; r.DuplicateSequences = 1 },
		"wrong-order":   func(r *voiceWSReceipt) { r.ReceivedSequences = []int{2, 1, 3} },
		"failure":       func(r *voiceWSReceipt) { r.Failure = "late-error" },
		"false-summary": func(r *voiceWSReceipt) { r.ReceivedSequences = []int{1, 1, 3}; r.DuplicateSequences = 0; r.Gaps = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.ReceivedSequences = append([]int(nil), valid.ReceivedSequences...)
			mutate(&candidate)
			if voiceWSReceiptCompleted(candidate) {
				t.Fatal("malformed completion accepted")
			}
		})
	}
}

func TestValidateVoiceWSReceiptSeparatesEarlyClose(t *testing.T) {
	base, id := "http://c2-voice-ws-target:8080", "voice-1"
	valid := completeVoiceWSReceipt("old-uid", 3)
	if err := validateVoiceWSReceipt(valid, base, id, 3); err != nil {
		t.Fatalf("valid completion: %v", err)
	}
	early := valid
	early.Outcome = "early-close"
	early.EndMarker = false
	early.CloseCode = 1006
	early.ReceivedSequences = []int{1}
	early.Gaps = 2
	early.Failure = "connection-closed-before-end"
	if err := validateVoiceWSReceipt(early, base, id, 3); err != nil {
		t.Fatalf("valid early close: %v", err)
	}
	for name, mutate := range map[string]func(*voiceWSReceipt){
		"false-end":  func(r *voiceWSReceipt) { r.EndMarker = true },
		"all-frames": func(r *voiceWSReceipt) { r.ReceivedSequences = []int{1, 2, 3} },
		"no-failure": func(r *voiceWSReceipt) { r.Failure = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := early
			candidate.ReceivedSequences = append([]int(nil), early.ReceivedSequences...)
			mutate(&candidate)
			if err := validateVoiceWSReceipt(candidate, base, id, 3); err == nil {
				t.Fatal("contradictory early close accepted")
			}
		})
	}
}

func TestVoiceWSOracleNoActionAndTimerReplacementAreDiscriminating(t *testing.T) {
	noActionAvailability := voiceWSAvailability{Samples: 1, MinimumReady: 3, OriginalSeen: true, ObservedReadyUIDs: []string{"old-uid", "peer-1", "peer-2"}, Observations: []voiceWSAvailabilityObservation{{AtUTC: "2026-09-21T00:00:00Z", Known: true, Category: "ready-endpoints", ReadyUIDs: []string{"old-uid", "peer-1", "peer-2"}}}}
	noAction := &c2VoiceWebSocketContinuity{originalUID: types.UID("old-uid"), receipt: completeVoiceWSReceipt("old-uid", 3), sharedProbe: completeVoiceWSReceipt("peer-1", 2), availability: noActionAvailability}
	got, err := noAction.SuccessOracle(context.Background(), nil)
	if err != nil || !got.Achieved {
		t.Fatalf("no action got=%+v err=%v", got, err)
	}
	early := completeVoiceWSReceipt("old-uid", 3)
	early.Outcome = "early-close"
	early.EndMarker = false
	early.CloseCode = 1006
	early.ReceivedSequences = []int{1}
	early.Gaps = 2
	early.Failure = "connection-closed-before-end"
	rotateAvailability := voiceWSAvailability{Samples: 2, MinimumReady: 2, OriginalSeen: true, OriginalAbsentSeen: true, ObservedReadyUIDs: []string{"old-uid", "new-uid", "peer-1", "peer-2"}, Observations: []voiceWSAvailabilityObservation{
		{AtUTC: "2026-09-21T00:00:00Z", Known: true, Category: "ready-endpoints", ReadyUIDs: []string{"old-uid", "peer-1", "peer-2"}},
		{AtUTC: "2026-09-21T00:00:01Z", Known: true, Category: "ready-endpoints", ReadyUIDs: []string{"new-uid", "peer-1", "peer-2"}},
	}}
	rotate := &c2VoiceWebSocketContinuity{originalUID: types.UID("old-uid"), replacementUID: types.UID("new-uid"), originalAPIAbsent: true, originalAbsenceObservedAt: "2026-09-21T00:00:01Z", replacementObservedAt: "2026-09-21T00:00:02Z", receipt: early, sharedProbe: completeVoiceWSReceipt("peer-1", 2), recovery: completeVoiceWSReceipt("new-uid", 2), availability: rotateAvailability}
	got, err = rotate.SuccessOracle(context.Background(), nil)
	if err != nil || got.Achieved {
		t.Fatalf("rotation got=%+v err=%v", got, err)
	}
	rotate.availability.MinimumReady = 1
	if _, err = rotate.SuccessOracle(context.Background(), nil); err == nil {
		t.Fatal("availability-floor breach accepted")
	}
}

func validatedVoiceWSObservation(t *testing.T, receipt voiceWSReceipt) voiceWSExchangeObservation {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return voiceWSExchangeObservation{
		ProducerStatus:       "validated",
		ProducerStdoutBytes:  len(raw),
		ProducerStdoutSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)),
		ProducerExitCode:     0,
		ReceiptDecoded:       true,
		ReceiptValidated:     true,
		Receipt:              receipt,
	}
}

func voiceWSEvidenceNoActionState(t *testing.T) c2VoiceWebSocketContinuity {
	t.Helper()
	target := completeVoiceWSReceipt("old-uid", voiceWSExpectedFrames)
	shared := completeVoiceWSReceipt("peer-1", 2)
	return c2VoiceWebSocketContinuity{
		originalUID:       types.UID("old-uid"),
		receipt:           target,
		sharedProbe:       shared,
		targetObservation: validatedVoiceWSObservation(t, target),
		sharedObservation: validatedVoiceWSObservation(t, shared),
		availability: voiceWSAvailability{
			Samples:           2,
			MinimumReady:      3,
			OriginalSeen:      true,
			ObservedReadyUIDs: []string{"old-uid", "peer-1", "peer-2"},
			Observations: []voiceWSAvailabilityObservation{
				{AtUTC: "2026-09-21T00:00:00Z", Known: true, Category: "ready-endpoints", ReadyUIDs: []string{"old-uid", "peer-1", "peer-2"}},
				{AtUTC: "2026-09-21T00:00:01Z", Known: true, Category: "ready-endpoints", ReadyUIDs: []string{"old-uid", "peer-1", "peer-2"}},
			},
		},
	}
}

func voiceWSEvidenceReplacementState(t *testing.T) c2VoiceWebSocketContinuity {
	t.Helper()
	state := voiceWSEvidenceNoActionState(t)
	early := completeVoiceWSReceipt("old-uid", voiceWSExpectedFrames)
	early.Outcome = "early-close"
	early.EndMarker = false
	early.CloseCode = 1006
	early.ReceivedSequences = []int{1, 2, 3, 4}
	early.Gaps = voiceWSExpectedFrames - len(early.ReceivedSequences)
	early.Failure = "SECRET-RECEIPT-FAILURE"
	recovery := completeVoiceWSReceipt("new-uid", 2)
	state.receipt = early
	state.targetObservation = validatedVoiceWSObservation(t, early)
	state.replacementUID = types.UID("new-uid")
	state.originalAPIAbsent = true
	state.originalAbsenceObservedAt = "2026-09-21T00:00:01Z"
	state.replacementObservedAt = "2026-09-21T00:00:02Z"
	state.recovery = recovery
	state.recoveryObservation = validatedVoiceWSObservation(t, recovery)
	state.availability.MinimumReady = 2
	state.availability.OriginalAbsentSeen = true
	state.availability.ObservedReadyUIDs = []string{"old-uid", "new-uid", "peer-1", "peer-2"}
	state.availability.Observations[1] = voiceWSAvailabilityObservation{AtUTC: "2026-09-21T00:00:01Z", Known: true, Category: "ready-endpoints", ReadyUIDs: []string{"new-uid", "peer-1", "peer-2"}}
	return state
}

type voiceWSEvidenceRunnerScenario struct {
	name         string
	mode         string
	state        c2VoiceWebSocketContinuity
	availability *voiceWSAvailability
	t            *testing.T
}

func (s *voiceWSEvidenceRunnerScenario) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{Name: s.name, Category: core.CategoryR6Claimed, Source: "voice benchmark evidence JSONL integration control", R6ResponseTag: core.R6Partial, R6Justification: "test-only wrapper exercises the voice producer evidence boundary without claiming defensive attribution", BenignControl: true, Realism: core.RealismExecutable, Mechanism: "test wrapper over voice evidence producer", ClaimLimits: voiceWSEvidenceClaimScope}
}

func (s *voiceWSEvidenceRunnerScenario) Setup(context.Context, *core.Env) error {
	s.state = c2VoiceWebSocketContinuity{}
	return nil
}

func (s *voiceWSEvidenceRunnerScenario) Execute(context.Context, *core.Env) (core.AttackResult, error) {
	switch s.mode {
	case "no-action":
		s.state = voiceWSEvidenceNoActionState(s.t)
		result, err := s.state.attackResult([]string{"actual bounded producer receipt"}, "execute-complete", nil)
		result.Notes = map[string]string{"legacySecret": "SECRET-LEGACY-NOTE"}
		return result, err
	case "replacement":
		s.state = voiceWSEvidenceReplacementState(s.t)
		result, err := s.state.attackResult([]string{"actual bounded early-close and recovery receipts"}, "execute-complete", nil)
		result.Notes = map[string]string{"legacySecret": "SECRET-LEGACY-NOTE"}
		return result, err
	case "invalid-partial":
		raw := []byte(`{"version":1,"partial":"SECRET-PARTIAL-PAYLOAD"}`)
		target := completeVoiceWSReceipt("old-uid", voiceWSExpectedFrames)
		s.state.originalUID = types.UID("old-uid")
		s.state.receipt = target
		s.state.targetObservation = validatedVoiceWSObservation(s.t, target)
		s.state.sharedObservation = voiceWSExchangeObservation{ProducerStatus: "exec-failed", ProducerStdoutBytes: len(raw), ProducerStdoutSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), ProducerExitCode: -1}
		s.state.availability = voiceWSAvailability{Samples: 1, MinimumReady: 2, OriginalSeen: true, ObservedReadyUIDs: []string{"old-uid", "peer-1"}, Observations: []voiceWSAvailabilityObservation{{AtUTC: "2026-09-21T00:00:00Z", Known: true, Category: "ready-endpoints", ReadyUIDs: []string{"old-uid", "peer-1"}}}}
		result, err := s.state.attackResult([]string{"producer started"}, "exchanges-observed", errors.New("SECRET-EXEC-ERROR"))
		result.Notes = map[string]string{"legacySecret": "SECRET-LEGACY-NOTE"}
		return result, err
	case "sampled-availability":
		s.state = voiceWSEvidenceNoActionState(s.t)
		s.state.availability = *s.availability
		result, err := s.state.attackResult([]string{"actual availability sampling loop"}, "execute-complete", nil)
		result.Notes = map[string]string{"legacySecret": "SECRET-LEGACY-NOTE"}
		return result, err
	default:
		return core.AttackResult{}, errors.New("unknown voice evidence test mode")
	}
}

func (s *voiceWSEvidenceRunnerScenario) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	return s.state.SuccessOracle(ctx, env)
}

func (*voiceWSEvidenceRunnerScenario) Teardown(context.Context, *core.Env) error { return nil }

func TestVoiceWSBenchmarkEvidenceSurvivesRunnerJSONLBoundedAndSanitized(t *testing.T) {
	const prefix = "voice-evidence-jsonl-"
	sampled := sampleVoiceWSAvailabilityForEvidenceTest(t, 20, 3)
	for _, mode := range []string{"no-action", "replacement", "invalid-partial", "sampled-availability"} {
		name := prefix + mode
		if registered, ok := core.LookupScenario(name); ok {
			scenario := registered.(*voiceWSEvidenceRunnerScenario)
			scenario.t = t
			scenario.availability = &sampled
		} else {
			core.RegisterScenario(&voiceWSEvidenceRunnerScenario{name: name, mode: mode, availability: &sampled, t: t})
		}
	}
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	writer, err := core.NewMetricWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	factory := func(_, _ string, _ int, _ int64, _ string) (*core.Env, func() error, error) {
		return &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Log: &ctLogger{}, Guard: ctGuard{}}, func() error { return nil }, nil
	}
	runner := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir(), ScenarioFilter: map[string]bool{prefix + "no-action": true, prefix + "replacement": true, prefix + "invalid-partial": true, prefix + "sampled-availability": true}, DefenderFilter: map[string]bool{"d-nomtd": true}, CleanupTimeout: 2 * time.Second}, factory, writer, nil)
	rows, err := runner.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows=%d want 4", len(rows))
	}
	read, err := report.ReadMetricsFile(path)
	if err != nil || len(read.Undecodable) != 0 || len(read.Metrics) != 4 {
		t.Fatalf("read=%+v err=%v", read, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET-LEGACY-NOTE", "SECRET-EXEC-ERROR", "SECRET-PARTIAL-PAYLOAD", "SECRET-RECEIPT-FAILURE", "SECRET-ENDPOINT-ERROR"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("unsafe value %q leaked to JSONL", secret)
		}
	}
	for _, row := range read.Metrics {
		if err := validateVoiceWSBenchmarkEvidence(row.BenchmarkEvidence); err != nil {
			t.Fatalf("%s evidence invalid after JSONL: %v", row.Scenario, err)
		}
		switch row.Scenario {
		case prefix + "no-action":
			if row.MeasurementState().Status != core.MeasurementValid || !row.OracleAchieved || row.BenchmarkEvidence["oracle.status"] != "observed-no-action" || row.BenchmarkEvidence["target.receipt.receivedSequences"] != "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20" {
				t.Fatalf("no-action row=%+v", row)
			}
		case prefix + "replacement":
			if row.MeasurementState().Status != core.MeasurementValid || row.OracleAchieved || row.BenchmarkEvidence["oracle.status"] != "observed-replacement-interruption" || row.BenchmarkEvidence["replacement.podUID"] != "new-uid" || row.BenchmarkEvidence["recovery.receipt.targetPodUID"] != "new-uid" {
				t.Fatalf("replacement row=%+v", row)
			}
		case prefix + "invalid-partial":
			if row.MeasurementState().Status != core.MeasurementInvalid || row.IsScored() || row.BenchmarkEvidence["oracle.status"] != "not-observed" || row.BenchmarkEvidence["target.producerStatus"] != "validated" || row.BenchmarkEvidence["target.receipt.receivedFrameCount"] != "20" || row.BenchmarkEvidence["shared.producerStatus"] != "exec-failed" || !isLowerHexSHA256(row.BenchmarkEvidence["shared.stdoutSHA256"]) {
				t.Fatalf("invalid partial row=%+v", row)
			}
		case prefix + "sampled-availability":
			if row.MeasurementState().Status != core.MeasurementInvalid || row.IsScored() || row.BenchmarkEvidence["oracle.status"] != "invalid-availability" || row.BenchmarkEvidence["availability.attempts"] != "20" || row.BenchmarkEvidence["availability.samples"] != "17" || row.BenchmarkEvidence["availability.failures"] != "3" || row.BenchmarkEvidence["availability.observationCount"] != "20" || row.BenchmarkEvidence["availability.observationsComplete"] != "true" || !strings.Contains(row.BenchmarkEvidence["availability.observation.00"], `"known":false,"category":"endpoint-read-unavailable","readyCount":-1`) || !strings.Contains(row.BenchmarkEvidence["availability.observation.19"], `"known":true,"category":"ready-endpoints","readyCount":3`) {
				t.Fatalf("sampled availability row=%+v", row)
			}
		}
	}
}

func TestVoiceWSBenchmarkEvidenceRefusesUnknownContradictoryAndUnboundedData(t *testing.T) {
	state := voiceWSEvidenceNoActionState(t)
	if err := state.updateVoiceWSBenchmarkEvidence("execute-complete", "not-observed"); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]string {
		out := make(map[string]string, len(state.benchmarkEvidence))
		for key, value := range state.benchmarkEvidence {
			out[key] = value
		}
		return out
	}
	for name, mutate := range map[string]func(map[string]string){
		"unknown-key": func(e map[string]string) { e["legacy.notes"] = "unsafe" },
		"oversized-value": func(e map[string]string) {
			e["target.receipt.outcome"] = strings.Repeat("x", voiceWSEvidenceMaxValue+1)
		},
		"malformed-hash":     func(e map[string]string) { e["target.stdoutSHA256"] = "ABC" },
		"changed-source-pin": func(e map[string]string) { e["source.serverSHA256"] = strings.Repeat("b", 64) },
		"malformed-time":     func(e map[string]string) { e["target.receipt.startedAtUTC"] = "yesterday" },
		"contradictory-list": func(e map[string]string) { e["target.receipt.receivedFrameCount"] = "19" },
		"contradictory-status": func(e map[string]string) {
			e["target.receiptValidated"] = "false"
		},
		"contradictory-attempt-count": func(e map[string]string) { e["availability.attempts"] = "3" },
		"false-observation-overflow": func(e map[string]string) {
			e["availability.observationOverflow"] = "true"
			e["availability.observationsComplete"] = "false"
		},
		"unknown-failure-category": func(e map[string]string) {
			e["availability.observation.00"] = `{"atUTC":"2026-09-21T00:00:00Z","known":false,"category":"SECRET-RAW-ERROR","readyCount":-1,"listComplete":false,"readyUIDs":[]}`
		},
		"too-many-sequences": func(e map[string]string) { e["target.receipt.receivedSequences"] = strings.Repeat("1,", 64) + "1" },
	} {
		t.Run(name, func(t *testing.T) {
			evidence := clone()
			mutate(evidence)
			if err := validateVoiceWSBenchmarkEvidence(evidence); err == nil {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
	state.availability.ObservedReadyUIDs = nil
	for i := 0; i < voiceWSReadyUIDLimit+1; i++ {
		state.availability.ObservedReadyUIDs = append(state.availability.ObservedReadyUIDs, fmt.Sprintf("pod-%02d", i))
	}
	if err := state.updateVoiceWSBenchmarkEvidence("execute-complete", "not-observed"); err != nil {
		t.Fatal(err)
	}
	if state.benchmarkEvidence["availability.readyUIDs"] != "BOUND_EXCEEDED" || state.benchmarkEvidence["availability.readyUIDListComplete"] != "false" || state.benchmarkEvidence["availability.readyUIDCount"] != "17" {
		t.Fatalf("overflow marker=%v", state.benchmarkEvidence)
	}
}

func TestVoiceWSWorkloadRotatesOnlyTargetAndPinsSources(t *testing.T) {
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned", BenignSessionNodeSelector: map[string]string{"kubernetes.io/hostname": "reviewed-node"}}, ScenarioName: voiceWSScenario, DefenderName: "d-r6blindtimer", Trial: 2}
	target := voiceWSDeployment(env, voiceWSTargetDeployment, "target", 1, true)
	peers := voiceWSDeployment(env, voiceWSPeerDeployment, "peer", 2, false)
	if target.Spec.Template.Labels[defenders.RotationTargetLabel] != "true" {
		t.Fatal("target is not rotation selected")
	}
	if _, present := peers.Spec.Template.Labels[defenders.RotationTargetLabel]; present {
		t.Fatal("peer availability replicas are rotation selected")
	}
	if *target.Spec.Replicas != 1 || *peers.Spec.Replicas != 2 {
		t.Fatal("fixture replica split changed")
	}
	if got := target.Spec.Template.Annotations["fixture.phorvex.ai/source-sha256"]; got != voiceWSServerSourceSHA256() || len(got) != 64 {
		t.Fatalf("server source pin=%q", got)
	}
	if got := target.Spec.Template.Annotations["fixture.phorvex.ai/runtime-bot-sha256"]; got != voiceWSRuntimeBotSHA256 {
		t.Fatalf("runtime source profile=%q", got)
	}
	if target.Spec.Template.Spec.Containers[0].Image != voiceWSRuntimeImage || peers.Spec.Template.Spec.Containers[0].Image != voiceWSRuntimeImage {
		t.Fatal("fixture image is not exact digest")
	}
	producer := voiceWSProducerPod(env)
	wantEnv := map[string]string{"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "http_proxy": "", "https_proxy": "", "all_proxy": "", "NO_PROXY": "*", "no_proxy": "*"}
	for _, item := range producer.Spec.Containers[0].Env {
		want, ok := wantEnv[item.Name]
		if !ok {
			continue
		}
		if item.Value != want {
			t.Fatalf("producer environment %s=%q, want %q", item.Name, item.Value, want)
		}
		delete(wantEnv, item.Name)
	}
	if len(wantEnv) != 0 {
		t.Fatalf("producer proxy environment not explicitly neutralized: %v", wantEnv)
	}
}

func TestVoiceWSFixtureHasNoProviderOrSemanticOracle(t *testing.T) {
	for _, forbidden := range []string{"OPENAI_API_KEY", "DEEPGRAM_API_KEY", "ELEVENLABS_API_KEY", "MONGODB_URI", "CHROMA", "run_bot", "transcript"} {
		if strings.Contains(voiceWSServerSource, forbidden) || strings.Contains(voiceWSClientSource, forbidden) {
			t.Fatalf("fixture source contains external/semantic path %q", forbidden)
		}
	}
	for _, required := range []string{"from fastapi import", "@app.websocket", "connected", "sequenceNumber", "end-"} {
		if !strings.Contains(voiceWSServerSource, required) {
			t.Fatalf("server source missing %q", required)
		}
	}
	for _, required := range []string{"import websockets", "websockets.connect", "urllib.request.ProxyHandler({})", "parsed.hostname != base_parsed.hostname", "object_pairs_hook=strict_object", "receivedSequences"} {
		if !strings.Contains(voiceWSClientSource, required) {
			t.Fatalf("client source missing %q", required)
		}
	}
}

func readyVoiceWSPod(name string, uid types.UID, role, replicaSetName string, replicaSetUID types.UID) *corev1.Pod {
	controller := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "owned", UID: uid, Labels: map[string]string{"app": voiceWSApp, "role": role}, Annotations: map[string]string{"fixture.phorvex.ai/source-sha256": voiceWSServerSourceSHA256(), "fixture.phorvex.ai/runtime-bot-sha256": voiceWSRuntimeBotSHA256}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: replicaSetName, UID: replicaSetUID, Controller: &controller}}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: voiceWSRuntimeImage, Command: []string{"python3", "-B", "-c", voiceWSServerSource}}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "fixture", Ready: true, Image: voiceWSRuntimeImage, ImageID: "docker-pullable://voice@" + voiceWSRuntimeDigest}}},
	}
}

func voiceWSTestControllerObjects() (*appsv1.Deployment, *appsv1.Deployment, *appsv1.ReplicaSet, *appsv1.ReplicaSet) {
	controller := true
	targetDeployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: voiceWSTargetDeployment, Namespace: "owned", UID: types.UID("target-deployment-uid")}}
	peerDeployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: voiceWSPeerDeployment, Namespace: "owned", UID: types.UID("peer-deployment-uid")}}
	targetRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "target-rs", Namespace: "owned", UID: types.UID("target-rs-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: targetDeployment.Name, UID: targetDeployment.UID, Controller: &controller}}}}
	peerRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "peer-rs", Namespace: "owned", UID: types.UID("peer-rs-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: peerDeployment.Name, UID: peerDeployment.UID, Controller: &controller}}}}
	return targetDeployment, peerDeployment, targetRS, peerRS
}

func sampleVoiceWSAvailabilityForEvidenceTest(t *testing.T, attempts, failedAttempts int) voiceWSAvailability {
	t.Helper()
	controller, ready := true, true
	serviceUID := types.UID("service-uid")
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: voiceWSSharedService, Namespace: "owned", UID: serviceUID}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": voiceWSApp}}}
	targetDeployment, peerDeployment, targetRS, peerRS := voiceWSTestControllerObjects()
	original := readyVoiceWSPod("target-original", types.UID("old-uid"), "target", targetRS.Name, targetRS.UID)
	peer1 := readyVoiceWSPod("peer-1", types.UID("peer-1"), "peer", peerRS.Name, peerRS.UID)
	peer2 := readyVoiceWSPod("peer-2", types.UID("peer-2"), "peer", peerRS.Name, peerRS.UID)
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "owned-slice", Namespace: "owned", Labels: map[string]string{discoveryv1.LabelServiceName: voiceWSSharedService}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: voiceWSSharedService, UID: serviceUID, Controller: &controller}}}}
	for _, pod := range []*corev1.Pod{original, peer1, peer2} {
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "owned", Name: pod.Name, UID: pod.UID}})
	}
	client := k8sfake.NewSimpleClientset(service, targetDeployment, peerDeployment, targetRS, peerRS, original, peer1, peer2, slice)
	stop := make(chan struct{})
	calls := 0
	client.Fake.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == attempts {
			close(stop)
		}
		if calls <= failedAttempts {
			return true, nil, fmt.Errorf("SECRET-ENDPOINT-ERROR-%d", calls)
		}
		return false, nil, nil
	})
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: client}
	got := sampleVoiceWSAvailabilityEvery(t.Context(), env, serviceUID, targetDeployment.UID, peerDeployment.UID, original.UID, stop, time.Millisecond)
	wantRetained := min(attempts, voiceWSSampleLimit)
	wantOverflow := attempts > voiceWSSampleLimit
	if calls != attempts || got.Samples != attempts-failedAttempts || got.Failures != failedAttempts || len(got.Observations) != wantRetained || got.ObservationOverflow != wantOverflow || got.MinimumReady != 3 || !got.OriginalSeen {
		t.Fatalf("sampling calls=%d availability=%+v", calls, got)
	}
	for i, observation := range got.Observations {
		if i < failedAttempts {
			if observation.Known || observation.Category != "endpoint-read-unavailable" || len(observation.ReadyUIDs) != 0 {
				t.Fatalf("failed observation %d=%+v", i, observation)
			}
		} else if !observation.Known || observation.Category != "ready-endpoints" || len(observation.ReadyUIDs) != 3 {
			t.Fatalf("known observation %d=%+v", i, observation)
		}
	}
	return got
}

func TestVoiceWSAvailabilitySamplingRetainsConfiguredWindowAndRefusesOverflow(t *testing.T) {
	full := sampleVoiceWSAvailabilityForEvidenceTest(t, voiceWSExpectedSampleCount, 0)
	state := voiceWSEvidenceNoActionState(t)
	state.availability = full
	if result, err := state.SuccessOracle(t.Context(), nil); err != nil || !result.Achieved {
		t.Fatalf("complete configured window result=%+v err=%v", result, err)
	}
	if state.benchmarkEvidence["availability.observationCount"] != strconv.Itoa(voiceWSExpectedSampleCount) || state.benchmarkEvidence["availability.observationsComplete"] != "true" || state.benchmarkEvidence["availability.observationOverflow"] != "false" {
		t.Fatalf("complete configured window evidence=%+v", state.benchmarkEvidence)
	}

	overflow := sampleVoiceWSAvailabilityForEvidenceTest(t, voiceWSSampleLimit+1, 0)
	state = voiceWSEvidenceNoActionState(t)
	state.availability = overflow
	if result, err := state.SuccessOracle(t.Context(), nil); err == nil || result.Achieved {
		t.Fatalf("overflow result=%+v err=%v", result, err)
	}
	if err := validateVoiceWSBenchmarkEvidence(state.benchmarkEvidence); err != nil {
		t.Fatalf("bounded overflow evidence invalid: %v", err)
	}
	if state.benchmarkEvidence["oracle.status"] != "invalid-availability" || state.benchmarkEvidence["availability.observationCount"] != "160" || state.benchmarkEvidence["availability.attempts"] != "161" || state.benchmarkEvidence["availability.observationsComplete"] != "false" || state.benchmarkEvidence["availability.observationOverflow"] != "true" {
		t.Fatalf("overflow evidence=%+v", state.benchmarkEvidence)
	}
}

func TestVoiceWSReadyEndpointUIDsRequireControllerOwnedExactObjects(t *testing.T) {
	controller, ready := true, true
	serviceUID := types.UID("service-uid")
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: voiceWSSharedService, Namespace: "owned", UID: serviceUID}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": voiceWSApp}}}
	targetDeployment, peerDeployment, targetRS, peerRS := voiceWSTestControllerObjects()
	peer1 := readyVoiceWSPod("peer-1", types.UID("peer-uid-1"), "peer", peerRS.Name, peerRS.UID)
	peer2 := readyVoiceWSPod("peer-2", types.UID("peer-uid-2"), "peer", peerRS.Name, peerRS.UID)
	foreign := readyVoiceWSPod("foreign", types.UID("foreign-uid"), "peer", peerRS.Name, peerRS.UID)
	foreign.Spec.Containers[0].Image = "example.invalid/foreign@sha256:deadbeef"
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "owned-slice", Namespace: "owned", Labels: map[string]string{discoveryv1.LabelServiceName: voiceWSSharedService}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: voiceWSSharedService, UID: serviceUID, Controller: &controller}}}, Endpoints: []discoveryv1.Endpoint{
		{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "owned", Name: peer1.Name, UID: peer1.UID}},
		{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "owned", Name: peer2.Name, UID: peer2.UID}},
		{Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "owned", Name: foreign.Name, UID: foreign.UID}},
	}}
	foreignSlice := slice.DeepCopy()
	foreignSlice.Name = "foreign-slice"
	foreignSlice.OwnerReferences[0].UID = types.UID("foreign-service")
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: k8sfake.NewSimpleClientset(service, targetDeployment, peerDeployment, targetRS, peerRS, peer1, peer2, foreign, slice, foreignSlice)}
	uids, err := voiceWSReadyEndpointUIDs(context.Background(), env, voiceWSSharedService, serviceUID, targetDeployment.UID, peerDeployment.UID)
	if err != nil {
		t.Fatal(err)
	}
	if len(uids) != 2 || uids[0] != peer1.UID || uids[1] != peer2.UID {
		t.Fatalf("ready UIDs=%v", uids)
	}
	if _, err = voiceWSReadyEndpointUIDs(context.Background(), env, voiceWSSharedService, types.UID("replacement-service"), targetDeployment.UID, peerDeployment.UID); err == nil {
		t.Fatal("replacement Service UID accepted")
	}
	changed := service.DeepCopy()
	changed.Spec.Selector = map[string]string{"app": voiceWSApp, "role": "foreign"}
	if _, err = env.Kube.CoreV1().Services("owned").Update(context.Background(), changed, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = voiceWSReadyEndpointUIDs(context.Background(), env, voiceWSSharedService, serviceUID, targetDeployment.UID, peerDeployment.UID); err == nil {
		t.Fatal("changed Service selector accepted")
	}
}

func TestValidateVoiceWSControllerReadsDeploymentAndReplicaSet(t *testing.T) {
	targetDeployment, peerDeployment, targetRS, peerRS := voiceWSTestControllerObjects()
	pod := readyVoiceWSPod("target-0", types.UID("pod-uid"), "target", targetRS.Name, targetRS.UID)
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: k8sfake.NewSimpleClientset(targetDeployment, peerDeployment, targetRS, peerRS, pod)}
	if err := validateVoiceWSController(context.Background(), env, pod, voiceWSTargetDeployment, targetDeployment.UID); err != nil {
		t.Fatalf("valid controller chain: %v", err)
	}
	if err := validateVoiceWSController(context.Background(), env, pod, voiceWSTargetDeployment, types.UID("recreated-deployment")); err == nil {
		t.Fatal("recreated Deployment UID accepted")
	}
	forged := pod.DeepCopy()
	forged.OwnerReferences[0].UID = types.UID("forged-rs")
	if err := validateVoiceWSController(context.Background(), env, forged, voiceWSTargetDeployment, targetDeployment.UID); err == nil {
		t.Fatal("forged ReplicaSet UID accepted")
	}
}

func TestVoiceWSProducerUsesExplicitThirtySecondForegroundExec(t *testing.T) {
	serviceUID, producerUID := types.UID("service-uid"), types.UID("producer-uid")
	selector := map[string]string{"app": voiceWSApp, "role": "target"}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: voiceWSTargetService, Namespace: "owned", UID: serviceUID}, Spec: corev1.ServiceSpec{Selector: selector}}
	producer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: voiceWSProducer, Namespace: "owned", UID: producerUID}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: k8sfake.NewSimpleClientset(service, producer), Rest: &rest.Config{Host: "https://example.invalid"}, Log: &ctLogger{}}
	receipt := completeVoiceWSReceipt("target-uid", voiceWSExpectedFrames)
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	defaultCalls, timedCalls := 0, 0
	core.SetExecer(func(context.Context, *rest.Config, kubernetes.Interface, string, string, string, []string) core.ExecResult {
		defaultCalls++
		return core.ExecResult{ExitCode: -1, Err: errors.New("default exec used")}
	})
	core.SetTimedExecer(func(ctx context.Context, _ *rest.Config, _ kubernetes.Interface, _, pod, container string, timeout time.Duration, command []string) core.ExecResult {
		timedCalls++
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || timeout != voiceWSExecTimeout || remaining <= 29*time.Second || remaining > voiceWSExecTimeout || pod != voiceWSProducer || container != "producer" {
			return core.ExecResult{ExitCode: -1, Err: fmt.Errorf("exec contract timeout=%s remaining=%s pod=%s container=%s", timeout, remaining, pod, container)}
		}
		if len(command) != 8 || command[0] != "python3" || command[5] != "voice-1" || command[6] != "20" || command[7] != "0.900" {
			return core.ExecResult{ExitCode: -1, Err: fmt.Errorf("producer argv=%v", command)}
		}
		timer := time.NewTimer(20*time.Second + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return core.ExecResult{ExitCode: -1, Err: ctx.Err()}
		case <-timer.C:
		}
		return core.ExecResult{Stdout: string(raw)}
	})
	t.Cleanup(func() { core.SetExecer(nil); core.SetTimedExecer(nil) })
	got, err := performVoiceWS(t.Context(), env, voiceWSTargetService, serviceUID, selector, "voice-1", voiceWSExpectedFrames, voiceWSFrameInterval, producerUID)
	if err != nil || !voiceWSReceiptCompleted(got.Receipt) || got.ProducerStatus != "validated" || !got.ReceiptDecoded || !got.ReceiptValidated || got.ProducerStdoutSHA256 != fmt.Sprintf("%x", sha256.Sum256(raw)) || defaultCalls != 0 || timedCalls != 1 {
		t.Fatalf("receipt=%+v default/timed=%d/%d err=%v", got, defaultCalls, timedCalls, err)
	}
	core.SetTimedExecer(func(ctx context.Context, _ *rest.Config, _ kubernetes.Interface, _, _, _ string, timeout time.Duration, _ []string) core.ExecResult {
		deadline, ok := ctx.Deadline()
		remaining := time.Until(deadline)
		if !ok || timeout <= time.Second || timeout > 2*time.Second || remaining <= time.Second || remaining > 2*time.Second {
			return core.ExecResult{ExitCode: -1, Err: fmt.Errorf("short parent bound not propagated: timeout=%s remaining=%s", timeout, remaining)}
		}
		return core.ExecResult{Stdout: `{"partial":true}`, ExitCode: -1, Err: context.DeadlineExceeded}
	})
	shortCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	partial, err := performVoiceWS(shortCtx, env, voiceWSTargetService, serviceUID, selector, "voice-1", voiceWSExpectedFrames, voiceWSFrameInterval, producerUID)
	if err == nil || !strings.Contains(err.Error(), "producer failed") || !strings.Contains(err.Error(), "deadline exceeded") || partial.ProducerStatus != "exec-failed" || partial.ProducerStdoutBytes != len(`{"partial":true}`) || !isLowerHexSHA256(partial.ProducerStdoutSHA256) || partial.ReceiptDecoded || partial.ReceiptValidated {
		t.Fatalf("earlier parent deadline observation=%+v err=%v", partial, err)
	}
}

func TestWaitVoiceWSTargetOutcomeRequiresOriginalAPIAbsence(t *testing.T) {
	targetDeployment, peerDeployment, targetRS, peerRS := voiceWSTestControllerObjects()
	replacement := readyVoiceWSPod("target-new", types.UID("new-uid"), "target", targetRS.Name, targetRS.UID)
	env := &core.Env{Config: config.TargetConfig{Namespace: "owned"}, Kube: k8sfake.NewSimpleClientset(targetDeployment, peerDeployment, targetRS, peerRS, replacement)}
	pod, replaced, timeline, err := waitVoiceWSTargetOutcome(context.Background(), env, "target-old", types.UID("old-uid"), targetDeployment.UID, time.Second)
	if err != nil || !replaced || pod.UID != replacement.UID || timeline.AbsenceObservedAt == "" || timeline.ReplacementObservedAt == "" {
		t.Fatalf("pod=%v replaced=%v timeline=%+v err=%v", pod, replaced, timeline, err)
	}
}
