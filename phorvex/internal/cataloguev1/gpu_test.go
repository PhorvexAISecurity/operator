package cataloguev1

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/phorvex/metricvalidity"
)

type gpuMemoryRecorder struct {
	intents  []Intent
	events   []Event
	metric   json.RawMessage
	eventErr error
}

func (r *gpuMemoryRecorder) Intent(value Intent) error {
	r.intents = append(r.intents, value)
	return nil
}
func (r *gpuMemoryRecorder) Event(value Event) error {
	if r.eventErr != nil {
		return r.eventErr
	}
	r.events = append(r.events, value)
	return nil
}
func (*gpuMemoryRecorder) Metric(Metric) error { return nil }
func (r *gpuMemoryRecorder) MetricRaw(value json.RawMessage) error {
	r.metric = append(r.metric[:0], value...)
	return nil
}
func (*gpuMemoryRecorder) Result(Result) error { return nil }

func gpuTestAuthority(t *testing.T, emitMetric bool) (Runtime, gpuHarnessConfig, json.RawMessage) {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "bearer-token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 64)), 0o400); err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := gpuHarnessConfig{
		Kubeconfig: kubeconfig, Context: "fixture-context", Namespace: "owned-gpu",
		ExpectedNamespaceUID: "11111111-1111-4111-8111-111111111111", OwnedAck: true,
		TrialsPerArm: 1, OutDir: filepath.Join(dir, "source-output"),
		DefenderFilter: []string{gpuDefender}, ScenarioFilter: []string{gpuScenario},
		GPU: &gpuFixtureConfig{
			Operation: "request-drain", Mode: "direct", NamespaceUID: "11111111-1111-4111-8111-111111111111",
			RunLabel: "fixed-run", NodeName: "gpu-node", NodeUID: "22222222-2222-4222-8222-222222222222",
			PodName: "gpu-model-abc", PodUID: "33333333-3333-4333-8333-333333333333",
			OwnerKind: "ReplicaSet", OwnerName: "gpu-model", OwnerUID: "44444444-4444-4444-8444-444444444444",
			ServiceName: "gpu-model", ServiceUID: "55555555-5555-4555-8555-555555555555",
			ContainerName: "vllm", Image: "example.invalid/vllm@sha256:" + strings.Repeat("a", 64),
			ImageID: "example.invalid/vllm@sha256:" + strings.Repeat("a", 64), StartedAt: "2026-09-23T12:00:00Z",
			Port: 8000, Model: "facebook/opt-125m", ModelDigest: "sha256:" + strings.Repeat("b", 64),
			EngineSourceSHA256: strings.Repeat("c", 64), ProxySourceGitSHA: strings.Repeat("d", 40), BearerTokenFile: token,
		},
	}
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "gpu-config.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	metric := gpuTestMetric(t, config, true)
	metricPath := filepath.Join(dir, "metric.jsonl")
	if err := os.WriteFile(metricPath, append(metric, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	provenancePath := filepath.Join(dir, "provenance.json")
	if err := os.WriteFile(provenancePath, gpuTestProvenance(t, config, metric), 0o600); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args")
	script := filepath.Join(dir, "harness")
	body := `#!/bin/sh
set -eu
[ "$1" = "-config" ]
[ "$3" = "-negative-control=false" ]
[ "$4" = "-adaptive=false" ]
printf '%s\n' "$@" > "$GPU_TEST_ARGS"
out=$(sed -n 's/.*"outDir":"\([^"]*\)".*/\1/p' "$2")
[ -n "$out" ]
mkdir -p "$out"
if [ "${GPU_TEST_EMIT:-}" = "yes" ]; then
  cp "$GPU_TEST_METRIC" "$out/metrics.jsonl"
  sed "s|__METRICS__|$out/metrics.jsonl|" "$GPU_TEST_PROVENANCE" > "$out/provenance.json"
fi
sleep 0.1
if [ "${GPU_TEST_LINGER:-}" = "yes" ]; then sleep 60 >/dev/null 2>&1 & fi
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GPU_TEST_ARGS", argsPath)
	t.Setenv("GPU_TEST_METRIC", metricPath)
	t.Setenv("GPU_TEST_PROVENANCE", provenancePath)
	if emitMetric {
		t.Setenv("GPU_TEST_EMIT", "yes")
	} else {
		t.Setenv("GPU_TEST_EMIT", "no")
	}
	return Runtime{KubeconfigPath: kubeconfig, KubeContext: config.Context, GPU: GPUFixtureRuntime{
		Enabled: true, Namespace: config.Namespace, FixtureConfigFile: configPath,
		HarnessBinary: script, HarnessDir: dir, KubeconfigPath: kubeconfig, KubeContext: config.Context,
	}}, config, metric
}

func gpuTestProvenance(t *testing.T, config gpuHarnessConfig, metricRaw json.RawMessage) []byte {
	t.Helper()
	var metric gpuMetricProjection
	if err := json.Unmarshal(metricRaw, &metric); err != nil {
		t.Fatal(err)
	}
	value := map[string]any{
		"masterSeed": 1, "trialsPerArm": 1, "context": config.Context, "namespace": config.Namespace,
		"metricsFile": "__METRICS__",
		"entries": []map[string]any{{
			"scenario": metric.Scenario, "defender": metric.Defender, "trial": metric.Trial,
			"oracleAchieved": metric.OracleAchieved, "benignControl": true,
			"scenarioRealism": metric.ScenarioRealism, "trialKind": string(metric.Validity.Kind),
			"measurementStatus": string(metric.Validity.Status), "scored": false,
			"oracleObserved": metric.Validity.OracleObserved, "unscoredReason": metric.Validity.UnscoredReason,
			"cleanupComplete": true,
		}},
		"run": map[string]any{
			"plannedTrials": 1, "executedTrials": 1, "writtenTrials": 1, "complete": true,
			"aborted": false, "finalTeardown": map[string]any{"attempted": true, "verified": true},
		},
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func gpuTestMetric(t *testing.T, config gpuHarnessConfig, oracle bool) json.RawMessage {
	t.Helper()
	receipt := map[string]any{
		"mode":          "direct",
		"create":        map[string]any{"operation_id": "00112233445566778899aabbccddeeff", "state": "DRAINING", "admission": "CLOSED"},
		"reopen":        map[string]any{"operation_id": "00112233445566778899aabbccddeeff", "state": "OPENED", "admission": "OPEN"},
		"postInference": map[string]any{"status": 200, "text": "ok"},
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string]string{
		"scenario": gpuScenario, "suiteVersion": "post25-vllm-functional-v4", "operation": "request-drain",
		"fixtureMode": "direct", "functionalArm": "direct-producer", "oracleStatus": "complete",
		"installedManagerDispatchProven": "false", "nativeHandlerDispatchProven": "false",
		"securityOutcome": "not-measured", "costOutcome": "not-measured", "cveOutcome": "not-measured",
		"availabilityComparisonEligible": "false", "costComparisonEligible": "false",
		"brainPerformanceComparisonEligible": "false", "workloadComparison": "unmatched-functional-protocol-check",
		"protocolOperationAttempts": "1", "protocolOperationAcknowledgements": "1",
		"restorationAttempts": "1", "restorationAcknowledgements": "1",
		"namespaceUID": config.ExpectedNamespaceUID, "podUID": config.GPU.PodUID, "serviceUID": config.GPU.ServiceUID,
		"ownerUID": config.GPU.OwnerUID, "nodeUID": config.GPU.NodeUID,
		"engineSourceSHA256": config.GPU.EngineSourceSHA256, "modelDigest": config.GPU.ModelDigest,
		"receiptJSON": string(receiptRaw), "receiptSHA256": digestBytes(receiptRaw),
	}
	validity := &metricvalidity.Validity{
		Version: metricvalidity.Version, Kind: metricvalidity.TrialOrdinary, Status: metricvalidity.StatusValid,
		Phase: metricvalidity.PhaseComplete, Reasons: []string{"complete: benign control"},
		AttackExecuted: true, OracleObserved: true, ObserverPresent: true, CostObserved: true,
		Scored: false, UnscoredReason: "benign functional-effect control is excluded from scoring",
		Baseline: metricvalidity.BaselineRef{Required: false, Defender: gpuDefender, Trial: 0, Kind: metricvalidity.TrialOrdinary},
		Cleanup:  metricvalidity.CleanupRecord{Attempted: []metricvalidity.CleanupStep{{Step: "scenario.Teardown"}}, Complete: true, Verified: true},
	}
	metric := map[string]any{
		"scenario": gpuScenario, "defender": gpuDefender, "trial": 0, "oracleAchieved": oracle,
		"disruptionVsOracle": 0, "defensiveActions": 0, "falseDefensiveActions": 0,
		"timeToActionSeconds": 0, "attackerDwellSeconds": 1,
		"scenarioRealism": "executable-mechanism", "scenarioBenignControl": true,
		"scenarioClaimLimits": gpuClaimLimits,
		"benchmarkEvidence":   evidence, "validity": validity,
	}
	raw, err := json.Marshal(metric)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func gpuTestJob(t *testing.T) Job {
	t.Helper()
	output := filepath.Join(t.TempDir(), "v1run-1")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	return Job{RunID: "v1run-1", Profile: GPUDrain, OutputDir: output, ResolvedTarget: "default", ResolvedTenant: "owned-gpu", Deadline: time.Now().Add(time.Minute)}
}

func TestGPUHandlerRunsOnlyFixedOneArmAndCopiesExactMetric(t *testing.T) {
	runtime, _, metric := gpuTestAuthority(t, true)
	handler := NewGPUDrainHandler()
	if err := handler.Validate(runtime); err != nil {
		t.Fatal(err)
	}
	recorder := &gpuMemoryRecorder{}
	job := gpuTestJob(t)
	result := handler.Run(context.Background(), JobContext{Job: job, Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeFunctionalPass || !result.Cleanup.Verified || result.Cleanup.Status != "PASS" {
		t.Fatalf("result = %+v", result)
	}
	if string(recorder.metric) != string(metric) {
		t.Fatal("handler did not preserve the exact harness metric bytes")
	}
	if len(recorder.intents) != 1 || !recorder.intents[0].Mutation || len(recorder.events) != 2 || recorder.events[1].Step != "gpu-request-drain-cleanup" {
		t.Fatalf("journal = intents %+v events %+v", recorder.intents, recorder.events)
	}
	args, err := os.ReadFile(os.Getenv("GPU_TEST_ARGS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(lines) != 4 || lines[0] != "-config" || lines[2] != "-negative-control=false" || lines[3] != "-adaptive=false" || lines[1] != filepath.Join(job.OutputDir, "gpu-harness-config.json") {
		t.Fatalf("args = %q", lines)
	}
	cleanup := handler.Reconcile(context.Background(), JobContext{Job: job, Runtime: runtime}, Journal{Records: []JournalRecord{{Intent: &recorder.intents[0]}}})
	if !cleanup.Verified || cleanup.UnsafeToRetry || cleanup.Details["source"] != "validated-terminal-provenance" {
		t.Fatalf("cleanup = %+v", cleanup)
	}
}

func TestGPUHandlerZeroExitWithoutMetricCannotVerifyOrReconcile(t *testing.T) {
	runtime, _, _ := gpuTestAuthority(t, false)
	handler := NewGPUDrainHandler()
	recorder := &gpuMemoryRecorder{}
	job := gpuTestJob(t)
	result := handler.Run(context.Background(), JobContext{Job: job, Runtime: runtime, Recorder: recorder})
	if result.Cleanup.Verified || !result.UnsafeToRetry || result.Outcome != OutcomeTestFailed {
		t.Fatalf("result = %+v", result)
	}
	cleanup := handler.Reconcile(context.Background(), JobContext{Job: job, Runtime: runtime}, Journal{Records: []JournalRecord{{Intent: &recorder.intents[0]}, {Event: &recorder.events[0]}}})
	if cleanup.Verified || !cleanup.UnsafeToRetry || cleanup.Details["requestsReplayed"] != "0" {
		t.Fatalf("cleanup = %+v", cleanup)
	}
}

func TestGPUHandlerMetricBeforeFinalTeardownCannotVerifyOrReconcile(t *testing.T) {
	runtime, _, _ := gpuTestAuthority(t, true)
	if err := os.Remove(os.Getenv("GPU_TEST_PROVENANCE")); err != nil {
		t.Fatal(err)
	}
	handler := NewGPUDrainHandler()
	recorder := &gpuMemoryRecorder{}
	job := gpuTestJob(t)
	result := handler.Run(context.Background(), JobContext{Job: job, Runtime: runtime, Recorder: recorder})
	if result.Cleanup.Verified || !result.UnsafeToRetry || len(recorder.metric) != 0 || !strings.Contains(result.Summary, "terminal evidence") {
		t.Fatalf("result = %+v metric=%d", result, len(recorder.metric))
	}
	cleanup := handler.Reconcile(context.Background(), JobContext{Job: job, Runtime: runtime}, Journal{Records: []JournalRecord{{Intent: &recorder.intents[0]}}})
	if cleanup.Verified || !cleanup.UnsafeToRetry || cleanup.Details["source"] != "" {
		t.Fatalf("cleanup = %+v", cleanup)
	}
}

func TestGPUHandlerZeroExitWithLingeringChildCannotPublishTerminal(t *testing.T) {
	runtime, _, _ := gpuTestAuthority(t, true)
	t.Setenv("GPU_TEST_LINGER", "yes")
	handler := NewGPUDrainHandler()
	recorder := &gpuMemoryRecorder{}
	job := gpuTestJob(t)
	result := handler.Run(context.Background(), JobContext{Job: job, Runtime: runtime, Recorder: recorder})
	if result.Cleanup.Verified || !result.UnsafeToRetry || len(recorder.metric) != 0 || !strings.Contains(result.Summary, "process group") {
		t.Fatalf("result = %+v metric=%d", result, len(recorder.metric))
	}
	if _, err := os.Stat(filepath.Join(job.OutputDir, "gpu-terminal.json")); !os.IsNotExist(err) {
		t.Fatalf("terminal receipt exists or stat failed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(job.OutputDir, "gpu-process.json"))
	if err != nil {
		t.Fatal(err)
	}
	var identity gpuProcessIdentity
	if err := json.Unmarshal(raw, &identity); err != nil {
		t.Fatal(err)
	}
	if !linuxProcessGroupExists(identity.PGID) {
		t.Fatal("test did not retain a lingering child process")
	}
	_ = syscall.Kill(-identity.PGID, syscall.SIGKILL)
}

func TestGPUHandlerRejectsWrongOneArmAndUnsafeTokenBeforeExecution(t *testing.T) {
	runtime, config, _ := gpuTestAuthority(t, true)
	config.TrialsPerArm = 2
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(runtime.GPU.FixtureConfigFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewGPUDrainHandler().Validate(runtime); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("error = %v", err)
	}
	config.TrialsPerArm = 1
	if err := os.Chmod(config.GPU.BearerTokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(config)
	if err := os.WriteFile(runtime.GPU.FixtureConfigFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewGPUDrainHandler().Validate(runtime); err == nil || !strings.Contains(err.Error(), "bearer token") {
		t.Fatalf("error = %v", err)
	}
}

func TestGPUHandlerRejectsTamperedMetricAuthority(t *testing.T) {
	runtime, config, _ := gpuTestAuthority(t, true)
	raw := gpuTestMetric(t, config, true)
	var metric map[string]any
	if err := json.Unmarshal(raw, &metric); err != nil {
		t.Fatal(err)
	}
	evidence := metric["benchmarkEvidence"].(map[string]any)
	evidence["serviceUID"] = "foreign"
	tampered, _ := json.Marshal(metric)
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	if err := os.WriteFile(path, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndValidateGPUMetric(path, config); err == nil || !strings.Contains(err.Error(), "serviceUID") {
		t.Fatalf("error = %v", err)
	}
	// The runtime remains valid; the failure is the retained metric authority.
	if err := NewGPUDrainHandler().Validate(runtime); err != nil {
		t.Fatal(err)
	}
}

func TestGPUHandlerPreservesInvalidHarnessMeasurementAsTestFailure(t *testing.T) {
	runtime, config, _ := gpuTestAuthority(t, true)
	valid := gpuTestMetric(t, config, true)
	var metric map[string]any
	if err := json.Unmarshal(valid, &metric); err != nil {
		t.Fatal(err)
	}
	metric["oracleAchieved"] = false
	validity := metric["validity"].(map[string]any)
	validity["status"] = "invalid"
	validity["phase"] = "attack-execute"
	validity["oracleObserved"] = false
	evidence := metric["benchmarkEvidence"].(map[string]any)
	evidence["oracleStatus"] = "incomplete"
	evidence["protocolOperationAttempts"] = "0"
	evidence["protocolOperationAcknowledgements"] = "0"
	evidence["restorationAttempts"] = "0"
	evidence["restorationAcknowledgements"] = "0"
	receiptRaw := []byte(`{"mode":"direct"}`)
	evidence["receiptJSON"] = string(receiptRaw)
	evidence["receiptSHA256"] = digestBytes(receiptRaw)
	invalid, err := json.Marshal(metric)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("GPU_TEST_METRIC"), append(invalid, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("GPU_TEST_PROVENANCE"), gpuTestProvenance(t, config, invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := &gpuMemoryRecorder{}
	result := NewGPUDrainHandler().Run(context.Background(), JobContext{Job: gpuTestJob(t), Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeTestFailed || !result.Cleanup.Verified || string(recorder.metric) != string(invalid) {
		t.Fatalf("result = %+v metricCopied=%v", result, string(recorder.metric) == string(invalid))
	}
}

func TestGPUHandlerRecordsEventFailureAndNeverClaimsCleanup(t *testing.T) {
	runtime, _, _ := gpuTestAuthority(t, true)
	recorder := &gpuMemoryRecorder{eventErr: errors.New("journal unavailable")}
	result := NewGPUDrainHandler().Run(context.Background(), JobContext{Job: gpuTestJob(t), Runtime: runtime, Recorder: recorder})
	if result.Cleanup.Verified || !result.UnsafeToRetry || !strings.Contains(result.Summary, "journal") || len(recorder.metric) != 0 {
		t.Fatalf("result = %+v metric=%d", result, len(recorder.metric))
	}
}

func TestGPUReconcileReapsOnlyExactPersistedProcessGroup(t *testing.T) {
	output := t.TempDir()
	job := Job{RunID: "v1run-1", OutputDir: output}
	harnessSHA, err := fileSHA256("/bin/sleep", 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if err := persistGPUProcessIdentity(filepath.Join(output, "gpu-process.json"), job, cmd, harnessSHA, strings.Repeat("a", 64)); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatal(err)
	}
	status := reapRetainedGPUProcess(JobContext{Job: job}, harnessSHA, strings.Repeat("a", 64))
	if status != "exact-leader-process-group-reaped" && status != "exact-leader-process-group-killed" {
		t.Fatalf("status = %s", status)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owned process did not exit")
	}
}

func TestGPUReconcileDoesNotSignalGroupWhenRecordedLeaderIsGone(t *testing.T) {
	output := t.TempDir()
	job := Job{RunID: "v1run-1", OutputDir: output}
	harnessSHA, err := fileSHA256("/bin/sh", 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 60 & wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := persistGPUProcessIdentity(filepath.Join(output, "gpu-process.json"), job, cmd, harnessSHA, strings.Repeat("a", 64)); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	deadline := time.Now().Add(time.Second)
	for !linuxProcessGroupHasPeer(pgid, pgid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !linuxProcessGroupHasPeer(pgid, pgid) {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		t.Fatal("child did not join the owned process group")
	}
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if !linuxProcessGroupExists(pgid) {
		t.Fatal("test did not retain the child after leader exit")
	}
	status := reapRetainedGPUProcess(JobContext{Job: job}, harnessSHA, strings.Repeat("a", 64))
	if status != "leader-absent-process-group-unresolved" {
		t.Fatalf("status = %s", status)
	}
	if !linuxProcessGroupExists(pgid) {
		t.Fatal("leader-absent group was signaled through a stale numeric PGID")
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}

func linuxProcessGroupHasPeer(pgid, leader int) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == leader {
			continue
		}
		group, _, err := readLinuxProcessIdentity(pid)
		if err == nil && group == pgid {
			return true
		}
	}
	return false
}
