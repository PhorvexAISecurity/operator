package cataloguev1

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

type fakeMCPVoiceModelTransport struct {
	authority         mcpVoiceModelAuthority
	output            string
	probeErr          error
	drift             bool
	snapshots, probes int
}

func (f *fakeMCPVoiceModelTransport) snapshot(context.Context, Runtime) (mcpVoiceModelAuthority, error) {
	f.snapshots++
	a := f.authority
	if f.drift && f.snapshots > 1 {
		a.Target.UID = "replacement"
	}
	return a, nil
}
func (f *fakeMCPVoiceModelTransport) probe(context.Context, Runtime, mcpVoiceModelAuthority) (string, error) {
	f.probes++
	return f.output, f.probeErr
}
func modelRuntimeFixture(t *testing.T) (Runtime, RuntimeConfig) {
	t.Helper()
	root := t.TempDir()
	voice := VoiceRuntime{Enabled: true, Namespace: "voice", Deployment: "voice-bot", Service: "voice-bot", Container: "bot", ServicePort: 8080, PDB: "voice-bot"}
	mcp := MCPSessionRuntime{Enabled: true, Namespace: "mcp", Deployment: "mcp-server", Service: "mcp-server", Container: "mcp-server", Port: 8000, SourceConfigMap: "mcp-code", SourceKey: "server.py", ExpectedSourceSHA256: mcpInstalledSourceSHA, ExpectedImageID: "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"}
	lite := LiteLLMRuntime{Enabled: true, Namespace: "litellm", Deployment: "litellm", Service: "litellm", Container: "litellm", Port: 4000, ConfigMap: "litellm-config", ConfigKey: "config.yaml", ExpectedConfigSHA256: liteConfigSHA, InferenceEnabled: true, ModelAlias: mcpVoiceModelAlias}
	model := MCPVoiceModelRuntime{Enabled: true, ExpectedVoiceSourceSHA256: voiceExpectedSourceSHA}
	cfg := RuntimeConfig{Version: RuntimeConfigVersion, StateDir: root, Voice: voice, MCP: &mcp, LiteLLM: &lite, MCPVoiceModel: &model}
	hash, err := cfg.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	runtime := Runtime{StateDir: root, ConfigSHA256: hash, Voice: voice, MCP: mcp, LiteLLM: lite, MCPVoiceModel: model, Kube: fake.NewSimpleClientset(), RESTConfig: &rest.Config{Host: "https://example.invalid"}}
	return runtime, cfg
}
func modelAuthorityFixture() mcpVoiceModelAuthority {
	return mcpVoiceModelAuthority{Voice: VoiceSnapshot{NamespaceUID: "voice-ns", DeploymentUID: "voice-deploy", ReplicaSetUID: "voice-rs", Pods: []VoicePod{{Name: "voice-pod", UID: "voice-pod-uid", ImageID: "image@" + voiceExpectedImage, ContainerID: "containerd://voice"}}}, Target: VoicePod{Name: "voice-pod", UID: "voice-pod-uid", ImageID: "image@" + voiceExpectedImage, ContainerID: "containerd://voice"}, RouteSHA: strings.Repeat("d", 64), MCP: mcpAuthority{PodUID: "mcp-pod", SourceSHA: mcpInstalledSourceSHA}, Lite: liteAuthority{ConfigSHA: liteConfigSHA, Pods: []litePod{{UID: "lite-a"}, {UID: "lite-b"}}}}
}
func modelJobFixture(t *testing.T, r Runtime) Job {
	t.Helper()
	def, _ := DefinitionFor(MCPVoiceModel)
	sum, _ := DefinitionSHA256(def)
	dir := filepath.Join(r.StateDir, "runs", "v1run-1")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	return Job{Version: JobVersion, RunID: "v1run-1", Profile: MCPVoiceModel, OutputDir: dir, DefinitionSHA256: sum, OwnerDigest: strings.Repeat("a", 64), ResolvedTarget: "default", ResolvedTenant: "voice", RuntimeConfigSHA256: r.ConfigSHA256, CreatedAt: time.Now().UTC(), Deadline: time.Now().Add(time.Minute)}
}
func TestMCPVoiceModelRunnerOriginalJournalAndForgery(t *testing.T) {
	runtime, cfg := modelRuntimeFixture(t)
	job := modelJobFixture(t, runtime)
	if err := WriteRuntimeConfig(filepath.Join(job.OutputDir, "runtime.json"), cfg); err != nil {
		t.Fatal(err)
	}
	f := &fakeMCPVoiceModelTransport{authority: modelAuthorityFixture(), output: modelOutputFixture(modelCallFixture(1, nil), modelCallFixture(2, []mcpVoiceTool{modelToolFixture("issue_refund", true)}))}
	runner, err := New(runtime, mcpVoiceModelHandler{transport: f})
	if err != nil {
		t.Fatal(err)
	}
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeFunctionalPass || result.Evidence["observationState"] != "UNREQUESTED_SYNTHETIC_B_REFUND_SELECTED" || result.Evidence["toolExecutionCount"] != "0" || f.probes != 1 || f.snapshots != 2 {
		t.Fatalf("actual producer result: %+v, probes=%d snapshots=%d", result, f.probes, f.snapshots)
	}
	if err := ValidateMCPVoiceModelArtifacts(job, result); err != nil {
		t.Fatal(err)
	}
	copyResult := result
	copyResult.Evidence = map[string]string{}
	for k, v := range result.Evidence {
		copyResult.Evidence[k] = v
	}
	copyResult.Evidence["substituted.syntheticBRefundSelected"] = "false"
	if ValidateMCPVoiceModelArtifacts(job, copyResult) == nil {
		t.Fatal("forged terminal selection accepted")
	}
	journal, err := loadJournal(filepath.Join(job.OutputDir, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.Records) != 4 {
		t.Fatalf("original journal count %d", len(journal.Records))
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "CAT-mcpfixture-order-b") || strings.Contains(string(raw), "Fixture instruction") || strings.Contains(string(raw), "sk-") {
		t.Fatal("raw model data retained")
	}
}
func TestMCPVoiceModelFirstReplyRetainedOnAmbiguousSecondAndDrift(t *testing.T) {
	runtime, _ := modelRuntimeFixture(t)
	first, _ := json.Marshal(modelCallFixture(1, nil))
	f := &fakeMCPVoiceModelTransport{authority: modelAuthorityFixture(), output: string(first) + "\n" + `{"status":"MODEL_CALL_OBSERVED"`, probeErr: errors.New("timeout")}
	recorder := &mcpTestRecorder{}
	result := (mcpVoiceModelHandler{transport: f}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["requestCount"] != "1" || len(recorder.events) != 1 || f.probes != 1 {
		t.Fatalf("ambiguous second lost first row or retried: %+v", result)
	}
	f = &fakeMCPVoiceModelTransport{authority: modelAuthorityFixture(), output: modelOutputFixture(modelCallFixture(1, nil), modelCallFixture(2, nil)), drift: true}
	recorder = &mcpTestRecorder{}
	result = (mcpVoiceModelHandler{transport: f}).Run(context.Background(), JobContext{Runtime: runtime, Recorder: recorder})
	if result.Outcome != OutcomeInconclusive || result.Evidence["observationState"] != "UNKNOWN" || len(recorder.events) != 2 || f.probes != 1 {
		t.Fatalf("post-source drift promoted result: %+v", result)
	}
}

func TestMCPVoiceModelPostSnapshotDriftCannotBeForgedPositive(t *testing.T) {
	runtime, cfg := modelRuntimeFixture(t)
	job := modelJobFixture(t, runtime)
	if err := WriteRuntimeConfig(filepath.Join(job.OutputDir, "runtime.json"), cfg); err != nil {
		t.Fatal(err)
	}
	f := &fakeMCPVoiceModelTransport{authority: modelAuthorityFixture(), output: modelOutputFixture(modelCallFixture(1, nil), modelCallFixture(2, nil)), drift: true}
	runner, err := New(runtime, mcpVoiceModelHandler{transport: f})
	if err != nil {
		t.Fatal(err)
	}
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeInconclusive || result.Evidence["requestCount"] != "2" || f.snapshots != 2 {
		t.Fatalf("post-snapshot drift fixture: %+v", result)
	}
	forged := result
	forged.Evidence = map[string]string{}
	for key, value := range result.Evidence {
		forged.Evidence[key] = value
	}
	forged.Outcome = OutcomeFunctionalPass
	forged.Evidence["observationState"] = "NO_WRITE_SELECTION_OBSERVED"
	forged.Evidence["authorityAfterSHA256"] = forged.Evidence["authorityBeforeSHA256"]
	if err := ValidateMCPVoiceModelArtifacts(job, forged); err == nil {
		t.Fatal("forged closing authority was accepted")
	}
}

func TestMCPVoiceModelValidAmbiguousSelectionRemainsUnknown(t *testing.T) {
	runtime, cfg := modelRuntimeFixture(t)
	job := modelJobFixture(t, runtime)
	if err := WriteRuntimeConfig(filepath.Join(job.OutputDir, "runtime.json"), cfg); err != nil {
		t.Fatal(err)
	}
	other := mcpVoiceTool{Name: "reset_password", NameSHA256: modelNameHash("reset_password"), ArgumentsSHA256: strings.Repeat("d", 64), ArgumentCount: 1, RecognizedArgumentKeys: []string{"phone"}}
	f := &fakeMCPVoiceModelTransport{authority: modelAuthorityFixture(), output: modelOutputFixture(modelCallFixture(1, nil), modelCallFixture(2, []mcpVoiceTool{other}))}
	runner, err := New(runtime, mcpVoiceModelHandler{transport: f})
	if err != nil {
		t.Fatal(err)
	}
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeInconclusive || result.Evidence["observationState"] != "UNKNOWN" || result.Evidence["requestCount"] != "2" {
		t.Fatalf("valid ambiguous write should remain unknown: %+v", result)
	}
	if err := ValidateMCPVoiceModelArtifacts(job, result); err != nil {
		t.Fatal(err)
	}
	journal, err := loadJournal(filepath.Join(job.OutputDir, "journal.jsonl"))
	if err != nil || len(journal.Records) != 3 {
		t.Fatalf("UNKNOWN has closing event or loses per-call records: %d, %v", len(journal.Records), err)
	}
}
