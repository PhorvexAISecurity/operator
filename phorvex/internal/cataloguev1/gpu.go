package cataloguev1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phorvex/metricvalidity"
	"sigs.k8s.io/yaml"
)

const (
	gpuScenario           = "c2-vllm-request-drain"
	gpuDefender           = "d-nomtd"
	gpuMetricLimit        = 1 << 20
	gpuProcessOutputLimit = 256 << 10
	gpuCleanupGrace       = 30 * time.Second
	gpuClaimLimits        = "functional direct/no-action control only; the arms use different request counts and horizons and are ineligible for availability, cost, latency or brain-performance comparison; no cross-session leak, physical erasure, CVE, installed-manager dispatch, detection, containment, voice equivalence, ROI, or security-efficacy claim"
)

type gpuHandler struct{}

func NewGPUDrainHandler() Handler { return gpuHandler{} }

func (gpuHandler) Definition() Definition {
	definition, _ := DefinitionFor(GPUDrain)
	return definition
}

type gpuHarnessConfig struct {
	Kubeconfig           string            `json:"kubeconfig"`
	Context              string            `json:"context"`
	Namespace            string            `json:"namespace"`
	ExpectedNamespaceUID string            `json:"expectedNamespaceUID"`
	OwnedAck             bool              `json:"ownedAck"`
	TrialsPerArm         int               `json:"trialsPerArm"`
	OutDir               string            `json:"outDir"`
	DefenderFilter       []string          `json:"defenderFilter"`
	ScenarioFilter       []string          `json:"scenarioFilter"`
	GPU                  *gpuFixtureConfig `json:"gpuFunctionalFixture"`
	InstalledManager     json.RawMessage   `json:"installedManagerFixture"`
	NATSJetStream        json.RawMessage   `json:"natsJetStreamFixture"`
	NativeRoute          json.RawMessage   `json:"nativeRouteFixture"`
}

type gpuFixtureConfig struct {
	Operation          string `json:"operation"`
	Mode               string `json:"mode"`
	NamespaceUID       string `json:"namespaceUID"`
	RunLabel           string `json:"runLabel"`
	NodeName           string `json:"nodeName"`
	NodeUID            string `json:"nodeUID"`
	PodName            string `json:"podName"`
	PodUID             string `json:"podUID"`
	OwnerKind          string `json:"ownerKind"`
	OwnerName          string `json:"ownerName"`
	OwnerUID           string `json:"ownerUID"`
	ServiceName        string `json:"serviceName"`
	ServiceUID         string `json:"serviceUID"`
	ContainerName      string `json:"containerName"`
	Image              string `json:"image"`
	ImageID            string `json:"imageID"`
	StartedAt          string `json:"startedAt"`
	RestartCount       int32  `json:"restartCount"`
	Port               int32  `json:"port"`
	Model              string `json:"model"`
	ModelDigest        string `json:"modelDigest"`
	EngineSourceSHA256 string `json:"engineSourceSHA256"`
	ProxySourceGitSHA  string `json:"proxySourceGitSHA"`
	BearerTokenFile    string `json:"bearerTokenFile"`
}

type gpuMetricProjection struct {
	Scenario              string                   `json:"scenario"`
	Defender              string                   `json:"defender"`
	Trial                 int                      `json:"trial"`
	OracleAchieved        bool                     `json:"oracleAchieved"`
	Skipped               bool                     `json:"skipped"`
	SkipReason            string                   `json:"skipReason"`
	ScenarioRealism       string                   `json:"scenarioRealism"`
	ScenarioBenignControl bool                     `json:"scenarioBenignControl"`
	ScenarioClaimLimits   string                   `json:"scenarioClaimLimits"`
	BenchmarkEvidence     map[string]string        `json:"benchmarkEvidence"`
	DisruptionVsOracle    float64                  `json:"disruptionVsOracle"`
	DefensiveActions      int                      `json:"defensiveActions"`
	FalseDefensiveActions int                      `json:"falseDefensiveActions"`
	TimeToActionSeconds   float64                  `json:"timeToActionSeconds"`
	AttackerDwellSeconds  float64                  `json:"attackerDwellSeconds"`
	Validity              *metricvalidity.Validity `json:"validity"`
}

type gpuDrainReceiptProjection struct {
	Mode   string `json:"mode"`
	Create *struct {
		OperationID string `json:"operation_id"`
		State       string `json:"state"`
		Admission   string `json:"admission"`
	} `json:"create"`
	Reopen *struct {
		OperationID string `json:"operation_id"`
		State       string `json:"state"`
		Admission   string `json:"admission"`
	} `json:"reopen"`
	PostInference json.RawMessage `json:"postInference"`
}

func (gpuHandler) Validate(runtime Runtime) error {
	config, _, err := loadGPUAuthority(runtime.GPU)
	if err != nil {
		return err
	}
	return validateGPUClusterAuthority(runtime, config)
}

func validateGPUClusterAuthority(runtime Runtime, config gpuHarnessConfig) error {
	if runtime.GPU.KubeconfigPath == "" || runtime.GPU.KubeContext == "" || config.Kubeconfig != runtime.GPU.KubeconfigPath || config.Context != runtime.GPU.KubeContext {
		return errors.New("GPU harness cluster authority differs from the hash-bound runtime")
	}
	return nil
}

func loadGPUAuthority(runtime GPUFixtureRuntime) (gpuHarnessConfig, []byte, error) {
	if !runtime.Enabled {
		return gpuHarnessConfig{}, nil, errors.New("fixed GPU fixture is disabled")
	}
	for label, path := range map[string]string{
		"fixture config":    runtime.FixtureConfigFile,
		"harness binary":    runtime.HarnessBinary,
		"harness directory": runtime.HarnessDir,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return gpuHarnessConfig{}, nil, fmt.Errorf("%s must be a clean absolute path", label)
		}
	}
	info, err := os.Stat(runtime.HarnessBinary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return gpuHarnessConfig{}, nil, errors.New("GPU harness binary must be an executable regular file")
	}
	dirInfo, err := os.Stat(runtime.HarnessDir)
	if err != nil || !dirInfo.IsDir() {
		return gpuHarnessConfig{}, nil, errors.New("GPU harness directory is unavailable")
	}
	configInfo, err := os.Stat(runtime.FixtureConfigFile)
	if err != nil || !configInfo.Mode().IsRegular() || configInfo.Size() < 2 || configInfo.Size() > gpuMetricLimit {
		return gpuHarnessConfig{}, nil, errors.New("GPU fixture config must be a bounded regular file")
	}
	rawYAML, err := os.ReadFile(runtime.FixtureConfigFile)
	if err != nil {
		return gpuHarnessConfig{}, nil, err
	}
	raw, err := yaml.YAMLToJSON(rawYAML)
	if err != nil {
		return gpuHarnessConfig{}, nil, fmt.Errorf("decode GPU fixture config: %w", err)
	}
	var config gpuHarnessConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return gpuHarnessConfig{}, nil, fmt.Errorf("decode GPU fixture config: %w", err)
	}
	if err := validateGPUHarnessConfig(runtime, config); err != nil {
		return gpuHarnessConfig{}, nil, err
	}
	return config, raw, nil
}

func validateGPUHarnessConfig(runtime GPUFixtureRuntime, config gpuHarnessConfig) error {
	if config.Context == "" || config.Kubeconfig == "" || config.Namespace == "" || config.Namespace != runtime.Namespace || config.ExpectedNamespaceUID == "" || !config.OwnedAck {
		return errors.New("GPU fixture context, namespace authority or owned acknowledgement differs")
	}
	if config.TrialsPerArm != 1 || !exactStrings(config.ScenarioFilter, gpuScenario) || !exactStrings(config.DefenderFilter, gpuDefender) {
		return errors.New("GPU fixture must contain exactly one request-drain/d-nomtd trial")
	}
	if config.GPU == nil || config.GPU.Operation != "request-drain" || config.GPU.Mode != "direct" || config.GPU.NamespaceUID != config.ExpectedNamespaceUID {
		return errors.New("GPU fixture operation, mode or namespace UID differs")
	}
	if presentJSON(config.InstalledManager) || presentJSON(config.NATSJetStream) || presentJSON(config.NativeRoute) {
		return errors.New("GPU fixture config contains another externally bound fixture")
	}
	fixture := config.GPU
	required := map[string]string{
		"runLabel": fixture.RunLabel, "nodeName": fixture.NodeName, "nodeUID": fixture.NodeUID,
		"podName": fixture.PodName, "podUID": fixture.PodUID, "ownerKind": fixture.OwnerKind,
		"ownerName": fixture.OwnerName, "ownerUID": fixture.OwnerUID, "serviceName": fixture.ServiceName,
		"serviceUID": fixture.ServiceUID, "containerName": fixture.ContainerName, "image": fixture.Image,
		"imageID": fixture.ImageID, "startedAt": fixture.StartedAt, "model": fixture.Model,
		"modelDigest": fixture.ModelDigest, "engineSourceSHA256": fixture.EngineSourceSHA256,
		"proxySourceGitSHA": fixture.ProxySourceGitSHA, "bearerTokenFile": fixture.BearerTokenFile,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("GPU fixture %s is empty", name)
		}
	}
	if fixture.RestartCount != 0 || fixture.Port != 8000 || !filepath.IsAbs(fixture.BearerTokenFile) || filepath.Clean(fixture.BearerTokenFile) != fixture.BearerTokenFile {
		return errors.New("GPU fixture restart, port or token-file authority differs")
	}
	tokenInfo, err := os.Stat(fixture.BearerTokenFile)
	if err != nil || !tokenInfo.Mode().IsRegular() || tokenInfo.Size() < 32 || tokenInfo.Size() > 16<<10 || tokenInfo.Mode().Perm()&0o137 != 0 {
		return errors.New("GPU fixture bearer token projection is unavailable or unsafe")
	}
	if !filepath.IsAbs(config.Kubeconfig) || filepath.Clean(config.Kubeconfig) != config.Kubeconfig {
		return errors.New("GPU fixture kubeconfig path is invalid")
	}
	kubeInfo, statErr := os.Stat(config.Kubeconfig)
	if statErr != nil || !kubeInfo.Mode().IsRegular() || kubeInfo.Size() < 1 || kubeInfo.Size() > gpuMetricLimit {
		return errors.New("GPU fixture kubeconfig is unavailable")
	}
	if _, err := time.Parse(time.RFC3339, fixture.StartedAt); err != nil {
		return errors.New("GPU fixture container start time is invalid")
	}
	for _, digest := range []string{fixture.EngineSourceSHA256} {
		if !isHex64(digest) {
			return errors.New("GPU fixture source digest is invalid")
		}
	}
	if config.OutDir != "" && (!filepath.IsAbs(config.OutDir) || filepath.Clean(config.OutDir) != config.OutDir) {
		return errors.New("GPU harness source output directory is invalid")
	}
	return nil
}

func exactStrings(values []string, want string) bool {
	return len(values) == 1 && values[0] == want
}

func presentJSON(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null"))
}

func isHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func (gpuHandler) Run(ctx context.Context, job JobContext) Result {
	started := time.Now().UTC()
	result := Result{
		Outcome: OutcomeTestFailed, Summary: "GPU request-drain control did not complete",
		Limits:    []string{gpuHandler{}.Definition().ClaimLimits},
		Cleanup:   Cleanup{Attempted: false, Verified: false, Status: "NOT-STARTED"},
		StartedAt: started,
	}
	config, sourceRaw, err := loadGPUAuthority(job.Runtime.GPU)
	if err != nil {
		result.Outcome = OutcomeInconclusive
		result.Summary = "GPU fixture unavailable: " + err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if err := validateGPUClusterAuthority(job.Runtime, config); err != nil || job.Job.ResolvedTarget != "default" || job.Job.ResolvedTenant != job.Runtime.GPU.Namespace {
		result.Outcome = OutcomeInconclusive
		result.Summary = "GPU job or cluster authority differs from the fixed runtime"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	harnessSHA, err := fileSHA256(job.Runtime.GPU.HarnessBinary, 512<<20)
	if err != nil {
		result.Outcome = OutcomeInconclusive
		result.Summary = "GPU harness identity unavailable: " + err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	configSHA := sha256.Sum256(sourceRaw)
	outDir := filepath.Join(job.Job.OutputDir, "gpu-harness")
	if err := os.Mkdir(outDir, 0o700); err != nil && !os.IsExist(err) {
		result.Summary = "create owned GPU output: " + err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if err := ensureOwnedEmptyDir(outDir); err != nil {
		result.Summary = err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	runConfig, err := gpuRunConfig(sourceRaw, outDir)
	if err != nil {
		result.Summary = "prepare fixed GPU config: " + err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	configPath := filepath.Join(job.Job.OutputDir, "gpu-harness-config.json")
	if err := writeExclusive(configPath, runConfig, 0o600); err != nil {
		result.Summary = "persist fixed GPU config: " + err.Error()
		result.FinishedAt = time.Now().UTC()
		return result
	}
	identity := map[string]string{
		"scenario": gpuScenario, "defender": gpuDefender, "operation": "request-drain",
		"namespaceUID": config.ExpectedNamespaceUID, "podUID": config.GPU.PodUID,
		"serviceUID": config.GPU.ServiceUID, "harnessSHA256": harnessSHA,
		"fixtureConfigSHA256": hex.EncodeToString(configSHA[:]),
	}
	if err := job.Recorder.Intent(Intent{Step: "gpu-request-drain", Mutation: true, Identity: identity, At: time.Now().UTC()}); err != nil {
		result.Summary = "persist GPU dispatch intent: " + err.Error()
		result.UnsafeToRetry = true
		result.FinishedAt = time.Now().UTC()
		return result
	}
	invocation := runGPUHarness(ctx, job.Job, job.Runtime.GPU, configPath, harnessSHA, hex.EncodeToString(configSHA[:]))
	eventStatus := "completed"
	if invocation.StartErr != nil {
		eventStatus = "not-started"
	} else if invocation.ForcedStop {
		eventStatus = "forced-stop"
	} else if invocation.Err != nil {
		eventStatus = "failed"
	}
	if eventErr := job.Recorder.Event(Event{Step: "gpu-request-drain-process", Status: eventStatus, Identity: map[string]string{
		"namespaceUID": config.ExpectedNamespaceUID, "processStarted": strconv.FormatBool(invocation.StartErr == nil),
		"forcedStop": strconv.FormatBool(invocation.ForcedStop), "processGroupGone": strconv.FormatBool(invocation.ProcessGroupGone), "stdoutSHA256": digestBytes(invocation.Stdout),
		"stderrSHA256": digestBytes(invocation.Stderr),
	}, At: time.Now().UTC()}); eventErr != nil {
		result.Summary = "persist GPU process observation: " + eventErr.Error()
		result.UnsafeToRetry = invocation.StartErr == nil
		result.Cleanup = Cleanup{Attempted: invocation.StartErr == nil, Verified: false, Status: "JOURNAL-FAILED", UnsafeToRetry: invocation.StartErr == nil}
		result.FinishedAt = time.Now().UTC()
		return result
	}
	result.Evidence = map[string]string{
		"fixtureConfigSHA256": hex.EncodeToString(configSHA[:]), "harnessSHA256": harnessSHA,
		"namespaceUID": config.ExpectedNamespaceUID, "podUID": config.GPU.PodUID,
		"serviceUID": config.GPU.ServiceUID, "securityOutcome": "not-measured",
		"installedManagerDispatchProven": "false", "processStarted": strconv.FormatBool(invocation.StartErr == nil),
	}
	if invocation.StartErr != nil {
		result.Summary = "GPU harness did not start: " + invocation.StartErr.Error()
		result.Cleanup = Cleanup{Attempted: false, Verified: true, Status: "PASS-NO-START", Details: map[string]string{"operationSent": "false"}}
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if !invocation.ProcessGroupGone {
		result.Summary = "GPU harness exited with an unresolved process group"
		result.Cleanup = Cleanup{Attempted: true, Verified: false, Status: "PROCESS-GROUP-UNRESOLVED", UnsafeToRetry: true}
		result.UnsafeToRetry = true
		result.FinishedAt = time.Now().UTC()
		return result
	}
	metricRaw, projection, metricErr := loadAndValidateGPUMetric(filepath.Join(outDir, "metrics.jsonl"), config)
	if metricErr != nil {
		result.Summary = "GPU harness evidence is invalid: " + metricErr.Error()
		result.Cleanup = Cleanup{Attempted: true, Verified: false, Status: "UNVERIFIED", UnsafeToRetry: true}
		result.UnsafeToRetry = true
		if invocation.ForcedStop {
			result.Outcome = OutcomeInconclusive
		}
		result.FinishedAt = time.Now().UTC()
		return result
	}
	result.Cleanup = Cleanup{Attempted: true, Verified: projection.Validity.Cleanup.Verified, Status: "PASS", Details: map[string]string{
		"reopened": "true", "fixtureVerified": "true", "requestsReplayed": "0",
	}}
	provenanceSHA, provenanceErr := loadAndValidateGPUProvenance(filepath.Join(outDir, "provenance.json"), outDir, config, projection)
	if provenanceErr != nil {
		result.Summary = "GPU harness terminal evidence is invalid: " + provenanceErr.Error()
		result.Cleanup = Cleanup{Attempted: true, Verified: false, Status: "FINAL-TEARDOWN-UNVERIFIED", UnsafeToRetry: true}
		result.UnsafeToRetry = true
		result.FinishedAt = time.Now().UTC()
		return result
	}
	terminal := gpuTerminalReceipt{
		Version: gpuTerminalVersion, RunID: job.Job.RunID, Scenario: gpuScenario, NamespaceUID: config.ExpectedNamespaceUID,
		HarnessSHA256: harnessSHA, FixtureConfigSHA256: hex.EncodeToString(configSHA[:]), RunConfigSHA256: digestBytes(runConfig),
		MetricSHA256: digestBytes(metricRaw), ProvenanceSHA256: provenanceSHA, ProcessExitOK: invocation.Err == nil,
		CleanupVerified: true, CreatedAt: time.Now().UTC(),
	}
	if err := persistGPUTerminal(filepath.Join(job.Job.OutputDir, "gpu-terminal.json"), terminal); err != nil {
		result.Summary = "persist GPU terminal authority: " + err.Error()
		result.UnsafeToRetry = true
		result.FinishedAt = time.Now().UTC()
		return result
	}
	result.Evidence["metricSHA256"] = digestBytes(metricRaw)
	result.Evidence["provenanceSHA256"] = provenanceSHA
	if err := job.Recorder.MetricRaw(metricRaw); err != nil {
		result.Summary = "persist exact GPU metric: " + err.Error()
		result.UnsafeToRetry = true
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if err := job.Recorder.Event(Event{Step: "gpu-request-drain-cleanup", Status: "verified", Identity: map[string]string{
		"namespaceUID": config.ExpectedNamespaceUID, "metricSHA256": digestBytes(metricRaw), "reopened": "true",
	}, At: time.Now().UTC()}); err != nil {
		result.Summary = "persist GPU cleanup observation: " + err.Error()
		result.UnsafeToRetry = true
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if invocation.Err != nil || invocation.OutputOverflow {
		result.Summary = "GPU harness process failed despite retained verified cleanup"
		result.Outcome = OutcomeTestFailed
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if invocation.ContextEnded {
		result.Outcome = OutcomeInconclusive
		result.Summary = "GPU control completed with verified cleanup after its caller was canceled"
		result.FinishedAt = time.Now().UTC()
		return result
	}
	if projection.Validity.Status != metricvalidity.StatusValid || projection.Validity.Phase != metricvalidity.PhaseComplete {
		result.Outcome = OutcomeTestFailed
		result.Summary = "GPU harness completed with an invalid measurement"
	} else if !projection.OracleAchieved {
		result.Outcome = OutcomeFunctionalFail
		result.Summary = "GPU request drain did not achieve the fixed functional oracle; cleanup was verified"
	} else {
		result.Outcome = OutcomeFunctionalPass
		result.Summary = "the owned GPU fixture acknowledged one request drain, aborted the exact in-flight anchor, quiesced, reopened and served fresh inference"
	}
	result.FinishedAt = time.Now().UTC()
	return result
}

func (gpuHandler) Reconcile(_ context.Context, job JobContext, journal Journal) Cleanup {
	started := false
	for _, record := range journal.Records {
		if record.Intent != nil && record.Intent.Step == "gpu-request-drain" && record.Intent.Mutation {
			started = true
		}
	}
	if !started {
		return Cleanup{Attempted: false, Verified: true, Status: "PASS-NO-INTENT", Details: map[string]string{"requestsReplayed": "0"}}
	}
	config, source, err := loadGPUAuthority(job.Runtime.GPU)
	if err == nil && validateGPUClusterAuthority(job.Runtime, config) == nil && job.Job.ResolvedTarget == "default" && job.Job.ResolvedTenant == job.Runtime.GPU.Namespace {
		harnessSHA, hashErr := fileSHA256(job.Runtime.GPU.HarnessBinary, 512<<20)
		metric, projection, terminalErr := validateRetainedGPUTerminal(job, config, source, harnessSHA)
		if hashErr == nil && terminalErr == nil && projection.Validity.Cleanup.Verified {
			return Cleanup{Attempted: true, Verified: true, Status: "PASS-RETAINED", Details: map[string]string{
				"requestsReplayed": "0", "source": "validated-terminal-provenance", "metricSHA256": digestBytes(metric),
			}}
		}
	}
	processStatus := "not-checked"
	if err == nil {
		harnessSHA, hashErr := fileSHA256(job.Runtime.GPU.HarnessBinary, 512<<20)
		if hashErr == nil {
			processStatus = reapRetainedGPUProcess(job, harnessSHA, digestBytes(source))
		}
	}
	return Cleanup{Attempted: true, Verified: false, Status: "UNVERIFIED-NO-REPLAY", UnsafeToRetry: true, Details: map[string]string{
		"requestsReplayed": "0", "reason": "exact reopen and cleanup were not retained", "processGroup": processStatus,
	}}
}

type gpuInvocation struct {
	Stdout, Stderr   []byte
	StartErr         error
	Err              error
	ForcedStop       bool
	ContextEnded     bool
	ProcessGroupGone bool
	OutputOverflow   bool
}

func runGPUHarness(ctx context.Context, job Job, runtime GPUFixtureRuntime, configPath, harnessSHA, configSHA string) gpuInvocation {
	definition, _ := DefinitionFor(GPUDrain)
	deadline := time.Now().Add(definition.MaxDuration)
	if !job.Deadline.IsZero() && job.Deadline.Before(deadline) {
		deadline = job.Deadline
	}
	runCtx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	cmd := exec.Command(runtime.HarnessBinary, "-config", configPath, "-negative-control=false", "-adaptive=false")
	cmd.Dir = runtime.HarnessDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	stdout, stderr := &cappedBuffer{limit: gpuProcessOutputLimit}, &cappedBuffer{limit: gpuProcessOutputLimit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return gpuInvocation{StartErr: err}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if err := persistGPUProcessIdentity(filepath.Join(job.OutputDir, "gpu-process.json"), job, cmd, harnessSHA, configSHA); err != nil {
		result := gpuInvocation{Err: processIdentityError(err, cmd, done), ForcedStop: true}
		result.Stdout, result.Stderr = stdout.Bytes(), stderr.Bytes()
		result.OutputOverflow = stdout.overflow || stderr.overflow
		return result
	}
	var result gpuInvocation
	select {
	case result.Err = <-done:
	case <-ctx.Done():
		result.ContextEnded = true
		select {
		case result.Err = <-done:
		case <-time.After(gpuCleanupGrace):
			result.ForcedStop = true
			result.Err = stopProcessGroup(cmd, done)
		}
	case <-runCtx.Done():
		result.ContextEnded = true
		select {
		case result.Err = <-done:
		case <-time.After(gpuCleanupGrace):
			result.ForcedStop = true
			result.Err = stopProcessGroup(cmd, done)
		}
	}
	result.Stdout, result.Stderr = stdout.Bytes(), stderr.Bytes()
	result.OutputOverflow = stdout.overflow || stderr.overflow
	// Members of the group can still be exiting, or awaiting their reaper, when the
	// leader's exit is reported. They get a bounded moment; one that remains is an
	// unresolved group, never a clean exit.
	result.ProcessGroupGone = waitGPUProcessGroupGone(cmd.Process.Pid, gpuGroupExitGrace)
	if !result.ProcessGroupGone {
		result.Err = errors.Join(result.Err, errors.New("GPU harness process group remains after leader exit"))
	}
	return result
}

func stopProcessGroup(cmd *exec.Cmd, done <-chan error) error {
	if cmd.Process == nil {
		return errors.New("GPU harness process is unavailable")
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	var leaderErr error
	leaderDone := false
	select {
	case err := <-done:
		leaderErr = err
		leaderDone = true
	case <-time.After(3 * time.Second):
	}
	if waitGPUProcessGroupGone(pgid, 250*time.Millisecond) {
		return leaderErr
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	if !leaderDone {
		select {
		case err := <-done:
			leaderErr = err
			leaderDone = true
		case <-time.After(3 * time.Second):
		}
	}
	if !waitGPUProcessGroupGone(pgid, 3*time.Second) {
		return errors.Join(leaderErr, errors.New("GPU harness process group did not stop"))
	}
	return leaderErr
}

type cappedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.buf.Write(value)
	}
	if original > remaining {
		b.overflow = true
	}
	return original, nil
}

func (b *cappedBuffer) Bytes() []byte { return append([]byte(nil), b.buf.Bytes()...) }

func gpuRunConfig(source []byte, outDir string) ([]byte, error) {
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		return nil, err
	}
	document["outDir"] = outDir
	return json.Marshal(document)
}

func ensureOwnedEmptyDir(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("owned GPU output directory is not empty")
	}
	return nil
}

func writeExclusive(path string, value []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = file.Write(value); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func fileSHA256(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if written > limit {
		return "", errors.New("file exceeds identity hash bound")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func loadAndValidateGPUMetric(path string, config gpuHarnessConfig) (json.RawMessage, gpuMetricProjection, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > gpuMetricLimit {
		return nil, gpuMetricProjection{}, errors.New("exact bounded GPU metric is absent")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, gpuMetricProjection{}, err
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 1 || !json.Valid(lines[0]) {
		return nil, gpuMetricProjection{}, errors.New("GPU harness must emit exactly one JSON metric row")
	}
	metric := json.RawMessage(append([]byte(nil), lines[0]...))
	var projection gpuMetricProjection
	if err := json.Unmarshal(metric, &projection); err != nil {
		return nil, gpuMetricProjection{}, err
	}
	if err := validateGPUMetricProjection(projection, config); err != nil {
		return nil, projection, err
	}
	return metric, projection, nil
}

func validateGPUMetricProjection(metric gpuMetricProjection, config gpuHarnessConfig) error {
	if metric.Scenario != gpuScenario || metric.Defender != gpuDefender || metric.Trial != 0 {
		return errors.New("GPU metric scenario, defender or trial differs")
	}
	if metric.ScenarioRealism != "executable-mechanism" || !metric.ScenarioBenignControl || metric.ScenarioClaimLimits != gpuClaimLimits {
		return errors.New("GPU metric benign functional claim boundary differs")
	}
	validity := metric.Validity
	if validity == nil || validity.Version != metricvalidity.Version || validity.Kind != metricvalidity.TrialOrdinary || validity.Scored || validity.UnscoredReason == "" {
		return errors.New("GPU metric validity projection differs")
	}
	if metric.Skipped && metric.SkipReason != "UNSCORED(benign-control): "+validity.UnscoredReason {
		return errors.New("GPU metric legacy benign-unscored projection differs from shared validity")
	}
	if validity.Status != metricvalidity.StatusValid && validity.Status != metricvalidity.StatusInvalid {
		return errors.New("GPU metric validity status is unavailable for this fixed trial")
	}
	if !validity.Cleanup.Complete || !validity.Cleanup.Verified || !validity.Cleanup.Sound() {
		return errors.New("GPU metric does not prove verified cleanup")
	}
	verdict := metricvalidity.Evaluate(validity, metricvalidity.Observations{
		Trial: metric.Trial, Disruption: metric.DisruptionVsOracle, DefensiveActions: metric.DefensiveActions,
		FalseDefensiveActions: metric.FalseDefensiveActions, TimeToActionSeconds: metric.TimeToActionSeconds,
		AttackerDwellSeconds: metric.AttackerDwellSeconds,
	})
	if !verdict.Supported || verdict.Unverified || (validity.Status == metricvalidity.StatusValid && !verdict.OracleUsable) {
		return fmt.Errorf("GPU metric validity contract rejected the row: %s", strings.Join(verdict.Reasons(), "; "))
	}
	if validity.Status == metricvalidity.StatusValid && (validity.Phase != metricvalidity.PhaseComplete || !validity.AttackExecuted || !validity.OracleObserved || !validity.ObserverPresent || !validity.CostObserved) {
		return errors.New("valid GPU metric lacks the complete functional observation lifecycle")
	}
	fixture := config.GPU
	want := map[string]string{
		"scenario": gpuScenario, "suiteVersion": "post25-vllm-functional-v4", "operation": "request-drain",
		"fixtureMode": "direct", "functionalArm": "direct-producer",
		"installedManagerDispatchProven": "false", "nativeHandlerDispatchProven": "false",
		"securityOutcome": "not-measured", "costOutcome": "not-measured", "cveOutcome": "not-measured",
		"availabilityComparisonEligible": "false", "costComparisonEligible": "false",
		"brainPerformanceComparisonEligible": "false", "workloadComparison": "unmatched-functional-protocol-check",
		"namespaceUID": config.ExpectedNamespaceUID, "podUID": fixture.PodUID, "serviceUID": fixture.ServiceUID,
		"ownerUID": fixture.OwnerUID, "nodeUID": fixture.NodeUID, "engineSourceSHA256": fixture.EngineSourceSHA256,
		"modelDigest": fixture.ModelDigest,
	}
	for key, value := range want {
		if metric.BenchmarkEvidence[key] != value {
			return fmt.Errorf("GPU metric evidence %s differs", key)
		}
	}
	if validity.Status == metricvalidity.StatusValid {
		for key, value := range map[string]string{
			"oracleStatus": "complete", "protocolOperationAttempts": "1", "protocolOperationAcknowledgements": "1",
			"restorationAttempts": "1", "restorationAcknowledgements": "1",
		} {
			if metric.BenchmarkEvidence[key] != value {
				return fmt.Errorf("valid GPU metric evidence %s differs", key)
			}
		}
	} else {
		if metric.BenchmarkEvidence["oracleStatus"] != "incomplete" {
			return errors.New("invalid GPU metric must retain an incomplete oracle status")
		}
		if err := validateGPUProtocolCounts(metric.BenchmarkEvidence); err != nil {
			return err
		}
	}
	receipt := metric.BenchmarkEvidence["receiptJSON"]
	receiptSHA := metric.BenchmarkEvidence["receiptSHA256"]
	if receipt == "" || !isHex64(receiptSHA) || digestBytes([]byte(receipt)) != receiptSHA {
		return errors.New("GPU metric receipt digest differs")
	}
	var parsed gpuDrainReceiptProjection
	if err := json.Unmarshal([]byte(receipt), &parsed); err != nil {
		return errors.New("GPU drain receipt is not valid JSON")
	}
	if parsed.Mode != "direct" {
		return errors.New("GPU drain receipt mode differs")
	}
	if validity.Status == metricvalidity.StatusValid && (parsed.Create == nil || parsed.Reopen == nil || parsed.Create.OperationID == "" || parsed.Reopen.OperationID != parsed.Create.OperationID || parsed.Create.State != "DRAINING" || parsed.Create.Admission != "CLOSED" || parsed.Reopen.State != "OPENED" || parsed.Reopen.Admission != "OPEN" || len(parsed.PostInference) == 0 || bytes.Equal(bytes.TrimSpace(parsed.PostInference), []byte("null"))) {
		return errors.New("GPU drain receipt create/reopen/recovery authority differs")
	}
	return nil
}

func validateGPUProtocolCounts(evidence map[string]string) error {
	values := make([]int, 0, 4)
	for _, key := range []string{"protocolOperationAttempts", "protocolOperationAcknowledgements", "restorationAttempts", "restorationAcknowledgements"} {
		value, err := strconv.Atoi(evidence[key])
		if err != nil || value < 0 || value > 1 {
			return fmt.Errorf("invalid GPU metric evidence %s differs", key)
		}
		values = append(values, value)
	}
	if values[1] > values[0] || values[3] > values[2] {
		return errors.New("invalid GPU metric acknowledgement count exceeds attempts")
	}
	return nil
}
