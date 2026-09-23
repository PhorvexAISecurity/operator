package cataloguev1

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const gpuTerminalVersion = 1

type gpuProvenance struct {
	TrialsPerArm int    `json:"trialsPerArm"`
	Context      string `json:"context"`
	Namespace    string `json:"namespace"`
	MetricsFile  string `json:"metricsFile"`
	Entries      []struct {
		Scenario          string `json:"scenario"`
		Defender          string `json:"defender"`
		Trial             int    `json:"trial"`
		OracleAchieved    bool   `json:"oracleAchieved"`
		BenignControl     bool   `json:"benignControl"`
		ScenarioRealism   string `json:"scenarioRealism"`
		TrialKind         string `json:"trialKind"`
		Status            string `json:"measurementStatus"`
		Scored            bool   `json:"scored"`
		OracleObserved    bool   `json:"oracleObserved"`
		UnscoredReason    string `json:"unscoredReason"`
		CleanupComplete   bool   `json:"cleanupComplete"`
		CleanupUnresolved bool   `json:"cleanupUnresolved"`
		Unverified        bool   `json:"unverified"`
	} `json:"entries"`
	Run *struct {
		PlannedTrials  int      `json:"plannedTrials"`
		ExecutedTrials int      `json:"executedTrials"`
		WrittenTrials  int      `json:"writtenTrials"`
		Complete       bool     `json:"complete"`
		Aborted        bool     `json:"aborted"`
		Barriers       []string `json:"barriers"`
		LateCleanups   []any    `json:"lateCleanups"`
		FinalTeardown  *struct {
			Attempted bool   `json:"attempted"`
			Verified  bool   `json:"verified"`
			Error     string `json:"error"`
			Blocked   bool   `json:"blocked"`
		} `json:"finalTeardown"`
	} `json:"run"`
}

type gpuTerminalReceipt struct {
	Version             int       `json:"version"`
	RunID               string    `json:"runID"`
	Scenario            string    `json:"scenario"`
	NamespaceUID        string    `json:"namespaceUID"`
	HarnessSHA256       string    `json:"harnessSHA256"`
	FixtureConfigSHA256 string    `json:"fixtureConfigSHA256"`
	RunConfigSHA256     string    `json:"runConfigSHA256"`
	MetricSHA256        string    `json:"metricSHA256"`
	ProvenanceSHA256    string    `json:"provenanceSHA256"`
	ProcessExitOK       bool      `json:"processExitOK"`
	CleanupVerified     bool      `json:"cleanupVerified"`
	CreatedAt           time.Time `json:"createdAt"`
}

func loadAndValidateGPUProvenance(path, outDir string, config gpuHarnessConfig, metric gpuMetricProjection) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 2 || info.Size() > gpuMetricLimit {
		return "", errors.New("bounded terminal GPU provenance is absent")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var provenance gpuProvenance
	if err := json.Unmarshal(raw, &provenance); err != nil {
		return "", fmt.Errorf("decode terminal GPU provenance: %w", err)
	}
	if provenance.TrialsPerArm != 1 || provenance.Context != config.Context || provenance.Namespace != config.Namespace || provenance.MetricsFile != filepath.Join(outDir, "metrics.jsonl") || len(provenance.Entries) != 1 {
		return "", errors.New("GPU provenance run authority differs")
	}
	entry := provenance.Entries[0]
	if entry.Scenario != metric.Scenario || entry.Defender != metric.Defender || entry.Trial != metric.Trial || entry.OracleAchieved != metric.OracleAchieved || !entry.BenignControl || entry.ScenarioRealism != metric.ScenarioRealism || entry.TrialKind != string(metric.Validity.Kind) || entry.Status != string(metric.Validity.Status) || entry.Scored || entry.OracleObserved != metric.Validity.OracleObserved || entry.UnscoredReason != metric.Validity.UnscoredReason || !entry.CleanupComplete || entry.CleanupUnresolved || entry.Unverified {
		return "", errors.New("GPU provenance metric projection differs")
	}
	if provenance.Run == nil || provenance.Run.PlannedTrials != 1 || provenance.Run.ExecutedTrials != 1 || provenance.Run.WrittenTrials != 1 || !provenance.Run.Complete || provenance.Run.Aborted || len(provenance.Run.Barriers) != 0 || len(provenance.Run.LateCleanups) != 0 || provenance.Run.FinalTeardown == nil || !provenance.Run.FinalTeardown.Attempted || !provenance.Run.FinalTeardown.Verified || provenance.Run.FinalTeardown.Error != "" || provenance.Run.FinalTeardown.Blocked {
		return "", errors.New("GPU provenance does not prove complete verified final teardown")
	}
	return digestBytes(raw), nil
}

func persistGPUTerminal(path string, value gpuTerminalReceipt) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeExclusive(path, append(raw, '\n'), 0o600)
}

func validateRetainedGPUTerminal(job JobContext, config gpuHarnessConfig, source []byte, harnessSHA string) (json.RawMessage, gpuMetricProjection, error) {
	outDir := filepath.Join(job.Job.OutputDir, "gpu-harness")
	wantConfig, err := gpuRunConfig(source, outDir)
	if err != nil {
		return nil, gpuMetricProjection{}, err
	}
	gotConfig, err := os.ReadFile(filepath.Join(job.Job.OutputDir, "gpu-harness-config.json"))
	if err != nil || !bytes.Equal(gotConfig, wantConfig) {
		return nil, gpuMetricProjection{}, errors.New("retained GPU run config differs")
	}
	metric, projection, err := loadAndValidateGPUMetric(filepath.Join(outDir, "metrics.jsonl"), config)
	if err != nil {
		return nil, projection, err
	}
	provenanceSHA, err := loadAndValidateGPUProvenance(filepath.Join(outDir, "provenance.json"), outDir, config, projection)
	if err != nil {
		return nil, projection, err
	}
	terminalRaw, err := os.ReadFile(filepath.Join(job.Job.OutputDir, "gpu-terminal.json"))
	if err != nil || len(terminalRaw) > maxRecordBytes {
		return nil, projection, errors.New("retained GPU terminal receipt is absent or unbounded")
	}
	var terminal gpuTerminalReceipt
	if err := json.Unmarshal(terminalRaw, &terminal); err != nil {
		return nil, projection, err
	}
	sourceSHA := digestBytes(source)
	if terminal.Version != gpuTerminalVersion || terminal.RunID != job.Job.RunID || terminal.Scenario != gpuScenario || terminal.NamespaceUID != config.ExpectedNamespaceUID || terminal.HarnessSHA256 != harnessSHA || terminal.FixtureConfigSHA256 != sourceSHA || terminal.RunConfigSHA256 != digestBytes(wantConfig) || terminal.MetricSHA256 != digestBytes(metric) || terminal.ProvenanceSHA256 != provenanceSHA || !terminal.ProcessExitOK || !terminal.CleanupVerified || terminal.CreatedAt.IsZero() {
		return nil, projection, errors.New("retained GPU terminal receipt authority differs")
	}
	return metric, projection, nil
}
