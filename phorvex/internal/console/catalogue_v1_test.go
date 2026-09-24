package console

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/metricvalidity"
	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func TestCatalogRetainsLimitedV1WhenLegacyHarnessUnavailable(t *testing.T) {
	cfg := Config{HarnessBin: filepath.Join(t.TempDir(), "missing-harness"), HarnessDir: t.TempDir(), StateDir: t.TempDir()}
	items := cfg.Catalog()
	if len(items) != 15 {
		t.Fatalf("items=%d, want nine existing entries, disabled Mongo, three Chroma/LiteLLM and two CRM entries", len(items))
	}
	responseRows, mongoRows := 0, 0
	for _, item := range items {
		if item.Name == "c2-nats-owned-client-response" {
			responseRows++
			if item.Available || item.LaunchKind != "named-suite" || item.Profile != natsResponseConfig || item.ClaimClass != "effect" {
				t.Fatalf("unconfigured response row gained launch authority: %+v", item)
			}
		} else if item.Name == "c2-mongo-uncredentialed-service-exposure" {
			mongoRows++
			if item.Available || item.LaunchKind != "named-suite" || item.Profile != mongoExposureConfig || item.ClaimClass != "configuration" {
				t.Fatalf("unconfigured Mongo row gained launch authority: %+v", item)
			}
		} else if !strings.HasPrefix(item.Name, "limited-v1-") && item.Name != string(cataloguev1.MCPSessionBaseline) &&
			item.Name != string(cataloguev1.ChromaOwnedVector) && item.Name != string(cataloguev1.LiteLLMHealth) && item.Name != string(cataloguev1.LiteLLMCredential) &&
			item.Name != string(cataloguev1.CRMRefund) && item.Name != string(cataloguev1.CRMReset) {
			t.Fatalf("unexpected entry %q", item.Name)
		}
		if item.LaunchKind == "" || item.ClaimClass == "" {
			t.Fatalf("entry lacks typed launch metadata: %+v", item)
		}
	}
	if responseRows != 1 {
		t.Fatalf("server-owned response row count=%d", responseRows)
	}
	if mongoRows != 1 {
		t.Fatalf("server-owned Mongo row count=%d", mongoRows)
	}
}

func TestGuardrailCalibrationCatalogueAPIIsSeparateAndDisabledByDefault(t *testing.T) {
	cfg := Config{}
	items := cfg.Catalog()
	var calibration, effect *CatalogItem
	for i := range items {
		if items[i].EntryID == limitedV1GuardrailCalibrationID {
			calibration = &items[i]
		}
		if items[i].EntryID == limitedV1GuardrailID {
			effect = &items[i]
		}
	}
	if calibration == nil || effect == nil {
		t.Fatal("separate calibration and effect entries are missing")
	}
	raw, err := json.Marshal(calibration)
	if err != nil {
		t.Fatal(err)
	}
	var api struct {
		LaunchKind            string   `json:"launchKind"`
		ClaimClass            string   `json:"claimClass"`
		ResponseGuidanceBasis string   `json:"responseGuidanceBasis"`
		ExpectedActuators     []string `json:"expectedActuators"`
		Available             bool     `json:"available"`
		BenignControl         *bool    `json:"benignControl"`
	}
	if err = json.Unmarshal(raw, &api); err != nil {
		t.Fatal(err)
	}
	if api.LaunchKind != "fixed-suite" || api.ClaimClass != "calibration" || api.ResponseGuidanceBasis != "none" || len(api.ExpectedActuators) != 0 || api.Available || api.BenignControl == nil || !*api.BenignControl {
		t.Fatalf("calibration API claim is unsupported: %s", raw)
	}
	if effect.LaunchKind != "live-vllm-effect" || effect.ClaimClass != "effect" || len(effect.ExpectedActuators) != 1 {
		t.Fatalf("effect entry changed: %+v", effect)
	}
}

func TestFixedSuiteMetricIsHiddenUntilTerminalAndTerminalFailureDominates(t *testing.T) {
	state := t.TempDir()
	cfg := Config{StateDir: state}
	rm := NewRunManager(cfg)
	id := "v1run-1"
	dir := cfg.runOutputPath(id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	validity := &metricvalidity.Validity{Version: metricvalidity.Version, Kind: metricvalidity.TrialOrdinary,
		Status: metricvalidity.StatusValid, Phase: metricvalidity.PhaseComplete, AttackExecuted: true, OracleObserved: true,
		ObserverPresent: true, Scored: false, UnscoredReason: "UNSCORED(benign-control)",
		Cleanup: metricvalidity.CleanupRecord{Attempted: []metricvalidity.CleanupStep{{Step: "cataloguev1.cleanup"}}, Complete: true, Verified: true}}
	row := runMetricRow{Scenario: string(cataloguev1.AuthUnauth), Defender: "d-functional", Trial: 0, OracleAchieved: true,
		ScenarioRealism: "executable-mechanism", ScenarioBenignControl: true, Validity: validity}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "metrics.jsonl"), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	rm.mu.Lock()
	rm.runOut[id] = id
	rm.runs[id] = &RunStatus{ID: id, Config: string(row.Scenario), State: "running", ExecutionKind: "fixed-suite", ClaimClass: "functional"}
	rm.mu.Unlock()
	_, trials, issues, _, ok := rm.RunEvidence(id)
	if !ok || len(trials) != 0 || len(issues) != 1 {
		t.Fatalf("running metric leaked: ok=%v trials=%d issues=%d", ok, len(trials), len(issues))
	}
	rm.mu.Lock()
	rm.runs[id].State = "error"
	rm.runs[id].Outcome = outcomeTestFailed
	rm.runs[id].CleanupStatus = "PASS"
	rm.mu.Unlock()
	definition, _ := cataloguev1.DefinitionFor(cataloguev1.AuthUnauth)
	definitionHash, _ := cataloguev1.DefinitionSHA256(definition)
	now := time.Now().UTC()
	job := cataloguev1.Job{Version: cataloguev1.JobVersion, RunID: id, Profile: cataloguev1.AuthUnauth, OutputDir: dir,
		DefinitionSHA256: definitionHash, OwnerDigest: strings.Repeat("a", 64), ResolvedTarget: "default", ResolvedTenant: "vllm",
		RuntimeConfigSHA256: strings.Repeat("b", 64), CreatedAt: now, Deadline: now.Add(time.Minute)}
	if err = cataloguev1.WriteJob(filepath.Join(dir, "job.json"), state, job); err != nil {
		t.Fatal(err)
	}
	result := cataloguev1.Result{Version: cataloguev1.ResultVersion, RunID: id, Profile: cataloguev1.AuthUnauth,
		DefinitionSHA256: definitionHash, OwnerDigest: job.OwnerDigest, ResolvedTarget: "default", ResolvedTenant: "vllm",
		RuntimeConfigSHA256: job.RuntimeConfigSHA256, Outcome: cataloguev1.OutcomeTestFailed, Summary: "terminal process failure",
		Cleanup: cataloguev1.Cleanup{Attempted: true, Verified: true, Status: "PASS"}, StartedAt: now, FinishedAt: now.Add(time.Second)}
	resultRaw, _ := json.Marshal(result)
	if err = os.WriteFile(filepath.Join(dir, "result.json"), append(resultRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	_, trials, _, _, ok = rm.RunEvidence(id)
	if !ok || len(trials) != 1 || trials[0].Outcome != outcomeTestFailed || trials[0].ClaimClass != "functional" {
		t.Fatalf("terminal failure did not dominate metric: ok=%v trials=%+v", ok, trials)
	}
}

func TestFixedSuiteStoppedBeforeWorkerStartHasNoEffect(t *testing.T) {
	state := t.TempDir()
	marker := filepath.Join(state, "executed")
	executable := filepath.Join(state, "worker")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\ntouch \""+marker+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	rm := NewRunManager(Config{StateDir: state, CatalogueV1: CatalogueV1Config{Executable: executable}})
	now := time.Now().UTC()
	job := cataloguev1.Job{Version: cataloguev1.JobVersion, RunID: "v1run-1", Profile: cataloguev1.AuthUnauth,
		OutputDir: filepath.Join(state, "runs", "v1run-1"), CreatedAt: now, Deadline: now.Add(time.Minute)}
	if err := os.MkdirAll(job.OutputDir, 0o750); err != nil {
		t.Fatal(err)
	}
	rm.mu.Lock()
	rm.runs[job.RunID] = &RunStatus{ID: job.RunID, State: "running", ExecutionKind: "fixed-suite"}
	rm.runOut[job.RunID] = job.RunID
	rm.stopping[job.RunID] = true
	rm.active = 1
	rm.mu.Unlock()
	rm.runFunctional(job.RunID, filepath.Join(job.OutputDir, "job.json"), job)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("worker executed before-stop marker: %v", err)
	}
	status, _ := rm.Status(job.RunID)
	if status.State == "done" || status.Outcome == outcomeFunctionalPass || !status.UnsafeToRetry {
		t.Fatalf("stopped pre-start job was promoted: %+v", status)
	}
}

func TestFixedSuiteMissingArtifactsAndPersistenceFailureNeverPass(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		writeResult, writeMetric, failPersist bool
	}{
		{name: "missing-result"}, {name: "missing-metric", writeResult: true},
		{name: "failed-status-persistence", writeResult: true, writeMetric: true, failPersist: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			cfg := Config{StateDir: state}
			if tc.failPersist {
				cfg.StateAppend = func(string, []byte) error { return errors.New("injected persistence failure") }
			}
			rm := NewRunManager(cfg)
			id, dir := "v1run-1", cfg.runOutputPath("v1run-1")
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			definition, _ := cataloguev1.DefinitionFor(cataloguev1.AuthUnauth)
			definitionHash, _ := cataloguev1.DefinitionSHA256(definition)
			now := time.Now().UTC()
			job := cataloguev1.Job{Version: cataloguev1.JobVersion, RunID: id, Profile: cataloguev1.AuthUnauth, OutputDir: dir,
				DefinitionSHA256: definitionHash, OwnerDigest: strings.Repeat("a", 64), ResolvedTarget: "default", ResolvedTenant: "vllm",
				RuntimeConfigSHA256: strings.Repeat("b", 64), CreatedAt: now, Deadline: now.Add(time.Minute)}
			result := cataloguev1.Result{Version: cataloguev1.ResultVersion, RunID: id, Profile: job.Profile, DefinitionSHA256: definitionHash,
				OwnerDigest: job.OwnerDigest, ResolvedTarget: job.ResolvedTarget, ResolvedTenant: job.ResolvedTenant, RuntimeConfigSHA256: job.RuntimeConfigSHA256,
				Outcome: cataloguev1.OutcomeFunctionalPass, Summary: "bounded pass", Cleanup: cataloguev1.Cleanup{Attempted: true, Verified: true, Status: "PASS"}, StartedAt: now, FinishedAt: now.Add(time.Second)}
			if tc.writeResult {
				raw, _ := json.Marshal(result)
				if err := os.WriteFile(filepath.Join(dir, "result.json"), append(raw, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.writeMetric {
				validity := &metricvalidity.Validity{Version: metricvalidity.Version, Kind: metricvalidity.TrialOrdinary, Status: metricvalidity.StatusValid,
					Phase: metricvalidity.PhaseComplete, AttackExecuted: true, OracleObserved: true, ObserverPresent: true, Scored: false,
					UnscoredReason: "UNSCORED(benign-control)", Cleanup: metricvalidity.CleanupRecord{Attempted: []metricvalidity.CleanupStep{{Step: "cataloguev1.cleanup"}}, Complete: true, Verified: true}}
				metric := cataloguev1.Metric{Scenario: string(job.Profile), Defender: "d-functional", Trial: 0, OracleAchieved: true,
					ScenarioRealism: "executable-mechanism", ScenarioBenignControl: true, ScenarioClaimLimits: definition.ClaimLimits,
					BenchmarkEvidence: map[string]string{"securityOutcome": "not-measured"}, Validity: validity}
				raw, _ := json.Marshal(metric)
				if err := os.WriteFile(filepath.Join(dir, "metrics.jsonl"), append(raw, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rm.mu.Lock()
			rm.runs[id] = &RunStatus{ID: id, State: "running", ExecutionKind: "fixed-suite"}
			rm.runOut[id] = id
			rm.active = 1
			rm.mu.Unlock()
			rm.finishFunctional(id, job, nil, false)
			status, _ := rm.Status(id)
			if status.State == "done" || status.Outcome == outcomeFunctionalPass || !status.UnsafeToRetry {
				t.Fatalf("invalid terminal promoted: %+v", status)
			}
		})
	}
}

func TestUnsafeFixedSuiteBlocksNewLaunch(t *testing.T) {
	state := t.TempDir()
	token, grant := filepath.Join(state, "token"), filepath.Join(state, "grant")
	if err := os.WriteFile(token, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grant, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: state, CatalogueV1: CatalogueV1Config{Enabled: true, LoopbackURL: "http://127.0.0.1:8090", ScopedTokenFile: token,
		AllowedTenant: "vllm", DeniedTenant: "other", DeniedTarget: "other-target", ExpectedSubject: "subject", GrantFile: grant}}
	for _, state := range []string{"partial", "done", "stopped", "error"} {
		t.Run(state, func(t *testing.T) {
			rm := NewRunManager(cfg)
			rm.mu.Lock()
			rm.runs["v1run-1"] = &RunStatus{ID: "v1run-1", State: state, ExecutionKind: "fixed-suite", UnsafeToRetry: true}
			rm.mu.Unlock()
			if _, err := rm.StartFunctional(cataloguev1.AuthUnauth, tsNow(), "owner"); err == nil || !strings.Contains(err.Error(), "requires reconciliation") {
				t.Fatalf("unsafe prior %s job did not block launch: %v", state, err)
			}
		})
	}
}
