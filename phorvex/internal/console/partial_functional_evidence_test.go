package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/metricvalidity"
	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func partialFunctionalFixture(t *testing.T, outcome cataloguev1.Outcome, cleanup cataloguev1.Cleanup, processErr error) (*RunManager, string, cataloguev1.Result) {
	t.Helper()
	state := t.TempDir()
	cfg := Config{StateDir: state}
	rm := NewRunManager(cfg)
	id := "v1run-1"
	dir := cfg.runOutputPath(id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	definition, err := cataloguev1.DefinitionFor(cataloguev1.AuthUnauth)
	if err != nil {
		t.Fatal(err)
	}
	definitionHash, err := cataloguev1.DefinitionSHA256(definition)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	job := cataloguev1.Job{Version: cataloguev1.JobVersion, RunID: id, Profile: cataloguev1.AuthUnauth, OutputDir: dir,
		DefinitionSHA256: definitionHash, OwnerDigest: strings.Repeat("a", 64), ResolvedTarget: "default", ResolvedTenant: "vllm",
		RuntimeConfigSHA256: strings.Repeat("b", 64), CreatedAt: now, Deadline: now.Add(time.Minute)}
	if err := cataloguev1.WriteJob(filepath.Join(dir, "job.json"), state, job); err != nil {
		t.Fatal(err)
	}
	result := cataloguev1.Result{Version: cataloguev1.ResultVersion, RunID: id, Profile: job.Profile,
		DefinitionSHA256: definitionHash, OwnerDigest: job.OwnerDigest, ResolvedTarget: job.ResolvedTarget,
		ResolvedTenant: job.ResolvedTenant, RuntimeConfigSHA256: job.RuntimeConfigSHA256,
		Outcome: outcome, Summary: "Voice owned cleanup was not verified", Evidence: map[string]string{"error": "owned Voice cleanup was not verified"},
		Cleanup: cleanup, UnsafeToRetry: !cleanup.Verified, StartedAt: now, FinishedAt: now.Add(time.Second)}
	if outcome == cataloguev1.OutcomeFunctionalPass {
		result.Summary = "bounded functional oracle completed"
		result.Evidence = map[string]string{"oracle": "complete"}
	}
	writePartialFixtureJSON(t, filepath.Join(dir, "result.json"), result)
	validityStatus := metricvalidity.StatusInvalid
	validityPhase := metricvalidity.PhaseCleanup
	if outcome == cataloguev1.OutcomeFunctionalPass {
		validityStatus, validityPhase = metricvalidity.StatusValid, metricvalidity.PhaseComplete
	}
	metric := cataloguev1.Metric{Scenario: string(job.Profile), Defender: "d-functional", Trial: 0,
		OracleAchieved: outcome == cataloguev1.OutcomeFunctionalPass, ScenarioRealism: "executable-mechanism", ScenarioBenignControl: true,
		ScenarioClaimLimits: definition.ClaimLimits, BenchmarkEvidence: map[string]string{"securityOutcome": "not-measured"},
		Validity: &metricvalidity.Validity{Version: metricvalidity.Version, Kind: metricvalidity.TrialOrdinary,
			Status: validityStatus, Phase: validityPhase, AttackExecuted: true, OracleObserved: outcome == cataloguev1.OutcomeFunctionalPass,
			ObserverPresent: true, Scored: false, UnscoredReason: "UNSCORED(benign-control)",
			Cleanup: metricvalidity.CleanupRecord{Attempted: []metricvalidity.CleanupStep{{Step: "cataloguev1.cleanup"}},
				Complete: cleanup.Verified, Verified: cleanup.Verified}}}
	writePartialFixtureJSON(t, filepath.Join(dir, "metrics.jsonl"), metric)
	rm.mu.Lock()
	rm.runs[id] = &RunStatus{ID: id, Config: string(job.Profile), State: "running", ExecutionKind: "fixed-suite", ClaimClass: "functional"}
	rm.runOut[id] = id
	rm.active = 1
	rm.mu.Unlock()
	rm.finishFunctional(id, job, processErr, false)
	return rm, dir, result
}

func writePartialFixtureJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func partialFunctionalAPI(t *testing.T, rm *RunManager, id string) map[string]json.RawMessage {
	t.Helper()
	s := &Server{cfg: rm.cfg, runs: rm}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/runs/evidence?id="+id, nil)
	s.runEvidence(w, r.WithContext(withRunID(r.Context(), id)))
	if w.Code != http.StatusOK {
		t.Fatalf("evidence HTTP %d: %s", w.Code, w.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestPartialFixedSuiteExposesValidatedFailureWithoutCreditingOracle(t *testing.T) {
	rm, _, _ := partialFunctionalFixture(t, cataloguev1.OutcomeTestFailed,
		cataloguev1.Cleanup{Attempted: true, Status: "FAIL", UnsafeToRetry: true, Details: map[string]string{"forwardsClosed": "true", "documentsRemaining": "0"}},
		errors.New("exit status 1"))
	status, _ := rm.Status("v1run-1")
	if status.State != "partial" || status.Outcome != "test-failed" || status.CleanupStatus != "FAIL" || !status.UnsafeToRetry {
		t.Fatalf("real terminal status differs: %+v", status)
	}
	result, err := rm.FunctionalResult("v1run-1")
	if err != nil || result == nil || result.Summary != "Voice owned cleanup was not verified" || result.Cleanup.Status != "FAIL" {
		t.Fatalf("validated partial failure hidden: result=%+v err=%v", result, err)
	}
	api := partialFunctionalAPI(t, rm, "v1run-1")
	var functional struct {
		Outcome       string              `json:"outcome"`
		Summary       string              `json:"summary"`
		Cleanup       cataloguev1.Cleanup `json:"cleanup"`
		UnsafeToRetry bool                `json:"unsafeToRetry"`
	}
	if err := json.Unmarshal(api["functionalResult"], &functional); err != nil {
		t.Fatal(err)
	}
	if functional.Outcome != "test-failed" || functional.Cleanup.Status != "FAIL" || !functional.UnsafeToRetry {
		t.Fatalf("API failed to retain typed partial cause: %+v", functional)
	}
	var trials []json.RawMessage
	if err := json.Unmarshal(api["trials"], &trials); err != nil || len(trials) != 0 {
		t.Fatalf("partial metric was credited: trials=%s err=%v", api["trials"], err)
	}
}

func TestCompletedFixedSuiteStillExposesValidatedFunctionalPass(t *testing.T) {
	rm, _, _ := partialFunctionalFixture(t, cataloguev1.OutcomeFunctionalPass,
		cataloguev1.Cleanup{Attempted: true, Verified: true, Status: "PASS"}, nil)
	status, _ := rm.Status("v1run-1")
	if status.State != "done" || status.Outcome != "functional-pass" || status.UnsafeToRetry {
		t.Fatalf("completed functional control changed: %+v", status)
	}
	result, err := rm.FunctionalResult("v1run-1")
	if err != nil || result == nil || result.Outcome != cataloguev1.OutcomeFunctionalPass {
		t.Fatalf("completed result unavailable: result=%+v err=%v", result, err)
	}
	api := partialFunctionalAPI(t, rm, "v1run-1")
	if string(api["functionalResult"]) == "null" {
		t.Fatal("completed functional result absent from evidence endpoint")
	}
}

func TestPartialFixedSuiteProjectsAuthoritativeRunUnsafeWithoutRewritingResult(t *testing.T) {
	rm, dir, _ := partialFunctionalFixture(t, cataloguev1.OutcomeTestFailed,
		cataloguev1.Cleanup{Attempted: true, Verified: true, Status: "PASS"},
		errors.New("worker exited after terminal result"))
	status, _ := rm.Status("v1run-1")
	if status.State != "partial" || status.Outcome != "test-failed" || status.CleanupStatus != "PASS" || !status.UnsafeToRetry {
		t.Fatalf("real process failure did not retain unsafe partial status: %+v", status)
	}
	rawBefore, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original cataloguev1.Result
	if err := json.Unmarshal(rawBefore, &original); err != nil || original.UnsafeToRetry {
		t.Fatalf("fixture did not retain producer's false unsafe flag: %+v err=%v", original, err)
	}
	projected, err := rm.FunctionalResult("v1run-1")
	if err != nil || projected == nil || !projected.UnsafeToRetry || projected.Cleanup.Status != "PASS" {
		t.Fatalf("authoritative unsafe state lost in typed projection: result=%+v err=%v", projected, err)
	}
	api := partialFunctionalAPI(t, rm, "v1run-1")
	var functional struct {
		UnsafeToRetry bool `json:"unsafeToRetry"`
	}
	if err := json.Unmarshal(api["functionalResult"], &functional); err != nil || !functional.UnsafeToRetry {
		t.Fatalf("HTTP projection hid partial retry risk: %s err=%v", api["functionalResult"], err)
	}
	var trials []json.RawMessage
	if err := json.Unmarshal(api["trials"], &trials); err != nil || len(trials) != 0 {
		t.Fatalf("partial failed result gained metric credit: trials=%s err=%v", api["trials"], err)
	}
	rawAfter, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil || string(rawAfter) != string(rawBefore) {
		t.Fatalf("read-only projection rewrote original producer result: err=%v", err)
	}
}

func TestPartialFixedSuiteRejectsMissingStaleAndPassArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *RunManager, string)
	}{
		{"missing-result", func(t *testing.T, _ *RunManager, dir string) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, "result.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-metric", func(t *testing.T, _ *RunManager, dir string) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, "metrics.jsonl")); err != nil {
				t.Fatal(err)
			}
		}},
		{"stale-status", func(_ *testing.T, rm *RunManager, _ string) {
			rm.mu.Lock()
			rm.runs["v1run-1"].Outcome = "inconclusive"
			rm.mu.Unlock()
		}},
		{"wrong-job", func(t *testing.T, _ *RunManager, dir string) {
			t.Helper()
			raw, err := os.ReadFile(filepath.Join(dir, "job.json"))
			if err != nil {
				t.Fatal(err)
			}
			var job cataloguev1.Job
			if err := json.Unmarshal(raw, &job); err != nil {
				t.Fatal(err)
			}
			job.OwnerDigest = strings.Repeat("c", 64)
			writePartialFixtureJSON(t, filepath.Join(dir, "job.json"), job)
		}},
		{"wrong-result", func(t *testing.T, _ *RunManager, dir string) {
			t.Helper()
			raw, err := os.ReadFile(filepath.Join(dir, "result.json"))
			if err != nil {
				t.Fatal(err)
			}
			var result cataloguev1.Result
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			result.RunID = "v1run-9"
			writePartialFixtureJSON(t, filepath.Join(dir, "result.json"), result)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rm, dir, _ := partialFunctionalFixture(t, cataloguev1.OutcomeTestFailed,
				cataloguev1.Cleanup{Attempted: true, Status: "FAIL", UnsafeToRetry: true}, errors.New("exit status 1"))
			tc.mutate(t, rm, dir)
			if result, err := rm.FunctionalResult("v1run-1"); err == nil || result != nil {
				t.Fatalf("unverified partial artifact accepted: result=%+v err=%v", result, err)
			}
			api := partialFunctionalAPI(t, rm, "v1run-1")
			if string(api["functionalResult"]) != "null" {
				t.Fatalf("unverified partial artifact projected: %s", api["functionalResult"])
			}
		})
	}
	rm, _, _ := partialFunctionalFixture(t, cataloguev1.OutcomeFunctionalPass,
		cataloguev1.Cleanup{Attempted: true, Verified: true, Status: "PASS"}, errors.New("worker exited after terminal result"))
	status, _ := rm.Status("v1run-1")
	if status.State != "partial" || !status.UnsafeToRetry {
		t.Fatalf("positive oracle process failure did not stay partial: %+v", status)
	}
	if result, err := rm.FunctionalResult("v1run-1"); err == nil || result != nil {
		t.Fatalf("partial functional pass was promoted: result=%+v err=%v", result, err)
	}
}
