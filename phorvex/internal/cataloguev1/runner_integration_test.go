package cataloguev1

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type runnerTestHandler struct {
	outcome        Outcome
	emitPassMetric bool
	runs           *int
	reconciles     *int
}

func (h runnerTestHandler) Definition() Definition {
	definition, _ := DefinitionFor(AuthUnauth)
	return definition
}
func (runnerTestHandler) Validate(Runtime) error { return nil }
func (h runnerTestHandler) Run(_ context.Context, jc JobContext) Result {
	if h.runs != nil {
		(*h.runs)++
	}
	if h.emitPassMetric {
		_ = jc.Recorder.Metric(metricFor(h.Definition(), Result{Outcome: OutcomeFunctionalPass, Cleanup: Cleanup{Attempted: true, Verified: true, Status: "PASS"}}))
	}
	return Result{Outcome: h.outcome, Summary: "bounded test outcome", Cleanup: Cleanup{Attempted: true, Verified: true, Status: "PASS"}}
}
func (h runnerTestHandler) Reconcile(context.Context, JobContext, Journal) Cleanup {
	if h.reconciles != nil {
		(*h.reconciles)++
	}
	return Cleanup{Attempted: true, Verified: true, Status: "PASS"}
}

func runnerTestJob(t *testing.T, runtime Runtime, handler Handler) Job {
	t.Helper()
	dir := filepath.Join(runtime.StateDir, "runs", "v1run-1")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	definitionHash, err := DefinitionSHA256(handler.Definition())
	if err != nil {
		t.Fatal(err)
	}
	return Job{Version: JobVersion, RunID: "v1run-1", Profile: AuthUnauth, OutputDir: dir,
		DefinitionSHA256: definitionHash, OwnerDigest: strings.Repeat("a", 64),
		ResolvedTarget: "default", ResolvedTenant: "vllm", RuntimeConfigSHA256: runtime.ConfigSHA256,
		CreatedAt: time.Now().UTC(), Deadline: time.Now().UTC().Add(time.Minute)}
}

func TestRunnerPublishesBoundTerminalResultAndMetric(t *testing.T) {
	runtime := Runtime{StateDir: t.TempDir(), ConfigSHA256: strings.Repeat("b", 64), AllowedTenant: "vllm"}
	handler := runnerTestHandler{outcome: OutcomeFunctionalPass}
	runner, err := New(runtime, handler)
	if err != nil {
		t.Fatal(err)
	}
	job := runnerTestJob(t, runtime, handler)
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeFunctionalPass {
		t.Fatalf("outcome=%s summary=%s", result.Outcome, result.Summary)
	}
	if err := ValidateResult(job, result); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(job.OutputDir, "metrics.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"verified":true`, `"verified":false`, 1))
	if err = os.WriteFile(filepath.Join(job.OutputDir, "metrics.jsonl"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); err == nil {
		t.Fatal("cleanup disagreement was accepted")
	}
}

func TestTerminalFailureDemotesEarlierValidMetric(t *testing.T) {
	runtime := Runtime{StateDir: t.TempDir(), ConfigSHA256: strings.Repeat("c", 64), AllowedTenant: "vllm"}
	handler := runnerTestHandler{outcome: OutcomeTestFailed, emitPassMetric: true}
	runner, err := New(runtime, handler)
	if err != nil {
		t.Fatal(err)
	}
	job := runnerTestJob(t, runtime, handler)
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeTestFailed {
		t.Fatalf("outcome=%s", result.Outcome)
	}
	if err := ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); err != nil {
		t.Fatal(err)
	}
}

func TestInconclusiveProducesInvalidNonSecurityMetric(t *testing.T) {
	runtime := Runtime{StateDir: t.TempDir(), ConfigSHA256: strings.Repeat("d", 64), AllowedTenant: "vllm"}
	handler := runnerTestHandler{outcome: OutcomeInconclusive}
	runner, err := New(runtime, handler)
	if err != nil {
		t.Fatal(err)
	}
	job := runnerTestJob(t, runtime, handler)
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeInconclusive {
		t.Fatalf("outcome=%s", result.Outcome)
	}
	if err := ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); err != nil {
		t.Fatal(err)
	}
}

func TestReconcileNeverReplaysHandlerRun(t *testing.T) {
	runs, reconciles := 0, 0
	runtime := Runtime{StateDir: t.TempDir(), ConfigSHA256: strings.Repeat("e", 64), AllowedTenant: "vllm"}
	handler := runnerTestHandler{outcome: OutcomeFunctionalPass, runs: &runs, reconciles: &reconciles}
	runner, err := New(runtime, handler)
	if err != nil {
		t.Fatal(err)
	}
	job := runnerTestJob(t, runtime, handler)
	job.CreatedAt = time.Now().Add(-2 * time.Minute)
	job.Deadline = time.Now().Add(-time.Minute)
	if err = os.WriteFile(filepath.Join(job.OutputDir, "journal.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	result := runner.Reconcile(context.Background(), job)
	if runs != 0 || reconciles != 1 {
		t.Fatalf("runs=%d reconciles=%d", runs, reconciles)
	}
	if result.Outcome != OutcomeInconclusive || !result.Cleanup.Verified {
		t.Fatalf("result=%+v", result)
	}
}

func TestExecuteRejectsResolvedAuthorityBeforeHandler(t *testing.T) {
	runs := 0
	runtime := Runtime{StateDir: t.TempDir(), ConfigSHA256: strings.Repeat("f", 64), AllowedTenant: "vllm"}
	handler := runnerTestHandler{outcome: OutcomeFunctionalPass, runs: &runs}
	runner, err := New(runtime, handler)
	if err != nil {
		t.Fatal(err)
	}
	job := runnerTestJob(t, runtime, handler)
	job.ResolvedTenant = "foreign"
	result := runner.Execute(context.Background(), job)
	if runs != 0 || result.Outcome != OutcomeTestFailed {
		t.Fatalf("runs=%d result=%+v", runs, result)
	}
}
