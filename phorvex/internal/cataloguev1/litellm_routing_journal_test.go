package cataloguev1

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A complete local HTTP run is persisted by the real Runner. Each adverse
// control changes a copy of those original records, then replays the same
// consumer that the runner uses before accepting a routing result.
func TestLiteLLMRoutingOriginalJournalConsumer(t *testing.T) {
	respond := routingValidPair(t)
	runtime, transport, _, podA, podB := routingRunFixture(t, respond, respond)
	runtime.StateDir = t.TempDir()
	config := RuntimeConfig{Version: RuntimeConfigVersion, StateDir: runtime.StateDir, LiteLLM: &runtime.LiteLLM}
	runtimeHash, err := config.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	runtime.ConfigSHA256 = runtimeHash
	runner, err := New(runtime, liteRoutingHandler{transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	job := liteJobForTest(t, runtime, LiteLLMRouting)
	job.RuntimeConfigSHA256 = runtimeHash
	if err := WriteRuntimeConfig(filepath.Join(job.OutputDir, "runtime.json"), config); err != nil {
		t.Fatal(err)
	}
	result := runner.Execute(context.Background(), job)
	if result.Outcome != OutcomeFunctionalPass {
		t.Fatalf("original four-request run: %s: %s", result.Outcome, result.Summary)
	}
	if err := ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); err != nil {
		t.Fatalf("shared terminal consumer: %v", err)
	}
	if err := ValidateLiteLLMRoutingArtifacts(job, result); err != nil {
		t.Fatalf("original journal consumer: %v", err)
	}
	if len(podA.requestedModels()) != 2 || len(podB.requestedModels()) != 2 {
		t.Fatal("runner did not issue exactly two requests per Pod")
	}
	journal, err := loadJournal(filepath.Join(job.OutputDir, "journal.jsonl"))
	if err != nil || len(journal.Records) != 8 {
		t.Fatalf("original journal has %d records: %v", len(journal.Records), err)
	}

	clone := func(t *testing.T) (Job, Result, Journal) {
		t.Helper()
		copyJob := job
		copyJob.OutputDir = t.TempDir()
		copyResult := result
		copyResult.Evidence = make(map[string]string, len(result.Evidence))
		for key, value := range result.Evidence {
			copyResult.Evidence[key] = value
		}
		var copyJournal Journal
		raw, err := json.Marshal(journal)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &copyJournal); err != nil {
			t.Fatal(err)
		}
		return copyJob, copyResult, copyJournal
	}
	write := func(t *testing.T, copyJob Job, records []JournalRecord) {
		t.Helper()
		var raw []byte
		for _, record := range records {
			line, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, append(line, '\n')...)
		}
		if err := os.WriteFile(filepath.Join(copyJob.OutputDir, "journal.jsonl"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		change func(Result, *Journal)
	}{
		{"event-reason", func(_ Result, j *Journal) { j.Records[1].Event.Identity["reason"] = "OTHER_REDACTED" }},
		{"event-status", func(_ Result, j *Journal) { j.Records[1].Event.Identity["httpStatus"] = "500" }},
		{"event-body-hash", func(_ Result, j *Journal) { j.Records[1].Event.Identity["bodySHA256"] = strings.Repeat("0", 64) }},
		{"event-model-hash", func(_ Result, j *Journal) {
			j.Records[1].Event.Identity["returnedModelSHA256"] = strings.Repeat("0", 64)
		}},
		{"event-model-relation", func(_ Result, j *Journal) { j.Records[1].Event.Identity["modelRelation"] = "OTHER_REDACTED" }},
		{"event-pod-uid", func(_ Result, j *Journal) { j.Records[1].Event.Identity["podUID"] = "other-pod" }},
		{"known-intent-alias", func(_ Result, j *Journal) { j.Records[0].Intent.Identity["modelAlias"] = "gpt-3.5-turbo" }},
		{"unknown-intent-alias", func(_ Result, j *Journal) { j.Records[2].Intent.Identity["modelAlias"] = "gpt-4o-mini" }},
		{"forged-alias-and-returned-model", func(r Result, j *Journal) {
			r.Evidence["modelAlias"] = "sk-synthetic-model"
			for _, pair := range []struct{ intent, event int }{{0, 1}, {4, 5}} {
				j.Records[pair.intent].Intent.Identity["modelAlias"] = "sk-synthetic-model"
				j.Records[pair.event].Event.Identity["returnedModel"] = "sk-synthetic-model"
			}
			r.Evidence["pod1.known.returnedModel"] = "sk-synthetic-model"
			r.Evidence["pod2.known.returnedModel"] = "sk-synthetic-model"
		}},
		{"missing-event", func(_ Result, j *Journal) { j.Records = append(j.Records[:1], j.Records[2:]...) }},
		{"duplicate-pod-stage", func(_ Result, j *Journal) {
			// Replace Pod 2's known pair with a second copy of Pod 1's known
			// pair. Four syntactically complete pairs alone are insufficient.
			j.Records[4] = j.Records[0]
			j.Records[5] = j.Records[1]
		}},
		{"terminal-reason", func(r Result, _ *Journal) { r.Evidence["pod1.known.reason"] = "OTHER_REDACTED" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyJob, copyResult, copyJournal := clone(t)
			tc.change(copyResult, &copyJournal)
			if err := WriteRuntimeConfig(filepath.Join(copyJob.OutputDir, "runtime.json"), config); err != nil {
				t.Fatal(err)
			}
			write(t, copyJob, copyJournal.Records)
			if err := ValidateLiteLLMRoutingArtifacts(copyJob, copyResult); err == nil {
				t.Fatal("altered original journal or terminal result was accepted")
			}
		})
	}
	t.Run("forged-functional-fail-with-no-original-requests", func(t *testing.T) {
		copyJob, copyResult, _ := clone(t)
		copyResult.Outcome = OutcomeFunctionalFail
		copyResult.Evidence["requestCount"] = "0"
		copyResult.Evidence["unknownModelState"] = "UNVERIFIED"
		if err := ValidateLiteLLMRoutingArtifacts(copyJob, copyResult); err == nil {
			t.Fatal("functional failure credited without an original request journal")
		}
	})
	t.Run("forged-functional-fail-over-original-typed-rejections", func(t *testing.T) {
		copyJob, copyResult, copyJournal := clone(t)
		copyResult.Outcome = OutcomeFunctionalFail
		copyResult.Evidence["unknownModelState"] = "UNVERIFIED"
		write(t, copyJob, copyJournal.Records)
		if err := WriteRuntimeConfig(filepath.Join(copyJob.OutputDir, "runtime.json"), config); err != nil {
			t.Fatal(err)
		}
		if err := ValidateLiteLLMRoutingArtifacts(copyJob, copyResult); err == nil {
			t.Fatal("functional failure credited without an original unknown-model completion")
		}
	})
}

func TestLiteLLMRoutingRunnerRetainsRedactedModelsAndUnknownFallback(t *testing.T) {
	for _, tc := range []struct {
		name, knownReturned, unknownReturned string
		outcome                              Outcome
	}{
		{"versioned-known", "openai/gpt-4o-mini-2026-09-25", "", OutcomeFunctionalPass},
		{"secret-echo-known", routingSyntheticMasterKey, "", OutcomeFunctionalPass},
		{"unknown-falls-back-to-known", routingKnownAlias, routingKnownAlias, OutcomeFunctionalFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			respond := func(alias string) routingFixtureReply {
				if alias == routingKnownAlias {
					return routingValidCompletion(t, tc.knownReturned)
				}
				if tc.unknownReturned != "" {
					return routingValidCompletion(t, tc.unknownReturned)
				}
				return routingTypedError(t, 404, "ModelNotFoundError", "model_not_found", "unknown model")
			}
			runtime, transport, _, podA, podB := routingRunFixture(t, respond, respond)
			runtime.StateDir = t.TempDir()
			config := RuntimeConfig{Version: RuntimeConfigVersion, StateDir: runtime.StateDir, LiteLLM: &runtime.LiteLLM}
			sha, err := config.SHA256()
			if err != nil {
				t.Fatal(err)
			}
			runtime.ConfigSHA256 = sha
			runner, err := New(runtime, liteRoutingHandler{transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			job := liteJobForTest(t, runtime, LiteLLMRouting)
			job.RuntimeConfigSHA256 = sha
			if err := WriteRuntimeConfig(filepath.Join(job.OutputDir, "runtime.json"), config); err != nil {
				t.Fatal(err)
			}
			result := runner.Execute(context.Background(), job)
			if result.Outcome != tc.outcome || result.Evidence["requestCount"] != "4" || len(podA.requestedModels()) != 2 || len(podB.requestedModels()) != 2 {
				t.Fatalf("returned-model result: %s, %s, evidence=%v", result.Outcome, result.Summary, result.Evidence)
			}
			if err := ValidateLiteLLMRoutingArtifacts(job, result); err != nil {
				t.Fatal(err)
			}
			if err := ValidateTerminalArtifacts(job, result, filepath.Join(job.OutputDir, "metrics.jsonl")); err != nil {
				t.Fatal(err)
			}
			journalBytes, err := os.ReadFile(filepath.Join(job.OutputDir, "journal.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			retained, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(journalBytes), routingSyntheticMasterKey) || strings.Contains(string(retained), routingSyntheticMasterKey) ||
				(tc.knownReturned != routingKnownAlias && (strings.Contains(string(journalBytes), tc.knownReturned) || strings.Contains(string(retained), tc.knownReturned))) {
				t.Fatal("returned model or synthetic credential retained in original journal/result")
			}
			if tc.outcome == OutcomeFunctionalFail && result.Evidence["pod1.unknown.status"] != "200" {
				t.Fatal("unknown-model fallback did not preserve the observed 200")
			}
		})
	}
}
