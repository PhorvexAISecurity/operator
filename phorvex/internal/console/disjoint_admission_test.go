package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

type voiceFailureProducer struct{ profile cataloguev1.ProfileID }

func (p voiceFailureProducer) Definition() cataloguev1.Definition {
	d, _ := cataloguev1.DefinitionFor(p.profile)
	return d
}
func (voiceFailureProducer) Validate(cataloguev1.Runtime) error { return nil }
func (voiceFailureProducer) Reconcile(context.Context, cataloguev1.JobContext, cataloguev1.Journal) cataloguev1.Cleanup {
	panic("disjoint admission must not reconcile Voice")
}
func (p voiceFailureProducer) Run(_ context.Context, jc cataloguev1.JobContext) cataloguev1.Result {
	const authority = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const request = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const target = "11111111-1111-4111-8111-111111111111"
	const replacement = "22222222-2222-4222-8222-222222222222"
	const first = "CA11111111111111111111111111111111"
	const firstStream = "MZ11111111111111111111111111111111"
	const second = "CA22222222222222222222222222222222"
	const secondStream = "MZ22222222222222222222222222222222"
	identity := func(values ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i < len(values); i += 2 {
			m[values[i]] = values[i+1]
		}
		return m
	}
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	mode, phase := "normal-media", "normal"
	if p.profile == cataloguev1.VoiceRecovery {
		mode, phase = "replacement-recovery", "interrupted"
	}
	must(jc.Recorder.Intent(cataloguev1.Intent{Step: "voice.prepare", Identity: identity("operationID", jc.Job.RunID, "ownerDigest", jc.Job.OwnerDigest, "mode", mode, "namespace", "voice")}))
	must(jc.Recorder.Event(cataloguev1.Event{Step: "voice.authority", Status: "ready", Identity: identity("authoritySHA256", authority,
		"namespaceUID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "deploymentUID", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"replicaSetUID", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "serviceUID", "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		"pdbUID", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")}))
	if p.profile == cataloguev1.VoiceRecovery {
		must(jc.Recorder.Event(cataloguev1.Event{Step: "voice.eviction-authority", Status: "allowed", Identity: identity("namespace", "voice", "resource", "pods/eviction", "verb", "create")}))
	}
	sessionIntent := func(phase, sid, stream string) {
		must(jc.Recorder.Intent(cataloguev1.Intent{Step: "voice.session", Identity: identity("phase", phase, "accountSID", "AC33333333333333333333333333333333", "callSID", sid, "streamSID", stream)}))
	}
	sessionEvent := func(phase, sid, stream string) {
		must(jc.Recorder.Event(cataloguev1.Event{Step: "voice.session", Status: "complete", Identity: identity(
			"phase", phase, "callSID", sid, "streamSID", stream, "framesSent", "4", "framesReceived", "3", "bytesReceived", "1600",
			"audioSHA256", authority, "closeCode", "1000", "stopSent", "true", "forwardClosed", "true", "error", "")}))
	}
	sessionIntent(phase, first, firstStream)
	if p.profile == cataloguev1.VoiceRecovery {
		must(jc.Recorder.Intent(cataloguev1.Intent{Step: "voice.eviction", Mutation: true, Identity: identity("dispatchOrdinal", "1", "pod", "voice-bot-a", "podUID", target, "resourceVersion", "10", "requestSHA256", request, "authoritySHA256", authority)}))
		must(jc.Recorder.Event(cataloguev1.Event{Step: "voice.eviction", Status: "accepted", Identity: identity("dispatched", "true", "reason", "", "requestSHA256", request)}))
	}
	sessionEvent(phase, first, firstStream)
	if p.profile == cataloguev1.VoiceRecovery {
		sessionIntent("recovery", second, secondStream)
		sessionEvent("recovery", second, secondStream)
		must(jc.Recorder.Event(cataloguev1.Event{Step: "voice.availability", Status: "observed", Identity: identity("samples", "2", "minimumReadyPods", "2", "minimumReadyEndpoints", "2", "maximumGapSeconds", "1.000000", "scope", "sparse-samples")}))
	}
	object := "1234567890abcdef12345678"
	must(jc.Recorder.Intent(cataloguev1.Intent{Step: "voice.transcript-delete", Mutation: true, Identity: identity("callSID", first, "objectID", object, "contentSHA256", authority)}))
	must(jc.Recorder.Event(cataloguev1.Event{Step: "voice.transcript-delete", Status: "accepted", Identity: identity("callSID", first, "objectID", object, "contentSHA256", authority)}))
	must(jc.Recorder.Event(cataloguev1.Event{Step: "voice.cleanup", Status: "FAIL", Identity: identity("remaining", "1", "forwardsClosed", "true")}))
	must(jc.Recorder.Event(cataloguev1.Event{Step: "voice.terminal", Status: "FAIL_OR_INCOMPLETE", Identity: identity("operationID", jc.Job.RunID, "unsafeToRetry", "true")}))
	evidence := identity("operationID", jc.Job.RunID, "authoritySHA256", authority, "podSourceFileSHA256", voiceSourceSHA,
		"targetPodName", "voice-bot-a", "targetPodUID", target, "targetContainerID", "containerd://target",
		"targetImageID", "registry/voice@"+voiceImageSHA, "session1.phase", phase, "session1.callSID", first,
		"session1.streamSID", firstStream, "voiceOutcome", "FAIL_OR_INCOMPLETE", "sessions", "1")
	if p.profile == cataloguev1.VoiceRecovery {
		for k, v := range identity("replacementPodUID", replacement, "session2.phase", "recovery", "session2.callSID", second,
			"session2.streamSID", secondStream, "evictionDisposition", "accepted", "evictionRequestSHA256", request,
			"evictionDispatches", "1", "sessions", "2") {
			evidence[k] = v
		}
	}
	now := time.Now().UTC()
	return cataloguev1.Result{Outcome: cataloguev1.OutcomeTestFailed, Summary: "owned Voice cleanup was not verified", Evidence: evidence,
		Limits: []string{p.Definition().ClaimLimits}, Cleanup: cataloguev1.Cleanup{Attempted: true, Status: "FAIL", UnsafeToRetry: true,
			Details: identity("documentsRemaining", "1", "forwardsClosed", "true")}, UnsafeToRetry: true, StartedAt: now, FinishedAt: now.Add(time.Millisecond)}
}

func disjointFixtureConfig(t *testing.T) Config {
	t.Helper()
	cfg, _, _ := crmAdmissionConfig(t)
	cfg.CatalogueV1.VoiceEnabled = true
	cfg.CatalogueV1.VoiceNamespace = "voice"
	cfg.CatalogueV1.VoiceDeployment = "voice-bot"
	cfg.CatalogueV1.VoiceService = "voice-bot"
	cfg.CatalogueV1.VoicePDB = "voice-bot"
	cfg.CatalogueV1.VoiceContainer = "bot"
	cfg.CatalogueV1.VoiceServicePort = 8080
	cfg.CatalogueV1.TranscriptSelector = "app=voice-bot"
	cfg.CatalogueV1.TranscriptContainer = "bot"
	cfg.CatalogueV1.ChromaEnabled = true
	cfg.CatalogueV1.ChromaNamespace = "document-store"
	cfg.CatalogueV1.ChromaDeployment = "chroma"
	cfg.CatalogueV1.ChromaService = "chroma"
	cfg.CatalogueV1.ChromaContainer = "chroma"
	cfg.CatalogueV1.ChromaPort = 8000
	cfg.CatalogueV1.ChromaImageID = "docker.io/chromadb/chroma@sha256:18e67eecc172abbcd9413d751bde64983b3d167fe497c98f979083eb24c0c942"
	cfg.CatalogueV1.ChromaVersionSourceSHA256 = "5458a79347d19a5d15966a76a3a5e02bdac384ef670ff0612cc93fc788c41f44"
	cfg.CatalogueV1.ChromaServerSourceSHA256 = "8dae4ea1f3357edf75ac446bbe0e3973151a542dc6de184c7be3b6be82925c41"
	cfg.CatalogueV1.ChromaSchemaSourceSHA256 = "2b6ec7c5796309be91f9af97e3bb4379a42652550146b2dda226c801894570b1"
	cfg.CatalogueV1.LiteLLMEnabled = true
	cfg.CatalogueV1.LiteLLMNamespace = "litellm"
	cfg.CatalogueV1.LiteLLMDeployment = "litellm"
	cfg.CatalogueV1.LiteLLMService = "litellm"
	cfg.CatalogueV1.LiteLLMContainer = "litellm"
	cfg.CatalogueV1.LiteLLMPort = 4000
	cfg.CatalogueV1.LiteLLMConfigMap = "litellm-config"
	cfg.CatalogueV1.LiteLLMConfigKey = "config.yaml"
	cfg.CatalogueV1.LiteLLMConfigSHA256 = "14ebebce3b18a492a7aadb5c011bfcd71d8d16d8e8745e305b4f2336664daafb"
	return cfg
}

func writeVoiceFailureRun(t *testing.T, cfg Config, profile cataloguev1.ProfileID) (*RunStatus, map[string]string) {
	t.Helper()
	const runID = "v1run-5"
	const owner = "issuer#fixture-owner"
	dir := cfg.runOutputPath(runID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	runtime := cfg.catalogueV1RuntimeConfig()
	runtimeSHA, err := runtime.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	definition, _ := cataloguev1.DefinitionFor(profile)
	definitionSHA, _ := cataloguev1.DefinitionSHA256(definition)
	ownerHash := sha256.Sum256([]byte(owner))
	now := time.Now().UTC()
	job := cataloguev1.Job{Version: cataloguev1.JobVersion, RunID: runID, Profile: profile, OutputDir: dir,
		DefinitionSHA256: definitionSHA, OwnerDigest: hex.EncodeToString(ownerHash[:]), ResolvedTarget: "default", ResolvedTenant: "voice",
		RuntimeConfigSHA256: runtimeSHA, CreatedAt: now, Deadline: now.Add(definition.MaxDuration)}
	if err := cataloguev1.WriteRuntimeConfig(filepath.Join(dir, "runtime.json"), runtime); err != nil {
		t.Fatal(err)
	}
	if err := cataloguev1.WriteJob(filepath.Join(dir, "job.json"), cfg.StateDir, job); err != nil {
		t.Fatal(err)
	}
	runner, err := cataloguev1.New(cataloguev1.Runtime{StateDir: cfg.StateDir, ConfigSHA256: runtimeSHA, Voice: runtime.Voice}, voiceFailureProducer{profile: profile})
	if err != nil {
		t.Fatal(err)
	}
	result := runner.Execute(context.Background(), job)
	if result.Outcome != cataloguev1.OutcomeTestFailed || !result.UnsafeToRetry {
		t.Fatalf("fixture producer did not create terminal failed Voice: %+v", result)
	}
	if err := cataloguev1.ValidateTerminalArtifacts(job, result, filepath.Join(dir, "metrics.jsonl")); err != nil {
		t.Fatal(err)
	}
	st := &RunStatus{ID: runID, Config: string(profile), State: "partial", ExecutionKind: "fixed-suite", ScopeTarget: "default",
		ScopeTenant: "voice", Owner: owner, Outcome: string(result.Outcome), CleanupStatus: result.Cleanup.Status, UnsafeToRetry: true,
		Finished: tsNow()}
	seed := NewRunManager(cfg)
	if err := seed.persistStatus(st, runID); err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{}
	for _, name := range []string{"job.json", "runtime.json", "result.json", "metrics.jsonl", "journal.jsonl"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		hashes[name] = hex.EncodeToString(h[:])
	}
	return st, hashes
}

func TestDisjointAdmissionFiveProfilesRealRouterAndRetainedVoice(t *testing.T) {
	profiles := []cataloguev1.ProfileID{cataloguev1.ChromaOwnedVector, cataloguev1.LiteLLMHealth, cataloguev1.LiteLLMCredential, cataloguev1.CRMRefund, cataloguev1.CRMReset}
	for _, priorProfile := range []cataloguev1.ProfileID{cataloguev1.VoiceMedia, cataloguev1.VoiceRecovery} {
		for _, profile := range profiles {
			t.Run(string(priorProfile)+"/"+string(profile), func(t *testing.T) {
				cfg := disjointFixtureConfig(t)
				prior, hashes := writeVoiceFailureRun(t, cfg, priorProfile)
				f := newAuthFixture(t, cfg, operatorGrant("op", []string{"document-store", "litellm", "crm-fixture"}, []string{wildcardScope}))
				path := "/api/runs/functional/admission?profile=" + string(profile)
				code, admission, _ := readAdmission(t, f, path)
				if code != http.StatusOK || !admission.Launchable || admission.ReasonCode != string(functionalReady) {
					t.Fatalf("disjoint GET: code=%d admission=%+v", code, admission)
				}
				post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"`+string(profile)+`"}`, "op"))
				if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), "v1run-6") {
					t.Fatalf("disjoint POST: code=%d body=%s", post.Code, post.Body.String())
				}
				deadline := time.Now().Add(3 * time.Second)
				for {
					candidate, ok := f.srv.runs.Status("v1run-6")
					if ok && candidate.State != "running" {
						if !candidate.UnsafeToRetry {
							t.Fatal("failed candidate did not create its own unsafe latch")
						}
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("candidate worker did not finish before fixture cleanup")
					}
					time.Sleep(10 * time.Millisecond)
				}
				if _, again, _ := readAdmission(t, f, path); again.Launchable || again.ReasonCode != string(functionalPriorUnsafe) {
					t.Fatalf("new unsafe candidate did not block subsequent admission: %+v", again)
				}
				old, ok := f.srv.runs.Status(prior.ID)
				if !ok || !reflect.DeepEqual(*old, *prior) {
					t.Fatalf("prior status changed: %+v", old)
				}
				for name, want := range hashes {
					b, err := os.ReadFile(filepath.Join(cfg.runOutputPath(prior.ID), name))
					h := sha256.Sum256(b)
					if err != nil || hex.EncodeToString(h[:]) != want {
						t.Fatalf("prior %s changed: %v", name, err)
					}
				}
				loaded := NewRunManager(cfg)
				got, ok := loaded.Status(prior.ID)
				if !ok || !reflect.DeepEqual(*got, *prior) {
					t.Fatalf("prior status changed on reload: %+v", got)
				}
			})
		}
	}
}

func TestDisjointAdmissionCorruptOriginalBlocksBeforeAllocation(t *testing.T) {
	for _, name := range []string{"job.json", "runtime.json", "result.json", "metrics.jsonl", "journal.jsonl"} {
		for _, mode := range []string{"corrupt", "missing"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				cfg := disjointFixtureConfig(t)
				writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
				path := filepath.Join(cfg.runOutputPath("v1run-5"), name)
				if mode == "corrupt" {
					if err := os.WriteFile(path, []byte("corrupt\n"), 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				f := newAuthFixture(t, cfg, operatorGrant("op", []string{"litellm"}, []string{wildcardScope}))
				admissionPath := "/api/runs/functional/admission?profile=" + string(cataloguev1.LiteLLMHealth)
				code, got, _ := readAdmission(t, f, admissionPath)
				if code != http.StatusOK || got.Launchable || got.ReasonCode != string(functionalPriorUnsafe) {
					t.Fatalf("corrupt original GET: %d %+v", code, got)
				}
				post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"catalogue-litellm-route-health"}`, "op"))
				if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
					t.Fatalf("corrupt original POST: %d seq=%d", post.Code, f.srv.runs.seq)
				}
			})
		}
	}
}

func TestDisjointAdmissionRejectsForeignOrAmbiguousVoiceEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, file, from, to string
	}{
		{"unknown-journal-step", "journal.jsonl", "voice.availability", "voice.foreign"},
		{"eviction-target-uid", "journal.jsonl", "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333"},
		{"ambiguous-eviction", "journal.jsonl", `"step":"voice.eviction","status":"accepted"`, `"step":"voice.eviction","status":"unknown"`},
		{"source-hash", "result.json", voiceSourceSHA, strings.Repeat("0", 64)},
		{"runtime-route", "runtime.json", "app=voice-bot", "app=foreign"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := disjointFixtureConfig(t)
			writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
			path := filepath.Join(cfg.runOutputPath("v1run-5"), tc.file)
			raw, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(raw), tc.from) {
				t.Fatalf("producer evidence missing mutation target %q: %v", tc.from, err)
			}
			changed := strings.Replace(string(raw), tc.from, tc.to, 1)
			if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
			f := newAuthFixture(t, cfg, operatorGrant("op", []string{"document-store"}, []string{wildcardScope}))
			profile := cataloguev1.ChromaOwnedVector
			code, got, _ := readAdmission(t, f, "/api/runs/functional/admission?profile="+string(profile))
			if code != http.StatusOK || got.Launchable || got.ReasonCode != string(functionalPriorUnsafe) {
				t.Fatalf("foreign Voice evidence admitted by GET: %d %+v", code, got)
			}
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"catalogue-chroma-owned-vector"}`, "op"))
			if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
				t.Fatalf("foreign Voice evidence admitted by POST: %d seq=%d", post.Code, f.srv.runs.seq)
			}
		})
	}
}

// This is the complete earlier VoiceRecovery result projection, created by a
// real Runner/Recorder journal. Absent result fields stay absent; the journal
// still binds the interrupted/recovery sessions and eviction effect.
func omitLegacyVoiceProjection(t *testing.T, cfg Config) {
	t.Helper()
	path := filepath.Join(cfg.runOutputPath("v1run-5"), "result.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result cataloguev1.Result
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"podSourceFileSHA256", "targetPodName", "targetImageID", "targetContainerID",
		"session1.callSID", "session1.streamSID", "session2.callSID", "session2.streamSID"} {
		delete(result.Evidence, key)
	}
	raw, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDisjointAdmissionLegacyVoiceRecoveryProjection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*testing.T, Config)
		admit bool
	}{
		{"complete-old-projection", nil, true},
		{"unknown-effect-evidence", func(t *testing.T, cfg Config) {
			path := filepath.Join(cfg.runOutputPath("v1run-5"), "result.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var result cataloguev1.Result
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			result.Evidence["foreignEffect"] = "write observed outside Voice footprint"
			raw, err = json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"unknown-cleanup-detail", func(t *testing.T, cfg Config) {
			path := filepath.Join(cfg.runOutputPath("v1run-5"), "result.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var result cataloguev1.Result
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			result.Cleanup.Details["otherNamespaceRemaining"] = "1"
			raw, err = json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"mixed-projection", func(t *testing.T, cfg Config) {
			path := filepath.Join(cfg.runOutputPath("v1run-5"), "result.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var result cataloguev1.Result
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			result.Evidence["session1.callSID"] = "CA11111111111111111111111111111111"
			raw, err = json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"foreign-eviction-uid", func(t *testing.T, cfg Config) {
			path := filepath.Join(cfg.runOutputPath("v1run-5"), "journal.jsonl")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(raw), `"podUID":"11111111-1111-4111-8111-111111111111"`, `"podUID":"33333333-3333-4333-8333-333333333333"`, 1)
			if changed == string(raw) {
				t.Fatal("producer eviction UID missing")
			}
			if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"foreign-recovery-sid", func(t *testing.T, cfg Config) {
			path := filepath.Join(cfg.runOutputPath("v1run-5"), "journal.jsonl")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(raw), `"callSID":"CA22222222222222222222222222222222"`, `"callSID":"CA33333333333333333333333333333333"`, 1)
			if changed == string(raw) {
				t.Fatal("producer recovery SID missing")
			}
			if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := disjointFixtureConfig(t)
			writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
			omitLegacyVoiceProjection(t, cfg)
			if tc.edit != nil {
				tc.edit(t, cfg)
			}
			f := newAuthFixture(t, cfg, operatorGrant("op", []string{"litellm"}, []string{wildcardScope}))
			path := "/api/runs/functional/admission?profile=" + string(cataloguev1.LiteLLMHealth)
			code, got, _ := readAdmission(t, f, path)
			if code != http.StatusOK || got.Launchable != tc.admit {
				t.Fatalf("legacy GET: %d %+v", code, got)
			}
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"catalogue-litellm-route-health"}`, "op"))
			if (post.Code == http.StatusOK) != tc.admit {
				t.Fatalf("legacy POST: %d", post.Code)
			}
			if !tc.admit && f.srv.runs.seq != 5 {
				t.Fatalf("blocked legacy allocated run %d", f.srv.runs.seq)
			}
		})
	}
	t.Run("old-media-without-uid", func(t *testing.T) {
		cfg := disjointFixtureConfig(t)
		writeVoiceFailureRun(t, cfg, cataloguev1.VoiceMedia)
		path := filepath.Join(cfg.runOutputPath("v1run-5"), "result.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var result cataloguev1.Result
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"targetPodUID", "podSourceFileSHA256", "targetPodName", "targetImageID", "targetContainerID", "session1.callSID", "session1.streamSID"} {
			delete(result.Evidence, key)
		}
		raw, err = json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		f := newAuthFixture(t, cfg, operatorGrant("op", []string{"litellm"}, []string{wildcardScope}))
		if _, got, _ := readAdmission(t, f, "/api/runs/functional/admission?profile="+string(cataloguev1.LiteLLMHealth)); got.Launchable {
			t.Fatalf("UID-free legacy media admitted: %+v", got)
		}
	})
}

func TestDisjointAdmissionRetainsSecondUnsafeAndSharedLimits(t *testing.T) {
	cfg := disjointFixtureConfig(t)
	writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
	f := newAuthFixture(t, cfg, operatorGrant("op", []string{"litellm"}, []string{wildcardScope}))
	profile := cataloguev1.LiteLLMHealth
	path := "/api/runs/functional/admission?profile=" + string(profile)
	if _, got, _ := readAdmission(t, f, path); !got.Launchable {
		t.Fatalf("positive source control unavailable: %+v", got)
	}
	f.srv.runs.mu.Lock()
	f.srv.runs.active = maxConcurrentRuns
	f.srv.runs.mu.Unlock()
	if _, got, _ := readAdmission(t, f, path); got.Launchable || got.ReasonCode != string(functionalConcurrent) {
		t.Fatalf("shared concurrency bypassed: %+v", got)
	}
	f.srv.runs.mu.Lock()
	f.srv.runs.active = 0
	f.srv.runs.lastStart = time.Now()
	f.srv.runs.mu.Unlock()
	if _, got, _ := readAdmission(t, f, path); got.Launchable || got.ReasonCode != string(functionalRateLimited) {
		t.Fatalf("shared rate limit bypassed: %+v", got)
	}
	f.srv.runs.mu.Lock()
	f.srv.runs.lastStart = time.Time{}
	f.srv.runs.runs["v1run-7"] = &RunStatus{ID: "v1run-7", Config: string(cataloguev1.ChromaOwnedVector), ExecutionKind: "fixed-suite", UnsafeToRetry: true}
	f.srv.runs.mu.Unlock()
	if _, got, _ := readAdmission(t, f, path); got.Launchable || got.ReasonCode != string(functionalPriorUnsafe) {
		t.Fatalf("second unsafe predecessor bypassed: %+v", got)
	}
	post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"catalogue-litellm-route-health"}`, "op"))
	if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
		t.Fatalf("second unsafe predecessor POST: %d seq=%d", post.Code, f.srv.runs.seq)
	}
	f.srv.runs.mu.Lock()
	f.srv.runs.runs["v1run-7"].ExecutionKind = "unknown"
	f.srv.runs.mu.Unlock()
	if _, got, _ := readAdmission(t, f, path); got.Launchable || got.ReasonCode != string(functionalPriorUnsafe) {
		t.Fatalf("second unsafe unknown-kind predecessor bypassed: %+v", got)
	}
	post = f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"catalogue-litellm-route-health"}`, "op"))
	if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
		t.Fatalf("second unsafe unknown-kind predecessor POST: %d seq=%d", post.Code, f.srv.runs.seq)
	}
}

func TestDisjointAdmissionCRMVoiceNamespaceCollision(t *testing.T) {
	for _, namespace := range []string{"voice", "phorvex-system"} {
		t.Run(namespace, func(t *testing.T) {
			cfg := disjointFixtureConfig(t)
			writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
			// Build a currently valid scoped CRM authority in a forbidden namespace.
			// The disjointness gate, not a failed Kubernetes lookup, must refuse it.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
					fmt.Fprintf(w, `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview","status":{"userInfo":{"username":"system:serviceaccount:%s:fixture-sa"}}}`, namespace)
				case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+namespace:
					fmt.Fprintf(w, `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"%s","uid":"11111111-1111-4111-8111-111111111111","labels":{"phorvex.ai/crm-capability-fixture":"true"}}}`, namespace)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			cfg.CatalogueV1.CRMNamespace = namespace
			kube := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: fixture\n  cluster:\n    server: %s\ncontexts:\n- name: fixture\n  context:\n    cluster: fixture\n    user: fixture\ncurrent-context: fixture\nusers:\n- name: fixture\n  user:\n    token: fixture-token\n", server.URL)
			if err := os.WriteFile(cfg.CatalogueV1.CRMKubeconfigPath, []byte(kube), 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(kube))
			cfg.CatalogueV1.CRMKubeconfigSHA256 = hex.EncodeToString(sum[:])
			if _, _, err := NewRunManager(cfg).functionalInputs(cataloguev1.CRMRefund); err != nil {
				t.Fatalf("CRM authority counterexample did not reach disjoint predicate: %v", err)
			}
			f := newAuthFixture(t, cfg, operatorGrant("op", []string{namespace}, []string{wildcardScope}))
			path := "/api/runs/functional/admission?profile=" + string(cataloguev1.CRMRefund)
			code, got, _ := readAdmission(t, f, path)
			if code != http.StatusOK || got.Launchable || got.ReasonCode != string(functionalPriorUnsafe) {
				t.Fatalf("CRM forbidden namespace collision admitted by GET: %d %+v", code, got)
			}
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"c2-crm-refund-capability"}`, "op"))
			if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
				t.Fatalf("CRM forbidden namespace collision admitted by POST: %d seq=%d", post.Code, f.srv.runs.seq)
			}
		})
	}
}

func TestDisjointAdmissionRejectsChangedOriginalStatusAndCurrentVoiceRoute(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*RunStatus, *Config)
	}{
		{"owner", func(st *RunStatus, _ *Config) { st.Owner = "issuer#other" }},
		{"target", func(st *RunStatus, _ *Config) { st.ScopeTarget = "foreign" }},
		{"tenant", func(st *RunStatus, _ *Config) { st.ScopeTenant = "foreign" }},
		{"profile", func(st *RunStatus, _ *Config) { st.Config = string(cataloguev1.GPUDrain) }},
		{"state", func(st *RunStatus, _ *Config) { st.State = "running" }},
		{"finish", func(st *RunStatus, _ *Config) { st.Finished = "" }},
		{"voice-route", func(_ *RunStatus, cfg *Config) { cfg.CatalogueV1.VoiceNamespace = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := disjointFixtureConfig(t)
			prior, _ := writeVoiceFailureRun(t, cfg, cataloguev1.VoiceRecovery)
			tc.edit(prior, &cfg)
			if tc.name != "voice-route" {
				if err := NewRunManager(cfg).persistStatus(prior, prior.ID); err != nil {
					t.Fatal(err)
				}
			}
			f := newAuthFixture(t, cfg, operatorGrant("op", []string{"litellm"}, []string{wildcardScope}))
			profile := cataloguev1.LiteLLMCredential
			code, got, _ := readAdmission(t, f, "/api/runs/functional/admission?profile="+string(profile))
			if code != http.StatusOK || got.Launchable || got.ReasonCode != string(functionalPriorUnsafe) {
				t.Fatalf("changed source status/route GET: %d %+v", code, got)
			}
			post := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/functional", `{"profile":"catalogue-litellm-credential-boundary"}`, "op"))
			if post.Code != http.StatusBadRequest || f.srv.runs.seq != 5 {
				t.Fatalf("changed source status/route POST: %d seq=%d", post.Code, f.srv.runs.seq)
			}
		})
	}
}
